###############################################################################
# Athena threat hunting (plan §6.1, FR-8)
#   * workgroup <name>-cs-forensics: settings ENFORCED, so a client cannot
#     lift the per-query scan cap or write unencrypted results
#   * Glue tables with partition projection: no crawlers, no MSCK REPAIR,
#     and a query only lists the partitions its WHERE clause selects
#   * one named query per detection/athena-queries/*.sql
###############################################################################

locals {
  glue_database = replace("${var.name}_forensics", "-", "_")
  archive       = "s3://${var.log_archive_bucket_name}"
  queries_dir   = "${path.module}/../../../../detection/athena-queries"
  query_files   = fileset(local.queries_dir, "*.sql")

  date_projection = {
    "type"          = "date"
    "format"        = "yyyy/MM/dd"
    "range"         = "${var.projection_start_date},NOW"
    "interval"      = "1"
    "interval.unit" = "DAYS"
  }
}

# -----------------------------------------------------------------------------
# Query results: own key + bucket (results contain log excerpts = sensitive)
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "athena_kms" {
  #checkov:skip=CKV_AWS_111:Key policy — Resource "*" means "this key"
  #checkov:skip=CKV_AWS_356:Key policy — Resource "*" is the only valid value inside a KMS key policy
  #checkov:skip=CKV_AWS_109:Root kms:* is the AWS default key-policy baseline; access is then granted by IAM
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "athena" {
  description             = "${var.name} Athena forensics query results"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.athena_kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "athena" {
  name          = "alias/${var.name}-athena-forensics"
  target_key_id = aws_kms_key.athena.key_id
}

resource "aws_s3_bucket" "athena_results" {
  #checkov:skip=CKV_AWS_18:Query results are transient (expire after var.athena_results_retention_days); Athena's own query history is the audit trail
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope (single-region by design, plan §1.2)
  #checkov:skip=CKV2_AWS_62:No event-driven processing of query results
  #checkov:skip=CKV_AWS_21:Versioning would keep every expired result; results are reproducible by re-running the query
  bucket        = "${var.name}-athena-results-${local.account_id}-${local.region}"
  force_destroy = var.athena_results_force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.athena.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    id     = "expire-results"
    status = "Enabled"
    filter {}
    expiration { days = var.athena_results_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

data "aws_iam_policy_document" "athena_results" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.athena_results.arn, "${aws_s3_bucket.athena_results.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "athena_results" {
  bucket     = aws_s3_bucket.athena_results.id
  policy     = data.aws_iam_policy_document.athena_results.json
  depends_on = [aws_s3_bucket_public_access_block.athena_results]
}

# -----------------------------------------------------------------------------
# Workgroup
# -----------------------------------------------------------------------------
resource "aws_athena_workgroup" "forensics" {
  name          = "${var.name}-cs-forensics"
  description   = "CloudShield forensics / threat hunting (FR-8). Scan cap and encryption are enforced."
  force_destroy = true # saved queries are recreated from detection/athena-queries

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = var.athena_bytes_scanned_cutoff

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.athena.arn
      }
    }
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Glue catalog
# -----------------------------------------------------------------------------
resource "aws_glue_catalog_database" "forensics" {
  name        = local.glue_database
  description = "CloudShield log archive tables (partition projection)."
}

# CloudTrail — AWS-documented CloudTrail SerDe layout.
resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail"
  database_name = aws_glue_catalog_database.forensics.name
  table_type    = "EXTERNAL_TABLE"

  parameters = merge(
    {
      "EXTERNAL"                  = "TRUE"
      "classification"            = "cloudtrail"
      "projection.enabled"        = "true"
      "projection.region.type"    = "enum"
      "projection.region.values"  = join(",", distinct(concat([local.region], var.cloudtrail_regions)))
      "storage.location.template" = "${local.archive}/cloudtrail/AWSLogs/${local.account_id}/CloudTrail/$${region}/$${timestamp}"
    },
    { for k, v in local.date_projection : "projection.timestamp.${k}" => v },
  )

  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "timestamp"
    type = "string"
  }

  storage_descriptor {
    location      = "${local.archive}/cloudtrail/AWSLogs/${local.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>,sourceidentity:string,ec2roledelivery:string>>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "readonly"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }
    columns {
      name = "eventtype"
      type = "string"
    }
    columns {
      name = "recipientaccountid"
      type = "string"
    }
    columns {
      name = "sharedeventid"
      type = "string"
    }
    columns {
      name = "vpcendpointid"
      type = "string"
    }
    columns {
      name = "eventcategory"
      type = "string"
    }
    columns {
      name = "tlsdetails"
      type = "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>"
    }
  }
}

# VPC Flow Logs — Parquet, Hive-style keys (modules/network). The fixed
# aws-account-id= / aws-service= / aws-region= segments are part of the
# template rather than (hyphenated) partition keys.
resource "aws_glue_catalog_table" "vpc_flow_logs" {
  name          = "vpc_flow_logs"
  database_name = aws_glue_catalog_database.forensics.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"                  = "TRUE"
    "classification"            = "parquet"
    "projection.enabled"        = "true"
    "projection.year.type"      = "integer"
    "projection.year.range"     = "${substr(var.projection_start_date, 0, 4)},2035"
    "projection.month.type"     = "integer"
    "projection.month.range"    = "1,12"
    "projection.month.digits"   = "2"
    "projection.day.type"       = "integer"
    "projection.day.range"      = "1,31"
    "projection.day.digits"     = "2"
    "projection.hour.type"      = "integer"
    "projection.hour.range"     = "0,23"
    "projection.hour.digits"    = "2"
    "storage.location.template" = "${local.archive}/vpc-flow-logs/AWSLogs/aws-account-id=${local.account_id}/aws-service=vpcflowlogs/aws-region=${local.region}/year=$${year}/month=$${month}/day=$${day}/hour=$${hour}"
  }

  dynamic "partition_keys" {
    for_each = ["year", "month", "day", "hour"]
    content {
      name = partition_keys.value
      type = "string"
    }
  }

  storage_descriptor {
    location      = "${local.archive}/vpc-flow-logs/AWSLogs/aws-account-id=${local.account_id}/aws-service=vpcflowlogs/aws-region=${local.region}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    # Same order as local.flow_log_format in modules/network (v5 custom format).
    dynamic "columns" {
      for_each = [
        ["version", "int"], ["account_id", "string"], ["interface_id", "string"],
        ["srcaddr", "string"], ["dstaddr", "string"], ["srcport", "int"], ["dstport", "int"],
        ["protocol", "bigint"], ["packets", "bigint"], ["bytes", "bigint"],
        ["start", "bigint"], ["end", "bigint"], ["action", "string"], ["log_status", "string"],
        ["vpc_id", "string"], ["subnet_id", "string"], ["instance_id", "string"],
        ["tcp_flags", "int"], ["type", "string"], ["pkt_srcaddr", "string"],
        ["pkt_dstaddr", "string"], ["flow_direction", "string"], ["traffic_path", "int"],
      ]
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

# GuardDuty findings export — one JSON finding per line. resource / service
# are kept as JSON strings and read with json_extract_scalar in queries.
resource "aws_glue_catalog_table" "guardduty_findings" {
  name          = "guardduty_findings"
  database_name = aws_glue_catalog_database.forensics.name
  table_type    = "EXTERNAL_TABLE"

  parameters = merge(
    {
      "EXTERNAL"                  = "TRUE"
      "classification"            = "json"
      "projection.enabled"        = "true"
      "storage.location.template" = "${local.archive}/guardduty/AWSLogs/${local.account_id}/GuardDuty/${local.region}/$${dt}"
    },
    { for k, v in local.date_projection : "projection.dt.${k}" => v },
  )

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "${local.archive}/guardduty/AWSLogs/${local.account_id}/GuardDuty/${local.region}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        "ignore.malformed.json" = "true"
        "case.insensitive"      = "true"
      }
    }

    dynamic "columns" {
      for_each = [
        ["schemaversion", "string"], ["accountid", "string"], ["region", "string"],
        ["id", "string"], ["arn", "string"], ["type", "string"],
        ["resource", "string"], ["service", "string"], ["severity", "double"],
        ["createdat", "string"], ["updatedat", "string"], ["title", "string"],
        ["description", "string"],
      ]
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

# -----------------------------------------------------------------------------
# Catalogued hunt queries (FR-8): the repo files ARE the saved queries.
# -----------------------------------------------------------------------------
resource "aws_athena_named_query" "hunt" {
  for_each    = local.query_files
  name        = trimsuffix(each.value, ".sql")
  description = "CloudShield hunt query from detection/athena-queries/${each.value}"
  workgroup   = aws_athena_workgroup.forensics.id
  database    = aws_glue_catalog_database.forensics.name
  query       = file("${local.queries_dir}/${each.value}")
}
