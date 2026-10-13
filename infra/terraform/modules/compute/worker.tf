###############################################################################
# EC2 report-worker — the PB-01 forensic target (plan §4.3, §6.5).
# Created only when var.enable_report_worker = true. Managed through SSM
# Session Manager: no SSH key, no inbound rules, no public IP.
#
# This is the ONLY workload resource carrying the SOAR scope tag, so the
# safety guard will act on it and on nothing else in TB2.
###############################################################################

data "aws_ssm_parameter" "al2023" {
  count = var.enable_report_worker ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "worker" {
  count              = var.enable_report_worker ? 1 : 0
  name               = "${var.name}-report-worker"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
  # Caps the role even if PB-01 (which may write inline policies onto it to
  # revoke sessions) is ever compromised. Required by PB-01's IAM condition.
  permissions_boundary = var.worker_permissions_boundary_arn
  tags                 = var.tags
}

# Session Manager only. These instance credentials are what scenario A
# "steals" via IMDS — keep them low-value on purpose.
resource "aws_iam_role_policy_attachment" "worker_ssm" {
  count      = var.enable_report_worker ? 1 : 0
  role       = aws_iam_role.worker[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "worker" {
  count = var.enable_report_worker ? 1 : 0
  name  = "${var.name}-report-worker"
  role  = aws_iam_role.worker[0].name
  tags  = var.tags
}

resource "aws_instance" "worker" {
  count                  = var.enable_report_worker ? 1 : 0
  ami                    = data.aws_ssm_parameter.al2023[0].insecure_value
  instance_type          = var.report_worker_instance_type
  subnet_id              = var.private_worker_subnet_ids[0]
  vpc_security_group_ids = [var.worker_security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.worker[0].name
  monitoring             = true
  ebs_optimized          = true

  # IMDSv2 required. Scenario A therefore uses the token flow (PUT then GET),
  # as a real SSRF-to-IMDS chain must today; IMDSv1 is NOT re-enabled for the lab.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
  }

  # The volume needs the scope tag too: PB-01's snapshot permission is
  # conditioned on the VOLUME's tag, not the instance's.
  volume_tags = merge(var.tags, var.soar_scope_tag, { Name = "${var.name}-report-worker-root" })

  tags = merge(var.tags, var.soar_scope_tag, {
    Name = "${var.name}-report-worker"
    Role = "report-worker"
  })

  lifecycle {
    # A new AL2023 AMI is published often; don't replace the instance (and
    # destroy evidence) just because the SSM parameter moved.
    ignore_changes = [ami]
  }
}
