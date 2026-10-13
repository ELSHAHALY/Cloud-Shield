###############################################################################
# Module: network  (plan §4.4 — VPC topology)
#
#   Public          10.20.0.0/24  · 10.20.1.0/24   NAT GW only
#   Private-app     10.20.10.0/24 · 10.20.11.0/24  Fargate tasks + internal NLB
#   Private-worker  10.20.20.0/24 · 10.20.21.0/24  EC2 report-worker (IR target)
#   Forensics       10.20.99.0/26 (one AZ)         evidence analysis, no internet
#
# Owner: S1 (Infra/DevSecOps)
###############################################################################

data "aws_region" "current" {}

locals {
  az_count = length(var.azs)
  region   = data.aws_region.current.region

  # VPC Flow Logs v5 custom format. The extra fields over the default
  # (flow-direction, pkt-*addr, tcp-flags, traffic-path) are what the C2 /
  # port-scan hunt queries in detection/athena-queries depend on.
  flow_log_format = join(" ", [
    "$${version}", "$${account-id}", "$${interface-id}", "$${srcaddr}", "$${dstaddr}",
    "$${srcport}", "$${dstport}", "$${protocol}", "$${packets}", "$${bytes}",
    "$${start}", "$${end}", "$${action}", "$${log-status}", "$${vpc-id}",
    "$${subnet-id}", "$${instance-id}", "$${tcp-flags}", "$${type}",
    "$${pkt-srcaddr}", "$${pkt-dstaddr}", "$${flow-direction}", "$${traffic-path}",
  ])

  interface_endpoints = var.enable_interface_endpoints ? toset([
    "ssm", "ssmmessages", "ec2messages", # Session Manager (no SSH, no bastion)
    "ecr.api", "ecr.dkr",                # image pulls without NAT
    "logs", "sts",
  ]) : toset([])
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "${var.name}-vpc" })
}

# Strip all rules from the default SG so nothing can accidentally use it
# (CIS AWS 5.4 / Checkov CKV2_AWS_12).
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-default-DO-NOT-USE" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-igw" })
}

# -----------------------------------------------------------------------------
# Subnets
# -----------------------------------------------------------------------------
resource "aws_subnet" "public" {
  count                   = local.az_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false # nothing in here should get a public IP implicitly
  tags                    = merge(var.tags, { Name = "${var.name}-public-${var.azs[count.index]}", Tier = "public" })
}

resource "aws_subnet" "private_app" {
  count             = local.az_count
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_app_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags              = merge(var.tags, { Name = "${var.name}-private-app-${var.azs[count.index]}", Tier = "private-app" })
}

resource "aws_subnet" "private_worker" {
  count             = local.az_count
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_worker_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags              = merge(var.tags, { Name = "${var.name}-private-worker-${var.azs[count.index]}", Tier = "private-worker" })
}

resource "aws_subnet" "forensics" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.forensics_subnet_cidr
  availability_zone = var.azs[0]
  tags              = merge(var.tags, { Name = "${var.name}-forensics", Tier = "forensics" })
}

# -----------------------------------------------------------------------------
# NAT — ONE gateway, not one per AZ. Accepted risk (plan §4.3): an AZ-a outage
# cuts egress for both private tiers. Saves ~US$33/month in a lab.
# -----------------------------------------------------------------------------
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.name}-nat-eip" })
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = merge(var.tags, { Name = "${var.name}-nat" })
  depends_on    = [aws_internet_gateway.this]
}

# -----------------------------------------------------------------------------
# Route tables
# -----------------------------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-rt-public" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Both private tiers share one table because they share the single NAT.
# Split it if per-tier egress control (e.g. Network Firewall) is added later.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-rt-private" })
}

resource "aws_route" "private_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_route_table_association" "private_app" {
  count          = local.az_count
  subnet_id      = aws_subnet.private_app[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_worker" {
  count          = local.az_count
  subnet_id      = aws_subnet.private_worker[count.index].id
  route_table_id = aws_route_table.private.id
}

# Forensics: a route table with ONLY the implicit local route. No IGW, no NAT,
# no gateway endpoints — evidence cannot leave the subnet by routing.
resource "aws_route_table" "forensics" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-rt-forensics" })
}

resource "aws_route_table_association" "forensics" {
  subnet_id      = aws_subnet.forensics.id
  route_table_id = aws_route_table.forensics.id
}

# -----------------------------------------------------------------------------
# Forensics NACL
# Plan §4.4 says "deny-all". A literal deny-all also blocks the analyst, so an
# analysis instance there would be unreachable. Compromise implemented here:
# traffic is allowed ONLY to/from the forensics subnet's own CIDR, so interface
# endpoints for SSM can later be placed INSIDE the subnet (see README gap list).
# Everything else hits the implicit final DENY.
# -----------------------------------------------------------------------------
resource "aws_network_acl" "forensics" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = [aws_subnet.forensics.id]
  tags       = merge(var.tags, { Name = "${var.name}-nacl-forensics" })
}

resource "aws_network_acl_rule" "forensics_in_self" {
  #checkov:skip=CKV_AWS_352:All ports, but ONLY from the forensics subnet itself; everything else hits the implicit deny
  network_acl_id = aws_network_acl.forensics.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.forensics_subnet_cidr
}

resource "aws_network_acl_rule" "forensics_out_self" {
  network_acl_id = aws_network_acl.forensics.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.forensics_subnet_cidr
}

# -----------------------------------------------------------------------------
# Worker-tier NACL — PB-01's quarantine switch (ADR-0003, handoff gap 10).
# Security groups are stateful: swapping onto the quarantine SG leaves already
# tracked connections alive. NACLs are stateless, so PB-01 inserts deny-all
# entries (rule numbers below 100) here to cut them. Until then the allow-all
# rules below behave exactly like the default NACL the subnets had before.
# Blast radius of the deny: the whole worker tier — only the report-worker
# lives there; app subnets keep the default NACL.
# -----------------------------------------------------------------------------
resource "aws_network_acl" "private_worker" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.private_worker[*].id
  tags       = merge(var.tags, { Name = "${var.name}-nacl-private-worker", Purpose = "soar-isolation" })
}

resource "aws_network_acl_rule" "private_worker_in" {
  #checkov:skip=CKV_AWS_352:Mirrors the default NACL; filtering is done by the worker SG (no inbound rules). Rules < 100 are reserved for PB-01's quarantine deny
  network_acl_id = aws_network_acl.private_worker.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "private_worker_out" {
  network_acl_id = aws_network_acl.private_worker.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# -----------------------------------------------------------------------------
# Gateway endpoints (free): S3 + DynamoDB traffic stays off the internet and
# off the NAT bill. Attached to the private table only, never forensics.
# -----------------------------------------------------------------------------
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = merge(var.tags, { Name = "${var.name}-vpce-s3" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${local.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = merge(var.tags, { Name = "${var.name}-vpce-dynamodb" })
}

# -----------------------------------------------------------------------------
# Interface endpoints (OPTIONAL, cost ~US$7.3/endpoint/AZ/month + data).
# 7 endpoints x 2 AZs ≈ US$100/month — more than the whole default budget.
# Off by default; the NAT covers the same traffic in the lab.
# -----------------------------------------------------------------------------
resource "aws_security_group" "endpoints" {
  count       = var.enable_interface_endpoints ? 1 : 0
  name        = "${var.name}-vpce"
  description = "HTTPS from inside the VPC to interface endpoints"
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-vpce" })

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${local.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private_app[*].id
  security_group_ids  = [aws_security_group.endpoints[0].id]
  tags                = merge(var.tags, { Name = "${var.name}-vpce-${each.key}" })
}

# -----------------------------------------------------------------------------
# VPC Flow Logs -> S3 log archive, Parquet, Hive partitions (Athena-ready)
# -----------------------------------------------------------------------------
resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = var.flow_logs_destination_arn
  log_format               = local.flow_log_format
  max_aggregation_interval = 60 # 1-min windows: faster detection, more objects

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = merge(var.tags, { Name = "${var.name}-flow-logs" })
}
