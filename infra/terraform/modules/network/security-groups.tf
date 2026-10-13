###############################################################################
# Workload security groups (TB2 — VPC private subnets)
#
#   nlb        -> internal NLB fronted by API Gateway REST VPC Link
#   app        -> Fargate tasks; only reachable from the NLB SG
#   worker     -> EC2 report-worker (forensic target); no inbound at all (SSM)
#   quarantine -> PB-01 swaps a compromised ENI onto this: zero rules
#
# Standalone rule resources (aws_vpc_security_group_*_rule) are used instead
# of inline blocks so later modules can add rules without fighting this one.
###############################################################################

# ---------------- NLB ----------------
resource "aws_security_group" "nlb" {
  #checkov:skip=CKV2_AWS_5:Attached by modules/compute to the internal NLB, which is feature-flagged off by default
  name        = "${var.name}-nlb"
  description = "Internal NLB for the docs API (REST API Gateway VPC Link)"
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-nlb" })
}

# REST API VPC Links reach the NLB over PrivateLink, which does not carry a
# source IP this SG could match; the NLB is configured to skip inbound SG
# evaluation for PrivateLink traffic (modules/compute). This rule only admits
# in-VPC callers (e.g. health checks, internal tools) on the listener port.
resource "aws_vpc_security_group_ingress_rule" "nlb_from_vpc" {
  security_group_id = aws_security_group.nlb.id
  description       = "Listener port from inside the VPC"
  ip_protocol       = "tcp"
  from_port         = var.nlb_listener_port
  to_port           = var.nlb_listener_port
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_app" {
  security_group_id            = aws_security_group.nlb.id
  description                  = "Forward to app tasks only"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.app.id
}

# ---------------- App (Fargate) ----------------
resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:Attached by modules/compute to the Fargate service, which is feature-flagged off by default
  name        = "${var.name}-app"
  description = "Fargate docs-api tasks"
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-app" })
}

resource "aws_vpc_security_group_ingress_rule" "app_from_nlb" {
  security_group_id            = aws_security_group.app.id
  description                  = "App port from the NLB only"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.nlb.id
}

# HTTPS out: ECR/Logs/STS via NAT, Cognito JWKS, S3/DynamoDB via gateway
# endpoints. Nothing else (no DNS-over-anything, no SSH, no random ports).
resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to AWS APIs and Cognito JWKS"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------------- Report-worker (EC2 forensic target) ----------------
resource "aws_security_group" "worker" {
  #checkov:skip=CKV2_AWS_5:Attached by modules/compute to the EC2 report-worker, which is feature-flagged off by default
  name        = "${var.name}-worker"
  description = "EC2 report-worker; no inbound, managed via SSM only"
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-worker" })
}

resource "aws_vpc_security_group_egress_rule" "worker_https" {
  security_group_id = aws_security_group.worker.id
  description       = "HTTPS to SSM and AWS APIs"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# Scenario A (T1046 port scan) needs the worker to emit connection attempts
# inside the VPC. Off by default; S3 turns it on only for the attack window.
resource "aws_vpc_security_group_egress_rule" "worker_scan_lab" {
  count             = var.allow_worker_lab_scan ? 1 : 0
  security_group_id = aws_security_group.worker.id
  description       = "LAB ONLY: scenario A port scan inside the VPC"
  ip_protocol       = "tcp"
  from_port         = 1
  to_port           = 65535
  cidr_ipv4         = var.vpc_cidr
}

# ---------------- Quarantine (PB-01) ----------------
# No ingress, no egress. Terraform removes AWS's default allow-all egress rule
# from security groups it creates, so this group really is empty.
# Caveat (documented for S3): SGs are stateful — swapping to this group does
# not tear down connections already tracked. PB-01 must also apply the
# quarantine NACL step or stop the process; see soar/README.md.
resource "aws_security_group" "quarantine" {
  #checkov:skip=CKV2_AWS_5:Attached at incident time by PB-01, never by Terraform
  name        = "${var.name}-quarantine"
  description = "PB-01 isolation: no inbound, no outbound. Do not add rules."
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-quarantine", Purpose = "soar-isolation" })
}
