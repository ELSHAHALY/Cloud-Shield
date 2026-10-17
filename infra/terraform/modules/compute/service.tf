###############################################################################
# App service — created only when var.container_image is set (digest-pinned).
#
#   API Gateway (REST) --VPC Link (PrivateLink)--> internal NLB --> Fargate
#
# The VPC Link itself belongs to the `edge` module (TB1); it consumes
# output.nlb_arn.
###############################################################################

# Phase E D22: local-mode switches must never reach a task definition
# (AWS_ENDPOINT_URL_<SERVICE> too: the SDK honours it on its own, audit E8). They
# are filtered out here AND the task definition refuses to plan if any was
# given (defence in depth: the filter alone would hide a mis-set variable).
locals {
  forbidden_env_keys = ["AUTH_LOCAL_ISSUER", "AUTH_LOCAL_JWKS_URI", "AWS_ENDPOINT_URL", "S3_PUBLIC_ENDPOINT"]
  forbidden_env_given = sort(concat(
    [for k in keys(var.container_environment) : k if contains(local.forbidden_env_keys, k) || startswith(k, "AUTH_LOCAL_") || startswith(k, "AWS_ENDPOINT_URL_")],
    [for k, v in var.container_environment : k if(k == "CLOUDSHIELD_ENV" ? v != "aws" : false)],
  ))
  container_environment = merge(
    {
      for k, v in var.container_environment : k => v
      if(contains(local.forbidden_env_keys, k) || startswith(k, "AUTH_LOCAL_") || startswith(k, "AWS_ENDPOINT_URL_") ? false : (k == "CLOUDSHIELD_ENV" ? v == "aws" : true))
    },
    # Injected by the module itself (posture read, D18), so dev never feeds
    # compute's own outputs back in as compute inputs.
    {
      APP_IMAGE           = coalesce(var.container_image, "none")
      ECR_REPOSITORY_NAME = aws_ecr_repository.app.name
    },
  )
}

resource "aws_lb" "app" {
  #checkov:skip=CKV_AWS_91:NLB access logs exist only for TLS listeners; TLS terminates at API Gateway (TB1) and the API writes FR-4 audit events
  #checkov:skip=CKV_AWS_150:Deletion protection is a variable; off in the lab so nightly teardown works
  count                            = local.enable_service ? 1 : 0
  name                             = substr("${var.name}-api-nlb", 0, 32)
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = var.private_app_subnet_ids
  security_groups                  = [var.nlb_security_group_id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = var.nlb_deletion_protection

  # REST API VPC Links arrive over PrivateLink without a matchable source IP.
  # "off" = PrivateLink traffic is not evaluated against the NLB SG's inbound
  # rules. The only PrivateLink consumer is our own API Gateway VPC Link, and
  # the endpoint service is not shared, so this does not open the NLB.
  enforce_security_group_inbound_rules_on_private_link_traffic = "off"

  tags = var.tags
}

resource "aws_lb_target_group" "app" {
  count       = local.enable_service ? 1 : 0
  name        = substr("${var.name}-api-tg", 0, 32)
  port        = var.app_port
  protocol    = "TCP"
  target_type = "ip" # required for Fargate awsvpc tasks
  vpc_id      = var.vpc_id

  deregistration_delay = 30

  health_check {
    protocol            = "HTTP"
    path                = var.health_check_path
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = var.tags
}

resource "aws_lb_listener" "app" {
  #checkov:skip=CKV_AWS_2:Internal NLB behind API Gateway; TLS terminates at the edge (TB1) and this hop stays inside the VPC via PrivateLink
  #checkov:skip=CKV_AWS_103:Same as above — no TLS listener on the internal hop
  count             = local.enable_service ? 1 : 0
  load_balancer_arn = aws_lb.app[0].arn
  port              = var.nlb_listener_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app[0].arn
  }

  tags = var.tags
}

resource "aws_ecs_task_definition" "app" {
  count                    = local.enable_service ? 1 : 0
  family                   = "${var.name}-docs-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  # Writable scratch space, because the root filesystem is read-only.
  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([
    {
      name      = "docs-api"
      image     = var.container_image
      essential = true
      user      = var.container_user
      # SIGTERM -> SIGKILL after 2 s (default 30 s) so a PB-04 StopTask kills
      # the processes well inside the 60 s MTTC (F21).
      stopTimeout            = 2
      readonlyRootFilesystem = true
      privileged             = false

      portMappings = [{
        containerPort = var.app_port
        protocol      = "tcp"
      }]

      environment = [for k, v in local.container_environment : { name = k, value = v }]

      mountPoints = [{
        sourceVolume  = "tmp"
        containerPath = "/tmp"
        readOnly      = false
      }]

      linuxParameters = {
        initProcessEnabled = true # needed for ECS Exec (PB-04 volatile capture)
        capabilities       = { drop = ["ALL"] }
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "docs-api"
        }
      }
    }
  ])

  tags = var.tags

  lifecycle {
    precondition {
      condition     = length(local.forbidden_env_given) == 0
      error_message = "container_environment must never carry local-mode settings (CLOUDSHIELD_ENV other than aws, AUTH_LOCAL_*, AWS_ENDPOINT_URL[_*], S3_PUBLIC_ENDPOINT): Phase E D22."
    }
  }
}

resource "aws_ecs_service" "app" {
  count                             = local.enable_service ? 1 : 0
  name                              = "docs-api"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.app[0].arn
  desired_count                     = var.desired_count
  launch_type                       = "FARGATE"
  platform_version                  = "LATEST"
  enable_execute_command            = true
  enable_ecs_managed_tags           = true
  propagate_tags                    = "SERVICE" # copies the scope tag (below) onto every task
  health_check_grace_period_seconds = 60

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_app_subnet_ids
    security_groups  = [var.app_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app[0].arn
    container_name   = "docs-api"
    container_port   = var.app_port
  }

  depends_on = [aws_lb_listener.app]
  # In scope for PB-04 only when explicitly opted in (the guard reads the
  # LIVE task tags, which propagate_tags copies from here).
  tags = merge(var.tags, var.soar_scope_app_service ? var.soar_scope_tag : {})
}
