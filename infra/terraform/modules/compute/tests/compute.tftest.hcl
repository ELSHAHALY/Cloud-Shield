# terraform test — offline, mocked AWS provider.

mock_provider "aws" {}

variables {
  name                      = "cs-test"
  vpc_id                    = "vpc-0aaaaaaaaaaaaaaaa"
  private_app_subnet_ids    = ["subnet-0aaaaaaaaaaaaaaaa", "subnet-0bbbbbbbbbbbbbbbb"]
  private_worker_subnet_ids = ["subnet-0cccccccccccccccc", "subnet-0dddddddddddddddd"]
  nlb_security_group_id     = "sg-0aaaaaaaaaaaaaaaa"
  app_security_group_id     = "sg-0bbbbbbbbbbbbbbbb"
  worker_security_group_id  = "sg-0cccccccccccccccc"
}

run "defaults_create_no_code_dependent_resources" {
  command = apply

  assert {
    condition     = length(aws_ecs_service.app) == 0 && length(aws_lb.app) == 0
    error_message = "No service or NLB without a container image."
  }
  assert {
    condition     = length(aws_instance.worker) == 0
    error_message = "Report-worker must be opt-in (cost, R3)."
  }
  assert {
    condition     = aws_ecr_repository.app.image_tag_mutability == "IMMUTABLE"
    error_message = "ECR tags must be immutable (TB4 supply chain)."
  }
  assert {
    condition     = aws_ecr_repository.app.image_scanning_configuration[0].scan_on_push
    error_message = "ECR must scan on push."
  }
}

run "service_hardening" {
  command = apply

  variables {
    container_image = "example.dkr.ecr.us-east-1.amazonaws.com/cs-test/docs-api@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  }

  assert {
    condition     = length(aws_ecs_service.app) == 1 && aws_lb.app[0].internal
    error_message = "Service + INTERNAL NLB expected."
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.app[0].container_definitions)[0].readonlyRootFilesystem
    error_message = "Root filesystem must be read-only."
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.app[0].container_definitions)[0].user == "1000:1000"
    error_message = "Container must run as non-root."
  }
  assert {
    condition     = aws_ecs_service.app[0].network_configuration[0].assign_public_ip == false
    error_message = "Tasks must not get public IPs."
  }
}

run "rejects_tag_pinned_image" {
  command = plan

  variables {
    container_image = "nginx:latest"
  }

  expect_failures = [var.container_image]
}

run "rejects_root_user" {
  command = plan

  variables {
    container_user = "0:0"
  }

  expect_failures = [var.container_user]
}

run "worker_is_hardened_and_in_scope" {
  command = apply

  variables {
    enable_report_worker = true
  }

  assert {
    condition     = aws_instance.worker[0].metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 must be required."
  }
  assert {
    condition     = aws_instance.worker[0].root_block_device[0].encrypted
    error_message = "Root volume must be encrypted."
  }
  assert {
    condition     = aws_instance.worker[0].tags["cloudshield:soar-scope"] == "in-scope"
    error_message = "The worker must carry the SOAR scope tag (it is the PB-01 target)."
  }
  assert {
    condition     = aws_instance.worker[0].volume_tags["cloudshield:soar-scope"] == "in-scope"
    error_message = "The worker's volume must carry the scope tag (PB-01 snapshot IAM condition)."
  }
}
