terraform {
  # >= 1.10 for S3-native state locking (use_lockfile), which removes the need
  # for a DynamoDB lock table.
  required_version = ">= 1.10, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  # Local state on purpose — see main.tf header.
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project_name
      Component = "bootstrap"
      ManagedBy = "terraform"
    }
  }
}
