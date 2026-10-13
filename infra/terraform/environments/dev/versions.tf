terraform {
  required_version = ">= 1.10, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Partial configuration: values come from backend.hcl (git-ignored) so the
  # account ID never lands in the repo. See backend.hcl.example.
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  # Every resource gets these. The SOAR safety guard (plan §6.2) will key off
  # tags, so consistent tagging is a security control here, not cosmetics.
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = var.owner
    }
  }
}
