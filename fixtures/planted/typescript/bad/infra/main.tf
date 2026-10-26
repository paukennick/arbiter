terraform {
  required_providers {
    aws = { source = "hashicorp/aws" } # expect: arbiter/supply.unpinned-terraform
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
  }
}

module "vpc" { # expect: arbiter/supply.unpinned-terraform
  source = "terraform-aws-modules/vpc/aws"
}

module "cdn" { # expect: arbiter/supply.unpinned-terraform
  source  = "terraform-aws-modules/cloudfront/aws"
  version = "~> 3.4"
}

module "edge" { # expect: arbiter/supply.unpinned-terraform
  source = "git::https://github.com/example/tf-edge.git?ref=main"
}

module "logs" {
  source = "./modules/logs"
}
