terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "5.74.0" }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.15.0"
}

module "cdn" {
  source  = "terraform-aws-modules/cloudfront/aws"
  version = "3.4.1"
}

module "edge" {
  source = "git::https://github.com/example/tf-edge.git?ref=8e5e7e5ab8b370d6c329ec480221332ada57f0ab"
}

module "logs" {
  source = "./modules/logs"
}
