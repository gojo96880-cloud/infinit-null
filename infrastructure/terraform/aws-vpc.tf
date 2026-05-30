terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "infinit_null" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "infinit-null-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.infinit_null.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  tags = { Name = "public-subnet" }
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.infinit_null.id
  cidr_block = "10.0.2.0/24"
  tags = { Name = "private-subnet" }
}

resource "aws_internet_gateway" "infinit_null" {
  vpc_id = aws_vpc.infinit_null.id
  tags = { Name = "igw" }
}
