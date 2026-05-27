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

  tags = {
    Name = "infinit-null-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.infinit_null.id
  cidr_block = "10.0.2.0/24"

  tags = {
    Name = "infinit-null-private-subnet"
  }
}

resource "aws_internet_gateway" "infinit_null" {
  vpc_id = aws_vpc.infinit_null.id

  tags = {
    Name = "infinit-null-igw"
  }
}

resource "aws_eks_cluster" "infinit_null" {
  name            = "infinit-null-cluster"
  role_arn        = aws_iam_role.eks_cluster_role.arn
  version         = "1.27"

  vpc_config {
    subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy
  ]
}

resource "aws_eks_node_group" "infinit_null" {
  cluster_name    = aws_eks_cluster.infinit_null.name
  node_group_name = "infinit-null-node-group"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [aws_subnet.private.id]

  scaling_config {
    desired_size = 3
    max_size     = 10
    min_size     = 1
  }

  instance_types = ["t3.medium"]
}

data "aws_availability_zones" "available" {
  state = "available"
}
