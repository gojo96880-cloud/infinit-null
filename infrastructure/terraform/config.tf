variable "aws_region" {
  description = "AWS region for deployment"
  default     = "us-east-1"
  type        = string
}

variable "cluster_name" {
  description = "EKS cluster name"
  default     = "infinit-null-cluster"
  type        = string
}

variable "environment" {
  description = "Environment name"
  default     = "production"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  default     = "10.0.0.0/16"
  type        = string
}
