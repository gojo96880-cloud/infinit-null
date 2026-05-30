variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
  type        = string
}

variable "cluster_name" {
  description = "EKS cluster name"
  default     = "infinit-null-cluster"
  type        = string
}

variable "environment" {
  description = "Environment"
  default     = "production"
  type        = string
}
