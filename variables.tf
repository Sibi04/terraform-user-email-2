variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "us-east-1" 
}

variable "vpc_cidr_block" {
  description = "The CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr_block" {
  description = "The CIDR block for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr_block" {
  description = "The CIDR block for the private subnet."
  type        = string
  default     = "10.0.2.0/24"
}

variable "alb_subnet_cidr_block" {
  type=string
  default = "10.0.3.0/24"
}

variable "private_subnet_db_2_cidr_block" {
  description = "The CIDR block for the private subnet for the second database."
  type        = string
  default     = "10.0.5.0/24"  
}

variable "private_subnet_b_cidr_block" {
  description = "The CIDR block for the private subnet for the second database."
  type        = string
  default     = "10.0.4.0/24"  
}

variable "private_subnet_app_2_b_cidr_block" {
  description = "The CIDR block for the private subnet for the second database."
  type        = string
  default     = "10.0.6.0/24"  
}


variable "project_name" {
  description = "A name for your project, used as a prefix for resources"
  type        = string
  default     = "ecs-db-insert"
}

variable "aws_account_id" {
  description = "Your AWS Account ID"
  type        = string
  # IMPORTANT: Replace this with your actual AWS Account ID
  default     = "227224898353" # <<< REPLACE WITH YOUR AWS ACCOUNT ID
}

variable "container_port" {
  description = "The port your application inside the container listens on"
  type        = number
  default     = 80
}

variable "task_execution_role" {
  description = "The name of the ECS task execution role"
  type        = string
  default     = "arn:aws:iam::227224898353:role/dev-ecs-task-role"
}

variable "lambda_rds_role"{ 
  description = "The name of the lambda role for rds-db"
  type        = string
  default= "arn:aws:iam::227224898353:role/dev-lambda-2-role"
}

variable "s3_bucket_name" {
  description = "The name of the S3 bucket for the website"
  type        = string
  default     = "website-index-1-227224898353"
}

variable "ec2_ssm_role"{
  description = "the role for ec2 ssm manager"
  type= string
  default= "arn:aws:iam::227224898353:role/dev-ec2-ssm-role"
}