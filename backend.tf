terraform {
  backend "s3" {
    bucket         = "tf-state-proj-2-80" # S3 bucket name
    key            = "states/terraform.tfstate" # Path inside the bucket
    region         =  "us-west-1" # AWS region for S3 bucket
  }
}
