provider "aws" {
  region = var.aws_region
  #profile ="personal"
}

resource "aws_vpc" "main_vpc" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_hostnames = true 
  enable_dns_support   = true
  tags = {
    Name = "my-terraform-vpc"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = var.public_subnet_cidr_block
  availability_zone       = "${var.aws_region}a" 
  map_public_ip_on_launch = true 
  tags = {
    Name = "my-terraform-public-subnet"
  }
}

resource "aws_subnet" "alb_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = var.alb_subnet_cidr_block
  availability_zone       = "${var.aws_region}b" 
  map_public_ip_on_launch = true 
  tags = {
    Name = "my-terraform-ALB-subnet"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = var.private_subnet_cidr_block
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "my-db-1-private-subnet"
  }
}

resource "aws_subnet" "private_subnet_db_2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = var.private_subnet_db_2_cidr_block
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "my-db-2-private-subnet"
  }
}

resource "aws_subnet" "private_subnet_b" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = var.private_subnet_b_cidr_block
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "my-app-private-subnet"
  }
}
resource "aws_subnet" "private_subnet_app_2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = var.private_subnet_app_2_b_cidr_block
  availability_zone = "${var.aws_region}c"

  tags = {
    Name = "my-app-2-private-subnet"
  }
}

resource "aws_route_table" "public_subent_route_table" {
 
    vpc_id= aws_vpc.main_vpc.id
    route {
      cidr_block= "0.0.0.0/0"
      gateway_id = aws_internet_gateway.vpc_igw.id 
    }
    route {
      cidr_block = var.vpc_cidr_block
      gateway_id = "local"
    }
    tags = {
      Name = "public-subnet-route-table"
    }
    depends_on = [ aws_internet_gateway.vpc_igw ]
}

resource "aws_route_table" "private_subent_route_table" {
 
    vpc_id= aws_vpc.main_vpc.id
   
    route {
      cidr_block = var.vpc_cidr_block
      gateway_id = "local"
    }
    route{
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_nat_gateway.nat_gw.id # Use NAT Gateway for private subnets
    }
    tags = {
      Name = "private-subnet-route-table"
    }
      # lifecycle {
      #   ignore_changes = [ 
      #     route
      #   ]
      # }
}

resource "aws_internet_gateway" "vpc_igw" {
   vpc_id=aws_vpc.main_vpc.id
   tags = {
     Name="vpc-terraform-igw"
   }
}

resource "aws_route_table_association" "public_subnet_association" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_subent_route_table.id
}

resource "aws_route_table_association" "alb_subnet_association" {
  subnet_id      = aws_subnet.alb_subnet.id
  route_table_id = aws_route_table.public_subent_route_table.id
}

resource "aws_route_table_association" "private_subnet_association" {
    subnet_id = aws_subnet.private_subnet.id
    route_table_id = aws_route_table.private_subent_route_table.id
}

resource "aws_route_table_association" "private_subnet_association_2" {
    subnet_id = aws_subnet.private_subnet_b.id
    route_table_id = aws_route_table.private_subent_route_table.id
}

resource "aws_route_table_association" "private_subnet_association_db_2" {
    subnet_id = aws_subnet.private_subnet_db_2.id
    route_table_id = aws_route_table.private_subent_route_table.id
}

resource "aws_route_table_association" "private_subnet_association_app_2" {
    subnet_id = aws_subnet.private_subnet_app_2.id
    route_table_id = aws_route_table.private_subent_route_table.id
}

resource "aws_security_group" "public_instance_sg" {
   name="public_instance_sg"
   description = "Security group for public instances"
   vpc_id = aws_vpc.main_vpc.id
   tags ={
     Name="public-instance-sg"
   }
}

resource "aws_vpc_security_group_ingress_rule" "public_instance_ingress" {
    security_group_id= aws_security_group.public_instance_sg.id

    cidr_ipv4="0.0.0.0/0"
    ip_protocol = -1
}

resource "aws_vpc_security_group_egress_rule" "public_instance_egress" {
  security_group_id = aws_security_group.public_instance_sg.id

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = -1

}

# RDS MySQL DB
resource "aws_db_instance" "default" {
  allocated_storage    = 10
  identifier = "user-email-db-instance"
  #db_name              = "rdsdb2"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  username             = "admin"
  password             = ";_<hBnG6ZOp3L*{Kgz7U#Cf&>Vch]:qe"
  parameter_group_name = "default.mysql8.0"
  multi_az=false
  db_subnet_group_name = aws_db_subnet_group.subnet_group-db.id
  publicly_accessible=false
  #subnet_group_name = "default"
  skip_final_snapshot  = true
  vpc_security_group_ids = [aws_security_group.public_instance_sg.id]

  depends_on = [ aws_db_subnet_group.subnet_group-db ]
  # lifecycle {
  #    prevent_destroy = true # Prevent accidental deletion
  # }
}

# Common dependencies layer
resource "aws_lambda_layer_version" "layer1" {
  filename            = "${path.module}/lambda_layer/pymysql-layer.zip"
  layer_name          = "example_dependencies_layer"
  description         = "Common dependencies for Lambda functions"
  compatible_runtimes = [ "python3.12"]
  compatible_architectures = ["x86_64"]
}

# Function using the layer
resource "aws_lambda_function" "db-connect" {
  filename      = "${path.module}/lambda/app.zip"
  function_name = "db-connect"
  role          = var.lambda_rds_role
  handler       = "app.lambda_handler"
  runtime       = "python3.12"
  timeout     = 120
  layers = [aws_lambda_layer_version.layer1.arn]
  environment {
    variables = {
       DB_HOST = aws_db_instance.default.address
       DB_USER = "readonly_user"
       #DB_PASSWORD = ";_<hBnG6ZOp3L*{Kgz7U#Cf&>Vch]:qe"
       DB_PASSWORD = "Sibi*2004" 
       DB_NAME = "user_email_db"
       SECRET_NAME = "db-password-2" 
    }
  }
  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet_app_2.id, aws_subnet.private_subnet_b.id]
    security_group_ids = [aws_security_group.public_instance_sg.id]
  }
  tracing_config {
    mode = "Active"
  }
  depends_on = [ aws_db_instance.default ]
}

resource "aws_db_subnet_group" "subnet_group-db" {
  name       = "subnet-group-db-user-mail"
  subnet_ids = [aws_subnet.private_subnet_db_2.id, aws_subnet.private_subnet.id]

  tags = {
    Name = "DB Rds subnet group"
  }
}
# API Gateway to trigger the Lambda function
resource "aws_api_gateway_rest_api" "my_api" {
  name        = "userEmail"
  description = "My API Gateway for Lambda"
}

resource "aws_api_gateway_resource" "my_resource" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id
  parent_id   = aws_api_gateway_rest_api.my_api.root_resource_id
  path_part   = "users"
}

resource "aws_api_gateway_method" "my_method" {
  rest_api_id   = aws_api_gateway_rest_api.my_api.id
  resource_id   = aws_api_gateway_resource.my_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "my_integration" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id
  resource_id = aws_api_gateway_resource.my_resource.id
  http_method = aws_api_gateway_method.my_method.http_method
  integration_http_method = "POST" # Lambda proxy integration uses POST
  type        = "AWS_PROXY"
  uri         = aws_lambda_function.db-connect.invoke_arn
  depends_on = [ aws_lambda_function.db-connect ]
}

resource "aws_api_gateway_deployment" "my_deployment" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.my_resource.id,
      aws_api_gateway_method.my_method.id,
      aws_api_gateway_integration.my_integration.id,
    ]))
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "my_stage" {
  deployment_id = aws_api_gateway_deployment.my_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.my_api.id
  stage_name    = "getMail"
}

resource "aws_lambda_permission" "apigw_lambda_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.db-connect.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.my_api.execution_arn}/*/*"
}

resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled" # Enable Container Insights
  }

  tags = {
    Name = "${var.project_name}-cluster"
  }
}

resource "aws_ecr_repository" "app_repo" {
  name                 = "rds-insert-repo"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
# 2. ECS Task Definition
resource "aws_ecs_task_definition" "app_task" {

  family                   = "${var.project_name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"  # 0.25 vCPU
  memory                   = "512"  # 0.5 GB
  execution_role_arn       = var.task_execution_role
  task_role_arn            = var.task_execution_role # Use the task role for app permissions

  container_definitions = jsonencode([
    {
      name        = "${var.project_name}-container",
      #image       = "${aws_ecr_repository.app_repo.repository_url}:latest", # Dynamically get ECR URI
      #mage = "808581944931.dkr.ecr.us-east-1.amazonaws.com/ecs-hello:latest",
      image = "${aws_ecr_repository.app_repo.repository_url}:latest",
      cpu         = 256,
      memory      = 512,
      essential   = true,
      environment = [
      {"name": "DB_NAME", "value": "user_email_db"},
      {"name": "DB_HOST", "value": "${aws_db_instance.default.address}" },
      {"name": "DB_PASSWORD", "value": "Sibi*2004"},
      {"name": "DB_USER", "value": "readonly_user"}
      ],
      portMappings = [
        {
          containerPort = var.container_port,
          hostPort      = var.container_port, # For Fargate, hostPort is ignored and dynamic
          protocol      = "tcp"
        }
      ],
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          "awslogs-group"         = "/ecs/${var.project_name}-task",
          "awslogs-region"        = var.aws_region, # Automatically gets the provider's region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  tags = {
    Name = "${var.project_name}-task-definition"
  }
  depends_on = [ aws_db_instance.default ]
}


resource "aws_cloudwatch_log_group" "ecs_task_log_group" {
  name              = "/ecs/${var.project_name}-task"
  retention_in_days = 7 # Retain logs for 7 days

  tags = {
    Name = "/ecs/${var.project_name}-task"
  }
}

# 3. ECS Service
resource "aws_ecs_service" "app_service" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app_task.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private_subnet_b.id, aws_subnet.private_subnet_app_2.id] # Reference existing private subnets
    security_groups  = [aws_security_group.public_instance_sg.id]
    assign_public_ip = true # Assign public IP to tasks
  }

  # Attach to Application Load Balancer
  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg.arn
    container_name   = "${var.project_name}-container"
    container_port   = var.container_port
  }

  # Optional: Enable deployment circuit breaker for automatic rollback
  deployment_controller {
    type = "ECS"
  }
  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  tags = {
    Name = "${var.project_name}-service"
  }

  depends_on =[aws_lb.app_alb] # Ensure ALB and TG are created before the service
}

# --- Application Load Balancer (ALB) ---

# 1. Security Group for Application Load Balancer
# This SG is created by Terraform as it's specific to the ALB being managed here.


# 2. ALB
resource "aws_lb" "app_alb" {
  name               = "${var.project_name}-alb"
  internal           = false # Internet-facing
  load_balancer_type = "application"
  security_groups    = [aws_security_group.public_instance_sg.id]
  subnets            = [aws_subnet.alb_subnet.id,aws_subnet.public_subnet.id] # Reference existing public subnets

  enable_deletion_protection = false # Set to true in production

  tags = {
    Name = "${var.project_name}-alb"
  }
  depends_on = [aws_lb_target_group.app_tg] # Ensure TG is created before ALB]
}

# 3. ALB Target Group
resource "aws_lb_target_group" "app_tg" {
  name        = "${var.project_name}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main_vpc.id # Reference existing VPC
  target_type = "ip" # For Fargate

  health_check {
    path                = "/health" # Your application's health check endpoint
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "${var.project_name}-tg"
  }
}

# 4. ALB Listener
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }

  tags = {
    Name = "${var.project_name}-http-listener"
  }
  depends_on = [ aws_lb_target_group.app_tg ]
}

resource "aws_s3_bucket" "website-index-808581944931" {
  bucket = var.s3_bucket_name
}

resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.website-index-808581944931.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  depends_on = [ aws_s3_bucket_object.example , aws_s3_bucket_object.add_user_web  ]
  
}

resource "aws_s3_bucket_object" "example" {
  key    = "index.html"
  bucket = aws_s3_bucket.website-index-808581944931.bucket
  source = "${path.module}/website/index.html"
  etag = filemd5("${path.module}/website/index.html")
  content_type = "text/html"
  force_destroy = true
   
}
resource "aws_s3_bucket_object" "add_user_web" {
  key    = "add_user.html"      
  bucket = aws_s3_bucket.website-index-808581944931.bucket
  source = "${path.module}/website/add_user.html"
  etag = filemd5("${path.module}/website/add_user.html")
  content_type = "text/html"
  force_destroy = true
   
}
resource "aws_s3_bucket_policy" "allow_access_from_account" {
  bucket = aws_s3_bucket.website-index-808581944931.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
          Service = "cloudfront.amazonaws.com"
      },
      Action = "s3:GetObject",
      Resource = "${aws_s3_bucket.website-index-808581944931.arn}/*",
      Condition = {
          StringEquals = {
            "AWS:SourceArn" = "${aws_cloudfront_distribution.s3_distribution.arn}"
            #"AWS:SourceArn" = "*"
          }
      }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.example, aws_cloudfront_distribution.s3_distribution]
  
  #, aws_cloudfront_distribution.s3_distribution]
}

resource "aws_s3_bucket_website_configuration" "website_config" {
  bucket = aws_s3_bucket.website-index-808581944931.id

  index_document {
    suffix = "index.html"
  }
}

locals {
   s3_origin_id = "s3Origin" 
}

locals {
   api_origin_id = "apiOrigin" 
}

resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "s3-oac-east-2"
  description                       = "OAC for S3 website bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}


# CloudFront Distribution

resource "aws_cloudfront_distribution" "s3_distribution" {
  enabled         = true
  is_ipv6_enabled = false
  comment         = "CloudFront for S3 Website"

  # origin {
  #   domain_name              = aws_s3_bucket.website-index-808581944931.bucket_regional_domain_name 
  #   #aws_s3_bucket.website-index-808581944931.website_endpoint
  #   #domain_name              = aws_s3_bucket_website_configuration.website_config.website_endpoint
  #   #domain_name = "website-index-2-808581944931.s3.us-east-2.amazonaws.com"
  #   origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  #   origin_id                = local.s3_origin_id
  # }
  origin {
  domain_name              = aws_s3_bucket.website-index-808581944931.bucket_regional_domain_name 
  origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  origin_id                = local.s3_origin_id

  # s3_origin_config {
  #   origin_access_identity = aws_cloudfront_origin_access_control.oac.id
  # }
}
#  origin {
#   domain_name = aws_s3_bucket.website-index-808581944931.website_endpoint
#   origin_id   = local.s3_origin_id

#   custom_origin_config {
#     http_port              = 80
#     https_port             = 443
#     origin_protocol_policy = "http-only"
#     origin_ssl_protocols   = ["TLSv1.2"]
#   }
# }
  # origin {
  #   domain_name              = aws_api_gateway_stage.my_stage.invoke_url
  #   #origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  #   origin_id                = local.api_origin_id
  # }

  # Default behavior
  default_cache_behavior {
    target_origin_id       = local.s3_origin_id
    viewer_protocol_policy = "allow-all"

    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    cached_methods   = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 3600   # 1 hour
    max_ttl     = 86400  # 1 day
  }

  # Ordered behavior for static assets
  # ordered_cache_behavior {
  #   path_pattern           = "/getMail/*"
  #   target_origin_id       = local.api_origin_id
  #   viewer_protocol_policy = "allow-all"

  #   allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
  #   cached_methods   = []

  #   forwarded_values {
  #     query_string = false
  #     cookies {
  #       forward = "none"
  #     }
  #   }

  #   min_ttl     = 0
  #   default_ttl = 86400    # 1 day
  #   max_ttl     = 31536000 # 1 year
  #   compress    = true
  # }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE" ,"IN"]
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  default_root_object = "index.html"
  #depends_on =[aws_s3_bucket.website-index-808581944931]
}

resource "aws_instance" "private_instance" {
  ami           = "ami-0de716d6197524dd9" # us-east-1
  instance_type = "t2.micro"
  subnet_id = aws_subnet.private_subnet_b.id
  vpc_security_group_ids = [aws_security_group.public_instance_sg.id]
  #key_name = aws_key_pair.my_key.key_name
  #associate_public_ip_address = true
 
  user_data = <<-EOF
                    #!/bin/bash
                    cd /tmp
                    sudo dnf install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
                    sudo systemctl enable amazon-ssm-agent
                    sudo systemctl start amazon-ssm-agent
                    sudo dnf install -y mariadb105
                  EOF
  tags = {
    Name = "private-rds-instance"
  }
  #depends_on = []  
}
resource "aws_eip" "nat_eip" {
  domain = "vpc" # Required for VPC EIPs
}

# Create NAT Gateway
resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet.id # NAT must be in a public subnet
  connectivity_type = "public"                # Default is public, but explicit

  tags = {
    Name = "nat-gateway"
  }
}
# Create SNS Topic
resource "aws_sns_topic" "user_mail" {
  name = "user-email-notification-topic"
}

# Create SNS Subscription
resource "aws_sns_topic_subscription" "user_subscription" {
  topic_arn = aws_sns_topic.user_mail.arn
  protocol  = "email"               # Options: http, https, email, email-json, sms, sqs, application, lambda
  endpoint  = "sibi_palvannan@trimble.com" # Replace with your email
}

resource "aws_cloudwatch_event_rule" "hourly_weekday_rule" {
  name                = "hourly-weekday-rule"
  description         = "Triggers every hour from 9 AM to 5 PM, Monday to Friday"
  schedule_expression = "cron(0 3-11 ? * MON-FRI *)"
}

# EventBridge Target -> Lambda
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.hourly_weekday_rule.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.sns-lambda.arn
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns-lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.hourly_weekday_rule.arn
}
resource "aws_lambda_function" "sns-lambda" {
  filename      = "${path.module}/SnsLambda/app.zip"
  function_name = "sns-email"
  role          = var.lambda_rds_role
  handler       = "app.lambda_handler"
  runtime       = "python3.12"
  timeout     = 120
  layers = [aws_lambda_layer_version.layer1.arn]
  environment {
    variables = {
       DB_HOST = aws_db_instance.default.address
       DB_USER = "readonly_user"
       #DB_PASSWORD = ";_<hBnG6ZOp3L*{Kgz7U#Cf&>Vch]:qe"
       DB_PASSWORD = "Sibi*2004" 
       DB_NAME = "user_email_db"
       SECRET_NAME = "db-password-2" 
       SNS_TOPIC_ARN = aws_sns_topic.user_mail.arn
    }
  }
   vpc_config {
    subnet_ids         = [aws_subnet.private_subnet_app_2.id, aws_subnet.private_subnet_b.id]
    security_group_ids = [aws_security_group.public_instance_sg.id]
  }
  tracing_config {
    mode = "Active"
  }
  depends_on = [ aws_db_instance.default ]
}
