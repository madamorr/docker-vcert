
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  backend "s3" {
    bucket  = "mr-aws-trial-bkt"
    key     = "lambda_deploy/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}

provider "aws" {
  region = var.aws_region
}



# Local values for computed configurations
locals {
  ecr_repository = var.ecr_repository != "" ? var.ecr_repository : "${var.project_name}/${var.environment}-vcert"
}



# Lambda Execution Role
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-${var.environment}-lambda-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-lambda-exec-role"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Inline policy for Secrets Manager access
resource "aws_iam_role_policy" "lambda_secrets_acm" {
  name = "${var.project_name}-${var.environment}-secrets-acm-policy"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:UpdateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DeleteSecret",
          "acm:ImportCertificate",
          "acm:DescribeCertificate",
          "acm:ListCertificates",
          "acm:DeleteCertificate",
          "acm:AddTagsToCertificate",
          "acm:RemoveTagsFromCertificate"
        ]
        Resource = "*"
      }
    ]
  })
}

# Basic logging permissions
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}



# lambda function
resource "aws_lambda_function" "lambda_function" {
  function_name = var.function_name
  package_type  = "Image"
  image_uri     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${local.ecr_repository}:${var.image_tag}"
  role          = aws_iam_role.lambda_exec.arn
  timeout       = 30

  environment {
    variables = {
      IMAGE_TAG = var.image_tag
    }
  }
  tags = {
    Name        = var.function_name
    Project     = var.project_name
    Environment = var.environment
  }
}


# EventBridge Rule (every hour)
resource "aws_cloudwatch_event_rule" "time" {
  name                = "${var.project_name}-${var.environment}-time-rule"
  description         = "Run ${var.function_name} lambda on schedule: ${var.schedule_expression}"
  schedule_expression = var.schedule_expression

  tags = {
    Name        = "${var.project_name}-${var.environment}-time-rule"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.time.arn
}

# Attach Lambda to the EventBridge rule
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.time.name
  target_id = "${var.project_name}-${var.environment}-lambda-target"
  arn       = aws_lambda_function.lambda_function.arn
}

data "aws_caller_identity" "current" {}
