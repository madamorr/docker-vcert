# Example Terraform variables file
# Copy this file to terraform.tfvars and update the values

# AWS region where resources will be created
aws_region = "us-east-1"

# Environment (dev, staging, prod)
environment = "dev"

# Project name - should match your existing IAM role naming pattern
project_name = "terraform-cicd"

# GitHub repository URL for CodeBuild source (required)
github_repo_url = "https://github.com/madamorr/docker-vcert.git"

#
# Name of the AWS Secrets Manager secret storing the GitHub Personal Access Token
# Update this to match your secret name
github_pat_secret_name = "github_pat"