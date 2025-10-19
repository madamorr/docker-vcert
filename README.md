# VCert-Lambda

A containerized AWS Lambda function for automated certificate management using Venafi's VCert tool. This solution automates the process of downloading certificates from Venafi, importing them into AWS Certificate Manager (ACM), and storing them in AWS Secrets Manager.

## Current Issu

When making changes to app.py, you will need to do the following steps in sequence:

1. Do not commit to the repo yet
2. Iterate image_tag from terraform.tfvars
3. Do a terraform plan and terraform apply
4. Then finally you can commit to the repo

Need to figure out how to stream line this further

## Project Structure

```
docker-vcert/
├── app.py                    # Lambda handler function
├── Dockerfile                # Container configuration for Lambda
├── requirements.txt          # Python dependencies
├── buildspec.yml             # AWS CodeBuild configuration
├── vcert                     # Venafi VCert binary (Linux x86-64)
├── main.tf                   # Terraform infrastructure configuration
├── variables.tf              # Terraform variable definitions
├── outputs.tf                # Terraform outputs
├── terraform.tfvars.example  # Example Terraform variables
└── README.md                 # This file
```

## Description

This project deploys a containerized AWS Lambda function that:

- **Integrates with Venafi**: Uses the VCert binary to interact with Venafi certificate management platform
- **Certificate Management**: Downloads certificates from Venafi API based on application names/tags
- **AWS Integration**:
  - Imports certificates into AWS Certificate Manager (ACM)
  - Stores certificate data in AWS Secrets Manager
  - Supports cross-account secret management
- **Automation**: Runs as a scheduled Lambda function for certificate lifecycle management

## Features

- ✅ Containerized Lambda deployment using AWS Lambda Python 3.13 runtime
- ✅ VCert binary integration for Venafi operations
- ✅ AWS ACM certificate import functionality
- ✅ AWS Secrets Manager integration for secure storage
- ✅ Self-signed certificate generation (for testing)
- ✅ AWS CodeBuild pipeline for Docker image builds
- 🚧 Venafi API integration (in development)
- 🚧 Certificate filtering by application/tags (planned)

## Prerequisites

- AWS CLI configured
- Docker installed
- Existing IAM role for CodeBuild (matching pattern: `*{project_name}*{environment}*codebuild*`)
- Existing IAM policy: `{project_name}-{environment}-codebuild-ecr-policy`
- VCert binary (included as `vcert` file)
- Terraform (for infrastructure deployment)
- GitHub repository access for CodeBuild

## Usage

### 1. Configure Variables

```bash
# Copy the example file and update with your values
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your specific values
```

### 2. Deploy Infrastructure

```bash
# Initialize and deploy Terraform
terraform init
terraform plan
terraform apply
```

### 3. Build and Deploy Container

```bash
# Build and push Docker image using CodeBuild
aws codebuild start-build --project-name {project_name}-{environment}-build

# OR build manually (get values from terraform output)
terraform output docker_build_command
```

### 3. Lambda Function Capabilities

The Lambda handler (`app.handler`) supports:

- **VCert Operations**: Execute VCert binary commands
- **Secret Management**:
  - Retrieve secrets from AWS Secrets Manager
  - Create/update secrets across regions
- **Certificate Operations**:
  - Generate self-signed certificates (testing)
  - Import certificates to ACM
  - Download certificates from Venafi (planned)
- **API Integration**: HTTP requests to external APIs

## Environment Variables

| Variable             | Description              | Required            |
| -------------------- | ------------------------ | ------------------- |
| `AWS_DEFAULT_REGION` | AWS region for resources | Yes                 |
| `AWS_ACCOUNT_ID`     | AWS account ID           | Yes (for CodeBuild) |
| `IMAGE_REPO_NAME`    | ECR repository name      | Yes (for CodeBuild) |
| `IMAGE_TAG`          | Docker image tag         | Yes (for CodeBuild) |

## Terraform Variables

| Variable          | Description                         | Default          | Required |
| ----------------- | ----------------------------------- | ---------------- | -------- |
| `aws_region`      | AWS region for resources            | `us-east-1`      | No       |
| `project_name`    | Project name for resource naming    | `terraform-cicd` | No       |
| `environment`     | Environment (dev/staging/prod)      | `dev`            | No       |
| `image_tag`       | Docker image tag                    | `5.11.1`         | No       |
| `github_repo_url` | GitHub repository URL for CodeBuild | None             | Yes      |

## Dependencies

- **Python Packages**:

  - `requests` - HTTP client for API calls
  - `cryptography` - Certificate operations and cryptographic functions
  - `boto3` - AWS SDK (included in Lambda runtime)

- **System Dependencies**:
  - VCert binary (Venafi certificate management tool)

## Development Status

### Completed

- [x] Basic Lambda function structure
- [x] Docker containerization
- [x] AWS service integrations (ACM, Secrets Manager)
- [x] CodeBuild pipeline configuration
- [x] Self-signed certificate generation for testing
- [x] Dynamic IAM role discovery
- [x] Terraform infrastructure automation
- [x] ECR repository with lifecycle policies

### In Progress

- [ ] Venafi API integration for certificate retrieval
- [ ] Certificate filtering logic by application name/tags
- [ ] Cross-account secret management implementation
- [ ] Error handling and logging improvements

### TODO

- [ ] Complete Venafi API integration
- [ ] Implement certificate filtering by application/tags
- [ ] Add comprehensive error handling
- [ ] Set up monitoring and alerting
- [ ] Add unit tests
- [ ] Create deployment documentation
- [ ] Implement certificate renewal automation

## Configuration

The Lambda function uses AWS Secrets Manager to store configuration. Create secrets with the following structure:

```json
{
  "venafi_api_key": "your-venafi-api-key",
  "venafi_endpoint": "https://your-venafi-instance.com",
  "target_applications": ["app1", "app2"]
}
```

## Security

- **Dynamic IAM Role Discovery**: Automatically finds CodeBuild roles matching your project naming pattern
- **Existing Policy Integration**: Uses your existing `{project_name}-{environment}-codebuild-ecr-policy`
- **ECR Repository Security**:
  - AES256 encryption enabled
  - Vulnerability scanning on push
  - Lifecycle policies for image management
- **Lambda Execution**: Secure container runtime with minimal permissions
- **Secrets Management**:
  - Encrypted at rest in Secrets Manager
  - Certificate private keys securely handled
  - Cross-region secret access support

## License

[Add your license information here]
