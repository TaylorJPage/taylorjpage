# 🏗️ AWS Terraform: VPC + Auto Scaling Infrastructure

This project builds a production-ready AWS environment using modular Terraform code.

## 🚀 Features

- ✅ Custom VPC with public/private subnets
- ✅ Internet Gateway & route table association
- ✅ Security Group allowing HTTP and SSH access
- ✅ Auto Scaling Group (ASG) via Launch Template
- ✅ EBS volume attached to each instance
- ✅ Modules for clean, reusable infrastructure

## 📁 Modules

modules/
├── vpc/ # VPC, subnets, route tables, IGW
├── sg/ # (Optional) Basic SG for legacy EC2 setup
├── ec2/ # (Optional) Standalone EC2 instance
├── autoscaling/ # Launch template + ASG + EBS volume mapping


> You can safely ignore `ec2` and `sg` if using the `autoscaling` module — they're included for learning/demo purposes.

---

## ⚙️ Variables (`terraform.tfvars`)

```hcl
region              = "us-east-1"
vpc_cidr            = "10.0.0.0/16"
public_subnet_cidr  = "10.0.1.0/24"
private_subnet_cidr = "10.0.2.0/24"

ami_id              = "ami-0c2b8ca1dad447f8a" # Amazon Linux 2
instance_type       = "t2.micro"
ebs_size            = 20

desired_capacity    = 2
min_size            = 1
max_size            = 3

🛠️ Usage

terraform init
terraform plan
terraform apply
