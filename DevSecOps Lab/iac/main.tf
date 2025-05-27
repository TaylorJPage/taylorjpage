provider "aws" {
  region = "us-east-1"
}

resource "aws_secretsmanager_secret" "my_secret" {
  name = "myapp/devsecret"
}

resource "aws_secretsmanager_secret_version" "my_secret_version" {
  secret_id     = aws_secretsmanager_secret.my_secret.id
  secret_string = jsonencode({
    username = "devuser"
    password = "s3cr3t!"
  })
}
