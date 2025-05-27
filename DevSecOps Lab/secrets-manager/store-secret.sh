#!/bin/bash
aws secretsmanager create-secret \
  --name myapp/devsecret \
  --secret-string '{"username":"devuser","password":"s3cr3t!"}' \
  --region us-east-1
