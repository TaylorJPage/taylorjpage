#!/bin/bash
aws secretsmanager get-secret-value \
  --secret-id myapp/devsecret \
  --region us-east-1
