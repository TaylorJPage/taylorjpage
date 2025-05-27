from flask import Flask
import boto3
import os

app = Flask(__name__)

@app.route("/")
def home():
    secret_name = os.environ.get("SECRET_NAME")
    region_name = os.environ.get("AWS_REGION", "us-east-1")

    try:
        client = boto3.client("secretsmanager", region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        secret = response["SecretString"]
    except Exception as e:
        secret = f"Error retrieving secret: {e}"

    return f"Hello from DevSecOps Lab!<br>Secret: {secret}"
