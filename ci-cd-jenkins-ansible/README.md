# ⚙️ CI/CD Pipeline: Jenkins + Ansible

This project demonstrates a CI/CD flow using:

- Jenkins pipeline (Jenkinsfile)
- Ansible provisioning of EC2
- Basic webserver deployment with Nginx

## 🔧 How to Use

1. Ensure Jenkins has the Ansible plugin and SSH credentials
2. Set your `ec2_hosts.ini` file with your EC2 IP and SSH key
3. Run the Jenkins pipeline or use `scripts/deploy.sh` locally
