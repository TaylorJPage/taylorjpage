#!/bin/bash
ansible-playbook -i ansible/inventory/ec2_hosts.ini ansible/playbook.yml
