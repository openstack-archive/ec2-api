OpenStack EC2 API README
-----------------------------

Support of EC2 API for OpenStack.
This project provides a standalone EC2 API service which pursues two goals:
1. Implement VPC API which now absent in nova's EC2 API
2. Create a standalone service for EC2 API support which later can accommodate
not only the VPC API but the rest of the EC2 API currently present in nova as 
well.

This service implements VPC API related commands only. For the rest of the 
EC2 API functionality it redirects request to original EC2 API in nova.

It doesn't replace existing nova EC2 API service in deployment it gets 
installed to a different port (8788 by default).

Installation
=====

Run install.sh

#TODO: The following should be automated later.

Change /etc/ec2api/ec2api.conf:
[database]
connection_nova = <connection to nova> #should be taken from nova.conf
[DEFAULT]
external_network = <public network name> #obtained by neutron net-external-list

The service gets installed on port 8788 by default. It can be changed before the
installation in install.sh script.

Usage
=====

Download aws cli from Amazon.
Create configuration file for aws cli in your home directory ~/.aws/config:

[default]
aws_access_key_id = 1b013f18d5ed47ae8ed0fbb8debc036b
aws_secret_access_key = 9bbc6f270ffd4dfdbe0e896947f41df3
region = us-east-1

Change the aws_access_key_id and aws_secret_acces_key above to the values
appropriate for your cloud (can be obtained by "keystone ec2-credentials-list"
command).

Run aws cli commands using new EC2 API endpoint URL (can be obtained from
keystone with the new port 8788) like this:

aws --endpoint-url http://10.0.2.15:8788/services/Cloud ec2 describe-instances 


Limitations
===========

This is an alpha-version, Tempest tests are not run yet.  
VPN-related functionality is not supported yet. 
Route-tables functionality is limited. 
Filtering in describe functions can be done by IDs only.
Security groups are attached to network interfaces only, not to instances yet.
Rollbacks in case of failure during object creation are not supported yet.
Some other not-listed here limitations exist also.

Supported Features
==================

VPC API except for the Limitations above is supported.
