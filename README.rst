OpenStack EC2 API README
-----------------------------

Support of EC2 API for OpenStack.
This project provides a standalone EC2 API service which pursues two goals:
 1. Implement VPC API which now absent in nova's EC2 API
 2. Create a standalone service for EC2 API support accommodates
not only the VPC API but the rest of the EC2 API currently present in nova as
well.

It doesn't replace existing nova EC2 API service in deployment it gets 
installed to a different port (8788 by default).

Installation
=====

Run install.sh

The EC2 API service gets installed on port 8788 by default. It can be changed
before the installation in install.sh script.

The services afterwards can be started as binaries:

::

 /usr/bin/ec2-api
 /usr/bin/ec2-api-metadata

or set up as Linux services.

To configure OpenStack for EC2 API metadata service:

for Nova-network
  add::

    [DEFAULT]
    metadata_port = 8789
    [neutron]
    service_metadata_proxy = True

  to /etc/nova.conf

  then restart nova-metadata (can be run as part of nova-api service) and
  nova-network services.

for Neutron
  add::

    [DEFAULT]
    nova_metadata_port = 8789

  to /etc/neutron/metadata_agent.ini

  then restart neutron-metadata service.

Usage
=====

Download aws cli from Amazon.
Create configuration file for aws cli in your home directory ~/.aws/config:

::

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

VPN-related and ACL-related functionality is not supported. 
Default VPC Security Groups had to be named "Default" instead of Amazon's
"default" due to conflict with OpenStack's default groups.
DryRun option is not supported.
Some exceptions are not exactly the same as reported by AWS.

Supported Features
==================

EC2 API with VPC API except for the limitations above

Additions to the legacy nova's EC2 API include:
1. VPC API
2. Filtering
3. Tags

References
==========

Blueprint:
https://blueprints.launchpad.net/nova/+spec/ec2-api

Spec:
https://review.openstack.org/#/c/147882/
