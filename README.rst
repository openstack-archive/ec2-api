OpenStack EC2 API README
-----------------------------

Support of EC2 API for OpenStack.
This project provides a standalone EC2 API service which pursues two goals:
 1. Implement VPC API which is now absent in nova's EC2 API
 2. Create a standalone service for EC2 API support which accommodates
not only the VPC API but the rest of the EC2 API currently present in nova as
well.

Installation
=====

Run install.sh

The EC2 API service gets installed on port 8788 by default. It can be changed
before the installation in install.sh script.

The services afterwards can be started as binaries:

::

 /usr/bin/ec2-api
 /usr/bin/ec2-api-metadata
 /usr/bin/ec2-api-s3

or set up as Linux services.

Installation in devstack:

In order to install ec2-api with devstack the following should be added to
the local.conf or localrc the following line:

::

 enable_plugin ec2-api https://git.openstack.org/openstack/ec2-api

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

S3 server is intended only to support EC2 operations which require S3 server
(e.g. CreateImage) in OpenStack deployments without regular object storage.
It must not be used as a substitution for all-purposes object storage server.
Do not start it if the deployment has its own object storage or uses a public
one (e.g. AWS S3).

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

aws --endpoint-url http://10.0.2.15:8788 ec2 describe-instances


Limitations
===========

General:
 * DryRun option is not supported.
 * Some exceptions are not exactly the same as reported by AWS.

Not supported functionality features:
 * Network ACL
 * VPC Peering connection
 * Classic Link
 * Reserved Instances
 * Spot Instances
 * Placement Groups
 * Monitoring Instances and Volumes
 * Instances Tasks - Bundle, Export, Import

Availability zone related:
 * messages AvailabilityZone property
 * regionName AvailabilityZone property

Image related:
 * CopyImage
 * platform Image property
 * productCodes Image property
 * hypervisor Image property
 * imageOwnerAlias Image property
 * sriovNetSupport Image property
 * stateReason Image property
 * virtualizationType Image property
 * encrypted EbsBlockDevice property
 * iops EbsBlockDevice property
 * volumeType EbsBlockDevice property
 * selective filtering by Image Owner

Instance related:
 * DescribeInstanceStatus
 * ReportInstanceStatus
 * productCodes Instance property
 * ebsOptimized Instance property
 * sriovNetSupport Instance property
 * monitoring Instance property
 * placement Instance property
 * platform Instance property
 * publicDnsName Instance property
 * stateTransitionReason Instance property
 * architecture Instance property
 * hypervisor Instance property
 * iamInstanceProfile Instance property
 * instanceLifecycle Instance property
 * spotInstanceRequestId Instance property
 * stateReason Instance property
 * virtualizationType Instance property
 * instanceInitiatedShutdownBehavior Instance attribute
 * attachTime EbsInstanceBlockDevice property

Network interface related:
 * availabilityZone NetworkInterface property

Snapshot related:
 * CopySnapshot
 * ModifySnapshotAttribute
 * ResetSnapshotAttribute
 * encryption Snapshot property
 * kmsKeyId Snapshot property
 * ownerAlias Snapshot property
 * selective filtering by Snapshot Owner, RestorableBy

Subnet related:
 * ModifySubnetAttribute
 * availabilityZone Subnet property
 * defaultForAz Subnet property
 * mapPublicIpOnLaunch Subnet property

Volume related:
 * DescribeVolumeAttribute
 * DescribeVolumeStatus
 * ModifyVolumeAttribute
 * kmsKeyId Volume property
 * iops Volume property
 * volumeType (current implementation isn't AWS compatible) Volume property

VPC related:
 * describeVpcAttribute
 * modifyVpcAttribute
 * instanceTenancy VPC property

DescribeAccountAttributes result properties:
 * pc-max-security-groups-per-interface AccountAttribute property
 * max-elastic-ips AccountAttribute property
 * vpc-max-elastic-ips AccountAttribute property

VpnGateway related:
 * availabilityZone property

CustomerGateway related:
 * bgpAsn property

VpnConnection related:
 * vgwTelemetry property
 * tunnel_inside_address CustomerGatewayConfiguration tag
 * clear_df_bit CustomerGatewayConfiguration tag
 * fragmentation_before_encryption CustomerGatewayConfiguration tag
 * dead_peer_detection CustomerGatewayConfiguration tag

Supported Features
==================

EC2 API with VPC API except for the limitations above.

Additions to the legacy nova's EC2 API include:
1. VPC API
2. Filtering
3. Tags
4. Paging

Legacy OpenStack release notice
===============================

EC2 API supports Havana, Icehouse, Juno with additional limitations:

Instance related:
 * rootDeviceName Instance property
 * kernelId Instance property
 * ramdiskId Instance property
 * userData Instance property
 * hostName Instance property
 * reservationId Reservation property (ec2api own ids are generated for
   instances launched not by ec2api)
 * launchIndex Instance property (0 for instances launched not by ec2api)

Volume related:
 * deleteOnTermination property

Network interface related:
 * deleteOnTermination (False value can be assigned but doesn't supported)

All these properties can be specified in RunInstance command though, they are
not reported in describe operations.

EC2 API supports Nova client (>=2.16.0) with no microversion support.
Additional limitations are the same, except network interfaces'
deleteOnTermination.


Preferred way to run EC2 API in older releases is to run it in virtual environment:
 * create virtual environment by running command 'python tools/install_venv.py'
 * run install inside venv 'tools/with_venv.sh ./install.sh'
 * and then you need to run EC2 API services: 'ec2-api', 'ec2-api-metadata', and 'ec2-api-s3'
Also you need to reconfigure metadata ports in nova(and neutron) config files
if you want metadata to work correctly. (See 'Installation' section).
After these steps you will have working EC2 API services at ports:
8788 for EC2 API and 3334 for S3 API. Don't forget to change keystone endpoints
if you want to run some automated scripts relying on keystone information.

References
==========

Blueprint:
https://blueprints.launchpad.net/nova/+spec/ec2-api

Spec:
https://review.openstack.org/#/c/147882/
