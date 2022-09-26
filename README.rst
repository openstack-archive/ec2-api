=================
OpenStack EC2 API
=================

.. image:: https://governance.openstack.org/tc/badges/ec2-api.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

.. Change things from this point on

Support of EC2 API for OpenStack.
This project provides a standalone EC2 API service which pursues two goals:

 1. Implement VPC API
 2. Create a standalone service for EC2 API support.

Installation
------------

For more detailed information, please see the `Installation Guide <https://docs.openstack.org/ec2-api/latest/install/index.html>`_.

Installation by install.sh
==========================

Run install.sh

The EC2 API service gets installed on port 8788 by default. It can be changed
before the installation in install.sh script.

The services afterwards can be started as binaries:

::

 /usr/local/bin/ec2-api
 /usr/local/bin/ec2-api-metadata
 /usr/local/bin/ec2-api-s3

or set up as Linux services.

Configuring OpenStack for EC2 API metadata service refering to section "EC2 metadata Configuration".

Installation on devstack
========================

Installation in devstack:

In order to install ec2-api with devstack the following should be added to
the local.conf or localrc the following line:

::

 enable_plugin ec2-api https://opendev.org/openstack/ec2-api

Devstack installation with ec2-api and ec2api-tempest-plugin for development:

1. install packages: awscli, git, python3, python3-devel, ruby
2. clone devstack repository

::

 git clone https://opendev.org/openstack/devstack

3. grant all permissions for your user for directory: "/opt"
4. create folder "/opt/stack/logs/"
5. clone repository "ec2api-tempest-plugin" to stack folder:

::

 git clone https://github.com/openstack/ec2api-tempest-plugin /opt/stack/ec2api-tempest-plugin

6. create local.conf:

::

 [[local|localrc]]
 ADMIN_PASSWORD=secret
 DATABASE_PASSWORD=$ADMIN_PASSWORD
 RABBIT_PASSWORD=$ADMIN_PASSWORD
 SERVICE_PASSWORD=$ADMIN_PASSWORD
 enable_plugin ec2-api https://opendev.org/openstack/ec2-api
 enable_plugin neutron-tempest-plugin https://github.com/openstack/neutron-tempest-plugin
 TEMPEST_PLUGINS='/opt/stack/ec2api-tempest-plugin'

7. go to devstack folder and start installation

::

 cd ~/devstack/
 ./stack.sh

8. check installed devstack

::

 source ~/devstack/accrc/admin/admin
 tempest list-plugins
 ps -aux | grep "ec2"
 aws --endpoint-url http://<IP-ADDRESS> --region <REGION> --profile admin ec2 describe-images
 openstack catalog list
 openstack flavor list
 openstack image list
 sudo journalctl -u devstack@ec2-api.service

9. run integration tests (ec2 tempest test)

::

 cd /opt/stack/tempest
 tox -eall -- ec2api_tempest_plugin --concurrency 1
 tox -eall ec2api_tempest_plugin.api.test_network_interfaces.NetworkInterfaceTest.test_create_max_network_interface

10. run ec2-api unit tests

::

 cd /opt/stack/ec2-api
 tox -epy36 ec2api.tests.unit.test_security_group.SecurityGroupTestCase.test_describe_security_groups_no_default_vpc

Configuring OpenStack for EC2 API metadata service refering to section "EC2 metadata Configuration".

EC2 metadata Configuration
==========================

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

  to /etc/neutron/metadata_agent.ini for legacy neutron or
  to neutron_ovn_metadata_agent.ini for OVN

  then restart neutron-metadata service.

S3 server is intended only to support EC2 operations which require S3 server
(e.g. CreateImage) in OpenStack deployments without regular object storage.
It must not be used as a substitution for all-purposes object storage server.
Do not start it if the deployment has its own object storage or uses a public
one (e.g. AWS S3).

Usage
-----

Download aws cli from Amazon.
Create configuration file for aws cli in your home directory ~/.aws/config:

::

 [default]
 aws_access_key_id = 1b013f18d5ed47ae8ed0fbb8debc036b
 aws_secret_access_key = 9bbc6f270ffd4dfdbe0e896947f41df3
 region = us-east-1

Change the aws_access_key_id and aws_secret_acces_key above to the values
appropriate for your cloud (can be obtained by "openstack ec2 credentials list"
command).

Run aws cli commands using new EC2 API endpoint URL (can be obtained from
openstack cli with the new port 8788) like this:

aws --endpoint-url http://10.0.2.15:8788 ec2 describe-instances


Supported Features and Limitations
----------------------------------

General:
 * DryRun option is not supported.
 * Some exceptions are not exactly the same as reported by AWS.

+----------+------------------------------------------+-----------------+----------------------------------------+
| AWS      |        Command                           | Functionality   | Limitations                            |
| Component|                                          | group           |                                        |
+==========+==========================================+=================+========================================+
|          | **bold** - supported, normal - supported |                 |                                        |
|          | with limitations, *italic* -not supported|                 |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *AcceptVpcPeeringConnection*             | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | **AllocateAddress**                      | addresses       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *AllocateHosts*                          | dedicated hosts | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *AssignIpv6Addresses*                    | network         | not supported                          |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | AssignPrivateIpAddresses                 | network         | allowReassignment parameter            |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | **AssociateAddress**                     | addresses       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **AssociateDhcpOptions**                 | DHCP options    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **AssociateRouteTable**                  | routes          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *AssociateSubnetCidrBlock*               | subnets         | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *AssociateVpcCidrBlock*                  | VPC             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *AttachClassicLinkVpc*                   | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **AttachInternetGateway**                | internet        |                                        |
|          |                                          | gateways        |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **AttachNetworkInterface**               | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, EBS | **AttachVolume**                         | volumes         |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **AttachVpnGateway**                     | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | AuthorizeSecurityGroupEgress             | security groups | EC2 classic way to pass cidr, protocol,|
|          |                                          |                 | sourceGroup, ports parameters          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | AuthorizeSecurityGroupIngress            | security groups | EC2 classic way to pass cidr, protocol,|
|          |                                          |                 | sourceGroup, ports parameters          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *BundleInstance*                         | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CancelBundleTask*                       | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CancelConversionTask*                   | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CancelExportTask*                       | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CancelImportTask*                       | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CancelReservedInstancesListing*         | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CancelSpotFleetRequests*                | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CancelSpotInstanceRequests*             | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ConfirmProductInstance*                 | product codes   | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | *CopyImage*                              | image           | not supported                          |
|          |                                          | provisioning    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | *CopySnapshot*                           | snapshots,s3    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | CreateCustomerGateway                    | VPC gateways    | BGPdynamicrouting                      |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **CreateDhcpOptions**                    | DHCP options    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CreateEgressOnlyInternetGateway*        | VPC gateways    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CreateFlowLogs*                         | infrastructural | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | CreateImage                              | images          | blockDeviceMapping parameter           |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CreateInstanceExportTask*               | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **CreateInternetGateway**                | VPC gateways    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **CreateKeyPair**                        | key pairs       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CreateNatGateway*                       | NAT gateways    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *CreateNetworkAcl*                       | ACL             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *CreateNetworkAclEntry*                  | ACL             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **CreateNetworkInterface**               | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CreatePlacementGroup*                   | clusters        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CreateReservedInstancesListing*         | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | CreateRoute                              | routes          | vpcPeeringConnection parameter         |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **CreateRouteTable**                     | routes          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | **CreateSecurityGroup**                  | security groups |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | **CreateSnapshot**                       | snapshots       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *CreateSpotDatafeedSubscription*         | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | CreateSubnet                             | subnets         | availabilityZone parameter             |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **CreateTags**                           | tags            |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | CreateVolume                             | volumes         | iops, encrypted, kmsKeyId parameters   |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **CreateVpc**                            | VPC             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *CreateVpcEndpoint*                      | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *CreateVpcPeeringConnection*             | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | CreateVpnConnection                      | VPN             | BGP dynamic routing                    |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **CreateVpnConnectionRoute**             | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | CreateVpnGateway                         | VPN             | BGP dynamic routing                    |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteCustomerGateway**                | VPC gateways    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteDhcpOptions**                    | DHCP options    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DeleteEgressOnlyInternetGateway*        | VPC gateways    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DeleteFlowLogs*                         | infrastructural | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteInternetGateway**                | VPC gateways    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **DeleteKeyPair**                        | key pairs       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DeleteNatGateway*                       | NAT gateways    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DeleteNetworkAcl*                       | ACL             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DeleteNetworkAclEntry*                  | ACL             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteNetworkInterface**               | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | *DeletePlacementGroup*                   | clusters        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteRoute**                          | routes          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteRouteTable**                     | routes          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | **DeleteSecurityGroup**                  | security groups |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | **DeleteSnapshot**                       | snapshots       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DeleteSpotDatafeedSubscription*         | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteSubnet**                         | subnets         |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **DeleteTags**                           | tags            |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | **DeleteVolume**                         | volumes         |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteVpc**                            | VPC             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DeleteVpcEndpoints*                     | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DeleteVpcPeeringConnection*             | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteVpnConnection**                  | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteVpnConnectionRoute**             | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DeleteVpnGateway**                     | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | **DeregisterImage**                      | images          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | DescribeAccountAttributes                | infrastructural | vpc-max-security-groups-per-interface, |
|          |                                          |                 | max-elastic-ips,                       |
|          |                                          |                 | vpc-max-elastic-ips attributes         |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | **DescribeAddresses**                    | addresses       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **DescribeAvailabilityZones**            | availability    |                                        |
|          |                                          | zones           |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeBundleTasks*                    | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribeClassicLinkInstances*           | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeConversionTasks*                | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeCustomerGateways**             | gateways        |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeDhcpOptions**                  | DHCP options    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeEgressOnlyInternetGateways*     | VPC gateways    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeExportTasks*                    | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeFlowLogs*                       | infrastructural | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeHosts*                          | dedicated hosts | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeIdentityIdFormat*               | resource IDs    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeIdFormat*                       | resource IDs    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | DescribeImageAttribute                   | images          | productCodes, sriovNetSupport          |
|          |                                          |                 | attributes                             |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | **DescribeImages**                       | images          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeImportImageTasks*               | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeImportSnapshotTasks*            | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | DescribeInstanceAttribute                | instances       | same limitations as for                |
|          |                                          |                 | ModifyInstanceAttribute                |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2,     | **DescribeInstances**                    | instances       |                                        |
| EBS, VPC |                                          |                 |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeInstanceStatus*                 | monitoring      | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeInternetGateways**             | gateways        |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **DescribeKeyPairs**                     | key pairs       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribeMovingAddresses*                | infrastructural | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeNatGateways*                    | NAT gateways    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribeNetworkAcls*                    | ACL             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeNetworkInterfaceAttribute**    | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeNetworkInterfaces**            | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | *DescribePlacementGroups*                | clusters        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribePrefixLists*                    | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | DescribeRegions                          | availability    | RegionNameparameter                    |
|          |                                          | zones           |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeReservedInstances*              | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeReservedInstancesListings*      | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeReservedInstancesModifications* | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeReservedInstancesOfferings*     | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeRouteTables**                  | routes          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeScheduledInstanceAvailability*  | scheduled       | not supported                          |
|          |                                          | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeScheduledInstances*             | scheduled       | not supported                          |
|          |                                          | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeSecurityGroupReferences*        | security groups | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | DescribeSecurityGroups                   | security groups | cidr, protocol, port, sourceGroup      |
|          |                                          |                 | parameters                             |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | *DescribeSnapshotAttribute*              | snapshots       | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | **DescribeSnapshots**                    | snapshots       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeSpotDatafeedSubscription*       | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeSpotFleetInstances*             | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeSpotFleetRequestHistory*        | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeSpotFleetRequests*              | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeSpotInstanceRequests*           | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeSpotPriceHistory*               | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeStaleSecurityGroups*            | security groups | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeSubnets**                      | subnets         |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **DescribeTags**                         | tags            |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | *DescribeVolumeAttribute*                | volumes         | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | **DescribeVolumes**                      | volumes         |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeVolumeStatus*                   | monitoring      | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribeVpcAttribute*                   | VPC             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribeVpcClassicLink*                 | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DescribeVpcClassicLinkDnsSupport*       | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribeVpcEndpoints*                   | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribeVpcEndpointServices*            | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DescribeVpcPeeringConnections*          | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeVpcs**                         | VPC             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeVpnConnections**               | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DescribeVpnGateways**                  | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DetachClassicLinkVpc*                   | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DetachInternetGateway**                | VPC             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DetachNetworkInterface**               | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, EBS | DetachVolume                             | volumes         | instance_id, device, force parameters  |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DetachVpnGateway**                     | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DisableVgwRoutePropagation**           | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *DisableVpcClassicLink*                  | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DisableVpcClassicLinkDnsSupport*        | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | **DisassociateAddress**                  | addresses       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **DisassociateRouteTable**               | routes          |                                        |
|          | *DisassociateSubnetCidrBlock*            | subnets         | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *DisassociateVpcCidrBlock*               | VPC             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **EnableVgwRoutePropagation**            | VPN             |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | *EnableVolumeIO*                         | monitoring      | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *EnableVpcClassicLink*                   | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *EnableVpcClassicLinkDnsSupport*         | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **GetConsoleOutput**                     | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *GetConsoleScreenshot*                   | instances       | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **GetPasswordData**                      | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ImportImage*                            | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ImportInstance*                         | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **ImportKeyPair**                        | keypairs        |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ImportSnapshot*                         | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ImportVolume*                           | tasks,s3        | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ModifyHosts*                            | dedicated hosts | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ModifyIdentityIdFormat*                 | resource IDs    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ModifyIdFormat*                         | resource IDs    | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | ModifyImageAttribute                     | images          | productCodes attribute                 |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | ModifyInstanceAttribute                  | instances       | only disableApiTermination,            |
|          |                                          |                 | sourceDestCheck,instanceType supported |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ModifyInstancePlacement*                | dedicated hosts | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **ModifyNetworkInterfaceAttribute**      | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ModifyReservedInstances*                | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | *ModifySnapshotAttribute*                | snapshots       | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ModifySpotFleetRequest*                 | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *ModifySubnetAttribute*                  | subnets         | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | *ModifyVolumeAttribute*                  | volumes         | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *ModifyVpcAttribute*                     | VPC             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *ModifyVpcEndpoint*                      | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ModifyVpcPeeringConnectionOptions*      | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *MonitorInstances*                       | monitoring      | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *MoveAddressToVpc*                       | infrastructural | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *PurchaseReservedInstancesOffering*      | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *PurchaseScheduledInstances*             | scheduled       | not supported                          |
|          |                                          | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **RebootInstances**                      | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | RegisterImage                            | images          | virtualizationType, sriovNetSupport    |
|          |                                          |                 | parameters                             |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *RejectVpcPeeringConnection*             | cross-VPC       | not supported                          |
|          |                                          | connectivity    |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | **ReleaseAddress**                       | addresses       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ReleaseHosts*                           | dedicated hosts | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *ReplaceNetworkAclAssociation*           | ACL             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *ReplaceNetworkAclEntry*                 | ACL             | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **ReplaceRoute**                         | routes          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **ReplaceRouteTableAssociation**         | routes          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *ReportInstanceStatus*                   | monitoring      | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *RequestSpotFleet*                       | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *RequestSpotInstances*                   | market          | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | **ResetImageAttribute**                  | images          |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | ResetInstanceAttribute                   | instances       | same limitations as for                |
|          |                                          |                 | ModifyInstanceAttribute                |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **ResetNetworkInterfaceAttribute**       | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EBS      | *ResetSnapshotAttribute*                 | snapshots       | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | *RestoreAddressToClassic*                | infrastructural | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | RevokeSecurityGroupEgress                | security groups | EC2 classic way to pass cidr, protocol,|
|          |                                          |                 | sourceGroup, ports parameters          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2, VPC | RevokeSecurityGroupIngress               | security groups | EC2 classic way to pass cidr, protocol,|
|          |                                          |                 | sourceGroup, ports parameters          |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2,     | RunInstances                             | instances       | placement, block_device_mapping partial|
| VPC, EBS |                                          |                 | support, monitoring,                   |
|          |                                          |                 | iamInstanceProfile, ebsOptimized,      |
|          |                                          |                 | shutdownInitiatedInstanceBehavior      |
|          |                                          |                 | parameters                             |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *RunScheduledInstances*                  | scheduled       | not supported                          |
|          |                                          | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **StartInstances**                       | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **StopInstances**                        | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| EC2      | **TerminateInstances**                   | instances       |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *UnassignIpv6Addresses*                  | network         | not supported                          |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
| VPC      | **UnassignPrivateIpAddresses**           | network         |                                        |
|          |                                          | interfaces      |                                        |
+----------+------------------------------------------+-----------------+----------------------------------------+
|          | *UnmonitorInstances*                     | monitoring      | not supported                          |
+----------+------------------------------------------+-----------------+----------------------------------------+


References
----------

Documentation:
https://docs.openstack.org/ec2-api/latest/

Wiki:
https://wiki.openstack.org/wiki/EC2API

Bugs:
https://launchpad.net/ec2-api

Source:
https://opendev.org/openstack/ec2-api

Blueprint:
https://blueprints.launchpad.net/nova/+spec/ec2-api

Spec:
https://review.opendev.org/#/c/147882/
