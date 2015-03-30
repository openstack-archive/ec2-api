# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import time

from oslo_log import log
from tempest_lib.common.utils import data_utils

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class BaseScenarioTest(base.EC2TestCase):

    def run_instance(self, **kwargs):
        kwargs.setdefault('ImageId', CONF.aws.image_id)
        kwargs.setdefault('InstanceType', CONF.aws.instance_type)
        kwargs.setdefault('Placement', {'AvailabilityZone': CONF.aws.aws_zone})
        kwargs['MinCount'] = 1
        kwargs['MaxCount'] = 1
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        self.addResourceCleanUp(self.client.TerminateInstances,
                                InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))
        return instance_id

    def get_instance_ip(self, instance_id):
        instance = self.get_instance(instance_id)
        public_ip = instance.get('PublicIpAddress')
        if public_ip:
            return public_ip

        alloc_id, public_ip = self.allocate_address('VpcId' in instance)

        kwargs = {'InstanceId': instance_id}
        if 'VpcId' in instance:
            kwargs['AllocationId'] = alloc_id
        else:
            kwargs['PublicIp'] = public_ip
        resp, data = self.client.AssociateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        if 'VpcId' in instance:
            self.addResourceCleanUp(self.client.DisassociateAddress,
                                    AssociationId=data['AssociationId'])
        else:
            self.addResourceCleanUp(self.client.DisassociateAddress,
                                    PublicIp=public_ip)

        return public_ip

    def allocate_address(self, is_vpc):
        kwargs = dict()
        if is_vpc:
            kwargs['Domain'] = 'vpc'
        resp, data = self.client.AllocateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        alloc_id = data.get('AllocationId')
        public_ip = data['PublicIp']
        if is_vpc:
            self.addResourceCleanUp(self.client.ReleaseAddress,
                                    AllocationId=alloc_id)
        else:
            self.addResourceCleanUp(self.client.ReleaseAddress,
                                    PublicIp=public_ip)

        return alloc_id, public_ip

    def create_key_pair(self, key_name):
        resp, data = self.client.CreateKeyPair(KeyName=key_name)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DeleteKeyPair, KeyName=key_name)
        return data.get('KeyMaterial')

    def create_standard_security_group(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        kwargs = {'GroupName': name, 'Description': desc}
        resp, data = self.client.CreateSecurityGroup(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DeleteSecurityGroup,
                                GroupName=name)
        time.sleep(2)

        kwargs = {
            'GroupName': name,
            'IpPermissions': [{
                'IpProtocol': 'icmp',
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [{
                    'CidrIp': '0.0.0.0/0'
                }],
            }, {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{
                    'CidrIp': '0.0.0.0/0'
                }],
            }]
        }
        resp, data = self.client.AuthorizeSecurityGroupIngress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        return name

    def prepare_vpc_default_security_group(self, vpc_id):
        resp, data = self.client.DescribeSecurityGroups(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['SecurityGroups']))
        group_id = data['SecurityGroups'][0]['GroupId']
        kwargs = {
            'GroupId': group_id,
            'IpPermissions': [{
                'IpProtocol': '-1',
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [{
                    'CidrIp': '0.0.0.0/0'
                }],
            }]
        }
        resp, data = self.client.AuthorizeSecurityGroupIngress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

    def prepare_route(self, vpc_id, gw_id):
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['RouteTables']))

        kwargs = {
            'DestinationCidrBlock': '0.0.0.0/0',
            'RouteTableId': data['RouteTables'][0]['RouteTableId'],
            'GatewayId': gw_id
        }
        resp, data = self.client.CreateRoute(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

    def create_vpc_and_subnet(self, cidr):
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        resp, data = self.client.CreateSubnet(VpcId=vpc_id, CidrBlock=cidr,
            AvailabilityZone=CONF.aws.aws_zone)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        self.addResourceCleanUp(self.client.DeleteSubnet, SubnetId=subnet_id)

        return vpc_id, subnet_id

    def create_network_interface(self, subnet_id):
        resp, data = self.client.CreateNetworkInterface(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.DeleteNetworkInterface,
                                NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        return ni_id

    def create_and_attach_internet_gateway(self, vpc_id):
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                InternetGatewayId=gw_id)
        resp, data = self.client.AttachInternetGateway(VpcId=vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DetachInternetGateway,
                                VpcId=vpc_id,
                                InternetGatewayId=gw_id)

        return gw_id
