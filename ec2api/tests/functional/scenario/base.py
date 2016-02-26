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
from tempest.lib.common.utils import data_utils

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class BaseScenarioTest(base.EC2TestCase):

    def get_instance_ip(self, instance_id):
        instance = self.get_instance(instance_id)
        public_ip = instance.get('PublicIpAddress')
        if public_ip:
            return public_ip

        is_vpc = 'VpcId' in instance
        alloc_id, public_ip = self.allocate_address(is_vpc)

        kwargs = {'InstanceId': instance_id}
        if is_vpc:
            kwargs['AllocationId'] = alloc_id
        else:
            kwargs['PublicIp'] = public_ip
        data = self.client.associate_address(*[], **kwargs)
        if is_vpc:
            self.addResourceCleanUp(self.client.disassociate_address,
                                    AssociationId=data['AssociationId'])
            self.get_address_assoc_waiter().wait_available(
                {'AllocationId': alloc_id})
        else:
            self.addResourceCleanUp(self.client.disassociate_address,
                                    PublicIp=public_ip)
            self.get_address_assoc_waiter().wait_available(
                {'PublicIp': public_ip})

        return public_ip

    def allocate_address(self, is_vpc):
        kwargs = dict()
        if is_vpc:
            kwargs['Domain'] = 'vpc'
        data = self.client.allocate_address(*[], **kwargs)
        alloc_id = data.get('AllocationId')
        public_ip = data['PublicIp']
        if is_vpc:
            self.addResourceCleanUp(self.client.release_address,
                                    AllocationId=alloc_id)
        else:
            self.addResourceCleanUp(self.client.release_address,
                                    PublicIp=public_ip)

        return alloc_id, public_ip

    def create_key_pair(self, key_name):
        data = self.client.create_key_pair(KeyName=key_name)
        self.addResourceCleanUp(self.client.delete_key_pair, KeyName=key_name)
        return data.get('KeyMaterial')

    def create_standard_security_group(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        kwargs = {'GroupName': name, 'Description': desc}
        self.client.create_security_group(*[], **kwargs)
        self.addResourceCleanUp(self.client.delete_security_group,
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
        self.client.authorize_security_group_ingress(*[], **kwargs)

        return name

    def prepare_vpc_default_security_group(self, vpc_id):
        data = self.client.describe_security_groups(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
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
        self.client.authorize_security_group_ingress(*[], **kwargs)

    def create_network_interface(self, subnet_id):
        data = self.client.create_network_interface(SubnetId=subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.delete_network_interface,
                                NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        return ni_id
