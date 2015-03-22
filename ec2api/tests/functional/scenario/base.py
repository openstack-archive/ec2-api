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

        resp, data = self.client.AllocateAddress(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        public_ip = data['PublicIp']
        self.addResourceCleanUp(self.client.ReleaseAddress, PublicIp=public_ip)

        resp, data = self.client.AssociateAddress(InstanceId=instance_id,
                                                  PublicIp=public_ip)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DisassociateAddress,
                                PublicIp=public_ip)

        return public_ip

    def create_key_pair(self, key_name):
        resp, data = self.client.CreateKeyPair(KeyName=key_name)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DeleteKeyPair, KeyName=key_name)
        return data.get('KeyMaterial')

    def prepare_security_group(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        resp, data = self.client.CreateSecurityGroup(GroupName=name,
                                                     Description=desc)
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
