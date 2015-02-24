# Copyright 2014 OpenStack Foundation
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
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF

LOG = log.getLogger(__name__)


class SecurityGroupTest(base.EC2TestCase):

    VPC_CIDR = '10.10.0.0/20'
    vpc_id = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(SecurityGroupTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

        resp, data = cls.client.CreateVpc(CidrBlock=cls.VPC_CIDR)
        cls.assertResultStatic(resp, data)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.addResourceCleanUpStatic(cls.client.DeleteVpc, VpcId=cls.vpc_id)
        cls.get_vpc_waiter().wait_available(cls.vpc_id)

    def test_create_delete_security_group(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        resp, data = self.client.CreateSecurityGroup(VpcId=self.vpc_id,
                                                     GroupName=name,
                                                     Description=desc)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSecurityGroup,
                                            GroupId=group_id)
        time.sleep(2)

        resp, data = self.client.DeleteSecurityGroup(GroupId=group_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.DescribeSecurityGroups(GroupIds=[group_id])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidGroup.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteSecurityGroup(GroupId=group_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidGroup.NotFound', data['Error']['Code'])

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "MismatchError: 'InvalidParameterValue' != 'ValidationError'")
    def test_create_invalid_name_desc(self):
        valid = data_utils.rand_name('sgName')
        invalid = 'name%"'
        resp, data = self.client.CreateSecurityGroup(VpcId=self.vpc_id,
                                                     GroupName=invalid,
                                                     Description=valid)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        resp, data = self.client.CreateSecurityGroup(VpcId=self.vpc_id,
                                                     GroupName=valid,
                                                     Description=invalid)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        resp, data = self.client.CreateSecurityGroup(VpcId=self.vpc_id,
                                                     GroupName=valid)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('MissingParameter', data['Error']['Code'])

        resp, data = self.client.CreateSecurityGroup(VpcId=self.vpc_id,
                                                     Description=valid)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('MissingParameter', data['Error']['Code'])

    def test_ingress_rules(self):
        self._test_rules(self.client.AuthorizeSecurityGroupIngress,
                         self.client.RevokeSecurityGroupIngress,
                         'IpPermissions')

    def test_egress_rules(self):
        self._test_rules(self.client.AuthorizeSecurityGroupEgress,
                         self.client.RevokeSecurityGroupEgress,
                         'IpPermissionsEgress')

    def _test_rules(self, add_func, del_func, field):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        resp, data = self.client.CreateSecurityGroup(VpcId=self.vpc_id,
                                                     GroupName=name,
                                                     Description=desc)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSecurityGroup,
                                            GroupId=group_id)
        time.sleep(2)
        resp, data = self.client.DescribeSecurityGroups(GroupIds=[group_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        count = len(data['SecurityGroups'][0][field])

        kwargs = {
            'GroupId': group_id,
            'IpPermissions': [{
                'IpProtocol': 'icmp',
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [{
                    'CidrIp': '10.0.0.0/8'
                }],
            }]
        }
        resp, data = add_func(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DescribeSecurityGroups(GroupIds=[group_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['SecurityGroups']))
        self.assertEqual(count + 1, len(data['SecurityGroups'][0][field]))
        found = False
        for perm in data['SecurityGroups'][0][field]:
            cidrs = [v['CidrIp'] for v in perm.get('IpRanges', [])]
            if (perm.get('FromPort') == -1 and
                    perm.get('ToPort') == -1 and
                    perm.get('IpProtocol') == 'icmp' and
                    len(perm.get('IpRanges')) == 1 and
                    '10.0.0.0/8' in cidrs):
                found = True
        self.assertTrue(found)

        resp, data = del_func(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = del_func(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidPermission.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteSecurityGroup(GroupId=group_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
