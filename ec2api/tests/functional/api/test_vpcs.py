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

import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class VPCTest(base.EC2TestCase):

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(VPCTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

    def test_create_delete_vpc(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.delete_vpc,
                                           VpcId=vpc_id)

        self.assertEqual(cidr, data['Vpc']['CidrBlock'])
        if CONF.aws.run_incompatible_tests:
            # NOTE(andrey-mp): not ready
            self.assertEqual('default', data['Vpc']['InstanceTenancy'])
        self.assertIsNotNone(data['Vpc'].get('DhcpOptionsId'))

        self.get_vpc_waiter().wait_available(vpc_id)

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

        self.assertRaises('InvalidVpcID.NotFound',
                          self.client.describe_vpcs,
                          VpcIds=[vpc_id])

        self.assertRaises('InvalidVpcID.NotFound',
                          self.client.delete_vpc,
                          VpcId=vpc_id)

    def test_create_more_than_one_vpc(self):
        cidr = '10.0.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id1 = data['Vpc']['VpcId']
        rc1 = self.addResourceCleanUp(self.client.delete_vpc, VpcId=vpc_id1)
        self.get_vpc_waiter().wait_available(vpc_id1)

        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id2 = data['Vpc']['VpcId']
        rc2 = self.addResourceCleanUp(self.client.delete_vpc, VpcId=vpc_id2)
        self.get_vpc_waiter().wait_available(vpc_id2)

        self.client.delete_vpc(VpcId=vpc_id1)
        self.cancelResourceCleanUp(rc1)
        self.get_vpc_waiter().wait_delete(vpc_id1)

        self.client.delete_vpc(VpcId=vpc_id2)
        self.cancelResourceCleanUp(rc2)
        self.get_vpc_waiter().wait_delete(vpc_id2)

    def test_describe_vpcs_base(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.delete_vpc,
                                           VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        # NOTE(andrey-mp): by real id
        data = self.client.describe_vpcs(VpcIds=[vpc_id])
        self.assertEqual(1, len(data['Vpcs']))

        # NOTE(andrey-mp): by fake id
        self.assertRaises('InvalidVpcID.NotFound',
                          self.client.describe_vpcs,
                          VpcIds=['vpc-0'])

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    def test_describe_vpcs_filters(self):
        cidr = '10.163.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.delete_vpc,
                                           VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        # NOTE(andrey-mp): by filter real cidr
        data = self.client.describe_vpcs(
            Filters=[{'Name': 'cidr', 'Values': [cidr]}])
        self.assertEqual(1, len(data['Vpcs']))

        # NOTE(andrey-mp): by filter fake cidr
        data = self.client.describe_vpcs(
            Filters=[{'Name': 'cidr', 'Values': ['123.0.0.0/16']}])
        self.assertEqual(0, len(data['Vpcs']))

        # NOTE(andrey-mp): by fake filter
        self.assertRaises('InvalidParameterValue',
                          self.client.describe_vpcs,
                          Filters=[{'Name': 'fake', 'Values': ['fake']}])

        data = self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "Invalid request on checking vpc atributes.")
    def test_vpc_attributes(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.delete_vpc,
                                           VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        self._check_attribute(vpc_id, 'EnableDnsHostnames')
        self._check_attribute(vpc_id, 'EnableDnsSupport')

        data = self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    def _check_attribute(self, vpc_id, attribute):
        req_attr = attribute[0].lower() + attribute[1:]
        data = self.client.describe_vpc_attribute(VpcId=vpc_id,
                                                  Attribute=req_attr)
        attr = data[attribute].get('Value')
        self.assertIsNotNone(attr)

        kwargs = {'VpcId': vpc_id, attribute: {'Value': not attr}}
        data = self.client.modify_vpc_attribute(*[], **kwargs)
        data = self.client.describe_vpc_attribute(VpcId=vpc_id,
                                                  Attribute=req_attr)
        self.assertNotEqual(attr, data[attribute].get('Value'))

    def test_create_with_invalid_cidr(self):
        def _rollback(fn_data):
            self.client.delete_vpc(VpcId=fn_data['Vpc']['VpcId'])

        # NOTE(andrey-mp): The largest uses a /16 netmask
        self.assertRaises('InvalidVpc.Range',
                          self.client.create_vpc, rollback_fn=_rollback,
                          CidrBlock='10.0.0.0/15')

        # NOTE(andrey-mp): The smallest VPC you can create uses a /28 netmask
        self.assertRaises('InvalidVpc.Range',
                          self.client.create_vpc, rollback_fn=_rollback,
                          CidrBlock='10.0.0.0/29')

    def test_describe_non_existing_vpc_by_id(self):
        vpc_id = 'vpc-00000000'
        self.assertRaises('InvalidVpcID.NotFound',
                          self.client.describe_vpcs,
                          VpcIds=[vpc_id])

    def test_describe_non_existing_vpc_by_cidr(self):
        data = self.client.describe_vpcs(
            Filters=[{'Name': 'cidr', 'Values': ['123.0.0.0/16']}])
        self.assertEqual(0, len(data['Vpcs']))

    def test_describe_with_invalid_filter(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.delete_vpc,
                                           VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        self.assertRaises('InvalidParameterValue',
                          self.client.describe_vpcs,
                          Filters=[{'Name': 'unknown', 'Values': ['unknown']}])

        data = self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)
