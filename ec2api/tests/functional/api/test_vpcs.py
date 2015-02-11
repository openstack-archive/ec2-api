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
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)

        self.assertEqual(cidr, data['Vpc']['CidrBlock'])
        if CONF.aws.run_incompatible_tests:
            # NOTE(andrey-mp): not ready
            self.assertEqual('default', data['Vpc']['InstanceTenancy'])
        self.assertIsNotNone(data['Vpc'].get('DhcpOptionsId'))

        self.get_vpc_waiter().wait_available(vpc_id)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

        resp, data = self.client.DescribeVpcs(VpcIds=[vpc_id])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidVpcID.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidVpcID.NotFound', data['Error']['Code'])

    def test_create_more_than_one_vpc(self):
        cidr = '10.0.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id1 = data['Vpc']['VpcId']
        rc1 = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id1)
        self.get_vpc_waiter().wait_available(vpc_id1)

        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id2 = data['Vpc']['VpcId']
        rc2 = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id2)
        self.get_vpc_waiter().wait_available(vpc_id2)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(rc1)
        self.get_vpc_waiter().wait_delete(vpc_id1)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id2)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(rc2)
        self.get_vpc_waiter().wait_delete(vpc_id2)

    def test_describe_vpcs_base(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        # NOTE(andrey-mp): by real id
        resp, data = self.client.DescribeVpcs(VpcIds=[vpc_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Vpcs']))

        # NOTE(andrey-mp): by fake id
        resp, data = self.client.DescribeVpcs(VpcIds=['vpc-0'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidVpcID.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    def test_describe_vpcs_filters(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        # NOTE(andrey-mp): by filter real cidr
        resp, data = self.client.DescribeVpcs(
            Filters=[{'Name': 'cidr', 'Values': [cidr]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Vpcs']))

        # NOTE(andrey-mp): by filter fake cidr
        resp, data = self.client.DescribeVpcs(
            Filters=[{'Name': 'cidr', 'Values': ['123.0.0.0/16']}])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(0, len(data['Vpcs']))

        if CONF.aws.run_incompatible_tests:
            # NOTE(andrey-mp): describe no attributes
            resp, data = self.client.DescribeVpcAttribute(VpcId=vpc_id)
            self.assertEqual(400, resp.status_code)
            self.assertEqual('InvalidParameterCombination',
                             data['Error']['Code'])

        # NOTE(andrey-mp): by fake filter
        resp, data = self.client.DescribeVpcs(
            Filters=[{'Name': 'fake', 'Values': ['fake']}])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue',
                         data['Error']['Code'])

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "Invalid request on checking vpc atributes.")
    def test_vpc_attributes(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        self._check_attribute(vpc_id, 'EnableDnsHostnames')
        self._check_attribute(vpc_id, 'EnableDnsSupport')

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    def _check_attribute(self, vpc_id, attribute):
        req_attr = attribute[0].lower() + attribute[1:]
        resp, data = self.client.DescribeVpcAttribute(VpcId=vpc_id,
                                                      Attribute=req_attr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        attr = data[attribute].get('Value')
        self.assertIsNotNone(attr)

        kwargs = {'VpcId': vpc_id, attribute: {'Value': not attr}}
        resp, data = self.client.ModifyVpcAttribute(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        resp, data = self.client.DescribeVpcAttribute(VpcId=vpc_id,
                                                      Attribute=req_attr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertNotEqual(attr, data[attribute].get('Value'))

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "InvalidParameterCombination' != 'InvalidRequest")
    def test_describe_invalid_attributes(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        # NOTE(andrey-mp): describe no attributes
        resp, data = self.client.DescribeVpcAttribute(VpcId=vpc_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterCombination',
                         data['Error']['Code'])

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    def test_create_with_invalid_cidr(self):
        # NOTE(andrey-mp): The largest uses a /16 netmask
        resp, data = self.client.CreateVpc(CidrBlock='10.0.0.0/15')
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteVpc,
                                    VpcId=data['Vpc']['VpcId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidVpc.Range', data['Error']['Code'])

        # NOTE(andrey-mp): The smallest VPC you can create uses a /28 netmask
        resp, data = self.client.CreateVpc(CidrBlock='10.0.0.0/29')
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteVpc,
                                    VpcId=data['Vpc']['VpcId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidVpc.Range', data['Error']['Code'])

    def test_describe_non_existing_vpc_by_id(self):
        vpc_id = 'vpc-00000000'
        resp, data = self.client.DescribeVpcs(VpcIds=[vpc_id])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidVpcID.NotFound', data['Error']['Code'])

    def test_describe_non_existing_vpc_by_cidr(self):
        resp, data = self.client.DescribeVpcs(
            Filters=[{'Name': 'cidr', 'Values': ['123.0.0.0/16']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Vpcs']))

    def test_describe_with_invalid_filter(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        resp, data = self.client.DescribeVpcs(
            Filters=[{'Name': 'unknown', 'Values': ['unknown']}])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)
