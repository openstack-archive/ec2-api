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

from oslo_log import log
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class SubnetTest(base.EC2TestCase):

    BASE_CIDR = '10.2.0.0'
    VPC_CIDR = BASE_CIDR + '/20'
    vpc_id = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(SubnetTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

        resp, data = cls.client.CreateVpc(CidrBlock=cls.VPC_CIDR)
        cls.assertResultStatic(resp, data)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.addResourceCleanUpStatic(cls.client.DeleteVpc, VpcId=cls.vpc_id)
        cls.get_vpc_waiter().wait_available(cls.vpc_id)

    def test_create_delete_subnet(self):
        cidr = self.BASE_CIDR + '/24'
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSubnet,
                                            SubnetId=subnet_id)
        self.assertEqual(cidr, data['Subnet']['CidrBlock'])
        self.assertIsNotNone(data['Subnet'].get('AvailableIpAddressCount'))

        self.get_subnet_waiter().wait_available(subnet_id)

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)

        resp, data = self.client.DescribeSubnets(SubnetIds=[subnet_id])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidSubnetID.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidSubnetID.NotFound', data['Error']['Code'])

    def test_dependency_subnet_to_vpc(self):
        resp, data = self.client.CreateVpc(CidrBlock=self.VPC_CIDR)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        vpc_clean = self.addResourceCleanUp(self.client.DeleteVpc,
                                            VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        cidr = self.BASE_CIDR + '/24'
        resp, data = self.client.CreateSubnet(VpcId=vpc_id,
                                              CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSubnet,
                                            SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('DependencyViolation', data['Error']['Code'])

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)

        self.client.DeleteVpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(vpc_clean)

    @testtools.skipUnless(
        CONF.aws.run_incompatible_tests,
        "bug with overlapped subnets")
    def test_create_overlapped_subnet(self):
        cidr = self.BASE_CIDR + '/24'
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSubnet,
                                            SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        cidr = '10.2.0.128/26'
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=cidr)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteSubnet,
                                    SubnetId=data['Subnet']['SubnetId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidSubnet.Conflict', data['Error']['Code'])

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)

    def test_create_subnet_invalid_cidr(self):
        # NOTE(andrey-mp): another cidr than VPC has
        cidr = '10.1.0.0/24'
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=cidr)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteSubnet,
                                    SubnetId=data['Subnet']['SubnetId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidSubnet.Range', data['Error']['Code'])

        # NOTE(andrey-mp): bigger cidr than VPC has
        cidr = self.BASE_CIDR + '/19'
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=cidr)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteSubnet,
                                    SubnetId=data['Subnet']['SubnetId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidSubnet.Range', data['Error']['Code'])

        # NOTE(andrey-mp): too small cidr
        cidr = self.BASE_CIDR + '/29'
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=cidr)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteSubnet,
                                    SubnetId=data['Subnet']['SubnetId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidSubnet.Range', data['Error']['Code'])

    def test_describe_subnets_base(self):
        cidr = self.BASE_CIDR + '/24'
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSubnet,
                                            SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        # NOTE(andrey-mp): by real id
        resp, data = self.client.DescribeSubnets(SubnetIds=[subnet_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Subnets']))

        # NOTE(andrey-mp): by fake id
        resp, data = self.client.DescribeSubnets(SubnetIds=['subnet-0'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidSubnetID.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)

    def test_describe_subnets_filters(self):
        cidr = self.BASE_CIDR + '/24'
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSubnet,
                                            SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        # NOTE(andrey-mp): by filter real cidr
        resp, data = self.client.DescribeSubnets(
            Filters=[{'Name': 'cidr', 'Values': [cidr]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Subnets']))

        # NOTE(andrey-mp): by filter fake cidr
        resp, data = self.client.DescribeSubnets(
            Filters=[{'Name': 'cidr', 'Values': ['123.0.0.0/16']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Subnets']))

        # NOTE(andrey-mp): by fake filter
        resp, data = self.client.DescribeSubnets(
            Filters=[{'Name': 'fake', 'Values': ['fake']}])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)
