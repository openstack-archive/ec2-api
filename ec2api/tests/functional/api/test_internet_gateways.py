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
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class InternetGatewayTest(base.EC2TestCase):

    VPC_CIDR = '10.4.0.0/20'
    VPC_CIDR_ALT = '10.5.0.0/20'
    vpc_id = None
    vpc_id_alt = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(InternetGatewayTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

        resp, data = cls.client.CreateVpc(CidrBlock=cls.VPC_CIDR)
        cls.assertResultStatic(resp, data)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.get_vpc_waiter().wait_available(cls.vpc_id)
        cls.addResourceCleanUpStatic(cls.client.DeleteVpc, VpcId=cls.vpc_id)

        resp, data = cls.client.CreateVpc(CidrBlock=cls.VPC_CIDR_ALT)
        cls.assertResultStatic(resp, data)
        cls.vpc_id_alt = data['Vpc']['VpcId']
        cls.get_vpc_waiter().wait_available(cls.vpc_id_alt)
        cls.addResourceCleanUpStatic(cls.client.DeleteVpc,
                                     VpcId=cls.vpc_id_alt)

    def test_create_attach_internet_gateway(self):
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        res_clean = self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                            InternetGatewayId=gw_id)
        self.assertEmpty(data['InternetGateway'].get('Attachments', []))

        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DetachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.DescribeInternetGateways(
            InternetGatewayIds=[gw_id])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidInternetGatewayID.NotFound',
                         data['Error']['Code'])

    def test_delete_attached_internet_gateway(self):
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        res_clean = self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                            InternetGatewayId=gw_id)
        self.assertEmpty(data['InternetGateway'].get('Attachments', []))

        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('DependencyViolation', data['Error']['Code'])

        resp, data = self.client.DetachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "Another error code returned - InvalidParameterValue")
    def test_attach_detach_invalid_internet_gateway(self):
        gw_id = "gw-1"
        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidInternetGatewayID.NotFound',
                         data['Error']['Code'])

        resp, data = self.client.DetachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidInternetGatewayID.NotFound',
                         data['Error']['Code'])

    def test_double_attach_internet_gateway(self):
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        res_clean = self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                            InternetGatewayId=gw_id)
        self.assertEmpty(data['InternetGateway'].get('Attachments', []))

        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('Resource.AlreadyAssociated', data['Error']['Code'])

        resp, data = self.client.DetachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_attach_one_internet_gateway_to_two_vpcs(self):
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        res_clean = self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                            InternetGatewayId=gw_id)
        self.assertEmpty(data['InternetGateway'].get('Attachments', []))

        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id_alt,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('Resource.AlreadyAssociated', data['Error']['Code'])

        resp, data = self.client.DetachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_describe_internet_gateways_base(self):
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        res_clean = self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                            InternetGatewayId=gw_id)
        self.assertEmpty(data['InternetGateway'].get('Attachments', []))

        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DetachInternetGateway,
                                VpcId=self.vpc_id,
                                InternetGatewayId=gw_id)

        time.sleep(2)
        # NOTE(andrey-mp): by real id
        resp, data = self.client.DescribeInternetGateways(
            InternetGatewayIds=[gw_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['InternetGateways']))

        # NOTE(andrey-mp): by fake id
        resp, data = self.client.DescribeInternetGateways(
            InternetGatewayIds=['igw-0'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidInternetGatewayID.NotFound',
                         data['Error']['Code'])

        resp, data = self.client.DetachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_describe_internet_gateways_filters(self):
        # NOTE(andrey-mp): by filter real vpc-id before creation
        resp, data = self.client.DescribeInternetGateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [self.vpc_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['InternetGateways']))

        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        res_clean = self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                            InternetGatewayId=gw_id)
        self.assertEmpty(data['InternetGateway'].get('Attachments', []))

        resp, data = self.client.AttachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DetachInternetGateway,
                                VpcId=self.vpc_id,
                                InternetGatewayId=gw_id)

        time.sleep(2)
        # NOTE(andrey-mp): by filter real vpc-id
        resp, data = self.client.DescribeInternetGateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [self.vpc_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['InternetGateways']))
        self.assertEqual(gw_id,
                         data['InternetGateways'][0]['InternetGatewayId'])

        # NOTE(andrey-mp): by filter fake vpc-id
        resp, data = self.client.DescribeInternetGateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': ['vpc-0']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['InternetGateways']))

        # NOTE(andrey-mp): by fake filter
        resp, data = self.client.DescribeInternetGateways(
            Filters=[{'Name': 'fake', 'Values': ['fake']}])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        resp, data = self.client.DetachInternetGateway(VpcId=self.vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
