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

import botocore.exceptions

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class VpnGatewayTest(base.EC2TestCase):

    VPC_CIDR = '10.41.0.0/20'
    vpc_id = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(VpnGatewayTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

        data = cls.client.create_vpc(CidrBlock=cls.VPC_CIDR)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.get_vpc_waiter().wait_available(cls.vpc_id)
        cls.addResourceCleanUpStatic(cls.client.delete_vpc, VpcId=cls.vpc_id)

    def test_create_delete_vpn_gateway(self):
        data = self.client.create_vpn_gateway(
            Type='ipsec.1', AvailabilityZone=CONF.aws.aws_zone)
        vgw_id = data['VpnGateway']['VpnGatewayId']
        vgw_clean = self.addResourceCleanUp(
            self.client.delete_vpn_gateway, VpnGatewayId=vgw_id)
        self.get_vpn_gateway_waiter().wait_available(vgw_id)

        self.client.delete_vpn_gateway(VpnGatewayId=vgw_id)
        self.cancelResourceCleanUp(vgw_clean)
        self.get_vpn_gateway_waiter().wait_delete(vgw_id)

        try:
            data = self.client.describe_vpn_gateways(
                VpnGatewayIds=[vgw_id])
            self.assertEqual(1, len(data['VpnGateways']))
            self.assertEqual('deleted', data['VpnGateways'][0]['State'])
        except botocore.exceptions.ClientError as ex:
            self.assertEqual('InvalidVpnGatewayID.NotFound',
                             ex.response['Error']['Code'])

    def test_attach_detach_vpn_gateway(self):
        data = self.client.create_vpn_gateway(
            Type='ipsec.1', AvailabilityZone=CONF.aws.aws_zone)
        vgw_id = data['VpnGateway']['VpnGatewayId']
        self.addResourceCleanUp(self.client.delete_vpn_gateway,
                                VpnGatewayId=vgw_id)
        self.get_vpn_gateway_waiter().wait_available(vgw_id)

        data = self.client.attach_vpn_gateway(VpnGatewayId=vgw_id,
                                              VpcId=self.vpc_id)
        attach_clean = self.addResourceCleanUp(
            self.client.detach_vpn_gateway,
            VpnGatewayId=vgw_id, VpcId=self.vpc_id)
        self.assertIn('VpcAttachment', data)
        self.assertEqual(self.vpc_id, data['VpcAttachment']['VpcId'])
        attach_waiter = self.get_vpn_gateway_attachment_waiter()
        attach_waiter.wait_available(vgw_id, 'attached')

        data = self.client.detach_vpn_gateway(VpnGatewayId=vgw_id,
                                              VpcId=self.vpc_id)
        self.cancelResourceCleanUp(attach_clean)
        attach_waiter.wait_delete(vgw_id)

        data = self.client.describe_vpn_gateways(VpnGatewayIds=[vgw_id])
        self.assertEqual(
             'detached',
             (data['VpnGateways'][0]['VpcAttachments'] or
              [{'State': 'detached'}])[0]['State'])
