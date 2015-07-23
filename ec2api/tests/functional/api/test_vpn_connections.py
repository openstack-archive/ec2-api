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
from lxml import etree

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class VpnConnectionTest(base.EC2TestCase):

    CUSTOMER_GATEWAY_IP = '198.51.100.77'
    CUSTOMER_VPN_CIDR = '172.16.25.0/24'
    cgw_id = None
    vgw_id = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(VpnConnectionTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

        data = cls.client.create_customer_gateway(
            Type='ipsec.1', PublicIp=cls.CUSTOMER_GATEWAY_IP, BgpAsn=65000)
        cls.cgw_id = data['CustomerGateway']['CustomerGatewayId']
        cls.addResourceCleanUpStatic(
            cls.client.delete_customer_gateway, CustomerGatewayId=cls.cgw_id)
        cls.get_customer_gateway_waiter().wait_available(cls.cgw_id)

        data = cls.client.create_vpn_gateway(
            Type='ipsec.1', AvailabilityZone=CONF.aws.aws_zone)
        cls.vgw_id = data['VpnGateway']['VpnGatewayId']
        cls.addResourceCleanUpStatic(
            cls.client.delete_vpn_gateway, VpnGatewayId=cls.vgw_id)
        cls.get_vpn_gateway_waiter().wait_available(cls.vgw_id)

    def test_create_delete_vpn_connection(self):
        data = self.client.create_vpn_connection(
            CustomerGatewayId=self.cgw_id, VpnGatewayId=self.vgw_id,
            Options={'StaticRoutesOnly': True}, Type='ipsec.1')
        vpn_id = data['VpnConnection']['VpnConnectionId']
        vpn_clean = self.addResourceCleanUp(
            self.client.delete_vpn_connection, VpnConnectionId=vpn_id)
        vpn_config = etree.fromstring(
            data['VpnConnection']['CustomerGatewayConfiguration'])
        psks = vpn_config.xpath(
            '/vpn_connection/ipsec_tunnel/ike/pre_shared_key')
        self.assertNotEmpty(psks)
        self.assertTrue(psks[0].text)
        vpn_waiter = self.get_vpn_connection_waiter()
        vpn_waiter.wait_available(vpn_id)

        self.client.delete_vpn_connection(VpnConnectionId=vpn_id)
        self.cancelResourceCleanUp(vpn_clean)
        vpn_waiter.wait_delete(vpn_id)

        try:
            data = self.client.describe_vpn_connections(
                VpnConnectionIds=[vpn_id])
            self.assertEqual(1, len(data['VpnConnections']))
            self.assertEqual('deleted', data['VpnConnections'][0]['State'])
        except botocore.exceptions.ClientError as ex:
            self.assertEqual('InvalidVpnConnectionID.NotFound',
                             ex.response['Error']['Code'])

    def test_create_delete_vpn_connection_route(self):
        data = self.client.create_vpn_connection(
            CustomerGatewayId=self.cgw_id, VpnGatewayId=self.vgw_id,
            Options={'StaticRoutesOnly': True}, Type='ipsec.1')
        vpn_id = data['VpnConnection']['VpnConnectionId']
        self.addResourceCleanUp(
            self.client.delete_vpn_connection, VpnConnectionId=vpn_id)
        vpn_waiter = self.get_vpn_connection_waiter()
        vpn_waiter.wait_available(vpn_id)

        data = self.client.create_vpn_connection_route(
            VpnConnectionId=vpn_id,
            DestinationCidrBlock=self.CUSTOMER_VPN_CIDR)

        data = self.client.describe_vpn_connections(VpnConnectionIds=[vpn_id])
        self.assertEqual(1, len(data['VpnConnections'][0]['Routes']))
        self.assertEqual(
            self.CUSTOMER_VPN_CIDR,
            data['VpnConnections'][0]['Routes'][0]['DestinationCidrBlock'])
        route_waiter = self.get_vpn_connection_route_waiter(
            self.CUSTOMER_VPN_CIDR)
        route_waiter.wait_available(vpn_id)

        data = self.client.delete_vpn_connection_route(
            VpnConnectionId=vpn_id,
            DestinationCidrBlock=self.CUSTOMER_VPN_CIDR)
        data = self.client.describe_vpn_connections(VpnConnectionIds=[vpn_id])
        route_waiter.wait_delete(vpn_id)
