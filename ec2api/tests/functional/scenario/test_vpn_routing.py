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

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class VpnRoutingTest(base.EC2TestCase):

    VPC_CIDR = '10.4.0.0/20'
    CUSTOMER_GATEWAY_IP = '198.51.100.77'
    CUSTOMER_VPN_CIDR = '172.16.25.0/24'

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(VpnRoutingTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

    def test_vpn_routing(self):
        vpc_id, _subnet_id = self.create_vpc_and_subnet(self.VPC_CIDR)

        data = self.client.create_customer_gateway(
            Type='ipsec.1', PublicIp=self.CUSTOMER_GATEWAY_IP, BgpAsn=65000)
        cgw_id = data['CustomerGateway']['CustomerGatewayId']
        self.addResourceCleanUpStatic(
            self.client.delete_customer_gateway, CustomerGatewayId=cgw_id)

        data = self.client.create_vpn_gateway(Type='ipsec.1')
        vgw_id = data['VpnGateway']['VpnGatewayId']
        self.addResourceCleanUpStatic(
            self.client.delete_vpn_gateway, VpnGatewayId=vgw_id)

        data = self.client.create_vpn_connection(
            CustomerGatewayId=cgw_id, VpnGatewayId=vgw_id,
            Options={'StaticRoutesOnly': True}, Type='ipsec.1')
        vpn_id = data['VpnConnection']['VpnConnectionId']
        self.addResourceCleanUp(self.client.delete_vpn_connection,
                                VpnConnectionId=vpn_id)

        data = self.client.attach_vpn_gateway(VpnGatewayId=vgw_id,
                                              VpcId=vpc_id)
        self.addResourceCleanUp(self.client.detach_vpn_gateway,
                                VpnGatewayId=vgw_id, VpcId=vpc_id)

        vpn_waiter = self.get_vpn_connection_waiter()
        vpn_waiter.wait_available(vpn_id)

        attach_waiter = self.get_vpn_gateway_attachment_waiter()
        attach_waiter.wait_available(vgw_id, 'attached')

        data = self.client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        rtb_id = data['RouteTables'][0]['RouteTableId']
        data = self.client.enable_vgw_route_propagation(RouteTableId=rtb_id,
                                                        GatewayId=vgw_id)
        data = self.client.create_vpn_connection_route(
            VpnConnectionId=vpn_id,
            DestinationCidrBlock=self.CUSTOMER_VPN_CIDR)

        route_waiter = self.get_vpn_connection_route_waiter(
            self.CUSTOMER_VPN_CIDR)
        route_waiter.wait_available(vpn_id)

        data = self.client.describe_route_tables(RouteTableIds=[rtb_id])
        route = next((r for r in data['RouteTables'][0]['Routes']
                      if r['DestinationCidrBlock'] == self.CUSTOMER_VPN_CIDR),
                     None)
        self.assertIsNotNone(route)
        self.assertEqual('active', route['State'])
        self.assertEqual('EnableVgwRoutePropagation', route['Origin'])
