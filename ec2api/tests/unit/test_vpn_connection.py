# Copyright 2014
# The Cloudscaling Group, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy

import mock

from ec2api.api import vpn_connection
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class VpnConnectionTestCase(base.ApiTestCase):

    @mock.patch('random.choice')
    def test_create_vpn_connection(self, random_choice):
        self.set_mock_db_items(
            fakes.DB_VPN_GATEWAY_1, fakes.DB_VPN_GATEWAY_2,
            fakes.DB_CUSTOMER_GATEWAY_1, fakes.DB_CUSTOMER_GATEWAY_2)
        self.neutron.create_ikepolicy.side_effect = (
            tools.get_neutron_create('ikepolicy', fakes.ID_OS_IKEPOLICY_1))
        self.neutron.create_ipsecpolicy.side_effect = (
            tools.get_neutron_create('ipsecpolicy', fakes.ID_OS_IPSECPOLICY_1))
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_VPN_CONNECTION_1))
        random_choice.side_effect = iter(fakes.PRE_SHARED_KEY_1)

        resp = self.execute(
            'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1',
             'Options.StaticRoutesOnly': 'True'})
        self.assertThat(
            resp,
            matchers.DictMatches(
                {'vpnConnection': (
                    tools.update_dict(fakes.EC2_VPN_CONNECTION_1,
                                      {'routes': None}))}))

        self.neutron.create_ikepolicy.assert_called_once_with(
            {'ikepolicy': tools.purge_dict(fakes.OS_IKEPOLICY_1, ('id',))})
        self.neutron.create_ipsecpolicy.assert_called_once_with(
            {'ipsecpolicy': tools.purge_dict(fakes.OS_IPSECPOLICY_1, ('id',))})
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'vpn',
            tools.patch_dict(fakes.DB_VPN_CONNECTION_1,
                             {'cidrs': []}, ('id', )),
            project_id=None)
        self.neutron.update_ikepolicy.assert_called_once_with(
            fakes.ID_OS_IKEPOLICY_1,
            {'ikepolicy': {'name': fakes.ID_EC2_VPN_CONNECTION_1}})
        self.neutron.update_ipsecpolicy.assert_called_once_with(
            fakes.ID_OS_IPSECPOLICY_1,
            {'ipsecpolicy': {'name': fakes.ID_EC2_VPN_CONNECTION_1}})

    def test_create_vpn_connection_idempotent(self):
        self.set_mock_db_items(
            fakes.DB_VPN_GATEWAY_1, fakes.DB_CUSTOMER_GATEWAY_1,
            fakes.DB_VPN_CONNECTION_1)

        resp = self.execute(
            'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1',
             'Options.StaticRoutesOnly': 'True'})
        self.assertThat({'vpnConnection': fakes.EC2_VPN_CONNECTION_1},
                        matchers.DictMatches(resp))
        self.assertFalse(self.neutron.create_ikepolicy.called)
        self.assertFalse(self.neutron.create_ipsecpolicy.called)
        self.assertFalse(self.db_api.add_item.called)

    def test_create_vpn_connection_invalid_parameters(self):
        self.assert_execution_error(
            'Unsupported', 'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1',
             'Options.StaticRoutesOnly': 'False'})

        self.assert_execution_error(
            'Unsupported', 'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1'})

        self.set_mock_db_items(fakes.DB_CUSTOMER_GATEWAY_1)
        self.assert_execution_error(
            'InvalidVpnGatewayID.NotFound', 'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1',
             'Options.StaticRoutesOnly': 'True'})

        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1)
        self.assert_execution_error(
            'InvalidCustomerGatewayID.NotFound', 'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1',
             'Options.StaticRoutesOnly': 'True'})

        self.set_mock_db_items(
            fakes.DB_VPN_GATEWAY_2, fakes.DB_CUSTOMER_GATEWAY_1,
            fakes.DB_VPN_CONNECTION_1)
        self.assert_execution_error(
            'InvalidCustomerGateway.DuplicateIpAddress', 'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1',
             'Options.StaticRoutesOnly': 'True'})

    @tools.screen_unexpected_exception_logs
    def test_create_vpn_connection_rollback(self):
        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1,
                               fakes.DB_CUSTOMER_GATEWAY_1)
        self.neutron.create_ikepolicy.side_effect = (
            tools.get_neutron_create('ikepolicy', fakes.ID_OS_IKEPOLICY_1))
        self.neutron.create_ipsecpolicy.side_effect = (
            tools.get_neutron_create('ipsecpolicy', fakes.ID_OS_IPSECPOLICY_1))
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_VPN_CONNECTION_1))
        self.neutron.update_ikepolicy.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1',
             'Options.StaticRoutesOnly': 'True'})

        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_VPN_CONNECTION_1)
        self.neutron.delete_ipsecpolicy.assert_called_once_with(
            fakes.ID_OS_IPSECPOLICY_1)
        self.neutron.delete_ikepolicy.assert_called_once_with(
            fakes.ID_OS_IKEPOLICY_1)

    def test_create_vpn_connection_route(self):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_2)

        resp = self.execute(
            'CreateVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': '192.168.123.0/24'})
        self.assertEqual({'return': True}, resp)

        vpn = copy.deepcopy(fakes.DB_VPN_CONNECTION_2)
        vpn['cidrs'].append('192.168.123.0/24')
        self.db_api.update_item.assert_called_once_with(mock.ANY, vpn)

    def test_create_vpn_connection_route_idempotent(self):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_2)

        resp = self.execute(
            'CreateVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': fakes.CIDR_VPN_2_PROPAGATED_1})
        self.assertEqual({'return': True}, resp)
        self.assertFalse(self.db_api.update_item.called)

    def test_create_vpn_connection_route_invalid_parameters(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidVpnConnectionID.NotFound', 'CreateVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': fakes.CIDR_VPN_2_PROPAGATED_1})

    def test_delete_vpn_connection_route(self):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_2)

        resp = self.execute(
            'DeleteVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': fakes.CIDR_VPN_2_PROPAGATED_1})
        self.assertEqual({'return': True}, resp)
        vpn = tools.update_dict(fakes.DB_VPN_CONNECTION_2,
                                {'cidrs': [fakes.CIDR_VPN_2_PROPAGATED_2]})
        self.db_api.update_item.assert_called_once_with(mock.ANY, vpn)

    def test_delete_vpn_connection_route_invalid_parameters(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidVpnConnectionID.NotFound', 'DeleteVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': fakes.CIDR_VPN_2_PROPAGATED_1})

        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_2)
        self.assert_execution_error(
            'InvalidRoute.NotFound', 'DeleteVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': '192.168.123.0/24'})

    def test_delete_vpn_connection(self):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_1)
        resp = self.execute('DeleteVpnConnection',
                            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_1})
        self.assertEqual({'return': True}, resp)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_VPN_CONNECTION_1)
        self.neutron.delete_ipsecpolicy.assert_called_once_with(
            fakes.ID_OS_IPSECPOLICY_1)
        self.neutron.delete_ikepolicy.assert_called_once_with(
            fakes.ID_OS_IKEPOLICY_1)

    def test_delete_vpn_connection_invalid_parameters(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidVpnConnectionID.NotFound', 'DeleteVpnConnection',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_1})

    @tools.screen_unexpected_exception_logs
    def test_delete_vpn_connection_rollback(self):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_1)
        self.neutron.delete_ikepolicy.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'DeleteVpnConnection',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_1})

        self.db_api.restore_item.assert_called_once_with(
            mock.ANY, 'vpn', fakes.DB_VPN_CONNECTION_1)
        self.assertFalse(self.neutron.create_ipsecpolicy.called)
        self.assertFalse(self.neutron.create_ikepolicy.called)

    def test_describe_vpn_connections(self):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_1,
                               fakes.DB_VPN_CONNECTION_2)

        resp = self.execute('DescribeVpnConnections', {})
        self.assertThat(
            resp,
            matchers.DictMatches(
                {'vpnConnectionSet': [fakes.EC2_VPN_CONNECTION_1,
                                      fakes.EC2_VPN_CONNECTION_2]},
                orderless_lists=True))

        resp = self.execute(
            'DescribeVpnConnections',
            {'VpnConnectionId.1': fakes.ID_EC2_VPN_CONNECTION_1})
        self.assertThat(
            resp,
            matchers.DictMatches(
                {'vpnConnectionSet': [fakes.EC2_VPN_CONNECTION_1]},
                orderless_lists=True))

        self.check_filtering(
            'DescribeVpnConnections', 'vpnConnectionSet',
            [('customer-gateway-id', fakes.ID_EC2_CUSTOMER_GATEWAY_1),
             ('state', 'available'),
             ('option.static-routes-only', True),
             ('route.destination-cidr-block', fakes.CIDR_VPN_2_PROPAGATED_1),
             ('type', 'ipsec.1'),
             ('vpn-connection-id', fakes.ID_EC2_VPN_CONNECTION_1),
             ('vpn-gateway-id', fakes.ID_EC2_VPN_GATEWAY_1)])

        self.check_tag_support(
            'DescribeVpnConnections', 'vpnConnectionSet',
            fakes.ID_EC2_VPN_CONNECTION_1, 'vpnConnectionId')

    def test_format_vpn_connection(self):
        db_vpn_connection_1 = tools.update_dict(fakes.DB_VPN_CONNECTION_1,
                                                {'cidrs': []})
        ec2_vpn_connection_1 = tools.update_dict(fakes.EC2_VPN_CONNECTION_1,
                                                 {'routes': [],
                                                  'vgwTelemetry': []})
        self.assertEqual(
            ec2_vpn_connection_1,
            vpn_connection._format_vpn_connection(db_vpn_connection_1))
