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
from unittest import mock

from neutronclient.common import exceptions as neutron_exception

from ec2api.api import common
from ec2api.api import vpn_connection as vpn_connection_api
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class VpnConnectionTestCase(base.ApiTestCase):

    @mock.patch('ec2api.api.vpn_connection.describe_vpn_connections')
    @mock.patch('ec2api.api.vpn_connection._reset_vpn_connections',
                wraps=vpn_connection_api._reset_vpn_connections)
    @mock.patch('random.choice')
    def test_create_vpn_connection(self, random_choice, reset_vpn_connections,
                                   describe_vpn_connections):
        self.set_mock_db_items(
            fakes.DB_VPN_GATEWAY_1, fakes.DB_VPN_GATEWAY_2,
            fakes.DB_CUSTOMER_GATEWAY_1, fakes.DB_CUSTOMER_GATEWAY_2,
            fakes.DB_VPC_1)
        self.neutron.create_ikepolicy.side_effect = (
            tools.get_neutron_create('ikepolicy', fakes.ID_OS_IKEPOLICY_1))
        self.neutron.create_ipsecpolicy.side_effect = (
            tools.get_neutron_create('ipsecpolicy', fakes.ID_OS_IPSECPOLICY_1))
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_VPN_CONNECTION_1))
        random_choice.side_effect = iter(fakes.PRE_SHARED_KEY_1)
        describe_vpn_connections.return_value = {
            'vpnConnectionSet': [fakes.EC2_VPN_CONNECTION_1]}

        resp = self.execute(
            'CreateVpnConnection',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1,
             'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1,
             'Type': 'ipsec.1',
             'Options.StaticRoutesOnly': 'True'})
        self.assertThat(
            resp,
            matchers.DictMatches(
                {'vpnConnection': fakes.EC2_VPN_CONNECTION_1}))

        self.neutron.create_ikepolicy.assert_called_once_with(
            {'ikepolicy': tools.purge_dict(fakes.OS_IKEPOLICY_1, ('id',))})
        self.neutron.create_ipsecpolicy.assert_called_once_with(
            {'ipsecpolicy': tools.purge_dict(fakes.OS_IPSECPOLICY_1, ('id',))})
        random_choice.assert_called_with(vpn_connection_api.SHARED_KEY_CHARS)
        new_vpn_connection_1 = tools.update_dict(
            fakes.DB_VPN_CONNECTION_1, {'cidrs': [],
                                        'os_ipsec_site_connections': {}})
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'vpn',
            tools.purge_dict(new_vpn_connection_1, ('id', 'vpc_id', 'os_id')))
        self.neutron.update_ikepolicy.assert_called_once_with(
            fakes.ID_OS_IKEPOLICY_1,
            {'ikepolicy': {'name': fakes.ID_EC2_VPN_CONNECTION_1}})
        self.neutron.update_ipsecpolicy.assert_called_once_with(
            fakes.ID_OS_IPSECPOLICY_1,
            {'ipsecpolicy': {'name': fakes.ID_EC2_VPN_CONNECTION_1}})
        reset_vpn_connections.assert_called_once_with(
            mock.ANY, self.neutron, mock.ANY, fakes.DB_VPN_GATEWAY_1,
            vpn_connections=[new_vpn_connection_1])
        self.assertIsInstance(reset_vpn_connections.call_args[0][2],
                              common.OnCrashCleaner)
        describe_vpn_connections.assert_called_once_with(
            mock.ANY, vpn_connection_id=[fakes.ID_EC2_VPN_CONNECTION_1])

    @mock.patch('ec2api.api.vpn_connection.describe_vpn_connections')
    def test_create_vpn_connection_idempotent(self, describe_vpn_connections):
        self.set_mock_db_items(
            fakes.DB_VPN_GATEWAY_1, fakes.DB_CUSTOMER_GATEWAY_1,
            fakes.DB_VPN_CONNECTION_1)
        describe_vpn_connections.return_value = {
            'vpnConnectionSet': [fakes.EC2_VPN_CONNECTION_1]}

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
        describe_vpn_connections.assert_called_once_with(
            mock.ANY, vpn_connection_id=[fakes.ID_EC2_VPN_CONNECTION_1])

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

    @mock.patch('ec2api.api.vpn_connection._reset_vpn_connections',
                wraps=vpn_connection_api._reset_vpn_connections)
    def test_create_vpn_connection_route(self, reset_vpn_connections):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_2,
                               fakes.DB_VPN_GATEWAY_2)

        resp = self.execute(
            'CreateVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': '192.168.123.0/24'})
        self.assertEqual({'return': True}, resp)

        vpn = copy.deepcopy(fakes.DB_VPN_CONNECTION_2)
        vpn['cidrs'].append('192.168.123.0/24')
        self.db_api.update_item.assert_called_once_with(mock.ANY, vpn)
        reset_vpn_connections.assert_called_once_with(
            mock.ANY, self.neutron, mock.ANY, fakes.DB_VPN_GATEWAY_2,
            vpn_connections=[vpn])

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

    @tools.screen_unexpected_exception_logs
    @mock.patch('ec2api.api.vpn_connection._reset_vpn_connections')
    def test_create_vpn_connection_route_rollback(self, reset_vpn_connections):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_2,
                               fakes.DB_VPN_GATEWAY_2)
        reset_vpn_connections.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'CreateVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': '192.168.123.0/24'})
        self.db_api.update_item.assert_called_with(
            mock.ANY, fakes.DB_VPN_CONNECTION_2)

    @mock.patch('ec2api.api.vpn_connection._reset_vpn_connections',
                wraps=vpn_connection_api._reset_vpn_connections)
    def test_delete_vpn_connection_route(self, reset_vpn_connections):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_2,
                               fakes.DB_VPN_GATEWAY_2)

        resp = self.execute(
            'DeleteVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': fakes.CIDR_VPN_2_PROPAGATED_1})
        self.assertEqual({'return': True}, resp)
        vpn = tools.update_dict(fakes.DB_VPN_CONNECTION_2,
                                {'cidrs': [fakes.CIDR_VPN_2_PROPAGATED_2]})
        self.db_api.update_item.assert_called_once_with(mock.ANY, vpn)
        reset_vpn_connections.assert_called_once_with(
            mock.ANY, self.neutron, mock.ANY, fakes.DB_VPN_GATEWAY_2,
            vpn_connections=[vpn])

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

    @tools.screen_unexpected_exception_logs
    @mock.patch('ec2api.api.vpn_connection._reset_vpn_connections')
    def test_delete_vpn_connection_route_rollback(self, reset_vpn_connections):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_2,
                               fakes.DB_VPN_GATEWAY_2)
        reset_vpn_connections.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'DeleteVpnConnectionRoute',
            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_2,
             'DestinationCidrBlock': fakes.CIDR_VPN_2_PROPAGATED_1})
        self.assert_any_call(self.db_api.update_item,
                             mock.ANY, fakes.DB_VPN_CONNECTION_2)

    def test_delete_vpn_connection(self):
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_1)
        resp = self.execute('DeleteVpnConnection',
                            {'VpnConnectionId': fakes.ID_EC2_VPN_CONNECTION_1})
        self.assertEqual({'return': True}, resp)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_VPN_CONNECTION_1)
        self.neutron.delete_ipsec_site_connection.assert_called_once_with(
            fakes.ID_OS_IPSEC_SITE_CONNECTION_2)
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
        self.assertFalse(self.neutron.create_ipsec_site_connection.called)
        self.assertFalse(self.neutron.create_ipsecpolicy.called)
        self.assertFalse(self.neutron.create_ikepolicy.called)

    def test_describe_vpn_connections(self):
        self.set_mock_db_items(
            fakes.DB_VPN_CONNECTION_1, fakes.DB_VPN_CONNECTION_2,
            fakes.DB_CUSTOMER_GATEWAY_1, fakes.DB_CUSTOMER_GATEWAY_2,
            fakes.DB_VPN_GATEWAY_1, fakes.DB_VPN_GATEWAY_2,
            fakes.DB_VPC_1, fakes.DB_VPC_2)
        self.neutron.list_ikepolicies.return_value = {
            'ikepolicies': [fakes.OS_IKEPOLICY_1, fakes.OS_IKEPOLICY_2]}
        self.neutron.list_ipsecpolicies.return_value = {
            'ipsecpolicies': [fakes.OS_IPSECPOLICY_1, fakes.OS_IPSECPOLICY_2]}
        self.neutron.list_ipsec_site_connections.return_value = {
            'ipsec_site_connections': []}
        self.neutron.list_routers.return_value = {
            'routers': [fakes.OS_ROUTER_1, fakes.OS_ROUTER_2]}

        resp = self.execute('DescribeVpnConnections', {})
        vpns = [tools.update_dict(
                    vpn, {'customerGatewayConfiguration': 'DONTCARE'})
                for vpn in (fakes.EC2_VPN_CONNECTION_1,
                            fakes.EC2_VPN_CONNECTION_2)]
        self.assertThat(
            resp,
            matchers.DictMatches(
                {'vpnConnectionSet': vpns},
                orderless_lists=True))
        for vpn in (fakes.EC2_VPN_CONNECTION_1, fakes.EC2_VPN_CONNECTION_2):
            config = next(v['customerGatewayConfiguration']
                          for v in resp['vpnConnectionSet']
                          if v['vpnConnectionId'] == vpn['vpnConnectionId'])
            self.assertThat(
                config.encode(),
                matchers.XMLMatches(
                    vpn['customerGatewayConfiguration'].encode(),
                    orderless_sequence=True))
            self.assertTrue(config.startswith(
                '<?xml version=\'1.0\' encoding=\'UTF-8\'?>'))
        self.neutron.list_ikepolicies.assert_called_once_with(
            tenant_id=fakes.ID_OS_PROJECT)
        self.neutron.list_ipsecpolicies.assert_called_once_with(
            tenant_id=fakes.ID_OS_PROJECT)
        self.neutron.list_ipsec_site_connections.assert_called_once_with(
            tenant_id=fakes.ID_OS_PROJECT)
        self.neutron.list_routers.assert_called_once_with(
            tenant_id=fakes.ID_OS_PROJECT)

        resp = self.execute(
            'DescribeVpnConnections',
            {'VpnConnectionId.1': fakes.ID_EC2_VPN_CONNECTION_1})
        self.assertThat(
            resp,
            matchers.DictMatches(
                {'vpnConnectionSet': [vpns[0]]},
                orderless_lists=True))

        self.check_filtering(
            'DescribeVpnConnections', 'vpnConnectionSet',
            [('customer-gateway-configuration',
              '*' + fakes.PRE_SHARED_KEY_1 + '*'),
             ('customer-gateway-id', fakes.ID_EC2_CUSTOMER_GATEWAY_1),
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
        ec2_vpn_connection_1 = tools.patch_dict(
            fakes.EC2_VPN_CONNECTION_1,
            {'routes': [], 'vgwTelemetry': []},
            ('customerGatewayConfiguration',))
        formatted = vpn_connection_api._format_vpn_connection(
            db_vpn_connection_1,
            {fakes.ID_EC2_CUSTOMER_GATEWAY_1: fakes.DB_CUSTOMER_GATEWAY_1},
            {}, {}, {}, {})
        formatted.pop('customerGatewayConfiguration')
        self.assertThat(ec2_vpn_connection_1, matchers.DictMatches(formatted))

    def test_format_customer_config(self):
        ikepolicy = {
            'auth_algorithm': 'sha1-fake',
            'encryption_algorithm': '3des',
            'lifetime': {'value': 1111},
            'pfs': 'group5',
            'phase1_negotiation_mode': 'main-fake',
        }
        ipsecpolicy = {
            'transform_protocol': 'ah-esp',
            'auth_algorithm': 'sha1-fake',
            'encryption_algorithm': 'aes-256',
            'lifetime': {'value': 2222},
            'pfs': 'group14',
            'encapsulation_mode': 'transport',
        }
        ipsec_site_connection = {
            'peer_address': '1.2.3.4',
            'psk': 'password',
            'mtu': 1400,
        }
        conf = vpn_connection_api._format_customer_config(
            fakes.DB_VPN_CONNECTION_1,
            {fakes.ID_EC2_CUSTOMER_GATEWAY_1: fakes.DB_CUSTOMER_GATEWAY_1},
            {fakes.ID_OS_IKEPOLICY_1: ikepolicy},
            {fakes.ID_OS_IPSECPOLICY_1: ipsecpolicy},
            {fakes.ID_OS_IPSEC_SITE_CONNECTION_2: ipsec_site_connection},
            {fakes.ID_EC2_VPN_GATEWAY_1: '5.6.7.8'})

        self.assertThat(
            {'ipsec_tunnel': {
                'customer_gateway': {
                    'tunnel_outside_address': {'ip_address': '1.2.3.4'}},
                'vpn_gateway': {
                    'tunnel_outside_address': {'ip_address': '5.6.7.8'}},
                'ike': {'authentication_protocol': 'sha1-fake',
                        'encryption_protocol': '3des',
                        'lifetime': 1111,
                        'perfect_forward_secrecy': 'group5',
                        'mode': 'main-fake',
                        'pre_shared_key': 'password'},
                'ipsec': {'protocol': 'ah-esp',
                          'authentication_protocol': 'sha1-fake',
                          'encryption_protocol': 'aes-256',
                          'lifetime': 2222,
                          'perfect_forward_secrecy': 'group14',
                          'mode': 'transport',
                          'tcp_mss_adjustment': 1400 - 40}}},
            matchers.IsSubDictOf(conf))

    def test_stop_vpn_connection(self):
        # delete several connections
        os_conn_ids = [fakes.random_os_id() for _x in range(3)]
        fake_conn = {
            'os_ipsec_site_connections': {
                fakes.random_ec2_id('subnet'): conn_id
                for conn_id in os_conn_ids}}
        vpn_connection_api._stop_vpn_connection(self.neutron, fake_conn)
        self.assertEqual(
            3, self.neutron.delete_ipsec_site_connection.call_count)
        for conn_id in os_conn_ids:
            self.neutron.delete_ipsec_site_connection.assert_any_call(conn_id)

        # delete several connections with exception suppressing
        self.neutron.reset_mock()
        self.neutron.delete_ipsec_site_connection.side_effect = [
            None, neutron_exception.NotFound(), None]
        vpn_connection_api._stop_vpn_connection(self.neutron, fake_conn)
        self.assertEqual(
            3, self.neutron.delete_ipsec_site_connection.call_count)

    @mock.patch('ec2api.api.vpn_connection._stop_vpn_connection',
                new_callable=tools.CopyingMock)
    def test_stop_gateway_vpn_connections(self, stop_vpn_connection):
        context = base.create_context()
        cleaner = common.OnCrashCleaner()
        vpn_connection_3 = tools.update_dict(
            fakes.DB_VPN_CONNECTION_1,
            {'id': fakes.random_ec2_id('vpn'),
             'os_ipsec_site_connections': {}})

        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_1, vpn_connection_3,
                               fakes.DB_VPN_CONNECTION_2)
        vpn_connection_api._stop_gateway_vpn_connections(
            context, self.neutron, cleaner, fakes.DB_VPN_GATEWAY_1)
        self.assertEqual(2, stop_vpn_connection.call_count)
        stop_vpn_connection.assert_any_call(
            self.neutron, fakes.DB_VPN_CONNECTION_1)
        stop_vpn_connection.assert_any_call(
            self.neutron, vpn_connection_3)
        self.assertEqual(2, self.db_api.update_item.call_count)
        self.db_api.update_item.assert_any_call(
            mock.ANY, tools.update_dict(fakes.DB_VPN_CONNECTION_1,
                                        {'os_ipsec_site_connections': {}}))
        self.db_api.update_item.assert_any_call(
            mock.ANY, vpn_connection_3)

        self.db_api.reset_mock()
        self.neutron.reset_mock()
        stop_vpn_connection.reset_mock()
        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_1)
        try:
            with common.OnCrashCleaner() as cleaner:
                vpn_connection_api._stop_gateway_vpn_connections(
                    context, self.neutron, cleaner, fakes.DB_VPN_GATEWAY_1)
                raise Exception('fake-exception')
        except Exception as ex:
            if str(ex) != 'fake-exception':
                raise
        self.db_api.update_item.assert_called_with(
            mock.ANY, fakes.DB_VPN_CONNECTION_1)

    @mock.patch('ec2api.api.vpn_connection._reset_vpn_connections')
    def test_update_vpn_routes(self, reset_vpn_connections):
        context = base.create_context()
        cleaner = common.OnCrashCleaner()

        self.set_mock_db_items()
        vpn_connection_api._update_vpn_routes(
            context, self.neutron, cleaner,
            fakes.DB_ROUTE_TABLE_1, [fakes.DB_SUBNET_1])
        self.assertFalse(reset_vpn_connections.called)

        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1)
        vpn_connection_api._update_vpn_routes(
            context, self.neutron, cleaner,
            fakes.DB_ROUTE_TABLE_1, [fakes.DB_SUBNET_1])
        reset_vpn_connections.assert_called_once_with(
            context, self.neutron, cleaner, fakes.DB_VPN_GATEWAY_1,
            route_tables=[fakes.DB_ROUTE_TABLE_1], subnets=[fakes.DB_SUBNET_1])

    @mock.patch('ec2api.api.vpn_connection._delete_subnet_vpn')
    @mock.patch('ec2api.api.vpn_connection._set_subnet_vpn')
    @mock.patch('ec2api.api.vpn_connection._get_route_table_vpn_cidrs',
                wraps=vpn_connection_api._get_route_table_vpn_cidrs)
    def test_reset_vpn_connections(self, get_route_table_vpn_cidrs,
                                   set_subnet_vpn, delete_subnet_vpn):
        context = base.create_context()
        cleaner = common.OnCrashCleaner()

        vpn_gateway_3 = {'id': fakes.random_ec2_id('vpn'),
                         'os_id': None,
                         'vpc_id': None}
        vpn_connection_api._reset_vpn_connections(
            context, self.neutron, cleaner, vpn_gateway_3)
        self.assertEqual(0, len(self.db_api.mock_calls))
        self.assertFalse(get_route_table_vpn_cidrs.called)
        self.assertFalse(set_subnet_vpn.called)
        self.assertFalse(delete_subnet_vpn.called)

        customer_gateway_3 = {'id': fakes.random_ec2_id('cgw')}
        subnet_3 = {'id': fakes.random_ec2_id('subnet'),
                    'vpc_id': fakes.ID_EC2_VPC_2}
        vpn_connection_3 = {'id': fakes.random_ec2_id('vpn'),
                            'vpn_gateway_id': fakes.ID_EC2_VPN_GATEWAY_1,
                            'customer_gateway_id': customer_gateway_3['id'],
                            'cidrs': []}
        self.set_mock_db_items(
            fakes.DB_VPC_1, fakes.DB_VPC_2,
            fakes.DB_CUSTOMER_GATEWAY_1, fakes.DB_CUSTOMER_GATEWAY_2,
            customer_gateway_3,
            fakes.DB_SUBNET_1, fakes.DB_SUBNET_2, subnet_3,
            fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_2,
            fakes.DB_ROUTE_TABLE_3,
            fakes.DB_VPN_CONNECTION_1, fakes.DB_VPN_CONNECTION_2,
            vpn_connection_3)

        # common case
        vpn_connection_api._reset_vpn_connections(
            context, self.neutron, cleaner, fakes.DB_VPN_GATEWAY_1)
        self.assertEqual(2, set_subnet_vpn.call_count)
        set_subnet_vpn.assert_any_call(
            context, self.neutron, cleaner, fakes.DB_SUBNET_2,
            fakes.DB_VPN_CONNECTION_1, fakes.DB_CUSTOMER_GATEWAY_1,
            [fakes.CIDR_VPN_1_STATIC])
        set_subnet_vpn.assert_any_call(
            context, self.neutron, cleaner, fakes.DB_SUBNET_2,
            vpn_connection_3, customer_gateway_3,
            [fakes.CIDR_VPN_1_STATIC])
        self.assertEqual(2, delete_subnet_vpn.call_count)
        delete_subnet_vpn.assert_any_call(
            context, self.neutron, cleaner, fakes.DB_SUBNET_1,
            fakes.DB_VPN_CONNECTION_1)
        delete_subnet_vpn.assert_any_call(
            context, self.neutron, cleaner, fakes.DB_SUBNET_1,
            vpn_connection_3)
        self.assertEqual(2, get_route_table_vpn_cidrs.call_count)
        get_route_table_vpn_cidrs.assert_any_call(
            fakes.DB_ROUTE_TABLE_1, fakes.DB_VPN_GATEWAY_1,
            [fakes.DB_VPN_CONNECTION_1, vpn_connection_3])
        get_route_table_vpn_cidrs.assert_any_call(
            fakes.DB_ROUTE_TABLE_3, fakes.DB_VPN_GATEWAY_1,
            [fakes.DB_VPN_CONNECTION_1, vpn_connection_3])

        # reset for the vpn connection
        set_subnet_vpn.reset_mock()
        delete_subnet_vpn.reset_mock()
        self.db_api.reset_mock()
        get_route_table_vpn_cidrs.reset_mock()
        vpn_connection_api._reset_vpn_connections(
            context, self.neutron, cleaner, fakes.DB_VPN_GATEWAY_1,
            vpn_connections=[fakes.DB_VPN_CONNECTION_1])
        self.assertEqual(1, set_subnet_vpn.call_count)
        self.assertEqual(1, delete_subnet_vpn.call_count)
        self.assertNotIn(mock.call(mock.ANY, 'vpn'),
                         self.db_api.get_items.mock_calls)

        # reset for the subnet list
        set_subnet_vpn.reset_mock()
        delete_subnet_vpn.reset_mock()
        self.db_api.reset_mock()
        get_route_table_vpn_cidrs.reset_mock()
        vpn_connection_api._reset_vpn_connections(
            context, self.neutron, cleaner, fakes.DB_VPN_GATEWAY_1,
            subnets=[fakes.DB_SUBNET_1])
        self.assertFalse(set_subnet_vpn.called)
        self.assertEqual(2, delete_subnet_vpn.call_count)
        self.assertNotIn(mock.call(mock.ANY, 'subnets'),
                         self.db_api.get_items.mock_calls)

        # reset for the subnet list and the route table
        set_subnet_vpn.reset_mock()
        delete_subnet_vpn.reset_mock()
        self.db_api.reset_mock()
        get_route_table_vpn_cidrs.reset_mock()
        vpn_connection_api._reset_vpn_connections(
            context, self.neutron, cleaner, fakes.DB_VPN_GATEWAY_1,
            subnets=[fakes.DB_SUBNET_2], route_tables=[fakes.DB_ROUTE_TABLE_3])
        self.assertEqual(2, set_subnet_vpn.call_count)
        self.assertFalse(delete_subnet_vpn.called)
        self.assertNotIn(mock.call(mock.ANY, 'subnets'),
                         self.db_api.get_items.mock_calls)
        self.assertNotIn(mock.call(mock.ANY, 'rtb'),
                         self.db_api.get_items.mock_calls)

    def test_set_subnet_vpn(self):
        context = base.create_context()
        cleaner = common.OnCrashCleaner()
        cidrs = [fakes.CIDR_VPN_1_STATIC, fakes.CIDR_VPN_1_PROPAGATED_1]

        # create ipsec site connection case
        id_os_connection = fakes.random_os_id()
        os_connection = {
            'vpnservice_id': fakes.ID_OS_VPNSERVICE_1,
            'ikepolicy_id': fakes.ID_OS_IKEPOLICY_1,
            'ipsecpolicy_id': fakes.ID_OS_IPSECPOLICY_1,
            'peer_address': fakes.IP_CUSTOMER_GATEWAY_ADDRESS_1,
            'peer_cidrs': cidrs,
            'psk': fakes.PRE_SHARED_KEY_1,
            'name': (fakes.ID_EC2_VPN_CONNECTION_1 + '/' +
                     fakes.ID_EC2_SUBNET_1),
            'peer_id': fakes.IP_CUSTOMER_GATEWAY_ADDRESS_1,
            'mtu': 1427,
            'initiator': 'response-only',
        }
        self.neutron.create_ipsec_site_connection.side_effect = (
            tools.get_neutron_create('ipsec_site_connection',
                                     id_os_connection))
        vpn_connection_api._set_subnet_vpn(
            context, self.neutron, cleaner, fakes.DB_SUBNET_1,
            copy.deepcopy(fakes.DB_VPN_CONNECTION_1),
            fakes.DB_CUSTOMER_GATEWAY_1, cidrs)

        self.neutron.create_ipsec_site_connection.assert_called_once_with(
            {'ipsec_site_connection': os_connection})
        vpn_connection_1 = copy.deepcopy(fakes.DB_VPN_CONNECTION_1)
        (vpn_connection_1['os_ipsec_site_connections']
         [fakes.ID_EC2_SUBNET_1]) = id_os_connection
        self.db_api.update_item.assert_called_once_with(
            context, vpn_connection_1)

        # update ipsec site connection case
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        vpn_connection_api._set_subnet_vpn(
            context, self.neutron, cleaner, fakes.DB_SUBNET_2,
            fakes.DB_VPN_CONNECTION_1, fakes.DB_CUSTOMER_GATEWAY_1, cidrs)
        self.neutron.update_ipsec_site_connection.assert_called_once_with(
            fakes.ID_OS_IPSEC_SITE_CONNECTION_2,
            {'ipsec_site_connection': {'peer_cidrs': cidrs}})
        self.assertFalse(self.neutron.create_ipsec_site_connection.called)
        self.assertFalse(self.db_api.update_item.called)

        # rollback creating of ipsec site connection case
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        try:
            with common.OnCrashCleaner() as cleaner:
                vpn_connection_api._set_subnet_vpn(
                    context, self.neutron, cleaner, fakes.DB_SUBNET_1,
                    copy.deepcopy(fakes.DB_VPN_CONNECTION_1),
                    fakes.DB_CUSTOMER_GATEWAY_1, cidrs)
                raise Exception('fake-exception')
        except Exception as ex:
            if str(ex) != 'fake-exception':
                raise
        self.neutron.delete_ipsec_site_connection.assert_called_once_with(
            id_os_connection)
        self.db_api.update_item.assert_called_with(
            mock.ANY, fakes.DB_VPN_CONNECTION_1)

        # rollback updating of ipsec site connection case
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        try:
            with common.OnCrashCleaner() as cleaner:
                vpn_connection_api._set_subnet_vpn(
                    context, self.neutron, cleaner, fakes.DB_SUBNET_2,
                    fakes.DB_VPN_CONNECTION_1, fakes.DB_CUSTOMER_GATEWAY_1,
                    cidrs)
                raise Exception('fake-exception')
        except Exception as ex:
            if str(ex) != 'fake-exception':
                raise
        self.assertFalse(self.neutron.delete_ipsec_site_connection.called)
        self.assertFalse(self.db_api.update_item.called)

    def test_delete_subnet_vpn(self):
        context = base.create_context()
        cleaner = common.OnCrashCleaner()

        # subnet is not connected to the vpn
        vpn_connection_api._delete_subnet_vpn(
            context, self.neutron, cleaner, fakes.DB_SUBNET_1,
            fakes.DB_VPN_CONNECTION_1)
        self.assertFalse(self.db_api.update_item.called)
        self.assertFalse(self.neutron.delete_ipsec_site_connection.called)

        # delete subnet vpn connection
        vpn_connection_api._delete_subnet_vpn(
            context, self.neutron, cleaner, fakes.DB_SUBNET_2,
            copy.deepcopy(fakes.DB_VPN_CONNECTION_1))
        self.db_api.update_item.assert_called_once_with(
            mock.ANY, tools.update_dict(fakes.DB_VPN_CONNECTION_1,
                                        {'os_ipsec_site_connections': {}}))
        self.neutron.delete_ipsec_site_connection.assert_called_once_with(
            fakes.ID_OS_IPSEC_SITE_CONNECTION_2)

        # delete subnet vpn connection, leave connections of other subnets
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        id_os_connection = fakes.random_os_id()
        vpn_connection_1 = copy.deepcopy(fakes.DB_VPN_CONNECTION_1)
        (vpn_connection_1['os_ipsec_site_connections']
         [fakes.ID_EC2_SUBNET_1]) = id_os_connection
        vpn_connection_api._delete_subnet_vpn(
            context, self.neutron, cleaner, fakes.DB_SUBNET_1,
            vpn_connection_1)
        self.db_api.update_item.assert_called_once_with(
            mock.ANY, fakes.DB_VPN_CONNECTION_1)
        self.neutron.delete_ipsec_site_connection.assert_called_once_with(
            id_os_connection)

        # rollback of deleting subnet vpn connection
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        try:
            with common.OnCrashCleaner() as cleaner:
                vpn_connection_api._delete_subnet_vpn(
                    context, self.neutron, cleaner, fakes.DB_SUBNET_2,
                    copy.deepcopy(fakes.DB_VPN_CONNECTION_1))
                raise Exception('fake-exception')
        except Exception as ex:
            if str(ex) != 'fake-exception':
                raise
        self.db_api.update_item.assert_called_with(
            mock.ANY, fakes.DB_VPN_CONNECTION_1)
        self.assertFalse(self.neutron.create_ipsec_site_connection.called)

    def test_get_route_table_vpn_cidrs(self):
        route_table_1 = copy.deepcopy(fakes.DB_ROUTE_TABLE_1)
        vpn_connection_1 = tools.update_dict(
            fakes.DB_VPN_CONNECTION_1, {'cidrs': []})
        vpn_connection_2 = tools.update_dict(
            vpn_connection_1, {'id': fakes.ID_EC2_VPN_CONNECTION_2})

        self.assertThat(
            vpn_connection_api._get_route_table_vpn_cidrs(
                route_table_1, fakes.DB_VPN_GATEWAY_1, []),
            matchers.DictMatches({}))

        self.assertThat(
            vpn_connection_api._get_route_table_vpn_cidrs(
                route_table_1, fakes.DB_VPN_GATEWAY_1,
                [vpn_connection_1, vpn_connection_2]),
            matchers.DictMatches({}))

        route_table_1['propagating_gateways'] = [fakes.ID_EC2_VPN_GATEWAY_1,
                                                 fakes.ID_EC2_VPN_GATEWAY_2]
        self.assertThat(
            vpn_connection_api._get_route_table_vpn_cidrs(
                route_table_1, fakes.DB_VPN_GATEWAY_1,
                [vpn_connection_1, vpn_connection_2]),
            matchers.DictMatches({}))

        vpn_connection_1['cidrs'] = ['cidr_1']
        self.assertThat(
            vpn_connection_api._get_route_table_vpn_cidrs(
                route_table_1, fakes.DB_VPN_GATEWAY_1,
                [vpn_connection_1, vpn_connection_2]),
            matchers.DictMatches({fakes.ID_EC2_VPN_CONNECTION_1: ['cidr_1']}))

        vpn_connection_2['cidrs'] = ['cidr_1', 'cidr_2']
        self.assertThat(
            vpn_connection_api._get_route_table_vpn_cidrs(
                route_table_1, fakes.DB_VPN_GATEWAY_1,
                [vpn_connection_1, vpn_connection_2]),
            matchers.DictMatches(
                {fakes.ID_EC2_VPN_CONNECTION_1: ['cidr_1'],
                 fakes.ID_EC2_VPN_CONNECTION_2: ['cidr_1', 'cidr_2']},
                orderless_lists=True))

        route_table_1['routes'] = [
            {'destination_cidr_block': 'fake_1',
             'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1},
            {'destination_cidr_block': 'fake_2',
             'gateway_id': None},
            {'destination_cidr_block': 'fake_3',
             'gateway_id': fakes.ID_EC2_IGW_1},
            {'destination_cidr_block': 'cidr_3',
             'gateway_id': fakes.ID_EC2_VPN_GATEWAY_1},
            {'destination_cidr_block': 'cidr_4',
             'gateway_id': fakes.ID_EC2_VPN_GATEWAY_1},
            {'destination_cidr_block': 'fake_4',
             'gateway_id': fakes.ID_EC2_VPN_GATEWAY_2}]

        self.assertThat(
            vpn_connection_api._get_route_table_vpn_cidrs(
                route_table_1, fakes.DB_VPN_GATEWAY_1,
                [vpn_connection_1, vpn_connection_2]),
            matchers.DictMatches(
                {fakes.ID_EC2_VPN_CONNECTION_1: ['cidr_1', 'cidr_3', 'cidr_4'],
                 fakes.ID_EC2_VPN_CONNECTION_2: ['cidr_1', 'cidr_2',
                                                 'cidr_3', 'cidr_4']},
                orderless_lists=True))

        route_table_1['propagating_gateways'] = [fakes.ID_EC2_VPN_GATEWAY_2]
        self.assertThat(
            vpn_connection_api._get_route_table_vpn_cidrs(
                route_table_1, fakes.DB_VPN_GATEWAY_1,
                [vpn_connection_1, vpn_connection_2]),
            matchers.DictMatches(
                {fakes.ID_EC2_VPN_CONNECTION_1: ['cidr_3', 'cidr_4'],
                 fakes.ID_EC2_VPN_CONNECTION_2: ['cidr_3', 'cidr_4']},
                orderless_lists=True))
