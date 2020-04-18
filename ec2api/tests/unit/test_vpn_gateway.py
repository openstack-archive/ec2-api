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

import fixtures
from neutronclient.common import exceptions as neutron_exception

from ec2api.api import common
from ec2api.api import vpn_gateway as vpn_gateway_api
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class VpnGatewayTestCase(base.ApiTestCase):

    def setUp(self):
        super(VpnGatewayTestCase, self).setUp()
        self.DB_VPN_GATEWAY_2_ATTACHED = tools.update_dict(
            fakes.DB_VPN_GATEWAY_2, {'vpc_id': fakes.ID_EC2_VPC_2})
        self.DB_VPN_GATEWAY_1_DETACHED = tools.update_dict(
            fakes.DB_VPN_GATEWAY_1, {'vpc_id': None})
        self.DB_SUBNET_1_NO_VPN = tools.purge_dict(
            fakes.DB_SUBNET_1, ('os_vpnservice_id',))

    def test_create_vpn_gateway(self):
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_VPN_GATEWAY_2))

        resp = self.execute('CreateVpnGateway',
                            {'Type': 'ipsec.1'})
        self.assertEqual({'vpnGateway': fakes.EC2_VPN_GATEWAY_2}, resp)
        self.db_api.add_item.assert_called_once_with(mock.ANY, 'vgw', {})

    def test_attach_vpn_gateway(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        subnet_2 = tools.patch_dict(fakes.DB_SUBNET_2,
                                    {'vpc_id': fakes.ID_EC2_VPC_2},
                                    ('os_vpnservice_id',))
        self.set_mock_db_items(
            fakes.DB_VPN_GATEWAY_1, fakes.DB_VPN_GATEWAY_2,
            fakes.DB_VPC_2, fakes.DB_IGW_1, fakes.DB_IGW_2,
            fakes.DB_SUBNET_1, subnet_2)
        subnet_2_updated = tools.update_dict(
            subnet_2, {'os_vpnservice_id': fakes.ID_OS_VPNSERVICE_2})
        os_vpnservice_2 = tools.patch_dict(fakes.OS_VPNSERVICE_2,
                                           {'router_id': fakes.ID_OS_ROUTER_2},
                                           ('id',))
        self.neutron.list_networks.return_value = (
            {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.create_vpnservice.side_effect = tools.get_neutron_create(
            'vpnservice', fakes.ID_OS_VPNSERVICE_2)

        def do_check():
            resp = self.execute('AttachVpnGateway',
                                {'VpcId': fakes.ID_EC2_VPC_2,
                                 'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2})
            self.assertEqual({'attachment': {'state': 'attached',
                                             'vpcId': fakes.ID_EC2_VPC_2}},
                             resp)
            self.assertEqual(2, self.db_api.update_item.call_count)
            self.db_api.update_item.assert_has_calls(
                [mock.call(mock.ANY, self.DB_VPN_GATEWAY_2_ATTACHED),
                 mock.call(mock.ANY, subnet_2_updated)])
            self.neutron.create_vpnservice.assert_called_once_with(
                {'vpnservice': os_vpnservice_2})

        do_check()
        self.neutron.add_gateway_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_2,
            {'network_id': fakes.ID_OS_PUBLIC_NETWORK})
        self.neutron.list_networks.assert_called_once_with(
            **{'router:external': True,
               'name': fakes.NAME_OS_PUBLIC_NETWORK})

        # Internet gateway is already attached
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        igw_2 = tools.update_dict(fakes.DB_IGW_2,
                                  {'vpc_id': fakes.ID_EC2_VPC_2})
        self.add_mock_db_items(igw_2)

        do_check()
        self.neutron.add_gateway_router.assert_not_called()

    def test_attach_vpn_gateway_idempotent(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1, fakes.DB_VPC_1)

        resp = self.execute('AttachVpnGateway',
                            {'VpcId': fakes.ID_EC2_VPC_1,
                             'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1})
        self.assertEqual({'attachment': {'state': 'attached',
                                         'vpcId': fakes.ID_EC2_VPC_1}},
                         resp)
        self.assertFalse(self.db_api.update_item.called)
        self.assertFalse(self.neutron.add_gateway_router.called)
        self.assertFalse(self.neutron.create_vpnservice.called)

    def test_attach_vpn_gateway_invalid_parameters(self):
        def do_check(error_code):
            self.assert_execution_error(
                error_code, 'AttachVpnGateway',
                {'VpcId': fakes.ID_EC2_VPC_2,
                 'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2})

            self.assertFalse(self.db_api.update_item.called)
            self.db_api.reset_mock()

        self.set_mock_db_items(fakes.DB_VPC_2)
        do_check('InvalidVpnGatewayID.NotFound')

        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_2)
        do_check('InvalidVpcID.NotFound')

        self.set_mock_db_items(
            tools.update_dict(fakes.DB_VPN_GATEWAY_2,
                              {'vpc_id': fakes.ID_EC2_VPC_1}),
            fakes.DB_VPC_2)
        do_check('VpnGatewayAttachmentLimitExceeded')

        self.set_mock_db_items(
            fakes.DB_VPN_GATEWAY_2, fakes.DB_VPC_2,
            tools.update_dict(fakes.DB_VPN_GATEWAY_1,
                              {'vpc_id': fakes.ID_EC2_VPC_2}))
        do_check('InvalidVpcState')

    @tools.screen_unexpected_exception_logs
    def test_attach_vpn_gateway_rollback(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        subnet_2 = tools.patch_dict(fakes.DB_SUBNET_2,
                                    {'vpc_id': fakes.ID_EC2_VPC_2},
                                    ('os_vpnservice_id',))
        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_2, fakes.DB_VPC_2,
                               subnet_2)
        self.neutron.list_networks.return_value = (
            {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.create_vpnservice.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'AttachVpnGateway',
            {'VpcId': fakes.ID_EC2_VPC_2,
             'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_VPN_GATEWAY_2)
        self.neutron.remove_gateway_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_2)

    def test_detach_vpn_gateway(self):
        self.set_mock_db_items(
            fakes.DB_VPN_GATEWAY_1, fakes.DB_VPC_1, fakes.DB_VPN_CONNECTION_1,
            fakes.DB_SUBNET_1,
            tools.update_dict(fakes.DB_SUBNET_2,
                              {'vpc_id': fakes.ID_EC2_VPC_2}))

        def do_check():
            resp = self.execute(
                'DetachVpnGateway',
                {'VpcId': fakes.ID_EC2_VPC_1,
                 'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1})
            self.assertEqual({'return': True}, resp)
            self.assertEqual(3, self.db_api.update_item.call_count)
            self.db_api.update_item.assert_has_calls(
                [mock.call(mock.ANY, self.DB_VPN_GATEWAY_1_DETACHED),
                 mock.call(mock.ANY,
                           tools.update_dict(
                               fakes.DB_VPN_CONNECTION_1,
                               {'os_ipsec_site_connections': {}})),
                 mock.call(mock.ANY, self.DB_SUBNET_1_NO_VPN)])
            self.neutron.delete_vpnservice.assert_called_once_with(
                fakes.ID_OS_VPNSERVICE_1)
            self.neutron.delete_ipsec_site_connection.assert_called_once_with(
                fakes.ID_OS_IPSEC_SITE_CONNECTION_2)

        do_check()
        self.neutron.remove_gateway_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_1)

        # Internet gateway is still attached
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        self.add_mock_db_items(fakes.DB_IGW_1)

        do_check()
        self.neutron.remove_gateway_router.assert_not_called()

    def test_detach_vpn_gateway_invalid_parameters(self):
        def do_check(error_code):
            self.assert_execution_error(
                error_code, 'DetachVpnGateway',
                {'VpcId': fakes.ID_EC2_VPC_1,
                 'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2})

            self.assertEqual(0, self.neutron.remove_gateway_router.call_count)
            self.assertEqual(0, self.db_api.update_item.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.set_mock_db_items()
        do_check('InvalidVpnGatewayID.NotFound')

        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_2)
        do_check('InvalidVpnGatewayAttachment.NotFound')

        self.set_mock_db_items(self.DB_VPN_GATEWAY_2_ATTACHED)
        do_check('InvalidVpnGatewayAttachment.NotFound')

    def test_detach_vpn_gateway_no_router(self):
        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1, fakes.DB_VPC_1)
        self.neutron.remove_gateway_router.side_effect = (
            neutron_exception.NotFound)

        resp = self.execute(
            'DetachVpnGateway',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1})

        self.assertEqual(True, resp['return'])
        self.neutron.remove_gateway_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_1)

    @tools.screen_unexpected_exception_logs
    def test_detach_vpn_gateway_rollback(self):
        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1, fakes.DB_VPC_1,
                               fakes.DB_SUBNET_1)
        self.neutron.remove_gateway_router.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'DetachVpnGateway',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1})

        self.db_api.update_item.assert_has_calls(
            [mock.call(mock.ANY, fakes.DB_SUBNET_1),
             mock.call(mock.ANY, fakes.DB_VPN_GATEWAY_1)])

    def test_delete_vpn_gateway(self):
        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_2)

        resp = self.execute(
            'DeleteVpnGateway',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2})

        self.assertEqual({'return': True}, resp)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_VPN_GATEWAY_2)

    def test_delete_vpn_gateway_invalid_parameters(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidVpnGatewayID.NotFound', 'DeleteVpnGateway',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1})

        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1)
        self.assert_execution_error(
            'IncorrectState', 'DeleteVpnGateway',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_1})

        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_2,
                               fakes.DB_VPN_CONNECTION_2)
        self.assert_execution_error(
            'IncorrectState', 'DeleteVpnGateway',
            {'VpnGatewayId': fakes.ID_EC2_VPN_GATEWAY_2})

    def test_describe_vpn_gateways(self):
        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1, fakes.DB_VPN_GATEWAY_2)

        resp = self.execute('DescribeVpnGateways', {})
        self.assertThat(resp['vpnGatewaySet'],
                        matchers.ListMatches([fakes.EC2_VPN_GATEWAY_1,
                                              fakes.EC2_VPN_GATEWAY_2]))

        resp = self.execute('DescribeVpnGateways',
                            {'VpnGatewayId.1': fakes.ID_EC2_VPN_GATEWAY_2})
        self.assertThat(resp['vpnGatewaySet'],
                        matchers.ListMatches([fakes.EC2_VPN_GATEWAY_2]))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_VPN_GATEWAY_2]))

        self.check_filtering(
            'DescribeVpnGateways', 'vpnGatewaySet',
            [('attachment.state', 'attached'),
             ('attachment.vpc-id', fakes.ID_EC2_VPC_1),
             ('state', 'available'),
             ('type', 'ipsec.1'),
             ('vpn-gateway-id', fakes.ID_EC2_VPN_GATEWAY_2)])
        self.check_tag_support(
            'DescribeVpnGateways', 'vpnGatewaySet',
            fakes.ID_EC2_VPN_GATEWAY_2, 'vpnGatewayId')

    @mock.patch('ec2api.api.vpn_connection._reset_vpn_connections')
    @mock.patch('ec2api.api.vpn_gateway._create_subnet_vpnservice')
    def test_start_vpn_in_subnet(self, create_subnet_vpnservice,
                                 reset_vpn_connection):
        context = base.create_context()
        cleaner = common.OnCrashCleaner()
        mock_manager = mock.Mock()
        mock_manager.attach_mock(create_subnet_vpnservice,
                                 'create_subnet_vpnservice')
        mock_manager.attach_mock(reset_vpn_connection, 'reset_vpn_connection')

        self.set_mock_db_items(fakes.DB_VPN_GATEWAY_1, fakes.DB_VPN_GATEWAY_2)
        vpn_gateway_api._start_vpn_in_subnet(
            context, self.neutron, cleaner, copy.deepcopy(fakes.DB_SUBNET_1),
            fakes.DB_VPC_1, fakes.DB_ROUTE_TABLE_1)
        mock_manager.assert_has_calls([
            mock.call.create_subnet_vpnservice(
                context, self.neutron, cleaner,
                fakes.DB_SUBNET_1, fakes.DB_VPC_1),
            mock.call.reset_vpn_connection(
                context, self.neutron, cleaner, fakes.DB_VPN_GATEWAY_1,
                subnets=[fakes.DB_SUBNET_1],
                route_tables=[fakes.DB_ROUTE_TABLE_1])])

        create_subnet_vpnservice.reset_mock()
        reset_vpn_connection.reset_mock()
        self.add_mock_db_items(self.DB_VPN_GATEWAY_1_DETACHED)
        vpn_gateway_api._start_vpn_in_subnet(
            context, self.neutron, cleaner, copy.deepcopy(fakes.DB_SUBNET_1),
            fakes.DB_VPC_1, fakes.DB_ROUTE_TABLE_1)
        self.assertFalse(create_subnet_vpnservice.called)
        self.assertFalse(reset_vpn_connection.called)

    @mock.patch('ec2api.api.vpn_connection._delete_subnet_vpn')
    @mock.patch('ec2api.api.vpn_gateway._safe_delete_vpnservice')
    def test_stop_vpn_in_subnet(self, delete_vpnservice, delete_subnet_vpn):
        context = base.create_context()
        cleaner = common.OnCrashCleaner()
        mock_manager = mock.Mock()
        mock_manager.attach_mock(delete_vpnservice, 'delete_vpnservice')
        mock_manager.attach_mock(delete_subnet_vpn, 'delete_subnet_vpn')

        self.set_mock_db_items(fakes.DB_VPN_CONNECTION_1,
                               fakes.DB_VPN_CONNECTION_2)
        vpn_gateway_api._stop_vpn_in_subnet(
            context, self.neutron, cleaner, copy.deepcopy(fakes.DB_SUBNET_1))
        mock_manager.has_calls([
            mock.call.delete_subnet_vpn(
                context, self.neutron, cleaner, fakes.DB_SUBNET_1,
                fakes.DB_VPN_CONNECTION_1),
            mock.call.delete_subnet_vpn(
                context, self.neutron, cleaner, fakes.DB_SUBNET_1,
                fakes.DB_VPN_CONNECTION_2),
            mock.call.delete_vpnservice(
                self.neutron, fakes.ID_OS_VPNSERVICE_1,
                fakes.ID_EC2_SUBNET_1)])

        delete_subnet_vpn.reset_mock()
        delete_vpnservice.reset_mock()
        vpn_gateway_api._stop_vpn_in_subnet(
            context, self.neutron, cleaner, self.DB_SUBNET_1_NO_VPN)
        self.assertFalse(delete_subnet_vpn.called)
        self.assertFalse(delete_vpnservice.called)

    def test_create_subnet_vpnservice(self):
        self.neutron.create_vpnservice.side_effect = tools.get_neutron_create(
            'vpnservice', fakes.ID_OS_VPNSERVICE_1)
        context = base.create_context()
        cleaner = common.OnCrashCleaner()

        vpn_gateway_api._create_subnet_vpnservice(
            context, self.neutron, cleaner,
            copy.deepcopy(self.DB_SUBNET_1_NO_VPN), fakes.DB_VPC_1)

        self.neutron.create_vpnservice.assert_called_once_with(
            {'vpnservice': tools.purge_dict(fakes.OS_VPNSERVICE_1,
                                            ('id',))})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY, fakes.DB_SUBNET_1)

        try:
            with common.OnCrashCleaner() as cleaner:
                vpn_gateway_api._create_subnet_vpnservice(
                    context, self.neutron, cleaner,
                    copy.deepcopy(self.DB_SUBNET_1_NO_VPN), fakes.DB_VPC_1)
                raise Exception('fake-exception')
        except Exception as ex:
            if str(ex) != 'fake-exception':
                raise
        self.db_api.update_item.assert_called_with(
            mock.ANY, self.DB_SUBNET_1_NO_VPN)
        self.neutron.delete_vpnservice.assert_called_once_with(
            fakes.ID_OS_VPNSERVICE_1)

    @mock.patch('ec2api.api.vpn_gateway._safe_delete_vpnservice')
    def test_delete_subnet_vpnservice(self, delete_vpnservice):
        context = base.create_context()
        cleaner = common.OnCrashCleaner()

        vpn_gateway_api._delete_subnet_vpnservice(
            context, self.neutron, cleaner, copy.deepcopy(fakes.DB_SUBNET_1))

        self.db_api.update_item.assert_called_once_with(
            mock.ANY, self.DB_SUBNET_1_NO_VPN)

        try:
            with common.OnCrashCleaner() as cleaner:
                vpn_gateway_api._delete_subnet_vpnservice(
                    context, self.neutron, cleaner,
                    copy.deepcopy(fakes.DB_SUBNET_1))
                raise Exception('fake-exception')
        except Exception as ex:
            if str(ex) != 'fake-exception':
                raise
        self.db_api.update_item.assert_called_with(
            mock.ANY, fakes.DB_SUBNET_1)
        self.assertFalse(self.neutron.create_vpnservice.called)

    def test_safe_delete_vpnservice(self):
        vpn_gateway_api._safe_delete_vpnservice(
            self.neutron, fakes.ID_OS_VPNSERVICE_1, fakes.ID_EC2_SUBNET_1)
        self.neutron.delete_vpnservice.assert_called_once_with(
            fakes.ID_OS_VPNSERVICE_1)

        self.neutron.delete_vpnservice.side_effect = (
            neutron_exception.NotFound())
        with fixtures.FakeLogger() as log:
            vpn_gateway_api._safe_delete_vpnservice(
                self.neutron, fakes.ID_OS_VPNSERVICE_1, fakes.ID_EC2_SUBNET_1)
        self.assertEqual(0, len(log.output))

        self.neutron.delete_vpnservice.side_effect = (
            neutron_exception.Conflict())
        with fixtures.FakeLogger() as log:
            vpn_gateway_api._safe_delete_vpnservice(
                self.neutron, fakes.ID_OS_VPNSERVICE_1, fakes.ID_EC2_SUBNET_1)
        self.assertIn(fakes.ID_EC2_SUBNET_1, log.output)
        self.assertIn(fakes.ID_OS_VPNSERVICE_1, log.output)
