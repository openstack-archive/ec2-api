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

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import route_table
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class RouteTableTestCase(base.ApiTestCase):

    def test_route_table_create(self):
        self.set_mock_db_items(fakes.DB_VPC_1)
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_ROUTE_TABLE_1))
        resp = self.execute('CreateRouteTable',
                            {'VpcId': fakes.ID_EC2_VPC_1})
        self.assertThat(
            resp['routeTable'],
            matchers.DictMatches(tools.purge_dict(fakes.EC2_ROUTE_TABLE_1,
                                                  ('associationSet',))))
        self.db_api.add_item.assert_called_once_with(
            mock.ANY,
            'rtb',
            {'vpc_id': fakes.ID_EC2_VPC_1,
             'routes': [{'destination_cidr_block': fakes.CIDR_VPC_1,
                         'gateway_id': None}]},
            project_id=None)
        self.db_api.get_item_by_id.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_VPC_1)

    def test_route_table_create_invalid_parameters(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidVpcID.NotFound', 'CreateRouteTable',
            {'VpcId': fakes.ID_EC2_VPC_1})

    @mock.patch('ec2api.api.route_table._update_routes_in_associated_subnets')
    def test_create_route(self, routes_updater):
        self.set_mock_db_items(
            fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_2,
            fakes.DB_VPC_1, fakes.DB_IGW_1,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2)

        def do_check(params, route_table, rollback_route_table_state):
            resp = self.execute('CreateRoute', params)
            self.assertEqual(True, resp['return'])

            self.db_api.update_item.assert_called_once_with(
                mock.ANY, route_table)
            routes_updater.assert_called_once_with(
                mock.ANY, route_table, mock.ANY,
                rollback_route_table_state)

            self.db_api.update_item.reset_mock()
            routes_updater.reset_mock()

        route_table = copy.deepcopy(fakes.DB_ROUTE_TABLE_1)
        route_table['routes'].append({'gateway_id': fakes.ID_EC2_IGW_1,
                                      'destination_cidr_block': '0.0.0.0/0'})
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'DestinationCidrBlock': '0.0.0.0/0',
                  'GatewayId': fakes.ID_EC2_IGW_1},
                 route_table, fakes.DB_ROUTE_TABLE_1)

        route_table = copy.deepcopy(fakes.DB_ROUTE_TABLE_1)
        route_table['routes'].append({
            'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1,
            'destination_cidr_block': '192.168.75.0/24'})
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'DestinationCidrBlock': '192.168.75.0/24',
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1},
                 route_table, fakes.DB_ROUTE_TABLE_1)

        route_table = copy.deepcopy(fakes.DB_ROUTE_TABLE_1)
        route_table['routes'].append({
            'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_2,
            'destination_cidr_block': '192.168.80.0/24'})
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'DestinationCidrBlock': '192.168.80.0/24',
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 route_table, fakes.DB_ROUTE_TABLE_1)

        # NOTE(ft): check idempotent calls
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': fakes.CIDR_EXTERNAL_NETWORK,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 fakes.DB_ROUTE_TABLE_2, fakes.DB_ROUTE_TABLE_2)

        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '0.0.0.0/0',
                  'GatewayId': fakes.ID_EC2_IGW_1},
                 fakes.DB_ROUTE_TABLE_2, fakes.DB_ROUTE_TABLE_2)

    def test_create_route_invalid_parameters(self):
        id_ec2_eni_vpc_2 = fakes.random_ec2_id('eni')
        eni_vpc_2 = fakes.gen_db_network_interface(
            id_ec2_eni_vpc_2, fakes.random_os_id(),
            fakes.ID_EC2_VPC_2, fakes.random_ec2_id('subnet'), '10.20.0.10',
            instance_id=fakes.ID_EC2_INSTANCE_2)

        eni_2_in_instance_1 = fakes.gen_db_network_interface(
            fakes.random_ec2_id('eni'), fakes.random_os_id(),
            fakes.ID_EC2_VPC_1, fakes.random_ec2_id('subnet'), '10.10.3.15',
            instance_id=fakes.ID_EC2_INSTANCE_1)

        self.set_mock_db_items(
            fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_2,
            fakes.DB_VPC_1, eni_vpc_2, fakes.DB_IGW_1, fakes.DB_IGW_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2)

        def do_check(params, error_code):
            self.assert_execution_error(error_code, 'CreateRoute', params)

        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'DestinationCidrBlock': 'not_a_cidr',
                  'GatewayId': fakes.ID_EC2_IGW_1},
                 'InvalidParameterValue')

        do_check({'RouteTableId': fakes.random_ec2_id('rtb'),
                  'DestinationCidrBlock': fakes.CIDR_VPC_1,
                  'GatewayId': fakes.ID_EC2_IGW_1},
                 'InvalidRouteTableID.NotFound')

        # NOTE(ft): redefine vpc local route
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'DestinationCidrBlock': fakes.CIDR_VPC_1,
                  'GatewayId': fakes.ID_EC2_IGW_1},
                 'InvalidParameterValue')

        # NOTE(ft): create route for cidr lesser than vpc cidr
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'DestinationCidrBlock': fakes.IP_NETWORK_INTERFACE_1 + '/24',
                  'GatewayId': fakes.ID_EC2_IGW_1},
                 'InvalidParameterValue')

        # NOTE(ft): redefine existed route by route with another attributes
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '0.0.0.0/0',
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1},
                 'RouteAlreadyExists')

        # NOTE(ft): missed traffic receiver
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '0.0.0.0/0'},
                 'MissingParameter')

        # NOTE(ft): more than one traffic receiver
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '0.0.0.0/0',
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
                  'GatewayId': fakes.ID_EC2_IGW_1},
                 'InvalidParameterCombination')

        # NOTE(ft): gateway from different vpc
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '192.168.100.0/0',
                  'GatewayId': fakes.ID_EC2_IGW_2},
                 'InvalidParameterValue')

        # NOTE(ft): network interface from different vpc
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '192.168.100.0/0',
                  'NetworkInterfaceId': id_ec2_eni_vpc_2},
                 'InvalidParameterValue')

        # NOTE(ft): not vpc instance
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '192.168.100.0/0',
                  'InstanceId': fakes.ID_EC2_INSTANCE_2},
                 'InvalidParameterValue')

        # NOTE(ft): multiple network interfaces in instance
        self.add_mock_db_items(eni_2_in_instance_1)
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '192.168.100.0/0',
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidInstanceID')

        # NOTE(ft): different vpc instance
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                  'DestinationCidrBlock': '192.168.100.0/0',
                  'InstanceId': fakes.ID_EC2_INSTANCE_2},
                 'InvalidParameterValue')

    @mock.patch('ec2api.api.route_table._update_routes_in_associated_subnets')
    def test_create_or_replace_route_rollback(self, routes_updater):
        self.set_mock_db_items(
            fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_2,
            fakes.DB_VPC_1, fakes.DB_IGW_1,
            fakes.gen_db_igw(fakes.ID_EC2_IGW_2, fakes.ID_EC2_VPC_1))
        routes_updater.side_effect = Exception()

        with tools.ScreeningLogger(log_name='ec2api.api'):
            self.assert_execution_error(
                self.ANY_EXECUTE_ERROR, 'CreateRoute',
                {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                 'DestinationCidrBlock': '0.0.0.0/0',
                 'GatewayId': fakes.ID_EC2_IGW_1})

            self.db_api.update_item.assert_any_call(mock.ANY,
                                                    fakes.DB_ROUTE_TABLE_1)

        with tools.ScreeningLogger(log_name='ec2api.api'):
            self.assert_execution_error(
                self.ANY_EXECUTE_ERROR, 'ReplaceRoute',
                {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                 'DestinationCidrBlock': '0.0.0.0/0',
                 'GatewayId': fakes.ID_EC2_IGW_2})

            self.db_api.update_item.assert_any_call(mock.ANY,
                                                    fakes.DB_ROUTE_TABLE_2)

    @mock.patch('ec2api.api.route_table._update_routes_in_associated_subnets')
    def test_replace_route(self, routes_updater):
        route_table = copy.deepcopy(fakes.DB_ROUTE_TABLE_1)
        route_table['routes'].append({'gateway_id': fakes.ID_EC2_IGW_1,
                                      'destination_cidr_block': '0.0.0.0/0'})
        self.set_mock_db_items(
            route_table, fakes.DB_VPC_1, fakes.DB_IGW_1,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2)

        resp = self.execute('ReplaceRoute',
                            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                             'DestinationCidrBlock': '0.0.0.0/0',
                             'NetworkInterfaceId':
                             fakes.ID_EC2_NETWORK_INTERFACE_1})
        self.assertEqual(True, resp['return'])

        rollback_route_table_state = route_table
        route_table = copy.deepcopy(fakes.DB_ROUTE_TABLE_1)
        route_table['routes'].append({
            'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1,
            'destination_cidr_block': '0.0.0.0/0'})
        self.db_api.update_item.assert_called_once_with(mock.ANY, route_table)
        routes_updater.assert_called_once_with(mock.ANY, route_table, mock.ANY,
                                               rollback_route_table_state)

    def test_replace_route_invalid_parameters(self):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1,
                               fakes.DB_VPC_1, fakes.DB_IGW_1)

        self.assert_execution_error(
            'InvalidParameterValue', 'ReplaceRoute',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
             'DestinationCidrBlock': '11.22.33.0/24',
             'GatewayId': fakes.ID_EC2_IGW_1})

    @mock.patch('ec2api.api.route_table._update_routes_in_associated_subnets')
    def test_delete_route(self, routes_updater):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_2)
        resp = self.execute('DeleteRoute',
                            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                             'DestinationCidrBlock':
                             fakes.CIDR_EXTERNAL_NETWORK})
        self.assertEqual(True, resp['return'])
        route_table = copy.deepcopy(fakes.DB_ROUTE_TABLE_2)
        route_table['routes'] = [
            r for r in route_table['routes']
            if r['destination_cidr_block'] != fakes.CIDR_EXTERNAL_NETWORK]
        self.db_api.update_item.assert_called_once_with(mock.ANY, route_table)
        routes_updater.assert_called_once_with(
            mock.ANY, route_table, mock.ANY, fakes.DB_ROUTE_TABLE_2)

    def test_delete_route_invalid_parameters(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidRouteTableID.NotFound', 'DeleteRoute',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
             'DestinationCidrBlock': '11.22.33.0/24'})

        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_2)
        self.assert_execution_error(
            'InvalidRoute.NotFound', 'DeleteRoute',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
             'DestinationCidrBlock': '11.22.33.0/24'})

        self.assert_execution_error(
            'InvalidParameterValue', 'DeleteRoute',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
             'DestinationCidrBlock': fakes.CIDR_VPC_1})

    @tools.screen_unexpected_exception_logs
    @mock.patch('ec2api.api.route_table._update_routes_in_associated_subnets')
    def test_delete_route_rollback(self, routes_updater):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_2)
        routes_updater.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'DeleteRoute',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2,
             'DestinationCidrBlock': fakes.CIDR_EXTERNAL_NETWORK})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_ROUTE_TABLE_2)

    @mock.patch('ec2api.api.route_table._update_subnet_host_routes')
    def test_associate_route_table(self, routes_updater):
        self.set_mock_db_items(fakes.DB_VPC_1, fakes.DB_ROUTE_TABLE_1,
                               fakes.DB_SUBNET_1)
        resp = self.execute('AssociateRouteTable',
                            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                             'SubnetId': fakes.ID_EC2_SUBNET_1})
        self.assertEqual(fakes.ID_EC2_SUBNET_1.replace('subnet', 'rtbassoc'),
                         resp['associationId'])
        subnet = tools.update_dict(
            fakes.DB_SUBNET_1,
            {'route_table_id': fakes.ID_EC2_ROUTE_TABLE_1})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY, subnet)
        routes_updater.assert_called_once_with(
            mock.ANY, subnet, fakes.DB_ROUTE_TABLE_1, cleaner=mock.ANY,
            rollback_route_table_object=fakes.DB_ROUTE_TABLE_1)

    def test_associate_route_table_invalid_parameters(self):
        def do_check(params, error_code):
            self.assert_execution_error(
                error_code, 'AssociateRouteTable', params)

        self.set_mock_db_items()
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'SubnetId': fakes.ID_EC2_SUBNET_1},
                 'InvalidRouteTableID.NotFound')

        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1)
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'SubnetId': fakes.ID_EC2_SUBNET_1},
                 'InvalidSubnetID.NotFound')

        id_ec2_subnet_vpc_2 = fakes.random_ec2_id('subnet')
        db_subnet_vpc_2 = {'id': id_ec2_subnet_vpc_2,
                           'os_id': fakes.random_os_id(),
                           'vpc_id': fakes.ID_EC2_VPC_2}
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1, db_subnet_vpc_2)
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'SubnetId': id_ec2_subnet_vpc_2},
                 'InvalidParameterValue')

        subnet_2 = tools.update_dict(
            fakes.DB_SUBNET_2,
            {'route_table_id': fakes.ID_EC2_ROUTE_TABLE_2})
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1, subnet_2)
        do_check({'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                  'SubnetId': fakes.ID_EC2_SUBNET_2},
                 'Resource.AlreadyAssociated')

    @tools.screen_unexpected_exception_logs
    @mock.patch('ec2api.api.route_table._update_subnet_host_routes')
    def test_associate_route_table_rollback(self, routes_updater):
        self.set_mock_db_items(fakes.DB_VPC_1, fakes.DB_ROUTE_TABLE_1,
                               fakes.DB_SUBNET_1)
        routes_updater.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'AssociateRouteTable',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1,
             'SubnetId': fakes.ID_EC2_SUBNET_1})

        self.db_api.update_item.assert_any_call(mock.ANY, fakes.DB_SUBNET_1)

    @mock.patch('ec2api.api.route_table._update_subnet_host_routes')
    def test_replace_route_table_association(self, routes_updater):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_2, fakes.DB_ROUTE_TABLE_3,
                               fakes.DB_SUBNET_2)
        resp = self.execute(
            'ReplaceRouteTableAssociation',
            {'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_3,
             'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2})
        self.assertEqual(fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_2,
                         resp['newAssociationId'])
        subnet = tools.update_dict(
            fakes.DB_SUBNET_2,
            {'route_table_id': fakes.ID_EC2_ROUTE_TABLE_2})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY, subnet)
        routes_updater.assert_called_once_with(
            mock.ANY, subnet, fakes.DB_ROUTE_TABLE_2, cleaner=mock.ANY,
            rollback_route_table_object=fakes.DB_ROUTE_TABLE_3)

    @mock.patch('ec2api.api.route_table._update_routes_in_associated_subnets')
    def test_replace_route_table_association_main(self, routes_updater):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_2,
                               fakes.DB_VPC_1)
        resp = self.execute('ReplaceRouteTableAssociation',
                            {'AssociationId':
                             fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_1,
                             'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2})
        self.assertEqual(fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_1,
                         resp['newAssociationId'])
        vpc = tools.update_dict(
            fakes.DB_VPC_1,
            {'route_table_id': fakes.ID_EC2_ROUTE_TABLE_2})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY, vpc)
        routes_updater.assert_called_once_with(
            mock.ANY, fakes.DB_ROUTE_TABLE_2, mock.ANY,
            fakes.DB_ROUTE_TABLE_1, is_main=True)

    def test_replace_route_table_association_invalid_parameters(self):
        def do_check(params, error_code):
            self.assert_execution_error(
                error_code, 'ReplaceRouteTableAssociation', params)

        self.set_mock_db_items()
        do_check({'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_1,
                  'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1},
                 'InvalidRouteTableID.NotFound')

        # NOTE(ft): association with vpc is obsolete
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1)
        do_check({'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_1,
                  'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1},
                 'InvalidAssociationID.NotFound')

        # NOTE(ft): association with subnet is obsolete (no subnet)
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_3)
        do_check({'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_3,
                  'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_3},
                 'InvalidAssociationID.NotFound')

        # NOTE(ft): association with subnet is obsolete (subnet is
        # disassociated)
        self.set_mock_db_items(
            fakes.DB_ROUTE_TABLE_3,
            tools.purge_dict(fakes.DB_SUBNET_2, ['route_table_id']))
        do_check({'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_3,
                  'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_3},
                 'InvalidAssociationID.NotFound')

        # NOTE(ft): association belongs to different vpc
        id_ec2_subnet_vpc_2 = fakes.random_ec2_id('subnet')
        db_subnet_vpc_2 = {'id': id_ec2_subnet_vpc_2,
                           'os_id': fakes.random_os_id(),
                           'vpc_id': fakes.ID_EC2_VPC_2,
                           'route_table_id': fakes.random_ec2_id('rtb')}
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_2, db_subnet_vpc_2)
        do_check({'AssociationId': ec2utils.change_ec2_id_kind(
                        id_ec2_subnet_vpc_2, 'rtbassoc'),
                  'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2},
                 'InvalidParameterValue')

    @mock.patch('ec2api.api.route_table._update_routes_in_associated_subnets')
    @mock.patch('ec2api.api.route_table._update_subnet_host_routes')
    def test_replace_route_table_association_rollback(self, routes_updater,
                                                      multiply_routes_updater):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_2,
                               fakes.DB_ROUTE_TABLE_3, fakes.DB_SUBNET_2,
                               fakes.DB_VPC_1)
        multiply_routes_updater.side_effect = Exception()

        with tools.ScreeningLogger(log_name='ec2api.api'):
            self.assert_execution_error(
                self.ANY_EXECUTE_ERROR, 'ReplaceRouteTableAssociation',
                {'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_1,
                 'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2})

            self.db_api.update_item.assert_any_call(
                mock.ANY, fakes.DB_VPC_1)

        self.db_api.reset_mock()
        routes_updater.side_effect = Exception()

        with tools.ScreeningLogger(log_name='ec2api.api'):
            self.assert_execution_error(
                self.ANY_EXECUTE_ERROR, 'ReplaceRouteTableAssociation',
                {'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_3,
                 'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2})

            self.db_api.update_item.assert_any_call(
                mock.ANY, fakes.DB_SUBNET_2)

    @mock.patch('ec2api.api.route_table._update_subnet_host_routes')
    def test_disassociate_route_table(self, routes_updater):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_3,
                               fakes.DB_SUBNET_2, fakes.DB_VPC_1)
        resp = self.execute(
            'DisassociateRouteTable',
            {'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_3})
        self.assertEqual(True, resp['return'])
        subnet = tools.purge_dict(fakes.DB_SUBNET_2, ('route_table_id',))
        self.db_api.update_item.assert_called_once_with(
            mock.ANY, subnet)
        routes_updater.assert_called_once_with(
            mock.ANY, subnet, fakes.DB_ROUTE_TABLE_1,
            cleaner=mock.ANY,
            rollback_route_table_object=fakes.DB_ROUTE_TABLE_3)

    def test_disassociate_route_table_invalid_parameter(self):
        def do_check(params, error_code):
            self.assert_execution_error(
                error_code, 'DisassociateRouteTable', params)

        self.set_mock_db_items()
        do_check({'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_1},
                 'InvalidAssociationID.NotFound')

        self.set_mock_db_items(
            tools.purge_dict(fakes.DB_SUBNET_1, ['route_table_id']))
        do_check({'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_2},
                 'InvalidAssociationID.NotFound')

        self.set_mock_db_items(fakes.DB_VPC_1)
        do_check({'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_1},
                 'InvalidParameterValue')

    @tools.screen_unexpected_exception_logs
    @mock.patch('ec2api.api.route_table._update_subnet_host_routes')
    def test_disassociate_route_table_rollback(self, routes_updater):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_3,
                               fakes.DB_SUBNET_2, fakes.DB_VPC_1)
        routes_updater.side_effect = Exception()

        self.assert_execution_error(
             self.ANY_EXECUTE_ERROR, 'DisassociateRouteTable',
             {'AssociationId': fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_3})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_SUBNET_2)

    def test_delete_route_table(self):
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_2, fakes.DB_VPC_1,
                               fakes.DB_SUBNET_1, fakes.DB_SUBNET_2)
        resp = self.execute('DeleteRouteTable',
                            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2})
        self.assertEqual(True, resp['return'])
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY,
            fakes.ID_EC2_ROUTE_TABLE_2)

    def test_delete_route_table_invalid_parameters(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidRouteTableID.NotFound', 'DeleteRouteTable',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1})

        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_1, fakes.DB_VPC_1)
        self.assert_execution_error(
            'DependencyViolation', 'DeleteRouteTable',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_1})

        subnet = tools.update_dict(
            fakes.DB_SUBNET_2,
            {'route_table_id': fakes.ID_EC2_ROUTE_TABLE_2})
        self.set_mock_db_items(fakes.DB_ROUTE_TABLE_2, fakes.DB_VPC_1, subnet)
        self.assert_execution_error(
            'DependencyViolation', 'DeleteRouteTable',
            {'RouteTableId': fakes.ID_EC2_ROUTE_TABLE_2})

    def test_describe_route_tables(self):
        self.set_mock_db_items(
            fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_2,
            fakes.DB_ROUTE_TABLE_3, fakes.DB_SUBNET_1, fakes.DB_SUBNET_2,
            fakes.DB_VPC_1, fakes.DB_VPC_2, fakes.DB_IGW_1, fakes.DB_IGW_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2,
            fakes.DB_INSTANCE_1)
        self.nova.servers.get.return_value = (
            mock.NonCallableMock(status='ACTIVE'))

        resp = self.execute('DescribeRouteTables', {})
        self.assertThat(resp['routeTableSet'],
                        matchers.ListMatches([fakes.EC2_ROUTE_TABLE_1,
                                              fakes.EC2_ROUTE_TABLE_2,
                                              fakes.EC2_ROUTE_TABLE_3]))

        resp = self.execute('DescribeRouteTables',
                            {'RouteTableId.1': fakes.ID_EC2_ROUTE_TABLE_1})
        self.assertThat(resp['routeTableSet'],
                        matchers.ListMatches([fakes.EC2_ROUTE_TABLE_1]))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_ROUTE_TABLE_1]))

        self.check_filtering(
            'DescribeRouteTables', 'routeTableSet',
            [('association.route-table-association-id',
              fakes.ID_EC2_ROUTE_TABLE_ASSOCIATION_1),
             ('association.route-table-id', fakes.ID_EC2_ROUTE_TABLE_1),
             ('association.subnet-id', fakes.ID_EC2_SUBNET_2),
             ('association.main', True),
             ('route-table-id', fakes.ID_EC2_ROUTE_TABLE_1),
             ('route.destination-cidr-block', fakes.CIDR_EXTERNAL_NETWORK),
             ('route.gateway-id', 'local'),
             ('route.instance-id', fakes.ID_EC2_INSTANCE_1),
             ('route.origin', 'CreateRouteTable'),
             ('route.state', 'active'),
             ('vpc-id', fakes.ID_EC2_VPC_1)])
        self.check_tag_support(
            'DescribeRouteTables', 'routeTableSet',
            fakes.ID_EC2_ROUTE_TABLE_1, 'routeTableId')

    def test_describe_route_tables_variations(self):
        igw_1 = tools.purge_dict(fakes.DB_IGW_1, ('vpc_id',))
        igw_2 = tools.update_dict(fakes.DB_IGW_2,
                                  {'vpc_id': fakes.ID_EC2_VPC_2})
        subnet_1 = tools.update_dict(
            fakes.DB_SUBNET_1,
            {'route_table_id': fakes.ID_EC2_ROUTE_TABLE_1})
        subnet_2 = tools.update_dict(
            fakes.DB_SUBNET_2,
            {'route_table_id': fakes.ID_EC2_ROUTE_TABLE_2})
        route_table_1 = copy.deepcopy(fakes.DB_ROUTE_TABLE_1)
        route_table_1['routes'].append(
            {'destination_cidr_block': '0.0.0.0/0',
             'gateway_id': fakes.ID_EC2_IGW_2})
        route_table_1['routes'].append(
            {'destination_cidr_block': '192.168.77.0/24',
             'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1})
        deleted_eni_id = fakes.random_ec2_id('eni')
        route_table_1['routes'].append(
            {'destination_cidr_block': '192.168.99.0/24',
             'network_interface_id': deleted_eni_id})
        route_table_2 = copy.deepcopy(fakes.DB_ROUTE_TABLE_2)
        route_table_2['routes'].append(
            {'destination_cidr_block': '192.168.88.0/24',
             'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_2})
        self.set_mock_db_items(
            route_table_1, route_table_2, fakes.DB_VPC_1, fakes.DB_VPC_2,
            igw_1, igw_2, subnet_1, subnet_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2)
        self.nova.servers.get.return_value = (
            mock.NonCallableMock(status='DOWN'))
        resp = self.execute('DescribeRouteTables', {})
        ec2_route_table_1 = copy.deepcopy(fakes.EC2_ROUTE_TABLE_1)
        ec2_route_table_1['routeSet'].append({
            'destinationCidrBlock': '0.0.0.0/0',
            'gatewayId': fakes.ID_EC2_IGW_2,
            'state': 'blackhole',
            'origin': 'CreateRoute'})
        ec2_route_table_1['routeSet'].append({
            'destinationCidrBlock': '192.168.77.0/24',
            'networkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
            'state': 'blackhole',
            'origin': 'CreateRoute'})
        ec2_route_table_1['routeSet'].append({
            'destinationCidrBlock': '192.168.99.0/24',
            'networkInterfaceId': deleted_eni_id,
            'state': 'blackhole',
            'origin': 'CreateRoute'})
        ec2_route_table_1['associationSet'].append({
            'routeTableAssociationId':
            fakes.ID_EC2_SUBNET_1.replace('subnet', 'rtbassoc'),
                'routeTableId': fakes.ID_EC2_ROUTE_TABLE_1,
                'subnetId': fakes.ID_EC2_SUBNET_1,
                'main': False})
        ec2_route_table_2 = copy.deepcopy(fakes.EC2_ROUTE_TABLE_2)
        ec2_route_table_2['routeSet'][1]['state'] = 'blackhole'
        ec2_route_table_2['routeSet'][2]['state'] = 'blackhole'
        ec2_route_table_2['routeSet'].append({
            'destinationCidrBlock': '192.168.88.0/24',
            'networkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
            'instanceId': fakes.ID_EC2_INSTANCE_1,
            'instanceOwnerId': fakes.ID_OS_PROJECT,
            'state': 'blackhole',
            'origin': 'CreateRoute'})
        ec2_route_table_2['associationSet'] = [{
            'routeTableAssociationId':
            fakes.ID_EC2_SUBNET_2.replace('subnet', 'rtbassoc'),
                'routeTableId': fakes.ID_EC2_ROUTE_TABLE_2,
                'subnetId': fakes.ID_EC2_SUBNET_2,
                'main': False}]
        self.assertThat(resp['routeTableSet'],
                        matchers.ListMatches([ec2_route_table_1,
                                              ec2_route_table_2]))

    def test_get_subnet_host_routes(self):
        self.set_mock_db_items(
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2,
            fakes.DB_IGW_1)

        host_routes = route_table._get_subnet_host_routes(
            mock.ANY, fakes.DB_ROUTE_TABLE_1, fakes.IP_GATEWAY_SUBNET_1)

        self.assertThat(host_routes,
                        matchers.ListMatches([
                            {'destination': fakes.CIDR_VPC_1,
                             'nexthop': fakes.IP_GATEWAY_SUBNET_1},
                            {'destination': '0.0.0.0/0',
                             'nexthop': '127.0.0.1'}]))

        host_routes = route_table._get_subnet_host_routes(
            mock.ANY, fakes.DB_ROUTE_TABLE_2, fakes.IP_GATEWAY_SUBNET_1)

        self.assertThat(host_routes,
                        matchers.ListMatches([
                            {'destination': fakes.CIDR_VPC_1,
                             'nexthop': fakes.IP_GATEWAY_SUBNET_1},
                            {'destination': fakes.CIDR_EXTERNAL_NETWORK,
                             'nexthop': fakes.IP_NETWORK_INTERFACE_2},
                            {'destination': '0.0.0.0/0',
                             'nexthop': fakes.IP_GATEWAY_SUBNET_1}]))

    @mock.patch('ec2api.api.route_table._get_subnet_host_routes')
    def test_update_subnet_host_routes(self, routes_getter):
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_1}
        routes_getter.return_value = 'fake_routes'

        route_table._update_subnet_host_routes(
            self._create_context(), fakes.DB_SUBNET_1,
            fakes.DB_ROUTE_TABLE_1, router_objects={'fake': 'objects'})

        self.neutron.show_subnet.assert_called_once_with(fakes.ID_OS_SUBNET_1)
        routes_getter.assert_called_once_with(
            mock.ANY, fakes.DB_ROUTE_TABLE_1, fakes.IP_GATEWAY_SUBNET_1,
            {'fake': 'objects'})
        self.neutron.update_subnet.assert_called_once_with(
            fakes.ID_OS_SUBNET_1,
            {'subnet': {'host_routes': 'fake_routes'}})

        self.neutron.reset_mock()
        routes_getter.reset_mock()

        routes_getter.side_effect = ['fake_routes', 'fake_previous_routes']

        try:
            with common.OnCrashCleaner() as cleaner:
                route_table._update_subnet_host_routes(
                    self._create_context(), fakes.DB_SUBNET_1,
                    fakes.DB_ROUTE_TABLE_1, cleaner,
                    fakes.DB_ROUTE_TABLE_2,
                    router_objects={'fake': 'objects'})
                raise Exception('fake_exception')
        except Exception as ex:
            if ex.message != 'fake_exception':
                raise

        self.neutron.show_subnet.assert_any_call(fakes.ID_OS_SUBNET_1)
        routes_getter.assert_any_call(
            mock.ANY, fakes.DB_ROUTE_TABLE_1, fakes.IP_GATEWAY_SUBNET_1,
            {'fake': 'objects'})
        routes_getter.assert_any_call(
            mock.ANY, fakes.DB_ROUTE_TABLE_2, fakes.IP_GATEWAY_SUBNET_1,
            None)
        self.neutron.update_subnet.assert_any_call(
            fakes.ID_OS_SUBNET_1,
            {'subnet': {'host_routes': 'fake_previous_routes'}})

    @mock.patch('ec2api.api.route_table._get_router_objects')
    @mock.patch('ec2api.api.route_table._update_subnet_host_routes')
    def test_update_routes_in_associated_subnets(self, routes_updater,
                                                 get_router_objects):
        subnet_default_rtb = {'id': 'fake_1',
                              'vpc_id': fakes.ID_EC2_VPC_1}
        subnet_rtb_2 = {'id': 'fake_2',
                        'vpc_id': fakes.ID_EC2_VPC_1,
                        'route_table_id': fakes.ID_EC2_ROUTE_TABLE_2}
        subnet_vpc_2 = {'id': 'fake_3',
                        'vpc_id': fakes.ID_EC2_VPC_2}
        self.db_api.get_items.return_value = [subnet_default_rtb,
                                              subnet_rtb_2, subnet_vpc_2]
        self.db_api.get_item_by_id.return_value = fakes.DB_VPC_1
        get_router_objects.return_value = {'fake': 'objects'}

        route_table._update_routes_in_associated_subnets(
            mock.MagicMock(), fakes.DB_ROUTE_TABLE_2, 'fake_cleaner',
            {'fake': 'table'})

        self.db_api.get_item_by_id.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_VPC_1)
        routes_updater.assert_called_once_with(
            mock.ANY, subnet_rtb_2, fakes.DB_ROUTE_TABLE_2,
            cleaner='fake_cleaner',
            rollback_route_table_object={'fake': 'table'},
            router_objects={'fake': 'objects'}, neutron=mock.ANY)
        get_router_objects.assert_called_once_with(mock.ANY,
                                                   fakes.DB_ROUTE_TABLE_2)

        self.db_api.get_item_by_id.reset_mock()
        routes_updater.reset_mock()
        get_router_objects.reset_mock()

        route_table._update_routes_in_associated_subnets(
            mock.MagicMock(), fakes.DB_ROUTE_TABLE_1, 'fake_cleaner',
            {'fake': 'table'}, is_main=True)

        self.assertEqual(0, self.db_api.get_item_by_id.call_count)
        routes_updater.assert_called_once_with(
            mock.ANY, subnet_default_rtb, fakes.DB_ROUTE_TABLE_1,
            cleaner='fake_cleaner',
            rollback_route_table_object={'fake': 'table'},
            router_objects={'fake': 'objects'}, neutron=mock.ANY)
        get_router_objects.assert_called_once_with(mock.ANY,
                                                   fakes.DB_ROUTE_TABLE_1)

    def test_get_router_objects(self):
        self.set_mock_db_items(fakes.DB_IGW_1, fakes.DB_NETWORK_INTERFACE_2)
        host_routes = route_table._get_router_objects('fake_context',
                                                      fakes.DB_ROUTE_TABLE_2)
        self.assertThat(host_routes, matchers.DictMatches({
            fakes.ID_EC2_IGW_1: fakes.DB_IGW_1,
            fakes.ID_EC2_NETWORK_INTERFACE_2:
                        fakes.DB_NETWORK_INTERFACE_2}))
