#    Copyright 2014 Cloudscaling Group, Inc
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

import mock
from neutronclient.common import exceptions as neutron_exception

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class SubnetTestCase(base.ApiTestCase):

    def test_create_subnet(self):
        self.db_api.get_item_by_id.side_effect = (
                fakes.get_db_api_get_item_by_id({
                        fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                        fakes.ID_DB_ROUTE_TABLE_1: fakes.DB_ROUTE_TABLE_1}))
        self.db_api.add_item.side_effect = (
                fakes.get_db_api_add_item(fakes.ID_DB_SUBNET_1))
        self.neutron.create_network.side_effect = (
                fakes.get_neutron_create('network', fakes.ID_OS_NETWORK_1,
                                         {'status': 'available'}))
        self.neutron.create_subnet.side_effect = (
                fakes.get_neutron_create('subnet', fakes.ID_OS_SUBNET_1))

        def check_response(resp):
            self.assertEqual(200, resp['status'])
            self.assertThat(fakes.EC2_SUBNET_1, matchers.DictMatches(
                    resp['subnet']))
            self.db_api.add_item.called_once_with(
                    mock.ANY, 'subnet',
                    tools.purge_dict(fakes.DB_SUBNET_1, ('id',)))
            self.neutron.create_network.assert_called_once_with(
                    {'network': {}})
            self.neutron.update_network.assert_called_once_with(
                    fakes.ID_OS_NETWORK_1,
                    {'network': {'name': fakes.ID_EC2_SUBNET_1}})
            self.neutron.create_subnet.assert_called_once_with(
                    {'subnet': tools.purge_dict(fakes.OS_SUBNET_1,
                                                 ('id', 'name'))})
            self.neutron.update_subnet.assert_called_once_with(
                    fakes.ID_OS_SUBNET_1,
                    {'subnet': {'name': fakes.ID_EC2_SUBNET_1}})
            self.neutron.add_interface_router.assert_called_once_with(
                    fakes.ID_OS_ROUTER_1,
                    {'subnet_id': fakes.ID_OS_SUBNET_1})

        resp = self.execute('CreateSubnet', {'VpcId': fakes.ID_EC2_VPC_1,
                                             'CidrBlock': fakes.CIDR_SUBNET_1})
        check_response(resp)

        self.neutron.reset_mock()
        self.db_api.reset_mock()

        resp = self.execute('CreateSubnet', {'VpcId': fakes.ID_EC2_VPC_1,
                                             'CidrBlock': fakes.CIDR_SUBNET_1,
                                             'AvailabilityZone': 'nova'})
        check_response(resp)

    def test_create_subnet_invalid_parameters(self):
        def check_response(resp, error_code):
            self.assertEqual(400, resp['status'])
            self.assertEqual(error_code, resp['Error']['Code'])
            self.assertEqual(0, self.neutron.create_network.call_count)
            self.assertEqual(0, self.neutron.create_subnet.call_count)
            self.assertEqual(0, self.neutron.add_interface_router.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.db_api.get_item_by_id.return_value = None
        resp = self.execute('CreateSubnet', {'VpcId': fakes.ID_EC2_VPC_1,
                                             'CidrBlock': fakes.CIDR_SUBNET_1})
        self.db_api.get_item_by_id.assert_called_once_with(mock.ANY, 'vpc',
                                                           fakes.ID_DB_VPC_1)
        check_response(resp, 'InvalidVpcID.NotFound')

        self.db_api.get_item_by_id.return_value = fakes.DB_VPC_1
        resp = self.execute('CreateSubnet', {'VpcId': fakes.ID_EC2_VPC_1,
                                             'CidrBlock': 'invalid_cidr'})
        self.assertEqual(0, self.db_api.get_item_by_id.call_count)
        check_response(resp, 'InvalidParameterValue')

        resp = self.execute('CreateSubnet', {'VpcId': fakes.ID_EC2_VPC_1,
                                             'CidrBlock': '10.10.0.0/30'})
        self.assertEqual(0, self.db_api.get_item_by_id.call_count)
        check_response(resp, 'InvalidSubnet.Range')

        resp = self.execute('CreateSubnet', {'VpcId': fakes.ID_EC2_VPC_1,
                                             'CidrBlock': '10.20.0.0/24'})
        self.db_api.get_item_by_id.assert_called_once_with(mock.ANY, 'vpc',
                                                           fakes.ID_DB_VPC_1)
        check_response(resp, 'InvalidSubnet.Range')

    @base.skip_not_implemented
    def test_create_subnet_overlimit(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_VPC_1
        self.neutron.create_network.side_effect = (
                fakes.get_neutron_create('network', fakes.ID_OS_NETWORK_1,
                                         {'status': 'available'}))
        self.neutron.create_subnet.side_effect = (
                fakes.get_neutron_create('subnet', fakes.ID_OS_SUBNET_1))

        def test_overlimit(func):
            self.neutron.reset_mock()
            saved_side_effect = func.side_effect
            func.side_effect = neutron_exception.Conflict

            resp = self.execute('CreateSubnet',
                                {'VpcId': fakes.ID_EC2_VPC_1,
                                 'CidrBlock': fakes.CIDR_SUBNET_1})

            self.assertEqual(400, resp['status'])
            self.assertEqual('SubnetLimitExceeded', resp['Error']['Code'])
            func.side_effect = saved_side_effect

        test_overlimit(self.neutron.create_network)
        test_overlimit(self.neutron.create_subnet)
        test_overlimit(self.neutron.add_interface_router)

    def test_create_subnet_rollback(self):
        self.db_api.get_item_by_id.side_effect = (
                fakes.get_db_api_get_item_by_id({
                        fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                        fakes.ID_DB_ROUTE_TABLE_1: fakes.DB_ROUTE_TABLE_1}))
        self.db_api.add_item.side_effect = (
                fakes.get_db_api_add_item(fakes.ID_DB_SUBNET_1))
        self.neutron.create_network.side_effect = (
                fakes.get_neutron_create('network', fakes.ID_OS_NETWORK_1,
                                         {'status': 'available'}))
        self.neutron.create_subnet.side_effect = (
                fakes.get_neutron_create('subnet', fakes.ID_OS_SUBNET_1))
        self.neutron.update_network.side_effect = Exception()

        self.execute('CreateSubnet', {'VpcId': fakes.ID_EC2_VPC_1,
                                      'CidrBlock': fakes.CIDR_SUBNET_1})

        # TODO(ft): check sequence of calls
        # remove interface router must be the first
        self.neutron.remove_interface_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_1, {'subnet_id': fakes.ID_OS_SUBNET_1})
        self.neutron.delete_subnet.assert_called_once_with(
                fakes.ID_OS_SUBNET_1)
        self.neutron.delete_network.assert_called_once_with(
                fakes.ID_OS_NETWORK_1)
        self.db_api.delete_item.assert_called_once_with(
                mock.ANY, fakes.ID_DB_SUBNET_1)

    @base.skip_not_implemented
    def test_create_subnet_not_consistent_os_vpc(self):
        pass

    def test_delete_subnet(self):
        self.db_api.get_item_by_id.side_effect = (
                fakes.get_db_api_get_item_by_id(
                        {fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                         fakes.ID_DB_SUBNET_1: fakes.DB_SUBNET_1}))
        self.neutron.show_subnet.return_value = (
                {'subnet': fakes.OS_SUBNET_1})
        self.db_api.get_items.return_value = []

        resp = self.execute('DeleteSubnet',
                            {'subnetId': fakes.ID_EC2_SUBNET_1})

        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_has_call(
                mock.ANY,
                fakes.ID_DB_SUBNET_1)
        self.db_api.get_item_by_id.assert_has_call(
                mock.ANY,
                fakes.ID_DB_VPC_1)
        self.db_api.delete_item.assert_called_once_with(
                mock.ANY,
                fakes.ID_DB_SUBNET_1)
        self.neutron.show_subnet.assert_called_once_with(
                fakes.ID_OS_SUBNET_1)
        self.neutron.remove_interface_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_1,
                {'subnet_id': fakes.ID_OS_SUBNET_1})

    def test_delete_subnet_no_subnet(self):
        self.db_api.get_item_by_id.return_value = None
        self.neutron.show_subnet.return_value = fakes.OS_SUBNET_1
        self.neutron.show_network.return_value = fakes.OS_NETWORK_1

        resp = self.execute('DeleteSubnet',
                            {'subnetId': fakes.ID_EC2_SUBNET_1})

        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidSubnetID.NotFound', resp['Error']['Code'])
        self.assertEqual(0, self.neutron.delete_network.call_count)
        self.assertEqual(0, self.neutron.delete_subnet.call_count)
        self.assertEqual(0, self.neutron.remove_interface_router.call_count)

    def test_delete_subnet_rollback(self):
        self.db_api.get_item_by_id.side_effect = (
                fakes.get_db_api_get_item_by_id(
                        {fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                         fakes.ID_DB_SUBNET_1: fakes.DB_SUBNET_1}))
        self.neutron.show_subnet.side_effect = Exception()

        self.execute('DeleteSubnet', {'subnetId': fakes.ID_EC2_SUBNET_1})

        self.db_api.restore_item.assert_called_once_with(
                mock.ANY, 'subnet', fakes.DB_SUBNET_1)
        self.neutron.add_interface_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_1, {'subnet_id': fakes.ID_OS_SUBNET_1})

    def test_delete_subnet_has_ports(self):
        self.db_api.get_item_by_id.side_effect = (
                fakes.get_db_api_get_item_by_id(
                        {fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                         fakes.ID_DB_SUBNET_1: fakes.DB_SUBNET_1}))
        self.db_api.get_items.return_value = [fakes.DB_NETWORK_INTERFACE_1]

        resp = self.execute('DeleteSubnet',
                            {'subnetId': fakes.ID_EC2_SUBNET_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('DependencyViolation', resp['Error']['Code'])

    def test_describe_subnets(self):
        self.db_api.get_items.return_value = (
                [fakes.DB_SUBNET_1, fakes.DB_SUBNET_2])
        self.neutron.list_subnets.return_value = (
                {'subnets': [fakes.OS_SUBNET_1, fakes.OS_SUBNET_2]})
        self.neutron.list_networks.return_value = (
                {'networks': [fakes.OS_NETWORK_1, fakes.OS_NETWORK_2]})

        resp = self.execute('DescribeSubnets', {})
        self.assertEqual(200, resp['status'])
        self.assertThat(resp['subnetSet'],
                        matchers.DictListMatches([fakes.EC2_SUBNET_1,
                                                  fakes.EC2_SUBNET_2]))

    @base.skip_not_implemented
    def test_describe_subnets_no_vpc(self):
        pass

    @base.skip_not_implemented
    def test_describe_subnets_not_consistent_os_vpc(self):
        pass

    def test_describe_subnets_not_consistent_os_subnet(self):
        self.db_api.get_items.return_value = (
                [fakes.DB_SUBNET_1, fakes.DB_SUBNET_2])
        self.neutron.list_subnets.return_value = (
                {'subnets': [fakes.OS_SUBNET_2]})
        self.neutron.list_networks.return_value = (
                {'networks': [fakes.OS_NETWORK_1]})

        resp = self.execute('DescribeSubnets', {})
        self.assertEqual(200, resp['status'])
        self.assertEqual([], resp['subnetSet'])

    @base.skip_not_implemented
    def test_describe_subnets_is_not_attached_to_router(self):
        pass
