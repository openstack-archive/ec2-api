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

from neutronclient.common import exceptions as neutron_exception
from unittest import mock

from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class AddressTestCase(base.ApiTestCase):

    def setUp(self):
        super(AddressTestCase, self).setUp()

    def test_allocate_ec2_classic_address(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        self.neutron.list_networks.return_value = (
            {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.create_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})

        resp = self.execute('AllocateAddress', {})
        self.assertEqual(fakes.IP_ADDRESS_1, resp['publicIp'])
        self.assertEqual('standard', resp['domain'])
        self.assertNotIn('allocationId', resp)
        self.assertEqual(0, self.db_api.add_item.call_count)
        self.neutron.create_floatingip.assert_called_once_with(
            {'floatingip': {
                'floating_network_id':
                fakes.ID_OS_PUBLIC_NETWORK}})

    def test_allocate_vpc_address(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        self.neutron.list_networks.return_value = (
            {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.create_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.db_api.add_item.return_value = fakes.DB_ADDRESS_1

        resp = self.execute('AllocateAddress', {'Domain': 'vpc'})

        self.assertEqual(fakes.IP_ADDRESS_1, resp['publicIp'])
        self.assertEqual('vpc', resp['domain'])
        self.assertEqual(fakes.ID_EC2_ADDRESS_1,
                         resp['allocationId'])
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'eipalloc',
            tools.purge_dict(fakes.DB_ADDRESS_1,
                             ('id', 'vpc_id')))
        self.neutron.create_floatingip.assert_called_once_with(
            {'floatingip': {
                'floating_network_id':
                fakes.ID_OS_PUBLIC_NETWORK}})
        self.neutron.list_networks.assert_called_once_with(
            **{'router:external': True,
               'name': fakes.NAME_OS_PUBLIC_NETWORK})
        self.db_api.reset_mock()
        self.neutron.create_floatingip.reset_mock()
        self.neutron.list_networks.reset_mock()

        self.configure(disable_ec2_classic=True)
        resp = self.execute('AllocateAddress', {})

        self.assertEqual(fakes.IP_ADDRESS_1, resp['publicIp'])
        self.assertEqual('vpc', resp['domain'])
        self.assertEqual(fakes.ID_EC2_ADDRESS_1,
                         resp['allocationId'])
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'eipalloc',
            tools.purge_dict(fakes.DB_ADDRESS_1,
                             ('id', 'vpc_id')))
        self.neutron.create_floatingip.assert_called_once_with(
            {'floatingip': {
                'floating_network_id':
                fakes.ID_OS_PUBLIC_NETWORK}})
        self.neutron.list_networks.assert_called_once_with(
            **{'router:external': True,
               'name': fakes.NAME_OS_PUBLIC_NETWORK})

    def test_allocate_address_invalid_parameters(self):
        self.assert_execution_error('InvalidParameterValue', 'AllocateAddress',
                                    {'Domain': 'fake_domain'})
        self.assertEqual(0, self.db_api.add_item.call_count)
        self.assertEqual(0, self.neutron.create_floatingip.call_count)

    def test_allocate_address_overlimit(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        self.neutron.list_networks.return_value = (
            {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.create_floatingip.side_effect = (
            neutron_exception.OverQuotaClient())
        self.assert_execution_error('AddressLimitExceeded', 'AllocateAddress',
                                    {'Domain': 'vpc'})
        self.assert_execution_error('AddressLimitExceeded', 'AllocateAddress',
                                    {})

    @tools.screen_unexpected_exception_logs
    def test_allocate_address_vpc_rollback(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        self.neutron.list_networks.return_value = (
            {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.create_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.db_api.add_item.side_effect = Exception()

        self.assert_execution_error(self.ANY_EXECUTE_ERROR, 'AllocateAddress',
                                    {'Domain': 'vpc'})

        self.neutron.delete_floatingip.assert_called_once_with(
            fakes.ID_OS_FLOATING_IP_1)

    # TODO(andrey-mp): api code has to be fixed
    # There is no add-floating-ip and remove-floating-ip command in
    # python-novaclient. Those command have been removed since 7.0.0
    # version (ocata) and ec2-api has version >9.1.0 since long.
    @base.skip_not_implemented
    def test_associate_address_ec2_classic(self):
        self.set_mock_db_items(fakes.DB_INSTANCE_1)
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})
        self.nova.servers.add_floating_ip.return_value = True

        resp = self.execute('AssociateAddress',
                            {'PublicIp': fakes.IP_ADDRESS_1,
                             'InstanceId': fakes.ID_EC2_INSTANCE_1})
        self.assertEqual(True, resp['return'])

        self.nova.servers.add_floating_ip.assert_called_once_with(
            fakes.ID_OS_INSTANCE_1,
            fakes.IP_ADDRESS_1)

    def test_associate_address_vpc(self):

        def do_check(params, fixed_ip):
            resp = self.execute('AssociateAddress', params)
            self.assertEqual(True, resp['return'])
            self.assertEqual(fakes.ID_EC2_ASSOCIATION_1, resp['associationId'])

            self.neutron.update_floatingip.assert_called_once_with(
                fakes.ID_OS_FLOATING_IP_1,
                {'floatingip': {'port_id': fakes.ID_OS_PORT_2,
                                'fixed_ip_address': fixed_ip}})
            self.db_api.update_item.assert_called_once_with(
                mock.ANY,
                tools.update_dict(
                    fakes.DB_ADDRESS_1,
                    {'network_interface_id':
                     fakes.ID_EC2_NETWORK_INTERFACE_2,
                     'private_ip_address': fixed_ip}))

            self.neutron.update_floatingip.reset_mock()
            self.db_api.update_item.reset_mock()

        self.set_mock_db_items(
            fakes.DB_ADDRESS_1, fakes.DB_IGW_1, fakes.DB_IGW_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 fakes.IP_NETWORK_INTERFACE_2)

        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2},
                 fakes.IP_NETWORK_INTERFACE_2)

        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
                  'PrivateIpAddress': fakes.IP_NETWORK_INTERFACE_2_EXT_1},
                 fakes.IP_NETWORK_INTERFACE_2_EXT_1)

        assigned_db_address_1 = tools.update_dict(
            fakes.DB_ADDRESS_1,
            {'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'private_ip_address': fakes.IP_NETWORK_INTERFACE_1})
        self.add_mock_db_items(assigned_db_address_1)
        assigned_floating_ip_1 = tools.update_dict(
            fakes.OS_FLOATING_IP_1,
            {'fixed_port_id': fakes.ID_OS_PORT_1,
             'fixed_ip_address': fakes.IP_NETWORK_INTERFACE_1})
        self.neutron.show_floatingip.return_value = (
            {'floatingip': assigned_floating_ip_1})
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1,
                  'AllowReassociation': 'True'},
                 fakes.IP_NETWORK_INTERFACE_2)

        self.configure(disable_ec2_classic=True)
        self.set_mock_db_items(
            fakes.DB_VPC_DEFAULT, fakes.DB_ADDRESS_1, fakes.DB_IGW_1,
            fakes.DB_NETWORK_INTERFACE_2)
        do_check({'PublicIp': fakes.IP_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 fakes.IP_NETWORK_INTERFACE_2)

    def test_associate_address_vpc_idempotent(self):

        def do_check(params):
            resp = self.execute('AssociateAddress', params)
            self.assertEqual(True, resp['return'])
            self.assertEqual(fakes.ID_EC2_ASSOCIATION_2, resp['associationId'])

        self.set_mock_db_items(fakes.DB_ADDRESS_2,
                               fakes.DB_NETWORK_INTERFACE_1,
                               fakes.DB_NETWORK_INTERFACE_2)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})

        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_2,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1})

        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_2,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2})

        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_2,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
                  'PrivateIpAddress': fakes.IP_NETWORK_INTERFACE_2})

    def test_associate_address_invalid_main_parameters(self):

        def do_check(params, error):
            self.assert_execution_error(error, 'AssociateAddress', params)

        do_check({},
                 'MissingParameter')

        do_check({'PublicIp': '0.0.0.0',
                  'AllocationId': 'eipalloc-0'},
                 'InvalidParameterCombination')

        do_check({'PublicIp': '0.0.0.0'},
                 'MissingParameter')

        do_check({'AllocationId': 'eipalloc-0'},
                 'MissingParameter')

    def test_associate_address_invalid_ec2_classic_parameters(self):
        # NOTE(ft): ec2 classic instance vs allocation_id parameter
        self.set_mock_db_items(fakes.DB_INSTANCE_2)
        self.assert_execution_error('InvalidParameterCombination',
                                    'AssociateAddress',
                                    {'AllocationId': 'eipalloc-0',
                                     'InstanceId': fakes.ID_EC2_INSTANCE_2})

        # NOTE(ft): ec2 classic instance vs not existing public IP
        self.neutron.list_floatingips.return_value = {'floatingips': []}
        self.assert_execution_error('AuthFailure', 'AssociateAddress',
                                    {'PublicIp': fakes.IP_ADDRESS_1,
                                     'InstanceId': fakes.ID_EC2_INSTANCE_2})

        # NOTE(ft): ec2 classic instance vs vpc public ip
        self.add_mock_db_items(fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.assert_execution_error('AuthFailure', 'AssociateAddress',
                                    {'PublicIp': fakes.IP_ADDRESS_1,
                                     'InstanceId': fakes.ID_EC2_INSTANCE_2})

    def test_associate_address_invalid_vpc_parameters(self):

        def do_check(params, error):
            self.assert_execution_error(error, 'AssociateAddress', params)

        # NOTE(ft): not registered instance id vs vpc address
        self.set_mock_db_items()
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidInstanceID.NotFound')

        # NOTE(ft): vpc instance vs public ip parmeter
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_2)
        do_check({'PublicIp': '0.0.0.0',
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidParameterCombination')

        # NOTE(ft): vpc instance vs not registered vpc address
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidAllocationID.NotFound')

        # NOTE(ft): not registered network interface id vs vpc address
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1},
                 'InvalidNetworkInterfaceID.NotFound')

        # NOTE(ft): vpc instance vs broken vpc address
        self.set_mock_db_items(fakes.DB_ADDRESS_1,
                               fakes.DB_NETWORK_INTERFACE_2)
        self.neutron.show_floatingip.side_effect = neutron_exception.NotFound
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidAllocationID.NotFound')
        self.neutron.show_floatingip.side_effect = None

        # NOTE(ft): already associated address vs network interface
        self.set_mock_db_items(fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2,
                               fakes.DB_NETWORK_INTERFACE_1)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})
        self.assert_execution_error(
            'Resource.AlreadyAssociated', 'AssociateAddress',
            {'AllocationId': fakes.ID_EC2_ADDRESS_2,
             'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1})

        # NOTE(ft): already associated address vs vpc instance
        self.set_mock_db_items(
            fakes.DB_ADDRESS_2,
            fakes.gen_db_network_interface(
                fakes.ID_EC2_NETWORK_INTERFACE_1,
                fakes.ID_OS_PORT_1,
                fakes.ID_EC2_VPC_1,
                fakes.ID_EC2_SUBNET_1,
                fakes.IP_NETWORK_INTERFACE_1,
                instance_id=fakes.ID_EC2_INSTANCE_1))
        self.assert_execution_error('Resource.AlreadyAssociated',
                                    'AssociateAddress',
                                    {'AllocationId': fakes.ID_EC2_ADDRESS_2,
                                     'InstanceId': fakes.ID_EC2_INSTANCE_1})

        # NOTE(ft): multiple network interfaces in vpc instance
        # w/o network interface selection
        self.add_mock_db_items(fakes.DB_NETWORK_INTERFACE_2)
        self.assert_execution_error('InvalidInstanceID', 'AssociateAddress',
                                    {'AllocationId': fakes.ID_EC2_ADDRESS_1,
                                     'InstanceId': fakes.ID_EC2_INSTANCE_1})

        # NOTE(ft): internet gateway isn't attached to the vpc
        self.set_mock_db_items(fakes.DB_ADDRESS_1,
                               fakes.DB_NETWORK_INTERFACE_2)
        self.assert_execution_error('Gateway.NotAttached', 'AssociateAddress',
                                    {'AllocationId': fakes.ID_EC2_ADDRESS_1,
                                     'InstanceId': fakes.ID_EC2_INSTANCE_1})

        # NOTE(tikitavi): associate to wrong public ip
        self.configure(disable_ec2_classic=True)
        self.set_mock_db_items(
            fakes.DB_VPC_DEFAULT, fakes.DB_IGW_DEFAULT, fakes.DB_ADDRESS_1,
            fakes.DB_INSTANCE_DEFAULT, tools.update_dict(
                fakes.DB_NETWORK_INTERFACE_DEFAULT,
                {'instance_id': fakes.ID_EC2_INSTANCE_DEFAULT}))
        do_check({'PublicIp': '0.0.0.0',
                  'InstanceId': fakes.ID_EC2_INSTANCE_DEFAULT},
                 'AuthFailure')

    @tools.screen_unexpected_exception_logs
    def test_associate_address_vpc_rollback(self):
        self.set_mock_db_items(fakes.DB_ADDRESS_1, fakes.DB_IGW_1,
                               fakes.DB_NETWORK_INTERFACE_1,
                               fakes.DB_NETWORK_INTERFACE_2)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.neutron.update_floatingip.side_effect = Exception()

        self.assert_execution_error(self.ANY_EXECUTE_ERROR, 'AssociateAddress',
                                    {'AllocationId': fakes.ID_EC2_ADDRESS_1,
                                     'InstanceId': fakes.ID_EC2_INSTANCE_1})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_ADDRESS_1)

    # TODO(andrey-mp): api code has to be fixed
    # There is no add-floating-ip and remove-floating-ip command in
    # python-novaclient. Those command have been removed since 7.0.0
    # version (ocata) and ec2-api has version >9.1.0 since long.
    @base.skip_not_implemented
    def test_dissassociate_address_ec2_classic(self):
        self.set_mock_db_items(fakes.DB_INSTANCE_1)
        self.nova.servers.remove_floating_ip.return_value = True
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1,
                       fakes.OS_PORT_2]})

        resp = self.execute('DisassociateAddress',
                            {'PublicIp': fakes.IP_ADDRESS_2})
        self.assertEqual(True, resp['return'])
        self.nova.servers.remove_floating_ip.assert_called_once_with(
            fakes.ID_OS_INSTANCE_1,
            fakes.IP_ADDRESS_2)

        # NOTE(Alex) Disassociate unassociated address in EC2 classic
        resp = self.execute('DisassociateAddress',
                            {'PublicIp': fakes.IP_ADDRESS_1})
        self.assertEqual(True, resp['return'])
        self.assertEqual(1, self.nova.servers.remove_floating_ip.call_count)

    def test_dissassociate_address_vpc(self):
        self.set_mock_db_items(fakes.DB_ADDRESS_2)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})

        resp = self.execute('DisassociateAddress',
                            {'AssociationId': fakes.ID_EC2_ASSOCIATION_2})
        self.assertEqual(True, resp['return'])

        self.neutron.update_floatingip.assert_called_once_with(
            fakes.ID_OS_FLOATING_IP_2,
            {'floatingip': {'port_id': None}})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.purge_dict(fakes.DB_ADDRESS_2, ['network_interface_id',
                                                  'private_ip_address']))
        self.neutron.update_floatingip.reset_mock()
        self.db_api.update_item.reset_mock()

        self.configure(disable_ec2_classic=True)

        resp = self.execute('DisassociateAddress',
                            {'PublicIp': fakes.IP_ADDRESS_2})
        self.assertEqual(True, resp['return'])

        self.neutron.update_floatingip.assert_called_once_with(
            fakes.ID_OS_FLOATING_IP_2,
            {'floatingip': {'port_id': None}})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.purge_dict(fakes.DB_ADDRESS_2, ['network_interface_id',
                                                  'private_ip_address']))

    def test_dissassociate_address_vpc_idempotent(self):
        self.set_mock_db_items(fakes.DB_ADDRESS_1)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})

        resp = self.execute('DisassociateAddress',
                            {'AssociationId': fakes.ID_EC2_ASSOCIATION_1})
        self.assertEqual(True, resp['return'])

        self.assertEqual(0, self.neutron.update_floatingip.call_count)
        self.assertEqual(0, self.db_api.update_item.call_count)

    def test_disassociate_address_invalid_parameters(self):

        def do_check(params, error):
            self.assert_execution_error(error, 'DisassociateAddress', params)

        do_check({},
                 'MissingParameter')

        do_check({'PublicIp': '0.0.0.0',
                  'AssociationId': 'eipassoc-0'},
                 'InvalidParameterCombination')

        # NOTE(ft): EC2 Classic public IP does not exists
        self.set_mock_db_items()
        self.neutron.list_floatingips.return_value = {'floatingips': []}

        self.assert_execution_error('AuthFailure', 'DisassociateAddress',
                                    {'PublicIp': fakes.IP_ADDRESS_2})

        # NOTE(ft): vpc address vs public ip parameter
        self.set_mock_db_items(fakes.DB_ADDRESS_1)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        do_check({'PublicIp': fakes.IP_ADDRESS_1},
                 'InvalidParameterValue')

        # NOTE(ft): not registered address
        self.set_mock_db_items()
        do_check({'AssociationId': fakes.ID_EC2_ASSOCIATION_1},
                 'InvalidAssociationID.NotFound')

        # NOTE(ft): registered broken vpc address
        self.set_mock_db_items(fakes.DB_ADDRESS_2)
        self.neutron.show_floatingip.side_effect = neutron_exception.NotFound
        do_check({'AssociationId': fakes.ID_EC2_ASSOCIATION_2},
                 'InvalidAssociationID.NotFound')

        # NOTE(tikitavi): disassociate to wrong public ip
        self.configure(disable_ec2_classic=True)
        self.set_mock_db_items()
        self.assert_execution_error('AuthFailure', 'DisassociateAddress',
                                    {'PublicIp': fakes.IP_ADDRESS_2})

        # NOTE(tikitavi): disassociate to unassociated ip
        self.set_mock_db_items(fakes.DB_ADDRESS_1)
        self.assert_execution_error('InvalidParameterValue',
                                    'DisassociateAddress',
                                    {'PublicIp': fakes.IP_ADDRESS_1})

    @tools.screen_unexpected_exception_logs
    def test_dissassociate_address_vpc_rollback(self):
        self.set_mock_db_items(fakes.DB_ADDRESS_2)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})
        self.neutron.update_floatingip.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'DisassociateAddress',
            {'AssociationId': fakes.ID_EC2_ASSOCIATION_2})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_ADDRESS_2)

    def test_release_address_ec2_classic(self):
        self.set_mock_db_items()
        self.neutron.delete_floatingip.return_value = True
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})

        resp = self.execute('ReleaseAddress',
                            {'PublicIp': fakes.IP_ADDRESS_1})
        self.assertEqual(True, resp['return'])

        self.neutron.delete_floatingip.assert_called_once_with(
            fakes.OS_FLOATING_IP_1['id'])

    def test_release_address_vpc(self):
        self.set_mock_db_items(fakes.DB_ADDRESS_1)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})

        resp = self.execute('ReleaseAddress',
                            {'AllocationId': fakes.ID_EC2_ADDRESS_1})
        self.assertEqual(True, resp['return'])

        self.neutron.delete_floatingip.assert_called_once_with(
            fakes.ID_OS_FLOATING_IP_1)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_ADDRESS_1)

    @mock.patch('ec2api.api.address.AddressEngineNeutron.disassociate_address')
    def test_release_address_default_vpc(self, disassociate_address):
        self.configure(disable_ec2_classic=True)
        self.set_mock_db_items(fakes.DB_VPC_DEFAULT,
                               fakes.DB_ADDRESS_DEFAULT,
                               fakes.DB_NETWORK_INTERFACE_DEFAULT)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})

        resp = self.execute('ReleaseAddress',
                            {'AllocationId': fakes.ID_EC2_ADDRESS_DEFAULT})
        self.assertEqual(True, resp['return'])

        disassociate_address.assert_called_once_with(
            mock.ANY, association_id=fakes.ID_EC2_ASSOCIATION_DEFAULT)
        self.neutron.delete_floatingip.assert_called_once_with(
            fakes.ID_OS_FLOATING_IP_2)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_ADDRESS_DEFAULT)

    def test_release_address_invalid_parameters(self):

        def do_check(params, error):
            self.assert_execution_error(error, 'ReleaseAddress', params)

        do_check({},
                 'MissingParameter')

        do_check({'PublicIp': '0.0.0.0',
                  'AllocationId': 'eipalloc-0'},
                 'InvalidParameterCombination')

        # NOTE(ft): EC2 Classic public IP is not found
        self.neutron.list_floatingips.return_value = {'floatingips': []}
        do_check({'PublicIp': fakes.IP_ADDRESS_1},
                 'AuthFailure')

        # NOTE(ft): vpc address vs public ip parameter
        self.set_mock_db_items(fakes.DB_ADDRESS_1)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        do_check({'PublicIp': fakes.IP_ADDRESS_1},
                 'InvalidParameterValue')

        # NOTE(ft): not registered address
        self.set_mock_db_items()
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1},
                 'InvalidAllocationID.NotFound')

        # NOTE(ft): registered broken vpc address
        self.set_mock_db_items(fakes.DB_ADDRESS_1)
        self.neutron.show_floatingip.side_effect = neutron_exception.NotFound
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1},
                 'InvalidAllocationID.NotFound')
        self.neutron.show_floatingip.side_effect = None

        # NOTE(ft): address is in use
        self.set_mock_db_items(fakes.DB_ADDRESS_2)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_2},
                 'InvalidIPAddress.InUse')

        # NOTE(tikitavi): address is in use in not default vpc
        self.configure(disable_ec2_classic=True)
        self.set_mock_db_items(fakes.DB_VPC_DEFAULT,
                               fakes.DB_VPC_1,
                               fakes.DB_ADDRESS_2,
                               fakes.DB_NETWORK_INTERFACE_2)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})

        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_2},
                 'InvalidIPAddress.InUse')

    @tools.screen_unexpected_exception_logs
    def test_release_address_vpc_rollback(self):
        self.set_mock_db_items(fakes.DB_ADDRESS_1)
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.neutron.delete_floatingip.side_effect = Exception()

        self.assert_execution_error(self.ANY_EXECUTE_ERROR, 'ReleaseAddress',
                                    {'AllocationId': fakes.ID_EC2_ADDRESS_1})

        self.db_api.restore_item.assert_called_once_with(
            mock.ANY, 'eipalloc', fakes.DB_ADDRESS_1)

    def test_describe_addresses_vpc(self):
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1,
                       fakes.OS_PORT_2]})
        self.set_mock_db_items(
            fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2, fakes.DB_INSTANCE_1,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2)

        resp = self.execute('DescribeAddresses', {})
        self.assertThat(resp['addressesSet'],
                        matchers.ListMatches([fakes.EC2_ADDRESS_1,
                                              fakes.EC2_ADDRESS_2]))

        self.db_api.get_items_by_ids = tools.CopyingMock(
            return_value=[fakes.DB_ADDRESS_1])
        resp = self.execute('DescribeAddresses',
                            {'AllocationId.1': fakes.ID_EC2_ADDRESS_1})
        self.assertThat(resp['addressesSet'],
                        matchers.ListMatches([fakes.EC2_ADDRESS_1]))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_ADDRESS_1]))

        self.check_filtering(
             'DescribeAddresses', 'addressesSet',
             [('allocation-id', fakes.ID_EC2_ADDRESS_1),
              ('association-id', fakes.ID_EC2_ASSOCIATION_2),
              ('domain', 'vpc'),
              ('instance-id', fakes.ID_EC2_INSTANCE_1),
              ('network-interface-id', fakes.ID_EC2_NETWORK_INTERFACE_2),
              ('network-interface-owner-id', fakes.ID_OS_PROJECT),
              ('private-ip-address', fakes.IP_NETWORK_INTERFACE_2),
              ('public-ip', fakes.IP_ADDRESS_2)])

    def test_describe_addresses_ec2_classic(self):
        self.set_mock_db_items(fakes.DB_INSTANCE_1)
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1,
                       fakes.OS_PORT_2]})
        resp = self.execute('DescribeAddresses', {})
        self.assertThat(resp['addressesSet'],
                        matchers.ListMatches([fakes.EC2_ADDRESS_CLASSIC_1,
                                              fakes.EC2_ADDRESS_CLASSIC_2]))
        resp = self.execute('DescribeAddresses', {'PublicIp.1':
                                                  fakes.IP_ADDRESS_2})
        self.assertThat(resp['addressesSet'],
                        matchers.ListMatches([fakes.EC2_ADDRESS_CLASSIC_2]))
