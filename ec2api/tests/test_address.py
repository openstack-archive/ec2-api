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

import copy

import mock
from neutronclient.common import exceptions as neutron_exception
from oslo.config import cfg

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class AddressTestCase(base.ApiTestCase):

    def setUp(self):
        super(AddressTestCase, self).setUp()
        id_to_ec2_inst_id_patcher = (
            mock.patch('ec2api.api.ec2utils.id_to_ec2_inst_id'))
        self.id_to_ec2_inst_id = id_to_ec2_inst_id_patcher.start()
        self.addCleanup(id_to_ec2_inst_id_patcher.stop)

    def test_allocate_ec2_classic_address(self):
        self.ec2.allocate_address.return_value = (
            copy.deepcopy(fakes.EC2OS_ADDRESS_1))

        resp = self.execute('AllocateAddress', {})
        self.assertEqual(200, resp['status'])
        self.assertEqual(fakes.IP_ADDRESS_1, resp['publicIp'])
        self.assertEqual('standard', resp['domain'])
        self.assertNotIn('allocationId', resp)
        self.assertEqual(0, self.db_api.add_item.call_count)
        self.ec2.allocate_address.assert_called_once_with()

    def test_allocate_vpc_address(self):
        conf = cfg.CONF
        self.addCleanup(conf.reset)
        conf.set_override('external_network', fakes.NAME_OS_PUBLIC_NETWORK)
        self.neutron.list_networks.return_value = (
            {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.create_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.db_api.add_item.return_value = fakes.DB_ADDRESS_1

        resp = self.execute('AllocateAddress', {'Domain': 'vpc'})

        self.assertEqual(200, resp['status'])
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
        resp = self.execute('AllocateAddress', {'Domain': 'fake_domain'})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidParameterValue', resp['Error']['Code'])
        self.assertEqual(0, self.db_api.add_item.call_count)
        self.assertEqual(0, self.neutron.create_floatingip.call_count)

    @base.skip_not_implemented
    def test_allocate_address_overlimit(self):
        resp = self.execute('AllocateAddress', {})
        self.assertEqual(400, resp['status'])
        self.assertEqual('AddressLimitExceeded', resp['Error']['Code'])
#        AddressLimitExceeded
#        standard - Too many addresses allocated
#        vpc - The maximum number of addresses has been reached.

    def test_allocate_address_vpc_rollback(self):
        conf = cfg.CONF
        self.addCleanup(conf.reset)
        conf.set_override('external_network', fakes.NAME_OS_PUBLIC_NETWORK)
        self.neutron.list_networks.return_value = (
            {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.create_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.db_api.add_item.side_effect = Exception()

        self.execute('AllocateAddress', {'Domain': 'vpc'})

        self.neutron.delete_floatingip.assert_called_once_with(
            fakes.ID_OS_FLOATING_IP_1)

    def test_associate_address_ec2_classic(self):
        self.db_api.get_items.return_value = []
        self.ec2.associate_address.return_value = True

        resp = self.execute('AssociateAddress',
                            {'PublicIp': fakes.IP_ADDRESS_1,
                             'InstanceId': fakes.ID_EC2_INSTANCE_2})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])
        self.assertNotIn('associationId', resp)

        self.ec2.associate_address.assert_called_once_with(
            public_ip=fakes.IP_ADDRESS_1,
            instance_id=fakes.ID_EC2_INSTANCE_2,
            network_interface_id=None, private_ip_address=None,
            allow_reassociation=False)

    def test_associate_address_vpc(self):

        def do_check(params, fixed_ip):
            resp = self.execute('AssociateAddress', params)
            self.assertEqual(200, resp['status'])
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
                     fakes.ID_DB_NETWORK_INTERFACE_2,
                     'private_ip_address': fixed_ip}))

            self.neutron.update_floatingip.reset_mock()
            self.db_api.update_item.reset_mock()

        self.db_api.get_items.return_value = [fakes.DB_NETWORK_INTERFACE_1,
                                              fakes.DB_NETWORK_INTERFACE_2]

        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_ADDRESS_1))
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 fakes.IP_NETWORK_INTERFACE_2)

        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_DB_ADDRESS_1:
                copy.deepcopy(fakes.DB_ADDRESS_1),
                fakes.ID_DB_NETWORK_INTERFACE_2:
                fakes.DB_NETWORK_INTERFACE_2}))
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2},
                 fakes.IP_NETWORK_INTERFACE_2)

        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
                  'PrivateIpAddress': fakes.IP_NETWORK_INTERFACE_2_EXT_1},
                 fakes.IP_NETWORK_INTERFACE_2_EXT_1)

        assigned_db_address_1 = tools.update_dict(
            fakes.DB_ADDRESS_1,
            {'network_interface_id': fakes.ID_DB_NETWORK_INTERFACE_1,
             'private_ip_address': fakes.IP_NETWORK_INTERFACE_1})
        assigned_floating_ip_1 = tools.update_dict(
            fakes.OS_FLOATING_IP_1,
            {'fixed_port_id': fakes.ID_OS_PORT_1,
             'fixed_ip_address': fakes.IP_NETWORK_INTERFACE_1})
        self.neutron.show_floatingip.return_value = (
            {'floatingip': assigned_floating_ip_1})
        self.db_api.get_item_by_id.side_effect = None
        self.db_api.get_item_by_id.return_value = assigned_db_address_1
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1,
                  'AllowReassociation': 'True'},
                 fakes.IP_NETWORK_INTERFACE_2)

    def test_associate_address_vpc_idempotent(self):
        def do_check(params):
            resp = self.execute('AssociateAddress', params)
            self.assertEqual(200, resp['status'])
            self.assertEqual(True, resp['return'])
            self.assertEqual(fakes.ID_EC2_ASSOCIATION_2, resp['associationId'])

        self.db_api.get_items.return_value = [fakes.DB_NETWORK_INTERFACE_1,
                                              fakes.DB_NETWORK_INTERFACE_2]
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(
                {fakes.ID_DB_ADDRESS_2:
                 copy.deepcopy(fakes.DB_ADDRESS_2),
                 fakes.ID_DB_NETWORK_INTERFACE_2:
                 fakes.DB_NETWORK_INTERFACE_2}))
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
            resp = self.execute('AssociateAddress', params)
            self.assertEqual(400, resp['status'])
            self.assertEqual(error, resp['Error']['Code'])

        do_check({},
                 'MissingParameter')

        do_check({'PublicIp': 'fake_ip',
                  'AllocationId': 'fake_allocation_id'},
                 'InvalidParameterCombination')

        do_check({'PublicIp': 'fake_ip'},
                 'MissingParameter')

        do_check({'AllocationId': 'fake_allocation_id'},
                 'MissingParameter')

    def test_associate_address_invalid_ec2_classic_parameters(self):
        # NOTE(ft): ec2 classic instance vs allocation_id parameter
        self.db_api.get_items.return_value = []
        resp = self.execute('AssociateAddress',
                            {'AllocationId': 'fake_allocation_id',
                             'InstanceId': fakes.ID_EC2_INSTANCE_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidParameterCombination', resp['Error']['Code'])

        # NOTE(ft): ec2 classic instance vs vpc public ip
        self.db_api.get_items.side_effect = (
            lambda _, kind: [fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2]
            if kind == 'eipalloc' else [])
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        resp = self.execute('AssociateAddress',
                            {'PublicIp': fakes.IP_ADDRESS_1,
                             'InstanceId': fakes.ID_EC2_INSTANCE_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('AuthFailure', resp['Error']['Code'])

    def test_associate_address_invalid_vpc_parameters(self):
        def do_check(params, error):
            resp = self.execute('AssociateAddress', params)
            self.assertEqual(400, resp['status'])
            self.assertEqual(error, resp['Error']['Code'])

        # NOTE(ft): vpc instance vs public ip parmeter
        self.db_api.get_items.return_value = [fakes.DB_NETWORK_INTERFACE_2]
        do_check({'PublicIp': 'fake_ip',
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidParameterCombination')

        self.db_api.get_item_by_id.return_value = None

        # NOTE(ft): vpc instance vs not registered vpc address
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidAllocationID.NotFound')

        # NOTE(ft): not registered network interface id vs vpc address
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1},
                 'InvalidNetworkInterfaceID.NotFound')

        self.db_api.get_item_by_id.return_value = fakes.DB_ADDRESS_1

        # NOTE(ft): vpc instance vs broken vpc address
        self.neutron.show_floatingip.side_effect = neutron_exception.NotFound
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidAllocationID.NotFound')
        self.neutron.show_floatingip.side_effect = None

        # NOTE(ft): already associated address vs network interface
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(
                {fakes.ID_DB_ADDRESS_2: fakes.DB_ADDRESS_2,
                 fakes.ID_DB_NETWORK_INTERFACE_1:
                 fakes.DB_NETWORK_INTERFACE_1}))
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_2,
                  'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1},
                 'Resource.AlreadyAssociated')

        # NOTE(ft): already associated address vs vpc instance
        self.db_api.get_items.return_value = [
            fakes.gen_db_network_interface(
                fakes.ID_DB_NETWORK_INTERFACE_1,
                fakes.ID_OS_NETWORK_1,
                fakes.ID_DB_VPC_1,
                fakes.ID_DB_SUBNET_1,
                fakes.IP_NETWORK_INTERFACE_1,
                instance_id=fakes.ID_DB_INSTANCE_1)]
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_2,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'Resource.AlreadyAssociated')

        # NOTE(ft): multiple network interfaces in vpc instance
        # w/o network interface selection
        self.db_api.get_items.return_value.append(fakes.DB_NETWORK_INTERFACE_2)
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1,
                  'InstanceId': fakes.ID_EC2_INSTANCE_1},
                 'InvalidInstanceID')

    def test_associate_address_ec2_classic_broken_vpc(self):
        self.db_api.get_items.side_effect = (
            lambda _, kind: [fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2]
            if kind == 'eipalloc' else [])
        self.neutron.show_floatingip.side_effect = neutron_exception.NotFound
        self.ec2.associate_address.return_value = True

        resp = self.execute('AssociateAddress',
                            {'PublicIp': fakes.IP_ADDRESS_1,
                             'InstanceId': fakes.ID_EC2_INSTANCE_2})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])
        self.assertNotIn('associationId', resp)

        self.ec2.associate_address.assert_called_once_with(
            public_ip=fakes.IP_ADDRESS_1,
            instance_id=fakes.ID_EC2_INSTANCE_2,
            network_interface_id=None, private_ip_address=None,
            allow_reassociation=False)

    def test_associate_address_vpc_rollback(self):
        self.db_api.get_items.return_value = [fakes.DB_NETWORK_INTERFACE_1,
                                              fakes.DB_NETWORK_INTERFACE_2]
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_ADDRESS_1))
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.neutron.update_floatingip.side_effect = Exception()

        self.execute('AssociateAddress',
                     {'AllocationId': fakes.ID_EC2_ADDRESS_1,
                      'InstanceId': fakes.ID_EC2_INSTANCE_1})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_ADDRESS_1)

    def test_dissassociate_address_ec2_classic(self):
        self.db_api.get_items.return_value = []
        self.ec2.disassociate_address.return_value = True

        resp = self.execute('DisassociateAddress',
                            {'PublicIp': fakes.IP_ADDRESS_2})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])

        self.ec2.disassociate_address.assert_called_once_with(
            public_ip=fakes.IP_ADDRESS_2)

    def test_dissassociate_address_vpc(self):
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_ADDRESS_2))
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})

        resp = self.execute('DisassociateAddress',
                            {'AssociationId': fakes.ID_EC2_ASSOCIATION_2})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])

        self.neutron.update_floatingip.assert_called_once_with(
            fakes.ID_OS_FLOATING_IP_2,
            {'floatingip': {'port_id': None}})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.purge_dict(fakes.DB_ADDRESS_2, ['network_interface_id',
                                                  'private_ip_address']))

    def test_dissassociate_address_vpc_idempotent(self):
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_ADDRESS_1))
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})

        resp = self.execute('DisassociateAddress',
                            {'AssociationId': fakes.ID_EC2_ASSOCIATION_1})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])

        self.assertEqual(0, self.neutron.update_floatingip.call_count)
        self.assertEqual(0, self.db_api.update_item.call_count)

    def test_disassociate_address_invalid_parameters(self):
        def do_check(params, error):
            resp = self.execute('DisassociateAddress', params)
            self.assertEqual(400, resp['status'])
            self.assertEqual(error, resp['Error']['Code'])

        do_check({},
                 'MissingParameter')

        do_check({'PublicIp': 'fake_ip',
                  'AssociationId': 'fake_allocation_id'},
                 'InvalidParameterCombination')

        # NOTE(ft): vpc address vs public ip parameter
        self.db_api.get_items.return_value = [fakes.DB_ADDRESS_1]
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        do_check({'PublicIp': fakes.IP_ADDRESS_1},
                 'InvalidParameterValue')

        # NOTE(ft): not registered address
        self.db_api.get_item_by_id.return_value = None
        do_check({'AssociationId': fakes.ID_EC2_ASSOCIATION_1},
                 'InvalidAssociationID.NotFound')

        # NOTE(ft): registered broken vpc address
        self.db_api.get_item_by_id.return_value = fakes.DB_ADDRESS_2
        self.neutron.show_floatingip.side_effect = neutron_exception.NotFound
        do_check({'AssociationId': fakes.ID_EC2_ASSOCIATION_2},
                 'InvalidAssociationID.NotFound')

    def test_dissassociate_address_vpc_rollback(self):
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_ADDRESS_2))
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})
        self.neutron.update_floatingip.side_effect = Exception()

        self.execute('DisassociateAddress',
                     {'AssociationId': fakes.ID_EC2_ASSOCIATION_2})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_ADDRESS_2)

    def test_release_address_ec2_classic(self):
        self.db_api.get_items.return_value = []
        self.ec2.release_address.return_value = True

        resp = self.execute('ReleaseAddress',
                            {'PublicIp': fakes.IP_ADDRESS_1})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])

        self.ec2.release_address.assert_called_once_with(
            public_ip=fakes.IP_ADDRESS_1)

    def test_release_address_vpc(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_ADDRESS_1
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})

        resp = self.execute('ReleaseAddress',
                            {'AllocationId': fakes.ID_EC2_ADDRESS_1})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])

        self.neutron.delete_floatingip.assert_called_once_with(
            fakes.ID_OS_FLOATING_IP_1)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_DB_ADDRESS_1)

    def test_release_address_invalid_parameters(self):
        def do_check(params, error):
            resp = self.execute('ReleaseAddress', params)
            self.assertEqual(400, resp['status'])
            self.assertEqual(error, resp['Error']['Code'])

        do_check({},
                 'MissingParameter')

        do_check({'PublicIp': 'fake_ip',
                  'AllocationId': 'fake_allocation_id'},
                 'InvalidParameterCombination')

        # NOTE(ft): vpc address vs public ip parameter
        self.db_api.get_items.return_value = [fakes.DB_ADDRESS_1]
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        do_check({'PublicIp': fakes.IP_ADDRESS_1},
                 'InvalidParameterValue')

        # NOTE(ft): not registered address
        self.db_api.get_item_by_id.return_value = None
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1},
                 'InvalidAllocationID.NotFound')

        # NOTE(ft): registered broken vpc address
        self.db_api.get_item_by_id.return_value = fakes.DB_ADDRESS_1
        self.neutron.show_floatingip.side_effect = neutron_exception.NotFound
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_1},
                 'InvalidAllocationID.NotFound')
        self.neutron.show_floatingip.side_effect = None

        # NOTE(ft): address is in use
        self.db_api.get_item_by_id.return_value = fakes.DB_ADDRESS_2
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_2})
        do_check({'AllocationId': fakes.ID_EC2_ADDRESS_2},
                 'InvalidIPAddress.InUse')

    def test_release_address_vpc_rollback(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_ADDRESS_1
        self.neutron.show_floatingip.return_value = (
            {'floatingip': fakes.OS_FLOATING_IP_1})
        self.neutron.delete_floatingip.side_effect = Exception()

        self.execute('ReleaseAddress',
                     {'AllocationId': fakes.ID_EC2_ADDRESS_1})

        self.db_api.restore_item.assert_called_once_with(
            mock.ANY, 'eipalloc', fakes.DB_ADDRESS_1)

    def test_describe_addresses_vpc(self):
        self.ec2.describe_addresses.return_value = (
            {'addressesSet': [copy.deepcopy(fakes.EC2OS_ADDRESS_1),
                              copy.deepcopy(fakes.EC2OS_ADDRESS_2)]})
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1,
                       fakes.OS_PORT_2]})
        self.db_api.get_items.side_effect = (
            lambda _, kind: [fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2]
            if kind == 'eipalloc' else
            [fakes.DB_NETWORK_INTERFACE_1,
             fakes.DB_NETWORK_INTERFACE_2]
            if kind == 'eni' else [])
        self.id_to_ec2_inst_id.return_value = fakes.ID_EC2_INSTANCE_1

        resp = self.execute('DescribeAddresses', {})
        self.assertEqual(200, resp['status'])
        self.assertThat(resp['addressesSet'],
                        matchers.ListMatches([fakes.EC2_ADDRESS_1,
                                                  fakes.EC2_ADDRESS_2]))
