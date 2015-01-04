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
from neutronclient.common import exceptions as neutron_exception

from ec2api.api import ec2utils
from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class NetworkInterfaceTestCase(base.ApiTestCase):

    def test_create_network_interface(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_SUBNET_1
        self.db_api.add_item.return_value = fakes.DB_NETWORK_INTERFACE_1
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_1}
        self.neutron.create_port.return_value = {'port': fakes.OS_PORT_1}

        def check_response(resp, auto_ips=False):
            self.assertEqual(200, resp['http_status_code'])
            self.assertThat(fakes.EC2_NETWORK_INTERFACE_1,
                            matchers.DictMatches(resp['networkInterface']))
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'eni',
                tools.purge_dict(fakes.DB_NETWORK_INTERFACE_1, ('id',)))
            if auto_ips:
                self.neutron.create_port.assert_called_once_with(
                    {'port':
                        {'network_id': fakes.OS_SUBNET_1['network_id'],
                         'fixed_ips':
                            [{'subnet_id': fakes.ID_OS_SUBNET_1}],
                         'security_groups': []}})
            else:
                self.neutron.create_port.assert_called_once_with(
                    {'port':
                        {'network_id': fakes.OS_SUBNET_1['network_id'],
                         'fixed_ips':
                            [{'ip_address': fakes.IP_NETWORK_INTERFACE_1}],
                         'security_groups': []}})
            self.neutron.update_port.assert_called_once_with(
                fakes.ID_OS_PORT_1,
                {'port': {'name':
                          fakes.ID_EC2_NETWORK_INTERFACE_1}})
            self.neutron.reset_mock()
            self.db_api.reset_mock()

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'PrivateIpAddress':
             fakes.EC2_NETWORK_INTERFACE_1['privateIpAddress'],
                 'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_1})
        check_response(resp)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'PrivateIpAddresses.1.PrivateIpAddress':
                 fakes.EC2_NETWORK_INTERFACE_1['privateIpAddress'],
                 'PrivateIpAddresses.1.Primary': True,
                 'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_1})
        check_response(resp)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_1})
        check_response(resp, True)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'SecondaryPrivateIpAddressCount': '1',
             'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_1})
        check_response(resp, True)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'SecondaryPrivateIpAddressCount': '0',
             'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_1})
        check_response(resp, True)

    def test_create_network_interface_multiple_ips(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_SUBNET_2
        self.db_api.add_item.return_value = fakes.DB_NETWORK_INTERFACE_2
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_2}
        self.neutron.create_port.return_value = {'port': fakes.OS_PORT_2}
        created_ec2_network_interface = tools.patch_dict(
            fakes.EC2_NETWORK_INTERFACE_2,
            {'privateIpAddressesSet': [
                tools.purge_dict(s, ['association'])
                for s in fakes.EC2_NETWORK_INTERFACE_2[
                    'privateIpAddressesSet']]},
            ['association'])

        def check_response(resp):
            self.assertEqual(200, resp['http_status_code'])
            self.assertThat(created_ec2_network_interface,
                            matchers.DictMatches(resp['networkInterface']))
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'eni',
                tools.purge_dict(fakes.DB_NETWORK_INTERFACE_2,
                                 ('id',
                                  'instance_id',
                                  'delete_on_termination',
                                  'attach_time')))
            self.neutron.update_port.assert_called_once_with(
                fakes.ID_OS_PORT_2,
                {'port': {'name':
                          fakes.ID_EC2_NETWORK_INTERFACE_2}})
            self.neutron.reset_mock()
            self.db_api.reset_mock()

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_2,
             'SecondaryPrivateIpAddressCount': '3',
             'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_2})
        self.neutron.create_port.assert_called_once_with(
            {'port': {'network_id': fakes.OS_SUBNET_2['network_id'],
                      'fixed_ips': [
                {'subnet_id': fakes.ID_OS_SUBNET_2},
                {'subnet_id': fakes.ID_OS_SUBNET_2},
                {'subnet_id': fakes.ID_OS_SUBNET_2}],
                'security_groups': []}})
        check_response(resp)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_2,
             'PrivateIpAddress':
             fakes.IPS_NETWORK_INTERFACE_2[0],
                 'PrivateIpAddresses.1.PrivateIpAddress':
                     fakes.IPS_NETWORK_INTERFACE_2[1],
                 'PrivateIpAddresses.1.Primary': False,
                 'PrivateIpAddresses.2.PrivateIpAddress':
                     fakes.IPS_NETWORK_INTERFACE_2[2],
                 'PrivateIpAddresses.2.Primary': False,
                 'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_2})
        self.neutron.create_port.assert_called_once_with(
            {'port':
             {'network_id': fakes.OS_SUBNET_2['network_id'],
              'fixed_ips': [
                 {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[0]},
                 {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[1]},
                 {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[2]}],
              'security_groups': []}})
        check_response(resp)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_2,
             'PrivateIpAddresses.1.PrivateIpAddress':
             fakes.IPS_NETWORK_INTERFACE_2[0],
                 'PrivateIpAddresses.1.Primary': True,
                 'PrivateIpAddresses.2.PrivateIpAddress':
                     fakes.IPS_NETWORK_INTERFACE_2[1],
                 'PrivateIpAddresses.2.Primary': False,
                 'PrivateIpAddresses.3.PrivateIpAddress':
                     fakes.IPS_NETWORK_INTERFACE_2[2],
                 'PrivateIpAddresses.3.Primary': False,
                 'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_2})
        self.neutron.create_port.assert_called_once_with(
            {'port':
             {'network_id': fakes.OS_SUBNET_2['network_id'],
              'fixed_ips': [
                 {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[0]},
                 {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[1]},
                 {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[2]}],
              'security_groups': []}})
        check_response(resp)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_2,
             'PrivateIpAddress':
             fakes.IPS_NETWORK_INTERFACE_2[0],
                 'PrivateIpAddresses.1.PrivateIpAddress':
                     fakes.IPS_NETWORK_INTERFACE_2[1],
                 'PrivateIpAddresses.1.Primary': False,
                 'SecondaryPrivateIpAddressCount': '1',
                 'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_2})
        self.neutron.create_port.assert_called_once_with(
            {'port':
             {'network_id': fakes.OS_SUBNET_2['network_id'],
              'fixed_ips': [
                 {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[0]},
                 {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[1]},
                 {'subnet_id': fakes.ID_OS_SUBNET_2}],
              'security_groups': []}})
        check_response(resp)

    def test_create_network_interface_invalid_parameters(self):
        def check_response(resp, error_code):
            self.assertEqual(400, resp['http_status_code'])
            self.assertEqual(error_code, resp['Error']['Code'])
            self.assertEqual(0, self.neutron.create_port.call_count)
            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.db_api.get_item_by_id.return_value = None
        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_2})
        self.db_api.get_item_by_id.assert_called_once_with(
            mock.ANY, 'subnet', fakes.ID_EC2_SUBNET_2)
        check_response(resp, 'InvalidSubnetID.NotFound')

        self.db_api.get_item_by_id.return_value = fakes.DB_SUBNET_1
        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'PrivateIpAddress':
             fakes.EC2_NETWORK_INTERFACE_2['privateIpAddress']})
        check_response(resp, 'InvalidParameterValue')

        self.neutron.side_effect = (
            neutron_exception.NeutronClientException())
        self.neutron.create_port.return_value = {'port': fakes.OS_PORT_1}
        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'PrivateIpAddress':
             fakes.EC2_NETWORK_INTERFACE_1['privateIpAddress']})
        check_response(resp, 'InvalidParameterValue')

    @mock.patch('ec2api.api.dhcp_options._add_dhcp_opts_to_port')
    def test_create_network_interface_rollback(self, _add_dhcp_opts_to_port):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_VPC_1: tools.update_dict(
                    fakes.DB_VPC_1,
                    {'dhcp_options_id':
                     fakes.ID_EC2_DHCP_OPTIONS_1}),
                fakes.ID_EC2_SUBNET_1: fakes.DB_SUBNET_1,
                fakes.ID_EC2_DHCP_OPTIONS_1: fakes.DB_DHCP_OPTIONS_1}))
        self.db_api.add_item.return_value = fakes.DB_NETWORK_INTERFACE_1
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_1}
        self.neutron.create_port.return_value = {'port': fakes.OS_PORT_1}
        _add_dhcp_opts_to_port.side_effect = Exception()

        self.execute('CreateNetworkInterface',
                     {'SubnetId': fakes.ID_EC2_SUBNET_1})

        self.neutron.delete_port.assert_called_once_with(fakes.ID_OS_PORT_1)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_NETWORK_INTERFACE_1)

    def test_delete_network_interface(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_NETWORK_INTERFACE_1
        self.db_api.get_items.return_value = []
        resp = self.execute(
            'DeleteNetworkInterface',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_has_call(
            mock.ANY,
            fakes.ID_EC2_NETWORK_INTERFACE_1)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY,
            fakes.ID_EC2_NETWORK_INTERFACE_1)
        self.neutron.delete_port.assert_called_once_with(
            fakes.ID_OS_PORT_1)

    def test_delete_network_interface_no_network_interface(self):
        self.db_api.get_item_by_id.return_value = None
        resp = self.execute(
            'DeleteNetworkInterface',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidNetworkInterfaceID.NotFound',
                         resp['Error']['Code'])
        self.assertEqual(0, self.neutron.delete_port.call_count)

    def test_delete_network_interface_is_in_use(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_NETWORK_INTERFACE_2
        resp = self.execute(
            'DeleteNetworkInterface',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_2})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidParameterValue', resp['Error']['Code'])
        self.assertEqual(0, self.neutron.delete_port.call_count)

    def test_delete_network_interface_with_public_ip(self):
        detached_network_interface_2 = fakes.gen_db_network_interface(
            fakes.ID_EC2_NETWORK_INTERFACE_2,
            fakes.ID_OS_PORT_2,
            fakes.ID_EC2_VPC_1,
            fakes.ID_EC2_SUBNET_2,
            fakes.IP_NETWORK_INTERFACE_2)
        self.db_api.get_item_by_id.return_value = detached_network_interface_2
        self.db_api.get_items.return_value = (
            [fakes.DB_ADDRESS_1,
             copy.deepcopy(fakes.DB_ADDRESS_2)])
        resp = self.execute(
            'DeleteNetworkInterface',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_has_call(
            mock.ANY,
            fakes.ID_EC2_NETWORK_INTERFACE_1)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY,
            fakes.ID_EC2_NETWORK_INTERFACE_2)
        self.neutron.delete_port.assert_called_once_with(
            fakes.ID_OS_PORT_2)
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.purge_dict(fakes.DB_ADDRESS_2,
                             ['network_interface_id',
                              'private_ip_address']))

    def test_delete_network_interface_rollback(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_NETWORK_INTERFACE_1
        self.db_api.get_items.return_value = []
        self.neutron.delete_port.side_effect = Exception()

        self.execute('DeleteNetworkInterface',
                     {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1})

        self.db_api.restore_item.assert_called_once_with(
            mock.ANY, 'eni', fakes.DB_NETWORK_INTERFACE_1)

    def test_describe_network_interfaces(self):
        self.db_api.get_items.side_effect = (
            lambda _, kind: [fakes.DB_NETWORK_INTERFACE_1,
                             fakes.DB_NETWORK_INTERFACE_2]
            if kind == 'eni' else
            [fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2]
            if kind == 'eipalloc' else [])
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})

        resp = self.execute('DescribeNetworkInterfaces', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertThat(resp['networkInterfaceSet'],
                        matchers.ListMatches(
                            [fakes.EC2_NETWORK_INTERFACE_1,
                             fakes.EC2_NETWORK_INTERFACE_2]))

    def test_describe_network_interface_attribute(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_NETWORK_INTERFACE_1

        resp = self.execute(
            'DescribeNetworkInterfaceAttribute',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Attribute': 'description'})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual(fakes.ID_EC2_NETWORK_INTERFACE_1,
                         resp['networkInterfaceId'])
        self.assertEqual(fakes.DESCRIPTION_NETWORK_INTERFACE_1,
                         resp['description'].get('value', None))

    def test_modify_network_interface_attribute(self):
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_NETWORK_INTERFACE_1))

        resp = self.execute(
            'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Description.Value': 'New description'})
        self.assertEqual(200, resp['http_status_code'])
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.update_dict(fakes.DB_NETWORK_INTERFACE_1,
                              {'description': 'New description'}))

    def test_modify_network_interface_attribute_invalid_parameters(self):
        resp = self.execute(
            'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Description.Value': 'New description',
             'SourceDestCheck.Value': 'True'})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidParameterCombination',
                         resp['Error']['Code'])

    def test_reset_network_interface_attribute(self):
        resp = self.execute(
            'ResetNetworkInterfaceAttribute',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Attribute': 'sourceDestCheck'})
        self.assertEqual(200, resp['http_status_code'])

    def test_attach_network_interface(self):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_NETWORK_INTERFACE_2: fakes.DB_NETWORK_INTERFACE_2,
                fakes.ID_EC2_INSTANCE_1: fakes.DB_INSTANCE_1}))
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_2]})
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE
        resp = self.execute(
            'AttachNetworkInterface',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_2,
             'InstanceId': fakes.ID_EC2_INSTANCE_1,
             'DeviceIndex': '1'})
        self.assertEqual(200, resp['http_status_code'])
        self.nova_servers.interface_attach.assert_called_once_with(
            fakes.ID_OS_INSTANCE_1, fakes.ID_OS_PORT_2, None, None)
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.update_dict(fakes.DB_NETWORK_INTERFACE_2,
                              {'instance_id': fakes.ID_EC2_INSTANCE_1,
                               'delete_on_termination': False}))

    def test_attach_network_interface_rollback(self):
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_NETWORK_INTERFACE_2))
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_2]})
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE
        self.nova_servers.interface_attach.side_effect = Exception()

        self.execute('AttachNetworkInterface',
                     {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
                      'InstanceId': fakes.ID_EC2_INSTANCE_1,
                      'DeviceIndex': '1'})

        self.db_api.update_item.assert_has_call(
            mock.ANY, fakes.DB_NETWORK_INTERFACE_2)

    def test_detach_network_interface(self):
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_NETWORK_INTERFACE_2))
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_2]})
        resp = self.execute(
            'DetachNetworkInterface',
            {'AttachmentId': ec2utils.change_ec2_id_kind(
                    fakes.ID_EC2_NETWORK_INTERFACE_2, 'eni-attach')})
        self.assertEqual(200, resp['http_status_code'])
        self.neutron.update_port.assert_called_once_with(
            fakes.ID_OS_PORT_2,
            {'port': {'device_id': '',
                      'device_owner': ''}}
        )
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.purge_dict(fakes.DB_NETWORK_INTERFACE_2,
                             {'instance_id',
                              'delete_on_termination',
                              'attach_time'}))

    def test_detach_network_interface_rollback(self):
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_NETWORK_INTERFACE_2))
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_2]})
        self.neutron.update_port.side_effect = Exception()

        self.execute(
            'DetachNetworkInterface',
            {'AttachmentId': fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_NETWORK_INTERFACE_2)

    def test_assign_unassign_private_ip_addresses(self):
        self.db_api.get_item_by_id.return_value = (
            copy.deepcopy(fakes.DB_NETWORK_INTERFACE_1))
        self.db_api.get_items.return_value = (
            [fakes.DB_SUBNET_1,
             fakes.DB_SUBNET_2])
        self.neutron.show_subnet.return_value = (
            {'subnet': fakes.OS_SUBNET_1})
        self.neutron.show_port.return_value = (
            {'port': copy.deepcopy(fakes.OS_PORT_1)})
        resp = self.execute(
            'AssignPrivateIpAddresses',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1,
             'PrivateIpAddress.1': '10.10.1.5',
             'PrivateIpAddress.2': '10.10.1.6',
            })
        self.assertEqual(200, resp['http_status_code'])
        self.neutron.update_port.assert_called_once_with(
            fakes.ID_OS_PORT_1,
            {'port':
             {'fixed_ips': [
                 {'subnet_id': fakes.ID_OS_SUBNET_1,
                  'ip_address': fakes.IP_NETWORK_INTERFACE_1},
                 {'ip_address': '10.10.1.5'},
                 {'ip_address': '10.10.1.6'}]}})
        resp = self.execute(
            'UnassignPrivateIpAddresses',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1,
             'PrivateIpAddress.1': '10.10.1.5',
             'PrivateIpAddress.2': '10.10.1.6',
            })
        self.assertEqual(200, resp['http_status_code'])
        self.neutron.update_port.assert_any_call(
            fakes.ID_OS_PORT_1,
            {'port':
             {'fixed_ips': [
                 {'subnet_id': fakes.ID_OS_SUBNET_1,
                  'ip_address': fakes.IP_NETWORK_INTERFACE_1}]}})
