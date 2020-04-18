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

from ec2api.api import ec2utils
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class NetworkInterfaceTestCase(base.ApiTestCase):

    def test_create_network_interface(self):
        self.set_mock_db_items(fakes.DB_SUBNET_1, fakes.DB_VPC_1,
                               fakes.DB_SECURITY_GROUP_1)
        self.db_api.add_item.return_value = fakes.DB_NETWORK_INTERFACE_1
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_1}
        self.neutron.create_port.return_value = {'port': fakes.OS_PORT_1}
        self.neutron.list_security_groups.return_value = (
            {'security_groups': [copy.deepcopy(fakes.OS_SECURITY_GROUP_1)]})

        def check_response(resp, auto_ips=False):
            self.assertThat(fakes.EC2_NETWORK_INTERFACE_1,
                            matchers.DictMatches(resp['networkInterface']))
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'eni',
                tools.purge_dict(fakes.DB_NETWORK_INTERFACE_1, ('id',)))
            if auto_ips:
                self.neutron.create_port.assert_called_once_with(
                    {'port':
                        {'network_id': fakes.ID_OS_NETWORK_1,
                         'fixed_ips':
                            [{'subnet_id': fakes.ID_OS_SUBNET_1}],
                         'security_groups': [fakes.ID_OS_SECURITY_GROUP_1]}})
            else:
                self.neutron.create_port.assert_called_once_with(
                    {'port':
                        {'network_id': fakes.ID_OS_NETWORK_1,
                         'fixed_ips':
                            [{'ip_address': fakes.IP_NETWORK_INTERFACE_1}],
                         'security_groups': [fakes.ID_OS_SECURITY_GROUP_1]}})
            self.neutron.update_port.assert_called_once_with(
                fakes.ID_OS_PORT_1,
                {'port': {'name':
                          fakes.ID_EC2_NETWORK_INTERFACE_1}})
            self.neutron.reset_mock()
            self.db_api.reset_mock()
            self.neutron.list_security_groups.return_value = (
                {'security_groups': [
                    copy.deepcopy(fakes.OS_SECURITY_GROUP_1)]})

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'PrivateIpAddress': fakes.IP_NETWORK_INTERFACE_1,
             'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_1})
        check_response(resp)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_1,
             'PrivateIpAddresses.1.PrivateIpAddress': (
                    fakes.IP_NETWORK_INTERFACE_1),
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
        self.set_mock_db_items(fakes.DB_SUBNET_2, fakes.DB_VPC_1,
                               fakes.DB_SECURITY_GROUP_1)
        self.db_api.add_item.return_value = fakes.DB_NETWORK_INTERFACE_2
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_2}
        self.neutron.create_port.return_value = {'port': fakes.OS_PORT_2}
        self.neutron.list_security_groups.return_value = (
            {'security_groups': [copy.deepcopy(fakes.OS_SECURITY_GROUP_1)]})
        created_ec2_network_interface = tools.patch_dict(
            fakes.EC2_NETWORK_INTERFACE_2,
            {'privateIpAddressesSet': [
                tools.purge_dict(s, ['association'])
                for s in fakes.EC2_NETWORK_INTERFACE_2[
                    'privateIpAddressesSet']]},
            ['association'])

        def check_response(resp):
            self.assertThat(created_ec2_network_interface,
                            matchers.DictMatches(resp['networkInterface']))
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'eni',
                tools.purge_dict(fakes.DB_NETWORK_INTERFACE_2,
                                 ('id',
                                  'device_index',
                                  'instance_id',
                                  'delete_on_termination',
                                  'attach_time')))
            self.neutron.update_port.assert_called_once_with(
                fakes.ID_OS_PORT_2,
                {'port': {'name':
                          fakes.ID_EC2_NETWORK_INTERFACE_2}})
            self.neutron.reset_mock()
            self.db_api.reset_mock()
            self.neutron.list_security_groups.return_value = (
                {'security_groups': [
                    copy.deepcopy(fakes.OS_SECURITY_GROUP_1)]})

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_2,
             'SecondaryPrivateIpAddressCount': '3',
             'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_2})
        self.neutron.create_port.assert_called_once_with(
            {'port': {'network_id': fakes.ID_OS_NETWORK_2,
                      'fixed_ips': [{'subnet_id': fakes.ID_OS_SUBNET_2},
                                    {'subnet_id': fakes.ID_OS_SUBNET_2},
                                    {'subnet_id': fakes.ID_OS_SUBNET_2}],
                      'security_groups': [fakes.ID_OS_SECURITY_GROUP_1]}})
        check_response(resp)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_2,
             'PrivateIpAddress': fakes.IPS_NETWORK_INTERFACE_2[0],
             'PrivateIpAddresses.1.PrivateIpAddress':
                 fakes.IPS_NETWORK_INTERFACE_2[1],
             'PrivateIpAddresses.1.Primary': False,
             'PrivateIpAddresses.2.PrivateIpAddress':
                 fakes.IPS_NETWORK_INTERFACE_2[2],
             'PrivateIpAddresses.2.Primary': False,
             'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_2})
        self.neutron.create_port.assert_called_once_with(
            {'port':
             {'network_id': fakes.ID_OS_NETWORK_2,
              'fixed_ips': [
                  {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[0]},
                  {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[1]},
                  {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[2]}],
              'security_groups': [fakes.ID_OS_SECURITY_GROUP_1]}})
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
             {'network_id': fakes.ID_OS_NETWORK_2,
              'fixed_ips': [
                  {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[0]},
                  {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[1]},
                  {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[2]}],
              'security_groups': [fakes.ID_OS_SECURITY_GROUP_1]}})
        check_response(resp)

        resp = self.execute(
            'CreateNetworkInterface',
            {'SubnetId': fakes.ID_EC2_SUBNET_2,
             'PrivateIpAddress': fakes.IPS_NETWORK_INTERFACE_2[0],
             'PrivateIpAddresses.1.PrivateIpAddress':
                 fakes.IPS_NETWORK_INTERFACE_2[1],
             'PrivateIpAddresses.1.Primary': False,
             'SecondaryPrivateIpAddressCount': '1',
             'Description': fakes.DESCRIPTION_NETWORK_INTERFACE_2})
        self.neutron.create_port.assert_called_once_with(
            {'port':
             {'network_id': fakes.ID_OS_NETWORK_2,
              'fixed_ips': [
                  {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[0]},
                  {'ip_address': fakes.IPS_NETWORK_INTERFACE_2[1]},
                  {'subnet_id': fakes.ID_OS_SUBNET_2}],
              'security_groups': [fakes.ID_OS_SECURITY_GROUP_1]}})
        check_response(resp)

    def test_create_network_interface_invalid_parameters(self):
        def do_check(args, error_code):
            self.neutron.reset_mock()
            self.db_api.reset_mock()
            self.assert_execution_error(
                error_code, 'CreateNetworkInterface', args)

        self.set_mock_db_items()
        do_check({'SubnetId': fakes.ID_EC2_SUBNET_2},
                 'InvalidSubnetID.NotFound')
        self.db_api.get_item_by_id.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_SUBNET_2)

        self.set_mock_db_items(fakes.DB_SUBNET_1, fakes.DB_VPC_1)
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_1}
        do_check({'SubnetId': fakes.ID_EC2_SUBNET_1,
                  'PrivateIpAddress': fakes.IP_NETWORK_INTERFACE_2},
                 'InvalidParameterValue')

        for cls in [neutron_exception.OverQuotaClient,
                    neutron_exception.IpAddressGenerationFailureClient]:
            self.neutron.create_port.side_effect = cls()
            do_check({'SubnetId': fakes.ID_EC2_SUBNET_1,
                      'PrivateIpAddress': fakes.IP_NETWORK_INTERFACE_1},
                     'InsufficientFreeAddressesInSubnet')

        for cls in [neutron_exception.IpAddressInUseClient,
                    neutron_exception.BadRequest]:
            self.neutron.create_port.side_effect = cls()
            do_check({'SubnetId': fakes.ID_EC2_SUBNET_1,
                      'PrivateIpAddress': fakes.IP_NETWORK_INTERFACE_1},
                     'InvalidParameterValue')

    @tools.screen_unexpected_exception_logs
    @mock.patch('ec2api.api.dhcp_options._add_dhcp_opts_to_port')
    def test_create_network_interface_rollback(self, _add_dhcp_opts_to_port):
        self.set_mock_db_items(
            tools.update_dict(
                fakes.DB_VPC_1,
                {'dhcp_options_id': fakes.ID_EC2_DHCP_OPTIONS_1}),
            fakes.DB_SUBNET_1, fakes.DB_DHCP_OPTIONS_1)
        self.db_api.add_item.return_value = fakes.DB_NETWORK_INTERFACE_1
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_1}
        self.neutron.create_port.return_value = {'port': fakes.OS_PORT_1}
        _add_dhcp_opts_to_port.side_effect = Exception()

        self.assert_execution_error(self.ANY_EXECUTE_ERROR,
                                    'CreateNetworkInterface',
                                    {'SubnetId': fakes.ID_EC2_SUBNET_1})

        self.neutron.delete_port.assert_called_once_with(fakes.ID_OS_PORT_1)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_NETWORK_INTERFACE_1)

    def test_delete_network_interface(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1)
        resp = self.execute(
            'DeleteNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1})
        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_any_call(
            mock.ANY,
            fakes.ID_EC2_NETWORK_INTERFACE_1)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY,
            fakes.ID_EC2_NETWORK_INTERFACE_1)
        self.neutron.delete_port.assert_called_once_with(
            fakes.ID_OS_PORT_1)

    def test_delete_network_interface_obsolete(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1)
        self.neutron.delete_port.side_effect = (
            neutron_exception.PortNotFoundClient())
        resp = self.execute(
            'DeleteNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1})
        self.assertEqual(True, resp['return'])

    def test_delete_network_interface_no_network_interface(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidNetworkInterfaceID.NotFound', 'DeleteNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1})
        self.assertEqual(0, self.neutron.delete_port.call_count)

    def test_delete_network_interface_is_in_use(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_2)
        self.assert_execution_error(
            'InvalidParameterValue', 'DeleteNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2})
        self.assertEqual(0, self.neutron.delete_port.call_count)

    def test_delete_network_interface_with_public_ip(self):
        detached_network_interface_2 = fakes.gen_db_network_interface(
            fakes.ID_EC2_NETWORK_INTERFACE_2,
            fakes.ID_OS_PORT_2,
            fakes.ID_EC2_VPC_1,
            fakes.ID_EC2_SUBNET_2,
            fakes.IP_NETWORK_INTERFACE_2)
        self.set_mock_db_items(detached_network_interface_2,
                               fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2)
        resp = self.execute(
            'DeleteNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2})
        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_any_call(
            mock.ANY,
            fakes.ID_EC2_NETWORK_INTERFACE_2)
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

    @tools.screen_unexpected_exception_logs
    def test_delete_network_interface_rollback(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1)
        self.neutron.delete_port.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'DeleteNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1})

        self.db_api.restore_item.assert_called_once_with(
            mock.ANY, 'eni', fakes.DB_NETWORK_INTERFACE_1)

    def test_describe_network_interfaces(self):
        self.set_mock_db_items(
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2,
            fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2,
            fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2,
            fakes.DB_SECURITY_GROUP_1)
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})
        self.neutron.list_security_groups.return_value = (
            {'security_groups': [copy.deepcopy(fakes.OS_SECURITY_GROUP_1)]})

        resp = self.execute('DescribeNetworkInterfaces', {})
        self.assertThat(resp['networkInterfaceSet'],
                        matchers.ListMatches(
                            [fakes.EC2_NETWORK_INTERFACE_1,
                             fakes.EC2_NETWORK_INTERFACE_2],
                            orderless_lists=True),
                        verbose=True)

        self.db_api.get_items_by_ids = tools.CopyingMock(
            return_value=[fakes.DB_NETWORK_INTERFACE_1])
        resp = self.execute(
            'DescribeNetworkInterfaces',
            {'NetworkInterfaceId.1': fakes.ID_EC2_NETWORK_INTERFACE_1})
        self.assertThat(resp['networkInterfaceSet'],
                        matchers.ListMatches(
                            [fakes.EC2_NETWORK_INTERFACE_1]))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_NETWORK_INTERFACE_1]))

        self.check_filtering(
            'DescribeNetworkInterfaces', 'networkInterfaceSet',
            [('addresses.private-ip-address',
              fakes.IP_NETWORK_INTERFACE_2_EXT_1,),
             ('addresses.primary', False),
             ('addresses.association.public-ip', fakes.IP_ADDRESS_2),
             ('addresses.association.owner-id', fakes.ID_OS_PROJECT),
             ('association.association-id', fakes.ID_EC2_ASSOCIATION_2),
             ('association.allocation-id', fakes.ID_EC2_ADDRESS_2),
             ('association.ip-owner-id', fakes.ID_OS_PROJECT),
             ('association.public-ip', fakes.IP_ADDRESS_2),
             ('attachment.attachment-id',
              fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH),
             ('attachment.instance-id', fakes.ID_EC2_INSTANCE_1),
             ('attachment.instance-owner-id', fakes.ID_OS_PROJECT),
             ('attachment.device-index', 0),
             ('attachment.status', 'attached'),
             ('attachment.attach.time', fakes.TIME_ATTACH_NETWORK_INTERFACE),
             ('attachment.delete-on-termination', False),
             ('description', fakes.DESCRIPTION_NETWORK_INTERFACE_1),
             ('group-id', fakes.ID_EC2_SECURITY_GROUP_1),
             ('group-name', fakes.NAME_DEFAULT_OS_SECURITY_GROUP),
             ('mac-address', fakes.MAC_ADDRESS),
             ('network-interface-id', fakes.ID_EC2_NETWORK_INTERFACE_1),
             ('owner-id', fakes.ID_OS_PROJECT),
             ('private-ip-address', fakes.IP_NETWORK_INTERFACE_1),
             ('requester-managed', False),
             ('source-dest-check', True),
             ('status', 'available'),
             ('vpc-id', fakes.ID_EC2_VPC_1),
             ('subnet-id', fakes.ID_EC2_SUBNET_2)])
        self.check_tag_support(
            'DescribeNetworkInterfaces', 'networkInterfaceSet',
            fakes.ID_EC2_NETWORK_INTERFACE_1, 'networkInterfaceId')

    def test_describe_network_interface_attribute(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1)

        resp = self.execute(
            'DescribeNetworkInterfaceAttribute',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Attribute': 'description'})
        self.assertEqual(fakes.ID_EC2_NETWORK_INTERFACE_1,
                         resp['networkInterfaceId'])
        self.assertEqual(fakes.DESCRIPTION_NETWORK_INTERFACE_1,
                         resp['description'].get('value', None))

    def test_modify_network_interface_attribute(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1,
                               fakes.DB_NETWORK_INTERFACE_2)

        self.execute(
            'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Description.Value': 'New description'})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.update_dict(fakes.DB_NETWORK_INTERFACE_1,
                              {'description': 'New description'}))

        self.db_api.reset_mock()
        self.execute(
            'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
             'Attachment.AttachmentId': (
                 fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH),
             'Attachment.DeleteOnTermination': 'True'})
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.update_dict(fakes.DB_NETWORK_INTERFACE_2,
                              {'delete_on_termination': True}))

    def test_modify_network_interface_attribute_invalid_parameters(self):
        self.assert_execution_error(
            'InvalidParameterCombination', 'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Description.Value': 'New description',
             'SourceDestCheck.Value': 'True'})

        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1,
                               fakes.DB_NETWORK_INTERFACE_2)

        self.assert_execution_error(
            'MissingParameter', 'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
             'Attachment.DeleteOnTermination': 'True'})

        self.assert_execution_error(
            'MissingParameter', 'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
             'Attachment.AttachmentId': (
                 fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH)})

        self.assert_execution_error(
            'InvalidAttachmentID.NotFound', 'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Attachment.AttachmentId': (
                 fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH),
             'Attachment.DeleteOnTermination': 'True'})

        self.assert_execution_error(
            'InvalidAttachmentID.NotFound', 'ModifyNetworkInterfaceAttribute',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
             'Attachment.AttachmentId': ec2utils.change_ec2_id_kind(
                 fakes.ID_EC2_NETWORK_INTERFACE_1, 'eni-attach'),
             'Attachment.DeleteOnTermination': 'True'})

    def test_reset_network_interface_attribute(self):
        self.execute(
            'ResetNetworkInterfaceAttribute',
            {'NetworkInterfaceId':
             fakes.ID_EC2_NETWORK_INTERFACE_1,
             'Attribute': 'sourceDestCheck'})

    def test_attach_network_interface(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1,
                               fakes.DB_INSTANCE_1)
        self.neutron.show_port.return_value = (
            {'port': fakes.OS_PORT_1})
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE
        self.execute(
            'AttachNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'InstanceId': fakes.ID_EC2_INSTANCE_1,
             'DeviceIndex': '1'})
        self.nova.servers.interface_attach.assert_called_once_with(
            fakes.ID_OS_INSTANCE_1, fakes.ID_OS_PORT_1, None, None)
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.update_dict(
                fakes.DB_NETWORK_INTERFACE_1,
                {'device_index': 1,
                 'instance_id': fakes.ID_EC2_INSTANCE_1,
                 'delete_on_termination': False,
                 'attach_time': fakes.TIME_ATTACH_NETWORK_INTERFACE}))

    def test_attach_network_interface_invalid_parameters(self):
        # NOTE(ft): eni is already attached
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_2)
        self.assert_execution_error(
            'InvalidParameterValue', 'AttachNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
             'InstanceId': fakes.ID_EC2_INSTANCE_2,
             'DeviceIndex': '1'})

        # NOTE(ft): device index is in use
        self.set_mock_db_items(
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2,
            fakes.DB_INSTANCE_1)
        self.assert_execution_error(
            'InvalidParameterValue', 'AttachNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'InstanceId': fakes.ID_EC2_INSTANCE_1,
             'DeviceIndex': '0'})

    @tools.screen_unexpected_exception_logs
    def test_attach_network_interface_rollback(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1,
                               fakes.DB_INSTANCE_1)
        self.neutron.show_port.return_value = (
            {'port': fakes.OS_PORT_2})
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE
        self.nova.servers.interface_attach.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'AttachNetworkInterface',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'InstanceId': fakes.ID_EC2_INSTANCE_1,
             'DeviceIndex': '1'})

        self.db_api.update_item.assert_any_call(
            mock.ANY, fakes.DB_NETWORK_INTERFACE_1)

    def test_detach_network_interface(self):
        network_interface = tools.update_dict(fakes.DB_NETWORK_INTERFACE_2,
                                              {'device_index': 1})
        self.set_mock_db_items(network_interface)
        self.neutron.show_port.return_value = (
            {'port': fakes.OS_PORT_2})
        self.execute(
            'DetachNetworkInterface',
            {'AttachmentId': ec2utils.change_ec2_id_kind(
                    fakes.ID_EC2_NETWORK_INTERFACE_2, 'eni-attach')})
        self.neutron.update_port.assert_called_once_with(
            fakes.ID_OS_PORT_2,
            {'port': {'device_id': '',
                      'device_owner': ''}}
        )
        self.db_api.update_item.assert_called_once_with(
            mock.ANY,
            tools.purge_dict(fakes.DB_NETWORK_INTERFACE_2,
                             {'device_index',
                              'instance_id',
                              'delete_on_termination',
                              'attach_time'}))

    def test_detach_network_interface_invalid_parameters(self):
        # NOTE(ft): eni is not found
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidAttachmentID.NotFound', 'DetachNetworkInterface',
            {'AttachmentId': ec2utils.change_ec2_id_kind(
                    fakes.ID_EC2_NETWORK_INTERFACE_2, 'eni-attach')})

        # NOTE(ft): eni is attached with device index = 0
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_2)
        self.assert_execution_error(
            'OperationNotPermitted', 'DetachNetworkInterface',
            {'AttachmentId': ec2utils.change_ec2_id_kind(
                    fakes.ID_EC2_NETWORK_INTERFACE_2, 'eni-attach')})

    @tools.screen_unexpected_exception_logs
    def test_detach_network_interface_rollback(self):
        network_interface = tools.update_dict(fakes.DB_NETWORK_INTERFACE_2,
                                              {'device_index': 1})
        self.set_mock_db_items(network_interface)
        self.neutron.show_port.return_value = (
            {'port': fakes.OS_PORT_2})
        self.neutron.update_port.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'DetachNetworkInterface',
            {'AttachmentId': fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH})

        self.db_api.update_item.assert_any_call(
            mock.ANY, network_interface)

    def test_assign_unassign_private_ip_addresses(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1, fakes.DB_SUBNET_1)
        self.neutron.show_subnet.return_value = (
            {'subnet': fakes.OS_SUBNET_1})
        self.neutron.show_port.return_value = (
            {'port': copy.deepcopy(fakes.OS_PORT_1)})
        self.execute(
            'AssignPrivateIpAddresses',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'PrivateIpAddress.1': '10.10.1.5',
             'PrivateIpAddress.2': '10.10.1.6',
             })
        self.neutron.update_port.assert_called_once_with(
            fakes.ID_OS_PORT_1,
            {'port':
             {'fixed_ips': [
                 {'subnet_id': fakes.ID_OS_SUBNET_1,
                  'ip_address': fakes.IP_NETWORK_INTERFACE_1},
                 {'ip_address': '10.10.1.5'},
                 {'ip_address': '10.10.1.6'}]}})
        self.execute(
            'UnassignPrivateIpAddresses',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
             'PrivateIpAddress.1': '10.10.1.5',
             'PrivateIpAddress.2': '10.10.1.6',
             })
        self.neutron.update_port.assert_any_call(
            fakes.ID_OS_PORT_1,
            {'port':
             {'fixed_ips': [
                 {'subnet_id': fakes.ID_OS_SUBNET_1,
                  'ip_address': fakes.IP_NETWORK_INTERFACE_1}]}})

    def test_assign_private_ip_addresses_invalid_parameters(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_1, fakes.DB_SUBNET_1)
        self.neutron.show_subnet.return_value = (
            {'subnet': fakes.OS_SUBNET_1})
        self.neutron.show_port.return_value = (
            {'port': copy.deepcopy(fakes.OS_PORT_1)})

        def do_check(error_code):
            self.assert_execution_error(
                error_code, 'AssignPrivateIpAddresses',
                {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_1,
                 'PrivateIpAddress.1': '10.10.1.5',
                 'PrivateIpAddress.2': '10.10.1.6',
                 })

        self.neutron.update_port.side_effect = (
            neutron_exception.IpAddressGenerationFailureClient())
        do_check('InsufficientFreeAddressesInSubnet')

        self.neutron.update_port.side_effect = (
            neutron_exception.IpAddressInUseClient())
        do_check('InvalidParameterValue')

        self.neutron.update_port.side_effect = (
            neutron_exception.BadRequest())
        do_check('InvalidParameterValue')

    def test_unassign_private_ip_addresses_invalid_parameters(self):
        self.set_mock_db_items(fakes.DB_NETWORK_INTERFACE_2, fakes.DB_SUBNET_2)
        self.neutron.show_subnet.return_value = (
            {'subnet': fakes.OS_SUBNET_2})
        self.neutron.show_port.return_value = (
            {'port': copy.deepcopy(fakes.OS_PORT_2)})

        self.assert_execution_error(
            'InvalidParameterValue', 'UnassignPrivateIpAddresses',
            {'NetworkInterfaceId': fakes.ID_EC2_NETWORK_INTERFACE_2,
             'PrivateIpAddress.1': '10.10.2.55'})
