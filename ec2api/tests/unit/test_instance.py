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

import base64
import copy
import datetime
import itertools
import random
from unittest import mock

from novaclient import exceptions as nova_exception

from ec2api.api import instance as instance_api
import ec2api.clients
from ec2api import exception
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class InstanceTestCase(base.ApiTestCase):

    def setUp(self):
        super(InstanceTestCase, self).setUp()
        self.network_interface_api = self.mock(
            'ec2api.api.instance.network_interface_api')
        self.address_api = self.mock('ec2api.api.address')
        self.security_group_api = self.mock(
            'ec2api.api.instance.security_group_api')
        self.utils_generate_uid = self.mock(
            'ec2api.api.instance._utils_generate_uid')

        self.fake_flavor = mock.Mock()
        self.fake_flavor.configure_mock(name='fake_flavor',
                                        id='fakeFlavorId')
        self.nova.flavors.get.return_value = self.fake_flavor
        self.nova.flavors.list.return_value = [self.fake_flavor]

    @mock.patch('ec2api.api.instance.describe_instances')
    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_vpc_default_security_group_id')
    def test_run_instances(self, get_vpc_default_security_group_id,
                           describe_instances):
        """Run instance with various network interface settings."""
        self.set_mock_db_items(
            fakes.DB_SUBNET_1, fakes.DB_NETWORK_INTERFACE_1, fakes.DB_IMAGE_1,
            fakes.DB_IMAGE_ARI_1, fakes.DB_IMAGE_AKI_1)
        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        self.network_interface_api.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_1})

        self.db_api.add_item.return_value = fakes.DB_INSTANCE_1
        self.nova.servers.create.return_value = (
            fakes.OSInstance({
                'id': fakes.ID_OS_INSTANCE_1,
                'flavor': {'id': 'fakeFlavorId'},
                'image': {'id': fakes.ID_OS_IMAGE_1}}))
        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1

        get_vpc_default_security_group_id.return_value = None

        def do_check(params, create_network_interface_kwargs=None,
                     delete_on_termination=None):
            delete_port_on_termination = (
                create_network_interface_kwargs is not None
                if delete_on_termination is None
                else delete_on_termination)
            eni = fakes.gen_ec2_network_interface(
                fakes.ID_EC2_NETWORK_INTERFACE_1,
                fakes.EC2_SUBNET_1,
                [fakes.IP_NETWORK_INTERFACE_1],
                description=fakes.DESCRIPTION_NETWORK_INTERFACE_1,
                ec2_instance_id=fakes.ID_EC2_INSTANCE_1,
                device_index=0,
                delete_on_termination=delete_port_on_termination)
            expected_reservation = fakes.gen_ec2_reservation(
                fakes.ID_EC2_RESERVATION_1,
                [tools.patch_dict(
                    fakes.gen_ec2_instance(
                        fakes.ID_EC2_INSTANCE_1,
                        private_ip_address=fakes.IP_NETWORK_INTERFACE_1,
                        ec2_network_interfaces=[eni],
                        image_id=fakes.ID_EC2_IMAGE_1,
                        reservation_id=fakes.ID_EC2_RESERVATION_1),
                    {'privateDnsName': None},
                    ['rootDeviceType', 'rootDeviceName'])])
            describe_instances.return_value = {
                'reservationSet': [expected_reservation]}

            params.update({'ImageId': fakes.ID_EC2_IMAGE_1,
                           'InstanceType': 'fake_flavor',
                           'MinCount': '1', 'MaxCount': '1'})
            resp = self.execute('RunInstances', params)

            self.assertThat(resp, matchers.DictMatches(expected_reservation))
            if create_network_interface_kwargs is not None:
                (self.network_interface_api.
                 create_network_interface.assert_called_once_with(
                     mock.ANY, fakes.ID_EC2_SUBNET_1,
                     **create_network_interface_kwargs))
            self.nova.servers.create.assert_called_once_with(
                fakes.EC2_INSTANCE_1['privateDnsName'],
                fakes.ID_OS_IMAGE_1, self.fake_flavor,
                min_count=1, max_count=1,
                kernel_id=None, ramdisk_id=None,
                availability_zone=None,
                block_device_mapping_v2=[],
                security_groups=None,
                nics=[{'port-id': fakes.ID_OS_PORT_1}],
                key_name=None, userdata=None)
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'i', tools.purge_dict(fakes.DB_INSTANCE_1, ('id',)))
            (self.network_interface_api.
             _attach_network_interface_item.assert_called_once_with(
                 mock.ANY, fakes.DB_NETWORK_INTERFACE_1,
                 fakes.ID_EC2_INSTANCE_1, 0,
                 delete_on_termination=delete_port_on_termination))
            describe_instances.assert_called_once_with(
                mock.ANY, [fakes.ID_EC2_INSTANCE_1])

            self.network_interface_api.reset_mock()
            self.nova.servers.reset_mock()
            self.db_api.reset_mock()
            describe_instances.reset_mock()

        do_check({'SubnetId': fakes.ID_EC2_SUBNET_1},
                 create_network_interface_kwargs={})
        do_check({'SubnetId': fakes.ID_EC2_SUBNET_1,
                  'SecurityGroupId.1': fakes.ID_EC2_SECURITY_GROUP_1,
                  'SecurityGroupId.2': fakes.ID_EC2_SECURITY_GROUP_2},
                 create_network_interface_kwargs={
                    'security_group_id': [fakes.ID_EC2_SECURITY_GROUP_1,
                                          fakes.ID_EC2_SECURITY_GROUP_2]})
        do_check({'SubnetId': fakes.ID_EC2_SUBNET_1,
                  'PrivateIpAddress': fakes.IP_FIRST_SUBNET_1},
                 create_network_interface_kwargs={
                    'private_ip_address': fakes.IP_FIRST_SUBNET_1})

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1,
                  'NetworkInterface.1.SecurityGroupId.1': (
                        fakes.ID_EC2_SECURITY_GROUP_1),
                  'NetworkInterface.1.PrivateIpAddress.1': (
                        fakes.IP_FIRST_SUBNET_1)},
                 create_network_interface_kwargs={
                    'security_group_id': [fakes.ID_EC2_SECURITY_GROUP_1],
                    'private_ip_address': [fakes.IP_FIRST_SUBNET_1]})

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1,
                  'NetworkInterface.1.DeleteOnTermination': 'False'},
                 create_network_interface_kwargs={},
                 delete_on_termination=False)
        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1,
                  'NetworkInterface.1.SecurityGroupId.1': (
                        fakes.ID_EC2_SECURITY_GROUP_1),
                  'NetworkInterface.1.DeleteOnTermination': 'False'},
                 create_network_interface_kwargs={
                    'security_group_id': [fakes.ID_EC2_SECURITY_GROUP_1]},
                 delete_on_termination=False)

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.NetworkInterfaceId': (
                        fakes.ID_EC2_NETWORK_INTERFACE_1)})

    @mock.patch('ec2api.api.instance.describe_instances')
    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_vpc_default_security_group_id')
    def test_run_instances_multiple_networks(self,
                                             get_vpc_default_security_group_id,
                                             describe_instances):
        """Run 2 instances at once on 2 subnets in all combinations."""
        self._build_multiple_data_model()

        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        get_vpc_default_security_group_id.return_value = None

        ec2_instances = [
            tools.patch_dict(
                fakes.gen_ec2_instance(
                    ec2_instance_id, launch_index=l_i,
                    ec2_network_interfaces=eni_pair,
                    reservation_id=fakes.ID_EC2_RESERVATION_1),
                {'privateDnsName': None},
                ['rootDeviceType', 'rootDeviceName'])
            for l_i, (ec2_instance_id, eni_pair) in enumerate(zip(
                self.IDS_EC2_INSTANCE,
                zip(*[iter(self.EC2_ATTACHED_ENIS)] * 2)))]
        ec2_reservation = fakes.gen_ec2_reservation(fakes.ID_EC2_RESERVATION_1,
                                                    ec2_instances)
        describe_instances.return_value = {'reservationSet': [ec2_reservation]}

        self.set_mock_db_items(
            fakes.DB_IMAGE_1, fakes.DB_SUBNET_1, fakes.DB_SUBNET_2,
            *self.DB_DETACHED_ENIS)
        self.network_interface_api.create_network_interface.side_effect = (
            [{'networkInterface': eni}
             for eni in self.EC2_DETACHED_ENIS])
        self.nova.servers.create.side_effect = [
            fakes.OSInstance({
                'id': os_instance_id,
                'flavor': {'id': 'fakeFlavorId'}})
            for os_instance_id in self.IDS_OS_INSTANCE]
        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1
        self.db_api.add_item.side_effect = self.DB_INSTANCES

        resp = self.execute(
            'RunInstances',
            {'ImageId': fakes.ID_EC2_IMAGE_1,
             'InstanceType': 'fake_flavor',
             'MinCount': '2',
             'MaxCount': '2',
             'NetworkInterface.1.DeviceIndex': '0',
             'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1,
             'NetworkInterface.2.DeviceIndex': '1',
             'NetworkInterface.2.SubnetId': fakes.ID_EC2_SUBNET_2,
             'NetworkInterface.2.DeleteOnTermination': 'False'})

        self.assertThat(resp, matchers.DictMatches(ec2_reservation),
                        verbose=True)

        self.network_interface_api.create_network_interface.assert_has_calls([
            mock.call(mock.ANY, ec2_subnet_id)
            for ec2_subnet_id in self.IDS_EC2_SUBNET_BY_PORT])
        self.nova.servers.create.assert_has_calls([
            mock.call(
                '%s-%s' % (fakes.ID_EC2_RESERVATION_1, launch_index),
                fakes.ID_OS_IMAGE_1, self.fake_flavor,
                min_count=1, max_count=1,
                kernel_id=None, ramdisk_id=None,
                availability_zone=None,
                block_device_mapping_v2=[],
                security_groups=None,
                nics=[{'port-id': port_id}
                      for port_id in port_ids],
                key_name=None, userdata=None)
            for launch_index, port_ids in enumerate(
                                        zip(*[iter(self.IDS_OS_PORT)] * 2))])
        (self.network_interface_api.
         _attach_network_interface_item.assert_has_calls([
             mock.call(mock.ANY, eni, ec2_instance_id, dev_ind,
                       delete_on_termination=dot)
             for eni, ec2_instance_id, dev_ind, dot in zip(
                 self.DB_DETACHED_ENIS,
                 itertools.chain(*map(lambda i: [i] * 2,
                                      self.IDS_EC2_INSTANCE)),
                 [0, 1] * 2,
                 [True, False, True, False])]))
        self.db_api.add_item.assert_has_calls([
            mock.call(mock.ANY, 'i', tools.purge_dict(db_instance, ['id']))
            for db_instance in self.DB_INSTANCES])

    @mock.patch('ec2api.api.instance._parse_block_device_mapping')
    @mock.patch('ec2api.api.instance.describe_instances')
    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_ec2_classic_os_network')
    def test_run_instances_other_parameters(self, get_ec2_classic_os_network,
                                            describe_instances,
                                            parse_block_device_mapping):
        self.set_mock_db_items(
            fakes.DB_IMAGE_1, fakes.DB_IMAGE_AKI_1, fakes.DB_IMAGE_ARI_1)
        self.glance.images.get.side_effect = (
            tools.get_by_1st_arg_getter({
                fakes.ID_OS_IMAGE_1: fakes.OSImage(fakes.OS_IMAGE_1),
                fakes.ID_OS_IMAGE_AKI_1: fakes.OSImage(fakes.OS_IMAGE_AKI_1),
                fakes.ID_OS_IMAGE_ARI_1: fakes.OSImage(fakes.OS_IMAGE_ARI_1)}))
        get_ec2_classic_os_network.return_value = {'id': fakes.random_os_id()}
        user_data = base64.b64decode(fakes.USER_DATA_INSTANCE_2)
        parse_block_device_mapping.return_value = []

        def do_check(extra_kwargs={}, extra_db_instance={}):
            describe_instances.side_effect = [
                {'reservationSet': []},
                {'reservationSet': [{'foo': 'bar'}]}]

            self.execute(
                'RunInstances',
                {'ImageId': fakes.ID_EC2_IMAGE_1,
                 'InstanceType': 'fake_flavor',
                 'MinCount': '1', 'MaxCount': '1',
                 'KernelId': fakes.ID_EC2_IMAGE_AKI_1,
                 'RamdiskId': fakes.ID_EC2_IMAGE_ARI_1,
                 'SecurityGroup.1': 'default',
                 'Placement.AvailabilityZone': 'fake_zone',
                 'ClientToken': 'fake_client_token',
                 'BlockDeviceMapping.1.DeviceName': '/dev/vdd',
                 'BlockDeviceMapping.1.Ebs.SnapshotId': (
                                                    fakes.ID_EC2_SNAPSHOT_1),
                 'BlockDeviceMapping.1.Ebs.DeleteOnTermination': 'False',
                 'UserData': fakes.USER_DATA_INSTANCE_2})

            self.nova.servers.create.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY, min_count=1, max_count=1,
                userdata=user_data, kernel_id=fakes.ID_OS_IMAGE_AKI_1,
                ramdisk_id=fakes.ID_OS_IMAGE_ARI_1, key_name=None,
                block_device_mapping_v2=[],
                availability_zone='fake_zone', security_groups=['default'],
                **extra_kwargs)
            self.nova.servers.reset_mock()
            db_instance = {'os_id': mock.ANY,
                           'vpc_id': None,
                           'reservation_id': mock.ANY,
                           'launch_index': 0,
                           'client_token': 'fake_client_token'}
            db_instance.update(extra_db_instance)
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'i', db_instance)
            self.db_api.reset_mock()
            parse_block_device_mapping.assert_called_once_with(
                mock.ANY,
                [{'device_name': '/dev/vdd',
                  'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_1,
                          'delete_on_termination': False}}])
            parse_block_device_mapping.reset_mock()

        do_check(
            extra_kwargs={
                'nics': [
                    {'net-id': get_ec2_classic_os_network.return_value['id']}],
            },
            extra_db_instance={'vpc_id': None})

    @mock.patch('ec2api.api.instance.describe_instances')
    def test_idempotent_run(self, describe_instances):
        self.set_mock_db_items()

        # NOTE(ft): check select corresponding instance by client_token
        describe_instances.return_value = {
            'reservationSet': [{'key': 'value'}]}

        resp = self.execute('RunInstances',
                            {'MinCount': '1', 'MaxCount': '1',
                             'ImageId': fakes.ID_EC2_IMAGE_1,
                             'InstanceType': 'fake_flavor',
                             'ClientToken': 'client-token-1'})
        self.assertEqual({'key': 'value'}, resp)
        describe_instances.assert_called_once_with(
            mock.ANY, filter=[{'name': 'client-token',
                               'value': ['client-token-1']}])

        # NOTE(ft): check pass to general run_instances logic if no
        # corresponding client_token is found
        describe_instances.return_value = {'reservationSet': []}

        self.assert_execution_error(
            'InvalidAMIID.NotFound', 'RunInstances',
            {'MinCount': '1', 'MaxCount': '1',
             'ImageId': fakes.ID_EC2_IMAGE_1,
             'InstanceType': 'fake_flavor',
             'ClientToken': 'client-token-2'})

    def test_run_instances_rollback(self):
        self.set_mock_db_items(fakes.DB_IMAGE_1, fakes.DB_SUBNET_1,
                               fakes.DB_NETWORK_INTERFACE_1)
        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)

        self.network_interface_api.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_1})
        self.db_api.add_item.return_value = fakes.DB_INSTANCE_1
        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1
        self.nova.servers.create.return_value = (
            fakes.OSInstance({'id': fakes.ID_OS_INSTANCE_1,
                              'flavor': {'id': 'fakeFlavorId'},
                              'image': {'id': fakes.ID_OS_IMAGE_1}}))
        (self.network_interface_api.
         _attach_network_interface_item.side_effect) = Exception()

        @tools.screen_unexpected_exception_logs
        def do_check(params, new_port=True):
            mock_manager = mock.MagicMock()
            mock_manager.attach_mock(self.network_interface_api,
                                     'network_interface_api')
            mock_manager.attach_mock(self.neutron, 'neutron')
            mock_manager.attach_mock(self.nova.servers, 'nova_servers')

            params.update({'ImageId': fakes.ID_EC2_IMAGE_1,
                           'InstanceType': 'fake_flavor',
                           'MinCount': '1', 'MaxCount': '1'})
            self.assert_execution_error(
                self.ANY_EXECUTE_ERROR, 'RunInstances', params)

            calls = [mock.call.nova_servers.delete(fakes.ID_OS_INSTANCE_1)]
            if new_port:
                calls.append(
                    mock.call.network_interface_api.delete_network_interface(
                        mock.ANY,
                        network_interface_id=fakes.ID_EC2_NETWORK_INTERFACE_1))
            mock_manager.assert_has_calls(calls)
            self.db_api.delete_item.assert_called_once_with(
                mock.ANY, fakes.ID_EC2_INSTANCE_1)

            self.network_interface_api.reset_mock()
            self.neutron.reset_mock()
            self.nova.servers.reset_mock()
            self.db_api.reset_mock()

        do_check({'SubnetId': fakes.ID_EC2_SUBNET_1})

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1})

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1,
                  'NetworkInterface.1.DeleteOnTermination': 'False'})

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.NetworkInterfaceId': (
                        fakes.ID_EC2_NETWORK_INTERFACE_1)},
                 new_port=False)

    @mock.patch('ec2api.api.instance.describe_instances')
    def test_run_instances_multiply_rollback(self, describe_instances):
        instances = [{'id': fakes.random_ec2_id('i'),
                      'os_id': fakes.random_os_id()}
                     for dummy in range(3)]
        os_instances = [fakes.OSInstance({'id': inst['os_id']})
                        for inst in instances]
        self.nova_admin.servers.list.return_value = os_instances[:2]
        network_interfaces = [{'id': fakes.random_ec2_id('eni'),
                               'os_id': fakes.random_os_id()}
                              for dummy in range(3)]

        self.set_mock_db_items(fakes.DB_IMAGE_1, fakes.DB_SUBNET_1,
                               *network_interfaces)
        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)

        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1

        def do_check():
            self.network_interface_api.create_network_interface.side_effect = [
                {'networkInterface': {'networkInterfaceId': eni['id']}}
                for eni in network_interfaces]
            self.db_api.add_item.side_effect = instances
            self.nova.servers.create.side_effect = os_instances
            expected_reservation = {
                'reservationId': fakes.ID_EC2_RESERVATION_1,
                'instancesSet': [{'instanceId': inst['id']}
                                 for inst in instances[:2]]}
            describe_instances.return_value = {
                'reservationSet': [expected_reservation]}

            resp = self.execute('RunInstances',
                                {'ImageId': fakes.ID_EC2_IMAGE_1,
                                 'InstanceType': 'fake_flavor',
                                 'MinCount': '2', 'MaxCount': '3',
                                 'SubnetId': fakes.ID_EC2_SUBNET_1})
            self.assertThat(resp, matchers.DictMatches(expected_reservation))

            self.nova.servers.delete.assert_called_once_with(
                instances[2]['os_id'])
            self.db_api.delete_item.assert_called_once_with(
                mock.ANY, instances[2]['id'])

            self.nova.servers.reset_mock()
            self.db_api.reset_mock()

        (self.network_interface_api.
         _attach_network_interface_item.side_effect) = [
            None, None, Exception()]
        with tools.ScreeningLogger(log_name='ec2api.api'):
            do_check()
            (self.network_interface_api.delete_network_interface.
             assert_called_once_with(
                 mock.ANY, network_interface_id=network_interfaces[2]['id']))

    def test_run_instances_invalid_parameters(self):
        self.assert_execution_error('InvalidParameterValue', 'RunInstances',
                                    {'ImageId': fakes.ID_EC2_IMAGE_1,
                                     'MinCount': '0', 'MaxCount': '0'})

        self.assert_execution_error('InvalidParameterValue', 'RunInstances',
                                    {'ImageId': fakes.ID_EC2_IMAGE_1,
                                     'MinCount': '1', 'MaxCount': '0'})

        self.assert_execution_error('InvalidParameterValue', 'RunInstances',
                                    {'ImageId': fakes.ID_EC2_IMAGE_1,
                                     'MinCount': '0', 'MaxCount': '1'})

        self.assert_execution_error('InvalidParameterValue', 'RunInstances',
                                    {'ImageId': fakes.ID_EC2_IMAGE_1,
                                     'MinCount': '2', 'MaxCount': '1'})

    @mock.patch('ec2api.api.ec2utils.check_and_create_default_vpc')
    @mock.patch('ec2api.api.instance.describe_instances')
    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_vpc_default_security_group_id')
    def test_run_instances_without_network_parameters(
            self, get_vpc_default_security_group_id, describe_instances,
            check_and_create):
        """Run instance without network interface settings."""
        self.configure(disable_ec2_classic=True)
        self.set_mock_db_items(fakes.DB_IMAGE_2,
                               fakes.DB_SUBNET_DEFAULT,
                               fakes.DB_NETWORK_INTERFACE_DEFAULT)

        check_and_create.return_value = fakes.DB_VPC_DEFAULT

        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_2)
        self.network_interface_api.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_DEFAULT})

        self.db_api.add_item.return_value = fakes.DB_INSTANCE_DEFAULT
        self.nova.servers.create.return_value = (
            fakes.OSInstance({
                'id': fakes.ID_OS_INSTANCE_DEFAULT,
                'flavor': {'id': 'fakeFlavorId'},
                'image': {'id': fakes.ID_OS_IMAGE_2}}))
        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_DEFAULT

        get_vpc_default_security_group_id.return_value = None

        describe_instances.return_value = {
            'reservationSet': [fakes.EC2_RESERVATION_DEFAULT]}

        params = {'ImageId': fakes.ID_EC2_IMAGE_2,
                  'InstanceType': 'fake_flavor',
                  'MinCount': '1', 'MaxCount': '1'}
        resp = self.execute('RunInstances', params)

        self.assertThat(resp, matchers.DictMatches(
            fakes.EC2_RESERVATION_DEFAULT))
        check_and_create.assert_called_once_with(mock.ANY)
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'i',
            tools.purge_dict(fakes.DB_INSTANCE_DEFAULT, ('id',)))
        self.nova.servers.create.assert_called_once_with(
            fakes.EC2_INSTANCE_DEFAULT['privateDnsName'],
            fakes.ID_OS_IMAGE_2, self.fake_flavor,
            min_count=1, max_count=1,
            kernel_id=None, ramdisk_id=None,
            availability_zone=None,
            block_device_mapping_v2=[],
            security_groups=None,
            nics=[{'port-id': fakes.ID_OS_PORT_DEFAULT}],
            key_name=None, userdata=None)
        (self.network_interface_api.create_network_interface.
            assert_called_once_with(mock.ANY, fakes.ID_EC2_SUBNET_DEFAULT))
        (self.network_interface_api._attach_network_interface_item.
            assert_called_once_with(
                 mock.ANY, fakes.DB_NETWORK_INTERFACE_DEFAULT,
                 fakes.ID_EC2_INSTANCE_DEFAULT, 0,
                 delete_on_termination=True))

    def test_run_instances_inconsistent_default_vpc(self):
        """Run instance without network interface settings. """
        """No default vpc"""
        self.configure(disable_ec2_classic=True)
        self.set_mock_db_items(fakes.DB_IMAGE_2)
        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_2)

        params = {'ImageId': fakes.ID_EC2_IMAGE_2,
                  'InstanceType': 'fake_flavor',
                  'MinCount': '1', 'MaxCount': '1'}

        with mock.patch('ec2api.api.ec2utils.check_and_create_default_vpc'
                        ) as check_and_create:
            check_and_create.return_value = None
            self.assert_execution_error('VPCIdNotSpecified',
                                        'RunInstances', params)

        self.add_mock_db_items(fakes.DB_VPC_DEFAULT)
        self.assert_execution_error('MissingInput', 'RunInstances', params)

    @mock.patch.object(fakes.OSInstance, 'delete', autospec=True)
    @mock.patch.object(fakes.OSInstance, 'get', autospec=True)
    def test_terminate_instances(self, os_instance_get, os_instance_delete):
        """Terminate 2 instances in one request."""
        self.set_mock_db_items(fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2)
        os_instances = [fakes.OSInstance(fakes.OS_INSTANCE_1),
                        fakes.OSInstance(fakes.OS_INSTANCE_2)]
        self.nova.servers.get.side_effect = os_instances

        resp = self.execute('TerminateInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                             'InstanceId.2': fakes.ID_EC2_INSTANCE_2})

        fake_state_change = {'previousState': {'code': 0,
                                               'name': 'pending'},
                             'currentState': {'code': 0,
                                              'name': 'pending'}}
        self.assertThat(
            resp,
            matchers.DictMatches(
                {'instancesSet': [
                    tools.update_dict({'instanceId': fakes.ID_EC2_INSTANCE_1},
                                      fake_state_change),
                    tools.update_dict({'instanceId': fakes.ID_EC2_INSTANCE_2},
                                      fake_state_change)]}))
        self.assertEqual(2, self.nova.servers.get.call_count)
        self.nova.servers.get.assert_any_call(fakes.ID_OS_INSTANCE_1)
        self.nova.servers.get.assert_any_call(fakes.ID_OS_INSTANCE_2)
        self.assertFalse(self.db_api.delete_item.called)
        self.assertEqual(2, os_instance_delete.call_count)
        self.assertEqual(2, os_instance_get.call_count)
        for call_num, inst_id in enumerate(os_instances):
            self.assertEqual(mock.call(inst_id),
                             os_instance_delete.call_args_list[call_num])
            self.assertEqual(mock.call(inst_id),
                             os_instance_get.call_args_list[call_num])

    def test_terminate_instances_multiple_networks(self):
        """Terminate an instance with various combinations of ports."""
        self._build_multiple_data_model()

        fake_state_change = {'previousState': {'code': 16,
                                               'name': 'running'},
                             'currentState': {'code': 16,
                                              'name': 'running'}}
        ec2_terminate_instances_result = {
            'instancesSet': [
                    tools.update_dict({'instanceId': fakes.ID_EC2_INSTANCE_1},
                                      fake_state_change),
                    tools.update_dict({'instanceId': fakes.ID_EC2_INSTANCE_2},
                                      fake_state_change)]}
        self.nova.servers.get.side_effect = (
            lambda ec2_id: fakes.OSInstance({'id': ec2_id,
                                             'vm_state': 'active'}))

        self.set_mock_db_items(*self.DB_INSTANCES)

        resp = self.execute('TerminateInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                             'InstanceId.2': fakes.ID_EC2_INSTANCE_2})

        self.assertThat(
            resp, matchers.DictMatches(ec2_terminate_instances_result))
        self.assertFalse(self.db_api.delete_item.called)

    def test_terminate_instances_invalid_parameters(self):
        self.assert_execution_error(
            'InvalidInstanceID.NotFound', 'TerminateInstances',
            {'InstanceId.1': fakes.random_ec2_id('i')})

    @mock.patch('ec2api.api.instance._get_os_instances_by_instances')
    def _test_instances_operation(self, operation, os_instance_operation,
                                  valid_state, invalid_state,
                                  get_os_instances_by_instances):
        os_instance_1 = fakes.OSInstance(fakes.OS_INSTANCE_1)
        os_instance_2 = fakes.OSInstance(fakes.OS_INSTANCE_2)
        for inst in (os_instance_1, os_instance_2):
            setattr(inst, 'OS-EXT-STS:vm_state', valid_state)

        self.set_mock_db_items(fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2)
        get_os_instances_by_instances.return_value = [os_instance_1,
                                                      os_instance_2]

        resp = self.execute(operation,
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                             'InstanceId.2': fakes.ID_EC2_INSTANCE_2})
        self.assertEqual({'return': True}, resp)
        self.assertEqual([mock.call(os_instance_1), mock.call(os_instance_2)],
                         os_instance_operation.mock_calls)
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2]))
        get_os_instances_by_instances.assert_called_once_with(
            mock.ANY, [fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2], exactly=True)

        setattr(os_instance_2, 'OS-EXT-STS:vm_state', invalid_state)
        os_instance_operation.reset_mock()
        self.assert_execution_error('IncorrectInstanceState', 'StartInstances',
                                    {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                                     'InstanceId.2': fakes.ID_EC2_INSTANCE_2})
        self.assertEqual(0, os_instance_operation.call_count)

    @mock.patch.object(fakes.OSInstance, 'start', autospec=True)
    def test_start_instances(self, os_instance_start):
        self._test_instances_operation('StartInstances', os_instance_start,
                                       instance_api.vm_states_STOPPED,
                                       instance_api.vm_states_ACTIVE)

    @mock.patch.object(fakes.OSInstance, 'stop', autospec=True)
    def test_stop_instances(self, os_instance_stop):
        self._test_instances_operation('StopInstances', os_instance_stop,
                                       instance_api.vm_states_ACTIVE,
                                       instance_api.vm_states_STOPPED)

    @mock.patch.object(fakes.OSInstance, 'reboot', autospec=True)
    def test_reboot_instances(self, os_instance_reboot):
        self._test_instances_operation('RebootInstances', os_instance_reboot,
                                       instance_api.vm_states_ACTIVE,
                                       instance_api.vm_states_BUILDING)

    @mock.patch('oslo_utils.timeutils.utcnow')
    def _test_instance_get_operation(self, operation, getter, key, utcnow):
        self.set_mock_db_items(fakes.DB_INSTANCE_2)
        os_instance_2 = fakes.OSInstance(fakes.OS_INSTANCE_2)
        self.nova.servers.get.return_value = os_instance_2
        getter.return_value = 'fake_data'
        utcnow.return_value = datetime.datetime(2015, 1, 19, 23, 34, 45, 123)
        resp = self.execute(operation,
                            {'InstanceId': fakes.ID_EC2_INSTANCE_2})
        expected_data = (base64.b64encode(getter.return_value.
                                          encode("latin-1"))
                               .decode("utf-8"))
        self.assertEqual({'instanceId': fakes.ID_EC2_INSTANCE_2,
                          'timestamp': '2015-01-19T23:34:45.000Z',
                          key: expected_data},
                         resp)
        self.db_api.get_item_by_id.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_INSTANCE_2)
        self.nova.servers.get.assert_called_once_with(fakes.ID_OS_INSTANCE_2)
        getter.assert_called_once_with(os_instance_2)

    @mock.patch.object(fakes.OSInstance, 'get_password', autospec=True)
    def test_get_password_data(self, get_password):
        self._test_instance_get_operation('GetPasswordData',
                                          get_password, 'passwordData')

    @mock.patch.object(fakes.OSInstance, 'get_console_output', autospec=True)
    def test_console_output(self, get_console_output):
        self._test_instance_get_operation('GetConsoleOutput',
                                          get_console_output, 'output')

    def test_describe_instances(self):
        """Describe 2 instances, one of which is vpc instance."""
        self.set_mock_db_items(
            fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2,
            fakes.DB_IMAGE_1, fakes.DB_IMAGE_2,
            fakes.DB_IMAGE_ARI_1, fakes.DB_IMAGE_AKI_1,
            fakes.DB_VOLUME_1, fakes.DB_VOLUME_2, fakes.DB_VOLUME_3)
        self.nova_admin.servers.list.return_value = [
            fakes.OSInstance_full(fakes.OS_INSTANCE_1),
            fakes.OSInstance_full(fakes.OS_INSTANCE_2)]
        self.nova_admin.servers.get.return_value = (
            fakes.OSInstance_full(fakes.OS_INSTANCE_1))
        self.cinder.volumes.list.return_value = [
            fakes.OSVolume(fakes.OS_VOLUME_1),
            fakes.OSVolume(fakes.OS_VOLUME_2),
            fakes.OSVolume(fakes.OS_VOLUME_3)]
        self.network_interface_api.describe_network_interfaces.side_effect = (
            lambda *args, **kwargs: copy.deepcopy({
                'networkInterfaceSet': [fakes.EC2_NETWORK_INTERFACE_1,
                                        fakes.EC2_NETWORK_INTERFACE_2]}))
        self.security_group_api.describe_security_groups.return_value = {
            'securityGroupInfo': [fakes.EC2_SECURITY_GROUP_1,
                                  fakes.EC2_SECURITY_GROUP_3]}

        resp = self.execute('DescribeInstances', {})

        self.assertThat(resp, matchers.DictMatches(
            {'reservationSet': [fakes.EC2_RESERVATION_1,
                                fakes.EC2_RESERVATION_2]},
            orderless_lists=True))
        self.nova_admin.servers.list.assert_called_once_with(
            search_opts={'all_tenants': True,
                         'project_id': fakes.ID_OS_PROJECT})
        self.cinder.volumes.list.assert_called_once_with(search_opts=None)

        self.nova_admin.reset_mock()
        self.db_api.get_items_by_ids = tools.CopyingMock(
            return_value=[fakes.DB_INSTANCE_1])
        resp = self.execute('DescribeInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1})
        self.assertThat(resp, matchers.DictMatches(
            {'reservationSet': [fakes.EC2_RESERVATION_1]},
            orderless_lists=True))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_INSTANCE_1]))
        (self.network_interface_api.describe_network_interfaces.
         assert_called_with(mock.ANY))
        self.assertFalse(self.nova_admin.servers.list.called)
        self.nova_admin.servers.get.assert_called_once_with(
            fakes.ID_OS_INSTANCE_1)

        self.check_filtering(
            'DescribeInstances', 'reservationSet',
            [('availability-zone', fakes.NAME_AVAILABILITY_ZONE),
             ('block-device-mapping.delete-on-termination', False),
             ('block-device-mapping.device-name',
              fakes.ROOT_DEVICE_NAME_INSTANCE_2),
             ('block-device-mapping.status', 'attached'),
             ('block-device-mapping.volume-id', fakes.ID_EC2_VOLUME_2),
             ('client-token', fakes.CLIENT_TOKEN_INSTANCE_2),
             # TODO(ft): support filtering by none/empty value
             # ('dns-name', ''),
             ('group-id', fakes.ID_EC2_SECURITY_GROUP_1),
             ('group-name', fakes.NAME_DEFAULT_OS_SECURITY_GROUP),
             ('image-id', fakes.ID_EC2_IMAGE_1),
             ('instance-id', fakes.ID_EC2_INSTANCE_2),
             ('instance-state-code', 0),
             ('instance-state-name', 'pending'),
             ('instance-type', 'fake_flavor'),
             ('instance.group-id', fakes.ID_EC2_SECURITY_GROUP_1),
             ('instance.group-name', fakes.NAME_DEFAULT_OS_SECURITY_GROUP),
             ('ip-address', fakes.IP_ADDRESS_2),
             ('kernel-id', fakes.ID_EC2_IMAGE_AKI_1),
             ('key-name', fakes.NAME_KEY_PAIR),
             ('launch-index', 0),
             ('launch-time', fakes.TIME_CREATE_INSTANCE_2),
             ('owner-id', fakes.ID_OS_PROJECT),
             ('private-dns-name', '%s-%s' % (fakes.ID_EC2_RESERVATION_1, 0)),
             ('private-ip-address', fakes.IP_NETWORK_INTERFACE_2),
             ('ramdisk-id', fakes.ID_EC2_IMAGE_ARI_1),
             ('reservation-id', fakes.ID_EC2_RESERVATION_1),
             ('root-device-name', fakes.ROOT_DEVICE_NAME_INSTANCE_1),
             ('root-device-type', 'ebs'),
             ('subnet-id', fakes.ID_EC2_SUBNET_2),
             ('vpc-id', fakes.ID_EC2_VPC_1),
             ('network-interface.description',
              fakes.DESCRIPTION_NETWORK_INTERFACE_2),
             ('network-interface.subnet-id', fakes.ID_EC2_SUBNET_2),
             ('network-interface.vpc-id', fakes.ID_EC2_VPC_1),
             ('network-interface.network-interface.id',
              fakes.ID_EC2_NETWORK_INTERFACE_2),
             ('network-interface.owner-id', fakes.ID_OS_PROJECT),
             ('network-interface.requester-managed', False),
             ('network-interface.status', 'in-use'),
             ('network-interface.mac-address', fakes.MAC_ADDRESS),
             ('network-interface.source-destination-check', True),
             ('network-interface.group-id', fakes.ID_EC2_SECURITY_GROUP_1),
             ('network-interface.group-name',
              fakes.NAME_DEFAULT_OS_SECURITY_GROUP),
             ('network-interface.attachment.attachment-id',
              fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH),
             ('network-interface.attachment.instance-id',
              fakes.ID_EC2_INSTANCE_1),
             ('network-interface.attachment.instance-owner-id',
              fakes.ID_OS_PROJECT),
             ('network-interface.addresses.private-ip-address',
              fakes.IP_NETWORK_INTERFACE_2_EXT_1),
             ('network-interface.attachment.device-index', 0),
             ('network-interface.attachment.status', 'attached'),
             ('network-interface.attachment.attach-time',
              fakes.TIME_ATTACH_NETWORK_INTERFACE),
             ('network-interface.attachment.delete-on-termination', False),
             ('network-interface.addresses.primary', False),
             ('network-interface.addresses.association.public-ip',
              fakes.IP_ADDRESS_2),
             ('network-interface.addresses.association.ip-owner-id',
              fakes.ID_OS_PROJECT),
             ('association.public-ip', fakes.IP_ADDRESS_2),
             ('association.ip-owner-id', fakes.ID_OS_PROJECT)])
        self.check_tag_support(
            'DescribeInstances', ['reservationSet', 'instancesSet'],
            fakes.ID_EC2_INSTANCE_1, 'instanceId')

    def test_describe_instances_ec2_classic(self):
        self.set_mock_db_items(
            fakes.DB_INSTANCE_2, fakes.DB_IMAGE_1, fakes.DB_IMAGE_2,
            fakes.DB_VOLUME_1, fakes.DB_VOLUME_2, fakes.DB_VOLUME_3)
        self.nova_admin.servers.list.return_value = [
            fakes.OSInstance_full(fakes.OS_INSTANCE_2)]
        self.cinder.volumes.list.return_value = [
            fakes.OSVolume(fakes.OS_VOLUME_1),
            fakes.OSVolume(fakes.OS_VOLUME_2),
            fakes.OSVolume(fakes.OS_VOLUME_3)]
        self.security_group_api.describe_security_groups.return_value = {
            'securityGroupInfo': [fakes.EC2_SECURITY_GROUP_1,
                                  fakes.EC2_SECURITY_GROUP_3]}

        resp = self.execute('DescribeInstances', {})

        self.assertThat(resp, matchers.DictMatches(
            {'reservationSet': [fakes.EC2_RESERVATION_2]},
            orderless_lists=True))

    def test_describe_instances_mutliple_networks(self):
        """Describe 2 instances with various combinations of network."""
        self._build_multiple_data_model()

        self.set_mock_db_items(*self.DB_INSTANCES)
        describe_network_interfaces = (
            self.network_interface_api.describe_network_interfaces)
        self.security_group_api.describe_security_groups.return_value = {
            'securityGroupInfo': [fakes.EC2_SECURITY_GROUP_1,
                                  fakes.EC2_SECURITY_GROUP_3]}

        def do_check(ips_by_instance=[], ec2_enis_by_instance=[],
                     ec2_instance_ips=[]):
            describe_network_interfaces.return_value = copy.deepcopy(
                {'networkInterfaceSet': list(
                                itertools.chain(*ec2_enis_by_instance))})
            self.nova_admin.servers.list.return_value = [
                fakes.OSInstance_full({
                    'id': os_id,
                    'flavor': {'id': 'fakeFlavorId'},
                    'addresses': {
                        subnet_name: [{'addr': addr,
                                       'version': 4,
                                       'OS-EXT-IPS:type': 'fixed'}]
                        for subnet_name, addr in ips},
                    'root_device_name': '/dev/vda',
                    'hostname': '%s-%s' % (fakes.ID_EC2_RESERVATION_1, l_i)})
                for l_i, (os_id, ips) in enumerate(zip(
                    self.IDS_OS_INSTANCE,
                    ips_by_instance))]

            resp = self.execute('DescribeInstances', {})

            instances = [fakes.gen_ec2_instance(
                            inst_id, launch_index=l_i, private_ip_address=ip,
                            ec2_network_interfaces=enis,
                            reservation_id=fakes.ID_EC2_RESERVATION_1)
                         for l_i, (inst_id, ip, enis) in enumerate(zip(
                             self.IDS_EC2_INSTANCE,
                             ec2_instance_ips,
                             ec2_enis_by_instance))]
            reservation_set = [fakes.gen_ec2_reservation(
                                    fakes.ID_EC2_RESERVATION_1, instances)]
            self.assertThat({'reservationSet': reservation_set},
                            matchers.DictMatches(resp, orderless_lists=True),
                            verbose=True)

        def ip_info(ind):
            return (self.EC2_ATTACHED_ENIS[ind]['subnetId'],
                    self.EC2_ATTACHED_ENIS[ind]['privateIpAddress'])

        # NOTE(ft): 2 instances; the first has 2 correct ports;
        # the second has the first port attached by EC2 API but later detached
        # by OpenStack and the second port created through EC2 API but
        # attached by OpenStack only
        do_check(
            ips_by_instance=[[ip_info(0), ip_info(1)], [ip_info(3)]],
            ec2_enis_by_instance=[
                [self.EC2_ATTACHED_ENIS[0], self.EC2_ATTACHED_ENIS[1]],
                []],
            ec2_instance_ips=[fakes.IP_FIRST_SUBNET_1, fakes.IP_LAST_SUBNET_2])

        # NOTE(ft): 2 instances: the first has the first port attached by
        # OpenStack only, the second port is attached correctly;
        # the second instance has one port created and attached by OpenStack
        # only
        do_check(
            ips_by_instance=[[ip_info(0), ip_info(1)], [ip_info(3)]],
            ec2_enis_by_instance=[[self.EC2_ATTACHED_ENIS[1]], []],
            ec2_instance_ips=[None, fakes.IP_LAST_SUBNET_2])

    @mock.patch('ec2api.api.instance._remove_instances')
    def test_describe_instances_auto_remove(self, remove_instances):
        self.set_mock_db_items(fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2,
                               fakes.DB_VOLUME_2)
        self.nova_admin.servers.list.return_value = [
            fakes.OSInstance_full(fakes.OS_INSTANCE_2)]
        self.cinder.volumes.list.return_value = [
            fakes.OSVolume(fakes.OS_VOLUME_2)]
        self.security_group_api.describe_security_groups.return_value = {
            'securityGroupInfo': [fakes.EC2_SECURITY_GROUP_3]}

        resp = self.execute('DescribeInstances', {})

        self.assertThat(resp,
                        matchers.DictMatches(
                            {'reservationSet': [fakes.EC2_RESERVATION_2]},
                            orderless_lists=True))
        remove_instances.assert_called_once_with(
            mock.ANY, [fakes.DB_INSTANCE_1])

    @mock.patch('ec2api.api.instance._format_instance')
    def test_describe_instances_sorting(self, format_instance):
        db_instances = [
            {'id': fakes.random_ec2_id('i'),
             'os_id': fakes.random_os_id(),
             'vpc_id': None,
             'launch_index': i,
             'reservation_id': fakes.ID_EC2_RESERVATION_1}
            for i in range(5)]
        random.shuffle(db_instances)
        self.set_mock_db_items(*db_instances)
        os_instances = [
            fakes.OSInstance_full({'id': inst['os_id']})
            for inst in db_instances]
        self.nova_admin.servers.list.return_value = os_instances
        format_instance.side_effect = (
            lambda context, instance, *args: (
                {'instanceId': instance['id'],
                 'amiLaunchIndex': instance['launch_index']}))

        resp = self.execute('DescribeInstances', {})
        self.assertEqual(
            [0, 1, 2, 3, 4],
            [inst['amiLaunchIndex']
             for inst in resp['reservationSet'][0]['instancesSet']])

    def test_describe_instances_invalid_parameters(self):
        self.assert_execution_error(
            'InvalidInstanceID.NotFound', 'DescribeInstances',
            {'InstanceId.1': fakes.random_ec2_id('i')})

        self.set_mock_db_items(fakes.DB_INSTANCE_2)
        self.assert_execution_error(
            'InvalidInstanceID.NotFound', 'DescribeInstances',
            {'InstanceId.1': fakes.ID_EC2_INSTANCE_2,
             'InstanceId.2': fakes.random_ec2_id('i')})

    def test_describe_instance_attributes(self):
        self.set_mock_db_items(fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2,
                               fakes.DB_IMAGE_ARI_1, fakes.DB_IMAGE_AKI_1,
                               fakes.DB_VOLUME_2)
        self.nova_admin.servers.get.side_effect = (
            tools.get_by_1st_arg_getter({
                fakes.ID_OS_INSTANCE_1: (
                    fakes.OSInstance_full(fakes.OS_INSTANCE_1)),
                fakes.ID_OS_INSTANCE_2: (
                    fakes.OSInstance_full(fakes.OS_INSTANCE_2))}))
        self.cinder.volumes.list.return_value = [
            fakes.OSVolume(fakes.OS_VOLUME_2)]
        self.security_group_api.describe_security_groups.return_value = {
            'securityGroupInfo': [fakes.EC2_SECURITY_GROUP_1,
                                  fakes.EC2_SECURITY_GROUP_3]}

        def do_check(instance_id, attribute, expected):
            resp = self.execute('DescribeInstanceAttribute',
                                {'InstanceId': instance_id,
                                 'Attribute': attribute})
            expected.update({'instanceId': instance_id})
            self.assertThat(resp, matchers.DictMatches(expected))

        do_check(fakes.ID_EC2_INSTANCE_2, 'blockDeviceMapping',
                 {'rootDeviceType': 'ebs',
                  'blockDeviceMapping': (
                        fakes.EC2_INSTANCE_2['blockDeviceMapping'])})
        do_check(fakes.ID_EC2_INSTANCE_2, 'groupSet',
                 {'groupSet': fakes.EC2_RESERVATION_2['groupSet']})
        do_check(fakes.ID_EC2_INSTANCE_2, 'instanceType',
                 {'instanceType': {'value': 'fake_flavor'}})
        do_check(fakes.ID_EC2_INSTANCE_1, 'kernel',
                 {'kernel': {'value': fakes.ID_EC2_IMAGE_AKI_1}})
        do_check(fakes.ID_EC2_INSTANCE_1, 'ramdisk',
                 {'ramdisk': {'value': fakes.ID_EC2_IMAGE_ARI_1}})
        do_check(fakes.ID_EC2_INSTANCE_2, 'rootDeviceName',
                 {'rootDeviceName': {
                        'value': fakes.ROOT_DEVICE_NAME_INSTANCE_2}})
        do_check(fakes.ID_EC2_INSTANCE_2, 'userData',
                 {'userData': {'value': fakes.USER_DATA_INSTANCE_2}})

    def _build_multiple_data_model(self):
        # NOTE(ft): generate necessary fake data
        # We need 4 detached ports in 2 subnets.
        # Sequence of all ports list is s1i1, s2i1, s1i2, s2i2,
        # where sNiM - port info of instance iM on subnet sN.
        # We generate port ids but use subnet and instance ids since
        # fakes contain enough ids for subnets an instances, but not for ports.
        instances_count = 2
        subnets_count = 2
        ports_count = instances_count * subnets_count
        ids_ec2_eni = [fakes.random_ec2_id('eni') for _ in range(ports_count)]
        ids_os_port = [fakes.random_os_id() for _ in range(ports_count)]

        ids_ec2_subnet = (fakes.ID_EC2_SUBNET_1, fakes.ID_EC2_SUBNET_2)
        ids_ec2_subnet_by_port = ids_ec2_subnet * 2
        ips = (fakes.IP_FIRST_SUBNET_1, fakes.IP_FIRST_SUBNET_2,
               fakes.IP_LAST_SUBNET_1, fakes.IP_LAST_SUBNET_2)

        ids_ec2_instance = [fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2]
        ids_ec2_instance_by_port = list(
            itertools.chain(*map(lambda i: [i] * subnets_count,
                                 ids_ec2_instance)))
        ids_os_instance = [fakes.ID_OS_INSTANCE_1, fakes.ID_OS_INSTANCE_2]

        dots_by_port = [True, False] * instances_count
        db_attached_enis = [
            fakes.gen_db_network_interface(
                ec2_id, os_id, fakes.ID_EC2_VPC_1,
                subnet_ec2_id, ip,
                instance_id=instance_ec2_id,
                device_index=dev_ind,
                delete_on_termination=dot)
            for (ec2_id, os_id, subnet_ec2_id, ip, instance_ec2_id, dev_ind,
                 dot) in zip(
                ids_ec2_eni,
                ids_os_port,
                ids_ec2_subnet_by_port,
                ips,
                ids_ec2_instance_by_port,
                list(range(subnets_count)) * instances_count,
                dots_by_port)]
        db_detached_enis = [
            fakes.gen_db_network_interface(
                ec2_id, os_id, fakes.ID_EC2_VPC_1,
                subnet_ec2_id, ip)
            for ec2_id, os_id, subnet_ec2_id, ip in zip(
                ids_ec2_eni,
                ids_os_port,
                ids_ec2_subnet_by_port,
                ips)]
        ec2_attached_enis = [
            fakes.gen_ec2_network_interface(
                db_eni['id'],
                None,  # ec2_subnet
                [db_eni['private_ip_address']],
                ec2_instance_id=ec2_instance_id,
                device_index=dev_ind,
                delete_on_termination=dot,
                ec2_subnet_id=ec2_subnet_id,
                ec2_vpc_id=fakes.ID_EC2_VPC_1)
            for db_eni, dot, ec2_subnet_id, ec2_instance_id, dev_ind in zip(
                db_attached_enis,
                dots_by_port,
                ids_ec2_subnet_by_port,
                ids_ec2_instance_by_port,
                list(range(subnets_count)) * instances_count)]
        ec2_detached_enis = [
            fakes.gen_ec2_network_interface(
                db_eni['id'],
                None,  # ec2_subnet
                [db_eni['private_ip_address']],
                ec2_subnet_id=ec2_subnet_id,
                ec2_vpc_id=fakes.ID_EC2_VPC_1)
            for db_eni, ec2_subnet_id in zip(
                db_detached_enis,
                ids_ec2_subnet_by_port)]
        db_instances = [
            {'id': db_id,
             'os_id': os_id,
             'vpc_id': fakes.ID_EC2_VPC_1,
             'reservation_id': fakes.ID_EC2_RESERVATION_1,
             'launch_index': l_i}
            for l_i, (db_id, os_id) in enumerate(zip(
                ids_ec2_instance,
                ids_os_instance))]

        self.IDS_EC2_SUBNET = ids_ec2_subnet
        self.IDS_OS_PORT = ids_os_port
        self.IDS_OS_INSTANCE = ids_os_instance
        self.IDS_EC2_INSTANCE = ids_ec2_instance
        self.IDS_EC2_SUBNET_BY_PORT = ids_ec2_subnet_by_port
        self.DB_DETACHED_ENIS = db_detached_enis
        self.EC2_ATTACHED_ENIS = ec2_attached_enis
        self.EC2_DETACHED_ENIS = ec2_detached_enis
        self.DB_INSTANCES = db_instances


# TODO(ft): add tests for get_vpc_default_security_group_id,

class InstancePrivateTestCase(base.BaseTestCase):

    def test_merge_network_interface_parameters(self):
        fake_context = base.create_context()
        engine = instance_api.InstanceEngineNeutron()

        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, None, 'subnet-1', None, None,
            [{'device_index': 0, 'private_ip_address': '10.10.10.10'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, None, None, '10.10.10.10', None,
            [{'device_index': 0, 'subnet_id': 'subnet-1'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, ['default'], None, None, None,
            [{'device_index': 0, 'subnet_id': 'subnet-1'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, None, None, None, ['sg-1'],
            [{'device_index': 0, 'subnet_id': 'subnet-1'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, None, 'subnet-1', None, None,
            [{'device_index': 1, 'associate_public_ip_address': True}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, None, 'subnet-1', None, None,
            [{'device_index': 0, 'associate_public_ip_address': True},
             {'device_index': 1, 'subnet_id': 'subnet-2'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, None, 'subnet-1', None, None,
            [{'device_index': 0}])

        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, ['default'], 'subnet-1', None, None, None)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, None, None, '10.10.10.10', None, None)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            fake_context, None, None, None, ['sg-1'], None)

        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1'}]),
            engine.merge_network_interface_parameters(
                fake_context, None, 'subnet-1', None, None, None))
        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1',
                     'private_ip_address': '10.10.10.10'}]),
            engine.merge_network_interface_parameters(
                fake_context, None, 'subnet-1', '10.10.10.10', None, None))
        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1',
                     'private_ip_address': '10.10.10.10',
                     'security_group_id': ['sg-1']}]),
            engine.merge_network_interface_parameters(
                fake_context, None, 'subnet-1', '10.10.10.10', ['sg-1'], None))
        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1',
                     'security_group_id': ['sg-1']}]),
            engine.merge_network_interface_parameters(
                fake_context, None, 'subnet-1', None, ['sg-1'], None))

        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1'}]),
            engine.merge_network_interface_parameters(
                fake_context, None, None, None, None,
                [{'device_index': 0, 'subnet_id': 'subnet-1'}]))
        self.assertEqual((['default'], []),
                         engine.merge_network_interface_parameters(
                                fake_context, ['default'], None, None, None,
                                None))
        self.assertEqual((None, []),
                         engine.merge_network_interface_parameters(
                                fake_context, None, None, None, None, None))

        self.configure(disable_ec2_classic=True)
        self.db_api = self.mock_db()
        self.db_api.set_mock_items(fakes.DB_VPC_DEFAULT,
                                   fakes.DB_SUBNET_DEFAULT)

        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': fakes.ID_EC2_SUBNET_DEFAULT}]),
            engine.merge_network_interface_parameters(
                fake_context, None, None, None, None, None))
        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': fakes.ID_EC2_SUBNET_DEFAULT,
                     'security_group_id': ['sg-id'],
                     'associate_public_ip_address': True}]),
            engine.merge_network_interface_parameters(
                fake_context, None, None, None, None,
                [{'device_index': 0,
                  'associate_public_ip_address': True,
                  'security_group_id': ['sg-id']}]))

        with mock.patch('ec2api.api.security_group.describe_security_groups'
                        ) as describe_sg:

            describe_sg.return_value = {
                'securityGroupInfo': [{'groupId': 'sg-named-id'}]
                }
            self.assertEqual((None, [{'device_index': 0,
                                      'subnet_id': fakes.ID_EC2_SUBNET_DEFAULT,
                                      'security_group_id': ['sg-id',
                                                            'sg-named-id'],
                                      'private_ip_address': 'private-ip'}]),
                             engine.merge_network_interface_parameters(
                                    fake_context, ['sg-name'], None,
                                    'private-ip', ['sg-id'], None))
            describe_sg.assert_called_once_with(mock.ANY,
                                                group_name=['sg-name'])

    def test_check_network_interface_parameters(self):
        engine = instance_api.InstanceEngineNeutron()

        self.assertRaises(
            exception.InvalidParameterValue,
            engine.check_network_interface_parameters,
            [{'subnet_id': 'subnet-1'}], False)
        self.assertRaises(
            exception.InvalidParameterValue,
            engine.check_network_interface_parameters,
            [{'device_index': 0, 'subnet_id': 'subnet-1'},
             {'device_index': 0, 'subnet_id': 'subnet-2'}], False)
        self.assertRaises(
            exception.InvalidParameterValue,
            engine.check_network_interface_parameters,
            [{'device_index': 0, 'private_ip_address': '10.10.10.10'}], False)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.check_network_interface_parameters,
            [{'device_index': 0,
              'network_interface_id': 'eni-1',
              'subnet_id': 'subnet-1'}],
            False)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.check_network_interface_parameters,
            [{'device_index': 0,
              'network_interface_id': 'eni-1',
              'private_ip_address': '10.10.10.10'}],
            False)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.check_network_interface_parameters,
            [{'device_index': 0,
              'network_interface_id': 'eni-1',
              'security_group_id': ['sg-1']}],
            False)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.check_network_interface_parameters,
            [{'device_index': 0,
              'network_interface_id': 'eni-1',
              'delete_on_termination': True}],
            False)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.check_network_interface_parameters,
            [{'device_index': 0, 'network_interface_id': 'eni-1'}],
            True)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.check_network_interface_parameters,
            [{'device_index': 0,
              'subnet_id': 'subnet-1',
              'private_ip_address': '10.10.10.10'}],
            True)
        self.assertRaises(
            exception.UnsupportedOperation,
            engine.check_network_interface_parameters,
            [{'device_index': 1, 'subnet_id': 'subnet-1'}], False)

        engine.check_network_interface_parameters(
            [{'device_index': 0, 'subnet_id': 'subnet-1'}], False)
        engine.check_network_interface_parameters(
            [{'device_index': 0,
              'subnet_id': 'subnet-1',
              'private_ip_address': '10.10.10.10',
              'security_group_id': ['sg-1'],
              'delete_on_termination': True}],
            False)
        engine.check_network_interface_parameters(
            [{'device_index': 0, 'network_interface_id': 'eni-1'}], False)
        engine.check_network_interface_parameters(
            [{'device_index': 0,
              'subnet_id': 'subnet-1',
              'security_group_id': ['sg-1'],
              'delete_on_termination': True},
             {'device_index': 1,
              'subnet_id': 'subnet-2'}],
            True)
        engine.check_network_interface_parameters([], False)

    @mock.patch('ec2api.db.api.IMPL')
    def test_parse_network_interface_parameters(self, db_api):
        engine = instance_api.InstanceEngineNeutron()
        context = base.create_context()
        db_api.get_item_by_id.side_effect = tools.get_db_api_get_item_by_id(
            fakes.DB_SUBNET_1,
            tools.update_dict(fakes.DB_SUBNET_2,
                              {'vpc_id': fakes.ID_EC2_VPC_2}),
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2)

        resp = engine.parse_network_interface_parameters(
            context,
            [{'device_index': 1,
              'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1},
             {'device_index': 0,
              'subnet_id': fakes.ID_EC2_SUBNET_1,
              'delete_on_termination': False,
              'security_group_id': [fakes.ID_EC2_SECURITY_GROUP_1]}])
        self.assertEqual(
            (fakes.ID_EC2_VPC_1,
             [{'device_index': 0,
               'create_args': (fakes.ID_EC2_SUBNET_1,
                               {'security_group_id': (
                                     [fakes.ID_EC2_SECURITY_GROUP_1])}),
               'delete_on_termination': False},
              {'device_index': 1,
               'network_interface': fakes.DB_NETWORK_INTERFACE_1,
               'delete_on_termination': False}]),
            resp)
        resp = engine.parse_network_interface_parameters(
            context,
            [{'device_index': 0,
              'subnet_id': fakes.ID_EC2_SUBNET_1,
              'associate_public_ip_address': True}])
        self.assertEqual(
            (fakes.ID_EC2_VPC_1,
             [{'device_index': 0,
               'create_args': (fakes.ID_EC2_SUBNET_1, {}),
               'delete_on_termination': True}]),
            resp)

        # NOTE(ft): a network interface has being attached twice
        self.assertRaises(
            exception.InvalidParameterValue,
            engine.parse_network_interface_parameters, context,
            [{'device_index': 0,
              'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1},
             {'device_index': 1,
              'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1}])
        # NOTE(ft): a network interface is in use
        self.assertRaises(
            exception.InvalidNetworkInterfaceInUse,
            engine.parse_network_interface_parameters, context,
            [{'device_index': 0,
              'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_2}])
        # NOTE(ft): specified objects are belonging to different VPCs
        self.assertRaises(
            exception.InvalidParameterValue,
            engine.parse_network_interface_parameters, context,
            [{'device_index': 0,
              'subnet_id': fakes.ID_EC2_SUBNET_1},
             {'device_index': 1,
              'subnet_id': fakes.ID_EC2_SUBNET_2}])
        self.assertRaises(
            exception.InvalidParameterValue,
            engine.parse_network_interface_parameters, context,
            [{'device_index': 0,
              'network_interface_id': fakes.ID_EC2_NETWORK_INTERFACE_1},
             {'device_index': 1,
              'subnet_id': fakes.ID_EC2_SUBNET_2}])

    @mock.patch('ec2api.api.ec2utils.get_os_image')
    def test_parse_image_parameters(self, get_os_image):
        fake_context = base.create_context()

        # NOTE(ft): check normal flow
        os_image = fakes.OSImage(fakes.OS_IMAGE_1)
        get_os_image.side_effect = [
            fakes.OSImage(fakes.OS_IMAGE_AKI_1),
            fakes.OSImage(fakes.OS_IMAGE_ARI_1),
            os_image]
        self.assertEqual(
            (os_image, fakes.ID_OS_IMAGE_AKI_1, fakes.ID_OS_IMAGE_ARI_1),
            instance_api._parse_image_parameters(
                fake_context, fakes.ID_EC2_IMAGE_1,
                fakes.ID_EC2_IMAGE_AKI_1, fakes.ID_EC2_IMAGE_ARI_1))
        get_os_image.assert_has_calls(
            [mock.call(fake_context, fakes.ID_EC2_IMAGE_AKI_1),
             mock.call(fake_context, fakes.ID_EC2_IMAGE_ARI_1),
             mock.call(fake_context, fakes.ID_EC2_IMAGE_1)])

        get_os_image.side_effect = None
        get_os_image.return_value = os_image
        get_os_image.reset_mock()
        self.assertEqual(
            (os_image, None, None),
            instance_api._parse_image_parameters(
                fake_context, fakes.ID_EC2_IMAGE_1, None, None))
        get_os_image.assert_called_once_with(
                fake_context, fakes.ID_EC2_IMAGE_1)

        # NOTE(ft): check cases of not available image
        os_image = fakes.OSImage({
            'id': fakes.random_os_id(),
            'status': None})
        get_os_image.return_value = os_image

        self.assertRaises(
            exception.InvalidAMIIDUnavailable,
            instance_api._parse_image_parameters,
            fake_context, fakes.random_ec2_id('ami'), None, None)

        os_image.status = 'active'
        os_image.image_state = 'decrypting'

        self.assertRaises(
            exception.InvalidAMIIDUnavailable,
            instance_api._parse_image_parameters,
            fake_context, fakes.random_ec2_id('ami'), None, None)

    @mock.patch('ec2api.db.api.IMPL')
    def test_parse_block_device_mapping(self, db_api):
        fake_context = base.create_context()

        db_api.get_item_by_id.side_effect = tools.get_db_api_get_item_by_id(
            fakes.DB_VOLUME_1, fakes.DB_VOLUME_2, fakes.DB_VOLUME_3,
            fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2)

        res = instance_api._parse_block_device_mapping(fake_context, [])
        self.assertEqual([], res)

        res = instance_api._parse_block_device_mapping(
            fake_context, [{'device_name': '/dev/vdf',
                            'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_1}},
                           {'device_name': '/dev/vdg',
                            'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_2,
                                    'volume_size': 111,
                                    'delete_on_termination': False}},
                           {'device_name': '/dev/vdh',
                            'ebs': {'snapshot_id': fakes.ID_EC2_VOLUME_1}},
                           {'device_name': '/dev/vdi',
                            'ebs': {'snapshot_id': fakes.ID_EC2_VOLUME_2,
                                    'delete_on_termination': True}},
                           {'device_name': '/dev/sdb1',
                            'ebs': {'volume_size': 55}}])

        expected = [{'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
                     'device_name': '/dev/vdf',
                     'source_type': 'snapshot',
                     'destination_type': 'volume'},
                    {'snapshot_id': fakes.ID_OS_SNAPSHOT_2,
                     'volume_size': 111,
                     'device_name': '/dev/vdg',
                     'source_type': 'snapshot',
                     'destination_type': 'volume',
                     'delete_on_termination': False},
                    {'volume_id': fakes.ID_OS_VOLUME_1,
                     'device_name': '/dev/vdh',
                     'source_type': 'volume',
                     'destination_type': 'volume'},
                    {'volume_id': fakes.ID_OS_VOLUME_2,
                     'device_name': '/dev/vdi',
                     'source_type': 'volume',
                     'destination_type': 'volume',
                     'delete_on_termination': True},
                    {'volume_size': 55,
                     'device_name': '/dev/sdb1',
                     'destination_type': 'volume'}]

        self.assertThat(expected,
                        matchers.ListMatches(res, orderless_lists=True),
                        verbose=True)

        res = instance_api._parse_block_device_mapping(
            fake_context, [{'device_name': '/dev/vdf',
                            'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_1}},
                           {'device_name': '/dev/vdf',
                            'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_2}}])
        expected = [{'snapshot_id': fakes.ID_OS_SNAPSHOT_2,
                     'device_name': '/dev/vdf',
                     'source_type': 'snapshot',
                     'destination_type': 'volume'}]
        self.assertThat(expected,
                        matchers.ListMatches(res, orderless_lists=True),
                        verbose=True)

        self.assertRaises(
            exception.InvalidBlockDeviceMapping,
            instance_api._parse_block_device_mapping,
            fake_context,
            [{'device_name': '/dev/vdf',
              'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_1}},
             {'device_name': 'vdf',
              'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_2}}])

    @mock.patch('ec2api.db.api.IMPL')
    def test_build_block_device_mapping(self, db_api):
        fake_context = base.create_context()
        db_api.get_item_by_id.side_effect = tools.get_db_api_get_item_by_id(
            fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2,
            fakes.DB_VOLUME_1, fakes.DB_VOLUME_2)

        # check bdm attributes' population
        bdms = [
            {'device_name': '/dev/sda1',
             'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_1}},
            {'device_name': '/dev/vdb',
             'ebs': {'snapshot_id': fakes.ID_EC2_VOLUME_1,
                     'delete_on_termination': False}},
            {'device_name': 'vdc',
             'ebs': {'volume_size': 100}},
        ]
        expected = [
            {'device_name': '/dev/sda1',
             'source_type': 'snapshot',
             'destination_type': 'volume',
             'uuid': fakes.ID_OS_SNAPSHOT_1,
             'delete_on_termination': True,
             'boot_index': 0},
            {'device_name': '/dev/vdb',
             'source_type': 'volume',
             'destination_type': 'volume',
             'uuid': fakes.ID_OS_VOLUME_1,
             'delete_on_termination': False,
             'boot_index': -1},
            {'device_name': 'vdc',
             'source_type': 'blank',
             'destination_type': 'volume',
             'volume_size': 100,
             'delete_on_termination': True,
             'boot_index': -1},
        ]
        result = instance_api._build_block_device_mapping(
            fake_context, bdms, fakes.OSImage(fakes.OS_IMAGE_1))
        self.assertEqual(expected, result)

        fake_image_template = {
            'id': fakes.random_os_id(),
            'root_device_name': '/dev/vda',
            'bdm_v2': True,
            'block_device_mapping': []}

        # check merging with image bdms
        fake_image_template['block_device_mapping'] = [
            {'boot_index': 0,
             'device_name': '/dev/vda',
             'source_type': 'snapshot',
             'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
             'delete_on_termination': True,
             'disk_bus': None},
            {'device_name': 'vdb',
             'source_type': 'snapshot',
             'snapshot_id': fakes.random_os_id(),
             'volume_size': 50},
            {'device_name': '/dev/vdc',
             'source_type': 'blank',
             'volume_size': 10},
        ]
        bdms = [
            {'device_name': '/dev/vda',
             'ebs': {'volume_size': 15}},
            {'device_name': 'vdb',
             'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_2,
                     'delete_on_termination': False}},
            {'device_name': '/dev/vdc',
             'ebs': {'volume_size': 20}},
        ]
        expected = [
            {'device_name': '/dev/vda',
             'source_type': 'snapshot',
             'destination_type': 'volume',
             'uuid': fakes.ID_OS_SNAPSHOT_1,
             'delete_on_termination': True,
             'volume_size': 15,
             'boot_index': 0},
            {'device_name': 'vdb',
             'source_type': 'snapshot',
             'destination_type': 'volume',
             'uuid': fakes.ID_OS_SNAPSHOT_2,
             'delete_on_termination': False,
             'boot_index': -1},
            {'device_name': '/dev/vdc',
             'source_type': 'blank',
             'destination_type': 'volume',
             'volume_size': 20,
             'delete_on_termination': False},
        ]
        result = instance_api._build_block_device_mapping(
            fake_context, bdms, fakes.OSImage(fake_image_template))
        self.assertEqual(expected, result)

        # check result order for adjusting some bdm of all
        fake_image_template['block_device_mapping'] = [
            {'device_name': '/dev/vdc',
             'source_type': 'blank',
             'volume_size': 10},
            {'device_name': '/dev/vde',
             'source_type': 'blank',
             'volume_size': 10},
            {'device_name': '/dev/vdf',
             'source_type': 'blank',
             'volume_size': 10},
            {'boot_index': -1,
             'source_type': 'blank',
             'volume_size': 10},
        ]
        bdms = [
            {'device_name': '/dev/vdh',
             'ebs': {'volume_size': 15}},
            {'device_name': '/dev/vde',
             'ebs': {'volume_size': 15}},
            {'device_name': '/dev/vdb',
             'ebs': {'volume_size': 15}},
        ]
        expected = [
            {'device_name': '/dev/vdh',
             'source_type': 'blank',
             'destination_type': 'volume',
             'volume_size': 15,
             'delete_on_termination': True,
             'boot_index': -1},
            {'device_name': '/dev/vde',
             'source_type': 'blank',
             'destination_type': 'volume',
             'volume_size': 15,
             'delete_on_termination': False},
            {'device_name': '/dev/vdb',
             'source_type': 'blank',
             'destination_type': 'volume',
             'volume_size': 15,
             'delete_on_termination': True,
             'boot_index': -1},
        ]
        result = instance_api._build_block_device_mapping(
            fake_context, bdms, fakes.OSImage(fake_image_template))
        self.assertEqual(expected, result)

        # check conflict of short and full device names
        fake_image_template['block_device_mapping'] = [
            {'device_name': '/dev/vdc',
             'source_type': 'blank',
             'volume_size': 10},
        ]
        bdms = [
            {'device_name': 'vdc',
             'ebs': {'volume_size': 15}},
        ]
        self.assertRaises(exception.InvalidBlockDeviceMapping,
                          instance_api._build_block_device_mapping,
                          fake_context, bdms,
                          fakes.OSImage(fake_image_template))

        # opposit combination of the same case
        fake_image_template['block_device_mapping'] = [
            {'device_name': 'vdc',
             'source_type': 'blank',
             'volume_size': 10},
        ]
        bdms = [
            {'device_name': '/dev/vdc',
             'ebs': {'volume_size': 15}},
        ]
        self.assertRaises(exception.InvalidBlockDeviceMapping,
                          instance_api._build_block_device_mapping,
                          fake_context, bdms,
                          fakes.OSImage(fake_image_template))

        # check fault on root device snapshot changing
        fake_image_template['block_device_mapping'] = [
            {'boot_index': 0,
             'source_type': 'snapshot',
             'snapshot_id': fakes.ID_EC2_SNAPSHOT_1},
        ]
        bdms = [
            {'device_name': '/dev/vda',
             'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_2}},
        ]
        self.assertRaises(exception.InvalidBlockDeviceMapping,
                          instance_api._build_block_device_mapping,
                          fake_context, bdms,
                          fakes.OSImage(fake_image_template))

        # same case for legacy bdm
        fake_image_template['block_device_mapping'] = [
            {'device_name': '/dev/vda',
             'snapshot_id': fakes.ID_EC2_SNAPSHOT_1},
        ]
        fake_image_template['bdm_v2'] = False
        bdms = [
            {'device_name': '/dev/vda',
             'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_2}},
        ]
        self.assertRaises(exception.InvalidBlockDeviceMapping,
                          instance_api._build_block_device_mapping,
                          fake_context, bdms,
                          fakes.OSImage(fake_image_template))

        # same case for legacy bdm with short names
        fake_image_template['block_device_mapping'] = [
            {'device_name': 'vda',
             'snapshot_id': fakes.ID_EC2_SNAPSHOT_1},
        ]
        fake_image_template['bdm_v2'] = False
        bdms = [
            {'device_name': 'vda',
             'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_2}},
        ]
        self.assertRaises(exception.InvalidBlockDeviceMapping,
                          instance_api._build_block_device_mapping,
                          fake_context, bdms,
                          fakes.OSImage(fake_image_template))

        fake_image_template['bdm_v2'] = True

        # check fault on reduce volume size
        fake_image_template['block_device_mapping'] = [
            {'device_name': 'vdc',
             'source_type': 'blank',
             'volume_size': 15},
        ]
        bdms = [
            {'device_name': '/dev/vdc',
             'ebs': {'volume_size': 10}},
        ]
        self.assertRaises(exception.InvalidBlockDeviceMapping,
                          instance_api._build_block_device_mapping,
                          fake_context, bdms,
                          fakes.OSImage(fake_image_template))

        # check fault on set snapshot id if bdm doesn't have one
        fake_image_template['block_device_mapping'] = [
            {'device_name': 'vdc',
             'source_type': 'blank',
             'volume_size': 10},
        ]
        bdms = [
            {'device_name': '/dev/vdc',
             'ebs': {'snapshot_id': fakes.ID_EC2_SNAPSHOT_1}},
        ]
        self.assertRaises(exception.InvalidBlockDeviceMapping,
                          instance_api._build_block_device_mapping,
                          fake_context, bdms,
                          fakes.OSImage(fake_image_template))

    @mock.patch('cinderclient.client.Client')
    @mock.patch('novaclient.client.Client')
    @mock.patch('ec2api.db.api.IMPL')
    def test_format_instance(self, db_api, nova, cinder):
        nova = nova.return_value
        fake_context = base.create_context()
        fake_flavors = {'fakeFlavorId': 'fake_flavor'}

        instance = {'id': fakes.random_ec2_id('i'),
                    'os_id': fakes.random_os_id(),
                    'launch_index': 0}
        os_instance = fakes.OSInstance_full({'id': instance['os_id'],
                                             'flavor': {'id': 'fakeFlavorId'}})

        # NOTE(ft): check instance state formatting
        setattr(os_instance, 'OS-EXT-STS:vm_state', 'active')
        formatted_instance = instance_api._format_instance(
            fake_context, instance, os_instance, [], {},
            None, None, fake_flavors, [])
        self.assertEqual({'name': 'running', 'code': 16},
                         formatted_instance['instanceState'])

        setattr(os_instance, 'OS-EXT-STS:vm_state', 'stopped')
        formatted_instance = instance_api._format_instance(
            fake_context, instance, os_instance, [], {},
            None, None, fake_flavors, [])
        self.assertEqual({'name': 'stopped', 'code': 80},
                         formatted_instance['instanceState'])

        # NOTE(ft): check auto creating of DB item for unknown OS images
        os_instance.image = {'id': fakes.random_os_id()}
        kernel_id = fakes.random_os_id()
        ramdisk_id = fakes.random_os_id()
        setattr(os_instance, 'OS-EXT-SRV-ATTR:kernel_id', kernel_id)
        setattr(os_instance, 'OS-EXT-SRV-ATTR:ramdisk_id', ramdisk_id)
        formatted_instance = instance_api._format_instance(
            fake_context, instance, os_instance, [], {},
            None, None, fake_flavors, [])
        db_api.add_item_id.assert_has_calls(
            [mock.call(mock.ANY, 'ami', os_instance.image['id'], None),
             mock.call(mock.ANY, 'aki', kernel_id, None),
             mock.call(mock.ANY, 'ari', ramdisk_id, None)],
            any_order=True)

    @mock.patch('cinderclient.client.Client')
    def test_format_instance_bdm(self, cinder):
        id_os_instance_1 = fakes.random_os_id()
        id_os_instance_2 = fakes.random_os_id()
        cinder = cinder.return_value
        cinder.volumes.list.return_value = [
            fakes.OSVolume({'id': '2',
                            'status': 'attached',
                            'attachments': [{'device': '/dev/sdb1',
                                             'server_id': id_os_instance_1}]}),
            fakes.OSVolume({'id': '5',
                            'status': 'attached',
                            'attachments': [{'device': '/dev/sdb3',
                                             'server_id': id_os_instance_1}]}),
            fakes.OSVolume({'id': '21',
                            'status': 'attached',
                            'attachments': [{'device': 'vda',
                                             'server_id': id_os_instance_2}]}),
        ]
        os_instance_1 = fakes.OSInstance_full({
            'id': id_os_instance_1,
            'volumes_attached': [{'id': '2',
                                  'delete_on_termination': False},
                                 {'id': '5',
                                  'delete_on_termination': True}],
            'root_device_name': '/dev/sdb1'})
        os_instance_2 = fakes.OSInstance_full({
            'id': id_os_instance_2,
            'volumes_attached': [{'id': '21',
                                  'delete_on_termination': False}],
            'root_device_name': '/dev/sdc1'})

        db_volumes_1 = {'2': {'id': 'vol-00000002'},
                        '5': {'id': 'vol-00000005'}}

        fake_context = base.create_context()

        result = {}
        instance_api._cloud_format_instance_bdm(
            fake_context, os_instance_1, result, db_volumes_1)
        self.assertThat(
            result,
            matchers.DictMatches({
                'rootDeviceType': 'ebs',
                'blockDeviceMapping': [
                        {'deviceName': '/dev/sdb1',
                         'ebs': {'status': 'attached',
                                 'deleteOnTermination': False,
                                 'volumeId': 'vol-00000002',
                                 }},
                        {'deviceName': '/dev/sdb3',
                         'ebs': {'status': 'attached',
                                 'deleteOnTermination': True,
                                 'volumeId': 'vol-00000005',
                                 }}]},
                orderless_lists=True), verbose=True)

        result = {}
        with mock.patch('ec2api.db.api.IMPL') as db_api:
            db_api.get_items.return_value = [{'id': 'vol-00000015',
                                              'os_id': '21'}]
            instance_api._cloud_format_instance_bdm(
                fake_context, os_instance_2, result)
        self.assertThat(
            result,
            matchers.DictMatches({
                'rootDeviceType': 'instance-store',
                'blockDeviceMapping': [
                        {'deviceName': 'vda',
                         'ebs': {'status': 'attached',
                                 'deleteOnTermination': False,
                                 'volumeId': 'vol-00000015',
                                 }}]}))

    @mock.patch('cinderclient.client.Client')
    def test_format_instance_bdm_while_attaching_volume(self, cinder):
        id_os_instance = fakes.random_os_id()
        cinder = cinder.return_value
        cinder.volumes.list.return_value = [
            fakes.OSVolume({'id': '2',
                            'status': 'attaching',
                            'attachments': [{'device': '/dev/sdb1',
                                             'server_id': id_os_instance}]})]
        os_instance = fakes.OSInstance_full({
            'id': id_os_instance,
            'volumes_attached': [{'id': '2',
                                  'delete_on_termination': False}],
            'root_device_name': '/dev/vda'})
        fake_context = base.create_context()

        result = {}
        instance_api._cloud_format_instance_bdm(
            fake_context, os_instance, result,
            {'2': {'id': 'vol-00000002'}})
        self.assertThat(
            result,
            matchers.DictMatches({
                'rootDeviceType': 'instance-store',
                'blockDeviceMapping': [
                        {'deviceName': '/dev/sdb1',
                         'ebs': {'status': 'attaching',
                                 'deleteOnTermination': False,
                                 'volumeId': 'vol-00000002',
                                 }}]}))

    def test_format_instance_bdm_no_bdm(self):
        context = base.create_context()
        os_instance_id = fakes.random_os_id()
        os_instance = fakes.OSInstance_full({'id': os_instance_id})

        res = {}
        setattr(os_instance, 'OS-EXT-SRV-ATTR:root_device_name', None)
        instance_api._cloud_format_instance_bdm(
            context, os_instance, res, {}, {os_instance_id: []})
        self.assertEqual({}, res)

        res = {}
        setattr(os_instance, 'OS-EXT-SRV-ATTR:root_device_name', '')
        instance_api._cloud_format_instance_bdm(
            context, os_instance, res, {}, {os_instance_id: []})
        self.assertEqual({}, res)

        res = {}
        setattr(os_instance, 'OS-EXT-SRV-ATTR:root_device_name', '/dev/vdd')
        instance_api._cloud_format_instance_bdm(
            context, os_instance, res, {}, {os_instance_id: []})
        self.assertEqual({'rootDeviceType': 'instance-store'}, res)

    @mock.patch('ec2api.api.instance._remove_instances')
    @mock.patch('novaclient.client.Client')
    def test_get_os_instances_by_instances(self, nova, remove_instances):
        nova = nova.return_value
        fake_context = base.create_context()
        os_instance_1 = fakes.OSInstance(fakes.OS_INSTANCE_1)
        os_instance_2 = fakes.OSInstance(fakes.OS_INSTANCE_2)

        def do_check(exactly_flag=None, specify_nova_client=False):
            nova.servers.get.side_effect = [os_instance_1,
                                            nova_exception.NotFound(404),
                                            os_instance_2]
            absent_instance = {'id': fakes.random_ec2_id('i'),
                               'os_id': fakes.random_os_id()}

            params = (fake_context, [fakes.DB_INSTANCE_1, absent_instance,
                                     fakes.DB_INSTANCE_2],
                      exactly_flag, nova if specify_nova_client else False)
            if exactly_flag:
                self.assertRaises(exception.InvalidInstanceIDNotFound,
                                  instance_api._get_os_instances_by_instances,
                                  *params)
            else:
                res = instance_api._get_os_instances_by_instances(*params)
                self.assertEqual([os_instance_1, os_instance_2],
                                 res)
            remove_instances.assert_called_once_with(fake_context,
                                                     [absent_instance])
            remove_instances.reset_mock()

        do_check(exactly_flag=True)
        # NOTE(ft): stop to return fake data by the mocked client and create
        # a new one to pass it into the function
        nova.servers.side_effect = None
        nova = mock.Mock()
        do_check(specify_nova_client=True)

    @mock.patch('ec2api.api.network_interface.delete_network_interface')
    @mock.patch('ec2api.api.network_interface._detach_network_interface_item')
    @mock.patch('ec2api.db.api.IMPL')
    def test_remove_instances(self, db_api, detach_network_interface_item,
                              delete_network_interface):
        fake_context = base.create_context()

        instances = [{'id': fakes.random_ec2_id('i')}
                     for dummy in range(4)]
        network_interfaces = [
            {'id': fakes.random_ec2_id('eni'),
             'instance_id': inst['id'],
             'delete_on_termination': num in (0, 1, 4, 6)}
            for num, inst in enumerate(itertools.chain(
                  *(list(zip(instances[:3], instances[:3])) +
                    [[{'id': fakes.random_ec2_id('i')}] * 2])))]
        network_interfaces.extend({'id': fakes.random_ec2_id('eni')}
                                  for dummy in range(2))

        instances_to_remove = instances[:2] + [instances[3]]
        network_interfaces_to_delete = network_interfaces[0:2]
        network_interfaces_to_detach = network_interfaces[0:4]

        db_api.get_items.side_effect = tools.get_db_api_get_items(
            *network_interfaces)

        instance_api._remove_instances(fake_context, instances_to_remove)

        for eni in network_interfaces_to_detach:
            detach_network_interface_item.assert_any_call(fake_context,
                                                          eni)
        for eni in network_interfaces_to_delete:
            delete_network_interface.assert_any_call(fake_context,
                                                     eni['id'])

    @mock.patch('cinderclient.client.Client')
    def test_get_os_volumes(self, cinder):
        cinder = cinder.return_value
        context = base.create_context()
        os_volume_ids = [fakes.random_os_id() for _i in range(5)]
        os_instance_ids = [fakes.random_os_id() for _i in range(2)]
        os_volumes = [
            fakes.OSVolume(
                {'id': os_volume_ids[0],
                 'status': 'attached',
                 'attachments': [{'server_id': os_instance_ids[0]}]}),
            fakes.OSVolume(
                {'id': os_volume_ids[1],
                 'status': 'attaching',
                 'attachments': []}),
            fakes.OSVolume(
                {'id': os_volume_ids[2],
                 'status': 'detaching',
                 'attachments': [{'server_id': os_instance_ids[0]}]}),
            fakes.OSVolume(
                {'id': os_volume_ids[3],
                 'status': 'attached',
                 'attachments': [{'server_id': os_instance_ids[1]}]}),
            fakes.OSVolume(
                {'id': os_volume_ids[4],
                 'status': 'available',
                 'attachments': []}),
        ]
        cinder.volumes.list.return_value = os_volumes
        res = instance_api._get_os_volumes(context)
        self.assertIn(os_instance_ids[0], res)
        self.assertIn(os_instance_ids[1], res)
        self.assertEqual([os_volumes[0], os_volumes[2]],
                         res[os_instance_ids[0]])
        self.assertEqual([os_volumes[3]], res[os_instance_ids[1]])
        cinder.volumes.list.assert_called_once_with(search_opts=None)

        context.is_os_admin = True
        instance_api._get_os_volumes(context)
        cinder.volumes.list.assert_called_with(
            search_opts={'all_tenants': True,
                         'project_id': context.project_id})

    @mock.patch('ec2api.clients.nova', wraps=ec2api.clients.nova)
    @mock.patch('ec2api.context.get_os_admin_context')
    @mock.patch('cinderclient.client.Client')
    @mock.patch('novaclient.client.Client')
    def test_is_ebs_instance(self, nova, cinder, get_os_admin_context,
                             nova_client_getter):
        nova = nova.return_value
        cinder = cinder.return_value
        context = base.create_context()
        os_instance = fakes.OSInstance_full({'id': fakes.random_os_id()})

        nova.servers.get.return_value = os_instance
        cinder.volumes.list.return_value = []
        self.assertFalse(instance_api._is_ebs_instance(context,
                                                       os_instance.id))

        cinder.volumes.list.return_value = [
            fakes.OSVolume(
                {'id': fakes.random_os_id(),
                 'status': 'attached',
                 'attachments': [{'device': '/dev/vda',
                                  'server_id': os_instance.id}]})]
        setattr(os_instance, 'OS-EXT-SRV-ATTR:root_device_name', '')
        self.assertFalse(instance_api._is_ebs_instance(context,
                                                       os_instance.id))

        setattr(os_instance, 'OS-EXT-SRV-ATTR:root_device_name', '/dev/vda')
        cinder.volumes.list.return_value = []
        self.assertFalse(instance_api._is_ebs_instance(context,
                                                       os_instance.id))

        cinder.volumes.list.return_value = [
            fakes.OSVolume(
                {'id': fakes.random_os_id(),
                 'status': 'attached',
                 'attachments': [{'device': '/dev/vda',
                                  'server_id': fakes.random_os_id()}]})]
        self.assertFalse(instance_api._is_ebs_instance(context,
                                                       os_instance.id))

        cinder.volumes.list.return_value = [
            fakes.OSVolume(
                {'id': fakes.random_os_id(),
                 'status': 'attached',
                 'attachments': [{'device': '/dev/vdb',
                                  'server_id': os_instance.id}]})]
        self.assertFalse(instance_api._is_ebs_instance(context,
                                                       os_instance.id))

        cinder.volumes.list.return_value = [
            fakes.OSVolume(
                {'id': fakes.random_os_id(),
                 'status': 'attached',
                 'attachments': [{'device': '/dev/vda',
                                  'server_id': os_instance.id}]})]
        self.assertTrue(instance_api._is_ebs_instance(context,
                                                      os_instance.id))
        nova_client_getter.assert_called_with(
            get_os_admin_context.return_value)
        cinder.volumes.list.assert_called_with(search_opts=None)

        cinder.volumes.list.return_value = [
            fakes.OSVolume(
                {'id': fakes.random_os_id(),
                 'status': 'attached',
                 'attachments': [{'device': 'vda',
                                  'server_id': os_instance.id}]})]
        self.assertTrue(instance_api._is_ebs_instance(context,
                                                      os_instance.id))
