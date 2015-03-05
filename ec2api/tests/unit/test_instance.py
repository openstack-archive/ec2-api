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
import datetime
import itertools
import random

import mock
from novaclient import exceptions as nova_exception
from oslotest import base as test_base

from ec2api.api import instance as instance_api
from ec2api import exception
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class InstanceTestCase(base.ApiTestCase):

    def setUp(self):
        super(InstanceTestCase, self).setUp()
        network_interface_api_patcher = mock.patch(
            'ec2api.api.instance.network_interface_api')
        self.network_interface_api = network_interface_api_patcher.start()
        self.addCleanup(network_interface_api_patcher.stop)
        address_api_patcher = mock.patch('ec2api.api.address')
        self.address_api = address_api_patcher.start()
        self.addCleanup(address_api_patcher.stop)
        security_group_api_patcher = mock.patch('ec2api.api.security_group')
        self.security_group_api = security_group_api_patcher.start()
        self.addCleanup(security_group_api_patcher.stop)
        utils_generate_uid_patcher = (
            mock.patch('ec2api.api.instance._utils_generate_uid'))
        self.utils_generate_uid = utils_generate_uid_patcher.start()
        self.addCleanup(utils_generate_uid_patcher.stop)
        novadb_patcher = (mock.patch('ec2api.api.instance.novadb'))
        self.novadb = novadb_patcher.start()
        self.addCleanup(novadb_patcher.stop)

        format_security_groups_ids_names = (
            self.security_group_api.format_security_groups_ids_names)
        format_security_groups_ids_names.return_value = {}

        self.fake_flavor = mock.Mock()
        self.fake_flavor.configure_mock(name='fake_flavor')
        self.nova_flavors.get.return_value = self.fake_flavor
        self.nova_flavors.list.return_value = [self.fake_flavor]

    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_ec2_network_interfaces')
    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_vpc_default_security_group_id')
    def test_run_instances(self, get_vpc_default_security_group_id,
                           get_ec2_network_interfaces):
        """Run instance with various network interface settings."""
        instance_api.instance_engine = (
            instance_api.InstanceEngineNeutron())
        self.set_mock_db_items(
            fakes.DB_SUBNET_1, fakes.DB_NETWORK_INTERFACE_1, fakes.DB_IMAGE_1,
            fakes.DB_IMAGE_ARI_1, fakes.DB_IMAGE_AKI_1)
        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        self.network_interface_api.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_1})

        self.db_api.add_item.return_value = fakes.DB_INSTANCE_1
        self.nova_servers.create.return_value = (
            fakes.OSInstance(
                fakes.ID_OS_INSTANCE_1, {'id': 'fakeFlavorId'},
                image={'id': fakes.ID_OS_IMAGE_1}))
        self.novadb.instance_get_by_uuid.return_value = fakes.NOVADB_INSTANCE_1
        self.novadb.block_device_mapping_get_all_by_instance.return_value = []
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
                [fakes.gen_ec2_instance(
                    fakes.ID_EC2_INSTANCE_1,
                    private_ip_address=fakes.IP_NETWORK_INTERFACE_1,
                    ec2_network_interfaces=[eni],
                    image_id=fakes.ID_EC2_IMAGE_1,
                    kernel_id=fakes.ID_EC2_IMAGE_AKI_1,
                    ramdisk_id=fakes.ID_EC2_IMAGE_ARI_1,
                    reservation_id=fakes.ID_EC2_RESERVATION_1)])
            get_ec2_network_interfaces.return_value = {
                    fakes.ID_EC2_INSTANCE_1: [eni]}

            params.update({'ImageId': fakes.ID_EC2_IMAGE_1,
                           'InstanceType': 'fake_flavor',
                           'MinCount': '1', 'MaxCount': '1'})
            resp = self.execute('RunInstances', params)

            self.assertEqual(200, resp['http_status_code'])
            resp.pop('http_status_code')
            self.assertThat(resp, matchers.DictMatches(expected_reservation))
            if create_network_interface_kwargs is not None:
                (self.network_interface_api.
                 create_network_interface.assert_called_once_with(
                     mock.ANY, fakes.ID_EC2_SUBNET_1,
                     **create_network_interface_kwargs))
            self.nova_servers.create.assert_called_once_with(
                '%s-%s' % (fakes.ID_EC2_RESERVATION_1, 0),
                fakes.ID_OS_IMAGE_1, self.fake_flavor,
                min_count=1, max_count=1,
                kernel_id=None, ramdisk_id=None,
                availability_zone=None,
                block_device_mapping={},
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
            self.novadb.instance_get_by_uuid.assert_called_once_with(
                mock.ANY, fakes.ID_OS_INSTANCE_1)
            get_ec2_network_interfaces.assert_called_once_with(
                mock.ANY, instance_ids=[fakes.ID_EC2_INSTANCE_1])
            self.assertEqual(2, self.db_api.get_item_ids.call_count)
            self.db_api.get_item_ids.assert_any_call(
                mock.ANY, 'aki', (fakes.ID_OS_IMAGE_AKI_1,))
            self.db_api.get_item_ids.assert_any_call(
                mock.ANY, 'ari', (fakes.ID_OS_IMAGE_ARI_1,))

            self.network_interface_api.reset_mock()
            self.nova_servers.reset_mock()
            self.db_api.reset_mock()
            self.novadb.reset_mock()
            get_ec2_network_interfaces.reset_mock()

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

    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_ec2_network_interfaces')
    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_vpc_default_security_group_id')
    def test_run_instances_multiple_networks(self,
                                             get_vpc_default_security_group_id,
                                             get_ec2_network_interfaces):
        """Run 2 instances at once on 2 subnets in all combinations."""
        instance_api.instance_engine = (
            instance_api.InstanceEngineNeutron())
        self._build_multiple_data_model()

        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        get_vpc_default_security_group_id.return_value = None

        get_ec2_network_interfaces.return_value = dict(
            (ec2_instance_id, list(eni_pair))
            for ec2_instance_id, eni_pair in zip(
                self.IDS_EC2_INSTANCE,
                zip(*[iter(self.EC2_ATTACHED_ENIS)] * 2)))
        ec2_instances = [
            fakes.gen_ec2_instance(ec2_instance_id, launch_index=l_i,
                                   ec2_network_interfaces=eni_pair,
                                   reservation_id=fakes.ID_EC2_RESERVATION_1)
            for l_i, (ec2_instance_id, eni_pair) in enumerate(zip(
                self.IDS_EC2_INSTANCE,
                zip(*[iter(self.EC2_ATTACHED_ENIS)] * 2)))]
        ec2_reservation = fakes.gen_ec2_reservation(fakes.ID_EC2_RESERVATION_1,
                                                    ec2_instances)

        self.set_mock_db_items(
            fakes.DB_IMAGE_1, fakes.DB_SUBNET_1, fakes.DB_SUBNET_2,
            *self.DB_DETACHED_ENIS)
        self.network_interface_api.create_network_interface.side_effect = (
            [{'networkInterface': eni}
             for eni in self.EC2_DETACHED_ENIS])
        self.nova_servers.create.side_effect = [
            fakes.OSInstance(os_instance_id, {'id': 'fakeFlavorId'})
            for os_instance_id in self.IDS_OS_INSTANCE]
        self.novadb.instance_get_by_uuid.side_effect = self.NOVADB_INSTANCES
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

        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(ec2_reservation),
                        verbose=True)

        self.network_interface_api.create_network_interface.assert_has_calls([
            mock.call(mock.ANY, ec2_subnet_id)
            for ec2_subnet_id in self.IDS_EC2_SUBNET_BY_PORT])
        self.nova_servers.create.assert_has_calls([
            mock.call(
                '%s-%s' % (fakes.ID_EC2_RESERVATION_1, launch_index),
                fakes.ID_OS_IMAGE_1, self.fake_flavor,
                min_count=1, max_count=1,
                kernel_id=None, ramdisk_id=None,
                availability_zone=None,
                block_device_mapping={},
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
    @mock.patch('ec2api.api.instance._format_reservation')
    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_ec2_classic_os_network')
    def test_run_instances_other_parameters(self, get_ec2_classic_os_network,
                                            format_reservation,
                                            parse_block_device_mapping):
        self.set_mock_db_items(
            fakes.DB_IMAGE_1, fakes.DB_IMAGE_AKI_1, fakes.DB_IMAGE_ARI_1)
        self.glance.images.get.side_effect = (
            fakes.get_by_1st_arg_getter({
                fakes.ID_OS_IMAGE_1: fakes.OSImage(fakes.OS_IMAGE_1),
                fakes.ID_OS_IMAGE_AKI_1: fakes.OSImage(fakes.OS_IMAGE_AKI_1),
                fakes.ID_OS_IMAGE_ARI_1: fakes.OSImage(fakes.OS_IMAGE_ARI_1)}))
        get_ec2_classic_os_network.return_value = {'id': fakes.random_os_id()}
        format_reservation.return_value = {}
        parse_block_device_mapping.return_value = 'fake_bdm'

        def do_check(engine, extra_kwargs={}, extra_db_instance={}):
            instance_api.instance_engine = engine

            resp = self.execute(
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
                 'BlockDeviceMapping.1.Ebs.DeleteOnTermination': 'False'})
            self.assertEqual(200, resp['http_status_code'])

            self.nova_servers.create.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY, min_count=1, max_count=1,
                userdata=None, kernel_id=fakes.ID_OS_IMAGE_AKI_1,
                ramdisk_id=fakes.ID_OS_IMAGE_ARI_1, key_name=None,
                block_device_mapping='fake_bdm',
                availability_zone='fake_zone', security_groups=['default'],
                **extra_kwargs)
            self.nova_servers.reset_mock()
            db_instance = {'os_id': mock.ANY,
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
                          'delete_on_termination': False}}],
                fakes.OSImage(fakes.OS_IMAGE_1))
            parse_block_device_mapping.reset_mock()

        do_check(
            instance_api.InstanceEngineNeutron(),
            extra_kwargs={
                'nics': [
                    {'net-id': get_ec2_classic_os_network.return_value['id']}],
            },
            extra_db_instance={'vpc_id': None})
        do_check(instance_api.InstanceEngineNova())

    @mock.patch('ec2api.api.instance._format_reservation')
    @mock.patch('ec2api.api.instance._get_os_instances_by_instances')
    def test_idempotent_run(self, get_os_instances_by_instances,
                            format_reservation):
        instance_engine = mock.MagicMock()
        instance_api.instance_engine = instance_engine
        get_ec2_network_interfaces = instance_engine.get_ec2_network_interfaces

        instances = [{'id': fakes.random_ec2_id('i'),
                      'os_id': fakes.random_os_id(),
                      'reservation_id': fakes.random_ec2_id('r'),
                      'client_token': 'client-token-%s' % ind}
                     for ind in range(3)]
        os_instances = [fakes.OSInstance(inst['os_id'])
                        for inst in instances]
        format_reservation.return_value = {'key': 'value'}

        # NOTE(ft): check select corresponding instance by client_token
        self.set_mock_db_items(instances[0], instances[1])
        get_os_instances_by_instances.return_value = [os_instances[1]]
        self.novadb.instance_get_by_uuid.return_value = 'novadb_instance'
        get_ec2_network_interfaces.return_value = 'ec2_network_interfaces'

        resp = self.execute('RunInstances',
                            {'MinCount': '1', 'MaxCount': '1',
                             'ImageId': fakes.ID_EC2_IMAGE_1,
                             'InstanceType': 'fake_flavor',
                             'ClientToken': 'client-token-1'})
        self.assertEqual({'http_status_code': 200,
                          'key': 'value'},
                         resp)
        format_reservation.assert_called_once_with(
            mock.ANY, instances[1]['reservation_id'],
            [(instances[1], os_instances[1], 'novadb_instance')],
            'ec2_network_interfaces')
        get_os_instances_by_instances.assert_called_once_with(
            mock.ANY, {instances[1]['os_id']: instances[1]})
        self.novadb.instance_get_by_uuid.assert_called_once_with(
            mock.ANY, os_instances[1].id)
        get_ec2_network_interfaces.assert_called_once_with(
            mock.ANY, [instances[1]['id']])

        # NOTE(ft): check pass to general run_instances logic if no
        # corresponding client_token is found
        instance_engine.run_instances.return_value = {}
        resp = self.execute('RunInstances',
                            {'MinCount': '1', 'MaxCount': '1',
                             'ImageId': fakes.ID_EC2_IMAGE_1,
                             'InstanceType': 'fake_flavor',
                             'ClientToken': 'client-token-2'})
        self.assertTrue(instance_engine.run_instances.called)

        # NOTE(ft): check pass to general run_instances logic if no more
        # corresponding OS instance exists
        instance_engine.reset_mock()
        get_os_instances_by_instances.return_value = []
        resp = self.execute('RunInstances',
                            {'MinCount': '1', 'MaxCount': '1',
                             'ImageId': fakes.ID_EC2_IMAGE_1,
                             'InstanceType': 'fake_flavor',
                             'ClientToken': 'client-token-1'})
        self.assertTrue(instance_engine.run_instances.called)

        # NOTE(ft): check case for several instances with same client_token,
        # but one no more exists in OS
        format_reservation.reset_mock()
        get_os_instances_by_instances.reset_mock()
        instance_engine.reset_mock()
        self.novadb.reset_mock()
        for inst in instances:
            inst['reservation_id'] = instances[0]['reservation_id']
            inst['client_token'] = 'client-token'
        self.set_mock_db_items(*instances)
        get_os_instances_by_instances.return_value = [os_instances[0],
                                                      os_instances[2]]
        self.novadb.instance_get_by_uuid.side_effect = ['novadb-instance-0',
                                                        'novadb-instance-2']
        get_ec2_network_interfaces.return_value = 'ec2_network_interfaces'

        resp = self.execute('RunInstances',
                            {'MinCount': '1', 'MaxCount': '1',
                             'ImageId': fakes.ID_EC2_IMAGE_1,
                             'InstanceType': 'fake_flavor',
                             'ClientToken': 'client-token'})
        self.assertEqual({'http_status_code': 200,
                          'key': 'value'},
                         resp)
        format_reservation.assert_called_once_with(
            mock.ANY, instances[0]['reservation_id'],
            [(instances[0], os_instances[0], 'novadb-instance-0'),
             (instances[2], os_instances[2], 'novadb-instance-2')],
            'ec2_network_interfaces')
        get_os_instances_by_instances.assert_called_once_with(
            mock.ANY, dict((inst['os_id'], inst) for inst in instances))
        self.assertEqual([mock.call(mock.ANY, os_instances[0].id),
                          mock.call(mock.ANY, os_instances[2].id)],
                         self.novadb.instance_get_by_uuid.mock_calls)
        get_ec2_network_interfaces.assert_called_once_with(
            mock.ANY, [instances[0]['id'], instances[2]['id']])

    def test_run_instances_rollback(self):
        instance_api.instance_engine = (
            instance_api.InstanceEngineNeutron())
        self.set_mock_db_items(fakes.DB_IMAGE_1, fakes.DB_SUBNET_1,
                               fakes.DB_NETWORK_INTERFACE_1)
        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)

        self.network_interface_api.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_1})
        self.db_api.add_item.return_value = fakes.DB_INSTANCE_1
        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1
        self.nova_servers.create.return_value = (
            fakes.OSInstance(fakes.ID_OS_INSTANCE_1, {'id': 'fakeFlavorId'},
                             image={'id': fakes.ID_OS_IMAGE_1}))
        self.novadb.instance_get_by_uuid.side_effect = Exception()

        def do_check(params, new_port=True, delete_on_termination=None):
            mock_manager = mock.MagicMock()
            mock_manager.attach_mock(self.network_interface_api,
                                     'network_interface_api')
            mock_manager.attach_mock(self.neutron, 'neutron')
            mock_manager.attach_mock(self.nova_servers, 'nova_servers')

            params.update({'ImageId': fakes.ID_EC2_IMAGE_1,
                           'InstanceType': 'fake_flavor',
                           'MinCount': '1', 'MaxCount': '1'})
            self.execute('RunInstances', params)

            calls = []
            calls.append(
                mock.call.network_interface_api._detach_network_interface_item(
                    mock.ANY, fakes.DB_NETWORK_INTERFACE_1))
            if not new_port:
                calls.append(
                    mock.call.neutron.update_port(
                        fakes.ID_OS_PORT_1,
                        {'port': {'device_id': '',
                                  'device_owner': ''}}))
            calls.append(
                mock.call.nova_servers.delete(fakes.ID_OS_INSTANCE_1))
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
            self.nova_servers.reset_mock()
            self.db_api.reset_mock()

        do_check({'SubnetId': fakes.ID_EC2_SUBNET_1})

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1})

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1,
                  'NetworkInterface.1.DeleteOnTermination': 'False'},
                 delete_on_termination=False)

        do_check({'NetworkInterface.1.DeviceIndex': '0',
                  'NetworkInterface.1.NetworkInterfaceId': (
                        fakes.ID_EC2_NETWORK_INTERFACE_1)},
                 new_port=False)

    @mock.patch('ec2api.api.instance.InstanceEngineNeutron.'
                'get_ec2_network_interfaces')
    @mock.patch('ec2api.api.instance._format_reservation')
    def test_run_instances_multiply_rollback(self, format_reservation,
                                             get_ec2_network_interfaces):
        instances = [{'id': fakes.random_ec2_id('i'),
                      'os_id': fakes.random_os_id()}
                     for dummy in range(3)]
        os_instances = [fakes.OSInstance(inst['os_id'])
                        for inst in instances]
        network_interfaces = [{'id': fakes.random_ec2_id('eni'),
                               'os_id': fakes.random_os_id()}
                              for dummy in range(3)]

        self.set_mock_db_items(fakes.DB_IMAGE_1, fakes.DB_SUBNET_1,
                               *network_interfaces)
        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)

        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1
        get_ec2_network_interfaces.return_value = []

        def do_check(engine):
            instance_api.instance_engine = engine

            self.network_interface_api.create_network_interface.side_effect = [
                {'networkInterface': {'networkInterfaceId': eni['id']}}
                for eni in network_interfaces]
            self.db_api.add_item.side_effect = instances
            self.nova_servers.create.side_effect = os_instances
            self.novadb.instance_get_by_uuid.side_effect = [
                {}, {}, Exception()]
            format_reservation.side_effect = (
                lambda _context, r_id, instance_info, *args, **kwargs: (
                    {'reservationId': r_id,
                     'instancesSet': [
                          {'instanceId': inst['id']}
                          for inst, _os_inst, _novadb_inst in instance_info]}))

            resp = self.execute('RunInstances',
                                {'ImageId': fakes.ID_EC2_IMAGE_1,
                                 'InstanceType': 'fake_flavor',
                                 'MinCount': '2', 'MaxCount': '3',
                                 'SubnetId': fakes.ID_EC2_SUBNET_1})
            self.assertEqual(200, resp['http_status_code'])
            resp.pop('http_status_code')
            self.assertThat(resp,
                            matchers.DictMatches(
                                {'reservationId': fakes.ID_EC2_RESERVATION_1,
                                 'instancesSet': [
                                     {'instanceId': inst['id']}
                                     for inst in instances[:2]]}))

            self.nova_servers.delete.assert_called_once_with(
                instances[2]['os_id'])
            self.db_api.delete_item.assert_called_once_with(
                mock.ANY, instances[2]['id'])

            self.nova_servers.reset_mock()
            self.db_api.reset_mock()

        do_check(instance_api.InstanceEngineNeutron())
        (self.network_interface_api._detach_network_interface_item.
         assert_called_once_with(mock.ANY, network_interfaces[2]))
        (self.network_interface_api.delete_network_interface.
         assert_called_once_with(
             mock.ANY, network_interface_id=network_interfaces[2]['id']))

        do_check(instance_api.InstanceEngineNova())

    def test_run_instances_invalid_parameters(self):
        resp = self.execute('RunInstances',
                            {'ImageId': fakes.ID_EC2_IMAGE_1,
                             'MinCount': '0', 'MaxCount': '0'})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidParameterValue', resp['Error']['Code'])

        resp = self.execute('RunInstances',
                            {'ImageId': fakes.ID_EC2_IMAGE_1,
                             'MinCount': '1', 'MaxCount': '0'})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidParameterValue', resp['Error']['Code'])

        resp = self.execute('RunInstances',
                            {'ImageId': fakes.ID_EC2_IMAGE_1,
                             'MinCount': '0', 'MaxCount': '1'})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidParameterValue', resp['Error']['Code'])

        resp = self.execute('RunInstances',
                            {'ImageId': fakes.ID_EC2_IMAGE_1,
                             'MinCount': '2', 'MaxCount': '1'})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidParameterValue', resp['Error']['Code'])

    @mock.patch.object(fakes.OSInstance, 'delete', autospec=True)
    @mock.patch.object(fakes.OSInstance, 'get', autospec=True)
    def test_terminate_instances(self, os_instance_get, os_instance_delete):
        """Terminate 2 instances in one request."""
        instance_api.instance_engine = (
            instance_api.InstanceEngineNeutron())
        self.set_mock_db_items(
            fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2,
            fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2)
        self.nova_servers.get.side_effect = [fakes.OS_INSTANCE_1,
                                             fakes.OS_INSTANCE_2]

        resp = self.execute('TerminateInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                             'InstanceId.2': fakes.ID_EC2_INSTANCE_2})

        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
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
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2]))
        (self.network_interface_api.
         detach_network_interface.assert_called_once_with(
             mock.ANY, fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH))
        self.assertEqual(2, self.nova_servers.get.call_count)
        self.nova_servers.get.assert_any_call(fakes.ID_OS_INSTANCE_1)
        self.nova_servers.get.assert_any_call(fakes.ID_OS_INSTANCE_2)
        self.assertEqual(
            0, self.address_api.dissassociate_address_item.call_count)
        self.assertFalse(self.db_api.delete_item.called)
        self.assertEqual(2, os_instance_delete.call_count)
        self.assertEqual(2, os_instance_get.call_count)
        for call_num, inst_id in enumerate([fakes.OS_INSTANCE_1,
                                            fakes.OS_INSTANCE_2]):
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
        self.nova_servers.get.side_effect = (
            lambda ec2_id: fakes.OSInstance(ec2_id, vm_state='active'))

        def do_check(mock_eni_list=[], detached_enis=[], deleted_enis=[]):
            self.set_mock_db_items(self.DB_FAKE_ENI,
                                   *(self.DB_INSTANCES + mock_eni_list))

            resp = self.execute('TerminateInstances',
                                {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                                 'InstanceId.2': fakes.ID_EC2_INSTANCE_2})

            self.assertEqual(200, resp['http_status_code'])
            resp.pop('http_status_code')
            self.assertThat(
                resp, matchers.DictMatches(ec2_terminate_instances_result))
            detach_network_interface = (
                self.network_interface_api.detach_network_interface)
            self.assertEqual(len(detached_enis),
                             detach_network_interface.call_count)
            for ec2_eni in detached_enis:
                detach_network_interface.assert_any_call(
                    mock.ANY,
                    ('eni-attach-%s' % ec2_eni['id'].split('-')[-1]))
            self.assertFalse(self.db_api.delete_item.called)

            detach_network_interface.reset_mock()
            self.db_api.delete_item.reset_mock()

        # NOTE(ft): 2 instances; the first has 2 correct ports;
        # the second has the first port attached by EC2 API but later detached
        # by OpenStack and the second port created through EC2 API but
        # attached by OpenStack only
        do_check(
            mock_eni_list=[
                self.DB_ATTACHED_ENIS[0], self.DB_ATTACHED_ENIS[1],
                self.DB_ATTACHED_ENIS[2], self.DB_DETACHED_ENIS[3]],
            detached_enis=[self.DB_ATTACHED_ENIS[1]],
            deleted_enis=[self.DB_ATTACHED_ENIS[0],
                          self.DB_ATTACHED_ENIS[2]])

        # NOTE(ft): 2 instances: the first has the first port attached by
        # OpenStack only, the second port is attached correctly;
        # the second instance has one port created and attached by OpenStack
        # only
        do_check(
            mock_eni_list=[self.DB_ATTACHED_ENIS[1]],
            detached_enis=[self.DB_ATTACHED_ENIS[1]],
            deleted_enis=[])

    def test_terminate_instances_invalid_parameters(self):
        resp = self.execute('TerminateInstances',
                            {'InstanceId.1': fakes.random_ec2_id('i')})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidInstanceID.NotFound', resp['Error']['Code'])

    @mock.patch('ec2api.api.instance._get_os_instances_by_instances')
    def _test_instances_operation(self, operation, os_instance_operation,
                                  valid_state, invalid_state,
                                  get_os_instances_by_instances):
        os_instance_1 = copy.deepcopy(fakes.OS_INSTANCE_1)
        os_instance_2 = copy.deepcopy(fakes.OS_INSTANCE_2)
        for inst in (os_instance_1, os_instance_2):
            setattr(inst, 'OS-EXT-STS:vm_state', valid_state)

        self.set_mock_db_items(fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2)
        get_os_instances_by_instances.return_value = [os_instance_1,
                                                      os_instance_2]

        resp = self.execute(operation,
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                             'InstanceId.2': fakes.ID_EC2_INSTANCE_2})
        self.assertEqual({'http_status_code': 200,
                          'return': True},
                         resp)
        self.assertEqual([mock.call(os_instance_1), mock.call(os_instance_2)],
                         os_instance_operation.mock_calls)
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2]))
        get_os_instances_by_instances.assert_called_once_with(
            mock.ANY, [fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2], exactly=True)

        setattr(os_instance_2, 'OS-EXT-STS:vm_state', invalid_state)
        os_instance_operation.reset_mock()
        resp = self.execute('StartInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                             'InstanceId.2': fakes.ID_EC2_INSTANCE_2})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('IncorrectInstanceState', resp['Error']['Code'])
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
        self.nova_servers.get.return_value = fakes.OS_INSTANCE_2
        getter.return_value = 'fake_data'
        utcnow.return_value = datetime.datetime(2015, 1, 19, 23, 34, 45, 123)
        resp = self.execute(operation,
                            {'InstanceId': fakes.ID_EC2_INSTANCE_2})
        self.assertEqual({'http_status_code': 200,
                          'instanceId': fakes.ID_EC2_INSTANCE_2,
                          'timestamp': '2015-01-19T23:34:45.000Z',
                          key: 'fake_data'},
                         resp)
        self.db_api.get_item_by_id.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_INSTANCE_2)
        self.nova_servers.get.assert_called_once_with(fakes.ID_OS_INSTANCE_2)
        getter.assert_called_once_with(fakes.OS_INSTANCE_2)

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
        instance_api.instance_engine = (
            instance_api.InstanceEngineNeutron())
        self.set_mock_db_items(
            fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2,
            fakes.DB_IMAGE_1, fakes.DB_IMAGE_2,
            fakes.DB_IMAGE_ARI_1, fakes.DB_IMAGE_AKI_1,
            fakes.DB_VOLUME_1, fakes.DB_VOLUME_2, fakes.DB_VOLUME_3)
        self.nova_servers.list.return_value = [fakes.OS_INSTANCE_1,
                                               fakes.OS_INSTANCE_2]
        self.novadb.instance_get_by_uuid.side_effect = (
            fakes.get_by_2nd_arg_getter({
                fakes.ID_OS_INSTANCE_1: fakes.NOVADB_INSTANCE_1,
                fakes.ID_OS_INSTANCE_2: fakes.NOVADB_INSTANCE_2}))
        self.novadb.block_device_mapping_get_all_by_instance.side_effect = (
            fakes.get_by_2nd_arg_getter({
                fakes.ID_OS_INSTANCE_1: fakes.NOVADB_BDM_INSTANCE_1,
                fakes.ID_OS_INSTANCE_2: fakes.NOVADB_BDM_INSTANCE_2}))
        self.network_interface_api.describe_network_interfaces.side_effect = (
            lambda *args, **kwargs: copy.deepcopy({
                'networkInterfaceSet': [fakes.EC2_NETWORK_INTERFACE_1,
                                        fakes.EC2_NETWORK_INTERFACE_2]}))

        resp = self.execute('DescribeInstances', {})

        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'reservationSet': [fakes.EC2_RESERVATION_1,
                                fakes.EC2_RESERVATION_2]},
            orderless_lists=True))

        self.db_api.get_items_by_ids = tools.CopyingMock(
            return_value=[fakes.DB_INSTANCE_1])
        resp = self.execute('DescribeInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'reservationSet': [fakes.EC2_RESERVATION_1]},
            orderless_lists=True))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_INSTANCE_1]))
        (self.network_interface_api.describe_network_interfaces.
         assert_called_with(mock.ANY))

        self.check_filtering(
            'DescribeInstances', 'reservationSet',
            [('block-device-mapping.device-name',
              fakes.ROOT_DEVICE_NAME_INSTANCE_2),
             ('client-token', fakes.CLIENT_TOKEN_INSTANCE_2),
             # TODO(ft): support filtering by none/empty value
             # ('dns-name', ''),
             ('image-id', fakes.ID_EC2_IMAGE_1),
             ('instance-id', fakes.ID_EC2_INSTANCE_2),
             ('instance-type', 'fake_flavor'),
             ('ip-address', fakes.IP_ADDRESS_2),
             ('kernel-id', fakes.ID_EC2_IMAGE_AKI_1),
             ('key-name', fakes.NAME_KEY_PAIR),
             # TODO(ft): support filtering by a none/empty value
             # ('launch-index', 0),
             # TODO(ft): fill the field in fakes with correct value
             # ('launch-time', ),
             ('private-dns-name', '%s-%s' % (fakes.ID_EC2_RESERVATION_1, 0)),
             ('private-ip-address', fakes.IP_NETWORK_INTERFACE_2),
             ('ramdisk-id', fakes.ID_EC2_IMAGE_ARI_1),
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
             # TODO(ft): support filtering by a boolean value
             # ('network-interface.requester-managed', False),
             ('network-interface.status', 'in-use'),
             # TODO(ft): declare a constant for the mac in fakes
             ('network-interface.mac-address', 'fb:10:2e:b2:ba:b7'),
             # TODO(ft): support filtering by a boolean value
             # ('network-interface.source-destination-check', True),
             ('reservation-id', fakes.ID_EC2_RESERVATION_1),
             ('owner-id', fakes.ID_OS_PROJECT)])
        self.check_tag_support(
            'DescribeInstances', ['reservationSet', 'instancesSet'],
            fakes.ID_EC2_INSTANCE_1, 'instanceId')

    def test_describe_instances_ec2_classic(self):
        instance_api.instance_engine = (
            instance_api.InstanceEngineNova())
        self.set_mock_db_items(
            fakes.DB_INSTANCE_2, fakes.DB_IMAGE_1, fakes.DB_IMAGE_2,
            fakes.DB_VOLUME_1, fakes.DB_VOLUME_2, fakes.DB_VOLUME_3)
        self.nova_servers.list.return_value = [fakes.OS_INSTANCE_2]
        self.novadb.instance_get_by_uuid.return_value = (
            fakes.NOVADB_INSTANCE_2)
        self.novadb.block_device_mapping_get_all_by_instance.return_value = (
            fakes.NOVADB_BDM_INSTANCE_2)

        resp = self.execute('DescribeInstances', {})

        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'reservationSet': [fakes.EC2_RESERVATION_2]},
            orderless_lists=True))

    def test_describe_instances_mutliple_networks(self):
        """Describe 2 instances with various combinations of network."""
        instance_api.instance_engine = (
            instance_api.InstanceEngineNeutron())
        self._build_multiple_data_model()

        self.set_mock_db_items(*self.DB_INSTANCES)
        self.novadb.instance_get_by_uuid.side_effect = (
            fakes.get_by_2nd_arg_getter(
                dict((os_id, novadb_instance)
                     for os_id, novadb_instance in zip(
                        self.IDS_OS_INSTANCE,
                        self.NOVADB_INSTANCES))))
        describe_network_interfaces = (
            self.network_interface_api.describe_network_interfaces)

        def do_check(ips_by_instance=[], ec2_enis_by_instance=[],
                     ec2_instance_ips=[]):
            describe_network_interfaces.return_value = copy.deepcopy(
                {'networkInterfaceSet': list(
                                itertools.chain(*ec2_enis_by_instance))})
            self.nova_servers.list.return_value = [
                fakes.OSInstance(
                     os_id, {'id': 'fakeFlavorId'},
                     addresses=dict((subnet_name,
                                     [{'addr': addr,
                                       'version': 4,
                                       'OS-EXT-IPS:type': 'fixed'}])
                                    for subnet_name, addr in ips))
                for os_id, ips in zip(
                    self.IDS_OS_INSTANCE,
                    ips_by_instance)]

            resp = self.execute('DescribeInstances', {})

            self.assertEqual(200, resp['http_status_code'])
            resp.pop('http_status_code')

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
        self.nova_servers.list.return_value = [fakes.OS_INSTANCE_2]
        self.novadb.instance_get_by_uuid.return_value = (
            fakes.NOVADB_INSTANCE_2)
        self.novadb.block_device_mapping_get_all_by_instance.return_value = (
            fakes.NOVADB_BDM_INSTANCE_2)

        resp = self.execute('DescribeInstances', {})

        self.assertThat(resp,
                        matchers.DictMatches(
                            {'http_status_code': 200,
                             'reservationSet': [fakes.EC2_RESERVATION_2]},
                            orderless_lists=True))
        remove_instances.assert_called_once_with(
            mock.ANY, [fakes.DB_INSTANCE_1], purge_linked_items=False)

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
            fakes.OSInstance(inst['os_id'])
            for inst in db_instances]
        self.nova_servers.list.return_value = os_instances
        format_instance.side_effect = (
            lambda context, instance, *args: (
                {'instanceId': instance['id'],
                 'amiLaunchIndex': instance['launch_index']}))

        resp = self.execute('DescribeInstances', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual(
            [0, 1, 2, 3, 4],
            [inst['amiLaunchIndex']
             for inst in resp['reservationSet'][0]['instancesSet']])

    def test_describe_instances_invalid_parameters(self):
        resp = self.execute('DescribeInstances', {'InstanceId.1':
                                                  fakes.random_ec2_id('i')})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidInstanceID.NotFound', resp['Error']['Code'])

        self.set_mock_db_items(fakes.DB_INSTANCE_2)
        resp = self.execute('DescribeInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_2,
                             'InstanceId.2': fakes.random_ec2_id('i')})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidInstanceID.NotFound', resp['Error']['Code'])

    def test_describe_instance_attributes(self):
        self.set_mock_db_items(fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2,
                               fakes.DB_IMAGE_ARI_1, fakes.DB_IMAGE_AKI_1,
                               fakes.DB_VOLUME_2)
        self.nova_servers.get.side_effect = (
            fakes.get_by_1st_arg_getter({
                fakes.ID_OS_INSTANCE_1: fakes.OS_INSTANCE_1,
                fakes.ID_OS_INSTANCE_2: fakes.OS_INSTANCE_2}))
        self.novadb.instance_get_by_uuid.side_effect = (
            fakes.get_by_2nd_arg_getter({
                fakes.ID_OS_INSTANCE_1: fakes.NOVADB_INSTANCE_1,
                fakes.ID_OS_INSTANCE_2: fakes.NOVADB_INSTANCE_2}))
        self.novadb.block_device_mapping_get_all_by_instance.side_effect = (
            fakes.get_by_2nd_arg_getter({
                fakes.ID_OS_INSTANCE_1: fakes.NOVADB_BDM_INSTANCE_1,
                fakes.ID_OS_INSTANCE_2: fakes.NOVADB_BDM_INSTANCE_2}))
        self.cinder.volumes.get.return_value = (
            fakes.CinderVolume(fakes.OS_VOLUME_2))

        def do_check(instance_id, attribute, expected):
            resp = self.execute('DescribeInstanceAttribute',
                                {'InstanceId': instance_id,
                                 'Attribute': attribute})
            expected.update({'http_status_code': 200,
                             'instanceId': instance_id})
            self.assertThat(resp, matchers.DictMatches(expected))

        do_check(fakes.ID_EC2_INSTANCE_2, 'blockDeviceMapping',
                 {'rootDeviceType': 'ebs',
                  'blockDeviceMapping': (
                        fakes.EC2_INSTANCE_2['blockDeviceMapping'])})
        do_check(fakes.ID_EC2_INSTANCE_2, 'disableApiTermination',
                 {'disableApiTermination': {'value': False}})
        do_check(fakes.ID_EC2_INSTANCE_2, 'groupSet',
                 {'groupSet': fakes.EC2_RESERVATION_2['groupSet']})
        do_check(fakes.ID_EC2_INSTANCE_2, 'instanceInitiatedShutdownBehavior',
                 {'instanceInitiatedShutdownBehavior': {'value': 'stop'}})
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
                range(subnets_count) * instances_count,
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
                range(subnets_count) * instances_count)]
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
        novadb_instances = [
            {'kernel_id': None,
             'ramdisk_id': None,
             'root_device_name': '/dev/vda',
             'hostname': '%s-%s' % (fakes.ID_EC2_RESERVATION_1, l_i)}
            for l_i, ec2_id in enumerate(ids_ec2_instance)]

        self.IDS_EC2_SUBNET = ids_ec2_subnet
        self.IDS_OS_PORT = ids_os_port
        self.IDS_OS_INSTANCE = ids_os_instance
        self.IDS_EC2_INSTANCE = ids_ec2_instance
        self.IDS_EC2_SUBNET_BY_PORT = ids_ec2_subnet_by_port
        self.DB_ATTACHED_ENIS = db_attached_enis
        self.DB_DETACHED_ENIS = db_detached_enis
        self.EC2_ATTACHED_ENIS = ec2_attached_enis
        self.EC2_DETACHED_ENIS = ec2_detached_enis
        self.DB_INSTANCES = db_instances
        self.NOVADB_INSTANCES = novadb_instances

        # NOTE(ft): additional fake data to check filtering, etc
        self.DB_FAKE_ENI = fakes.gen_db_network_interface(
            fakes.random_ec2_id('eni'), fakes.random_os_id(),
            fakes.ID_EC2_VPC_1, fakes.ID_EC2_SUBNET_2,
            'fake_ip')
        ec2_fake_eni = fakes.gen_ec2_network_interface(
            self.DB_FAKE_ENI['id'],
            fakes.EC2_SUBNET_2, ['fake_ip'])
        self.OS_FAKE_PORT = fakes.gen_os_port(
            fakes.random_os_id(), ec2_fake_eni,
            fakes.ID_OS_SUBNET_2, ['fake_ip'])


# TODO(ft): add tests for get_vpc_default_security_group_id,

class InstancePrivateTestCase(test_base.BaseTestCase):

    def test_merge_network_interface_parameters(self):
        engine = instance_api.InstanceEngineNeutron()

        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            None, 'subnet-1', None, None,
            [{'device_index': 0, 'private_ip_address': '10.10.10.10'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            None, None, '10.10.10.10', None,
            [{'device_index': 0, 'subnet_id': 'subnet-1'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            ['default'], None, None, None,
            [{'device_index': 0, 'subnet_id': 'subnet-1'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            None, None, None, ['sg-1'],
            [{'device_index': 0, 'subnet_id': 'subnet-1'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            None, 'subnet-1', None, None,
            [{'device_index': 1, 'associate_public_ip_address': True}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            None, 'subnet-1', None, None,
            [{'device_index': 0, 'associate_public_ip_address': True},
             {'device_index': 1, 'subnet_id': 'subnet-2'}])
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            None, 'subnet-1', None, None,
            [{'device_index': 0}])

        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            ['default'], 'subnet-1', None, None, None)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            None, None, '10.10.10.10', None, None)
        self.assertRaises(
            exception.InvalidParameterCombination,
            engine.merge_network_interface_parameters,
            None, None, None, ['sg-1'], None)

        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1'}]),
            engine.merge_network_interface_parameters(
                None, 'subnet-1', None, None, None))
        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1',
                     'private_ip_address': '10.10.10.10'}]),
            engine.merge_network_interface_parameters(
                None, 'subnet-1', '10.10.10.10', None, None))
        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1',
                     'private_ip_address': '10.10.10.10',
                     'security_group_id': ['sg-1']}]),
            engine.merge_network_interface_parameters(
                None, 'subnet-1', '10.10.10.10', ['sg-1'], None))
        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1',
                     'security_group_id': ['sg-1']}]),
            engine.merge_network_interface_parameters(
                None, 'subnet-1', None, ['sg-1'], None))

        self.assertEqual(
            (None, [{'device_index': 0,
                     'subnet_id': 'subnet-1'}]),
            engine.merge_network_interface_parameters(
                None, None, None, None,
                [{'device_index': 0, 'subnet_id': 'subnet-1'}]))
        self.assertEqual(
            (['default'], []),
            engine.merge_network_interface_parameters(
                ['default'], None, None, None, None))
        self.assertEqual((None, []),
                         engine.merge_network_interface_parameters(
                                None, None, None, None, None))

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
        context = mock.Mock()
        db_api.get_item_by_id.side_effect = fakes.get_db_api_get_item_by_id(
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
               'detach_on_crash': True,
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
        fake_context = mock.Mock(service_catalog=[{'type': 'fake'}])

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
            'status': None,
            'properties': {}})
        get_os_image.return_value = os_image

        self.assertRaises(
            exception.ImageNotActive,
            instance_api._parse_image_parameters,
            fake_context, fakes.random_ec2_id('ami'), None, None)

        os_image.status = 'active'
        os_image.properties['image_state'] = 'decrypting'

        self.assertRaises(
            exception.ImageNotActive,
            instance_api._parse_image_parameters,
            fake_context, fakes.random_ec2_id('ami'), None, None)

    @mock.patch('ec2api.db.api.IMPL')
    def test_parse_block_device_mapping(self, db_api):
        fake_context = mock.Mock(service_catalog=[{'type': 'fake'}])
        os_image = fakes.OSImage(fakes.OS_IMAGE_1)

        db_api.get_item_by_id.side_effect = fakes.get_db_api_get_item_by_id(
            fakes.DB_VOLUME_1, fakes.DB_VOLUME_2, fakes.DB_VOLUME_3,
            fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2)

        res = instance_api._parse_block_device_mapping(
            fake_context, [], os_image)
        self.assertEqual({}, res)

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
                            'ebs': {'volume_size': 55}}],
            os_image)
        self.assertThat(
            res,
            matchers.DictMatches(
                {'/dev/vdf': fakes.ID_OS_SNAPSHOT_1 + ':snap::True',
                 '/dev/vdg': fakes.ID_OS_SNAPSHOT_2 + ':snap:111:False',
                 '/dev/vdh': fakes.ID_OS_VOLUME_1 + ':vol::True',
                 '/dev/vdi': fakes.ID_OS_VOLUME_2 + ':vol::True',
                 '/dev/sdb1': '::55:'},
                orderless_lists=True))

    @mock.patch('ec2api.api.instance.novadb')
    @mock.patch('novaclient.v1_1.client.Client')
    @mock.patch('ec2api.db.api.IMPL')
    def test_format_instance(self, db_api, nova, novadb):
        nova = nova.return_value
        fake_context = mock.Mock(service_catalog=[{'type': 'fake'}])
        fake_flavor = mock.Mock()
        fake_flavor.configure_mock(name='fake_flavor')
        nova.flavors.get.return_value = fake_flavor

        instance = {'id': fakes.random_ec2_id('i'),
                    'os_id': fakes.random_os_id(),
                    'launch_index': 0}
        os_instance = fakes.OSInstance(instance['os_id'],
                                       flavor={'id': 'fakeFlavorId'})
        novadb_instance = {'kernel_id': None,
                           'ramdisk_id': None,
                           'hostname': instance['id']}

        # NOTE(ft): check instance state formatting
        setattr(os_instance, 'OS-EXT-STS:vm_state', 'active')
        formatted_instance = instance_api._format_instance(
            fake_context, instance, os_instance, novadb_instance, [], {})
        self.assertEqual({'name': 'running', 'code': 16},
                         formatted_instance['instanceState'])

        setattr(os_instance, 'OS-EXT-STS:vm_state', 'stopped')
        formatted_instance = instance_api._format_instance(
            fake_context, instance, os_instance, novadb_instance, [], {})
        self.assertEqual({'name': 'stopped', 'code': 80},
                         formatted_instance['instanceState'])

        # NOTE(ft): check auto creating of DB item for unknown OS images
        os_instance.image = {'id': fakes.random_os_id()}
        novadb_instance['kernel_id'] = fakes.random_os_id()
        novadb_instance['ramdisk_id'] = fakes.random_os_id()
        formatted_instance = instance_api._format_instance(
            fake_context, instance, os_instance, novadb_instance, [], {})
        db_api.add_item_id.assert_has_calls(
            [mock.call(mock.ANY, 'ami', os_instance.image['id']),
             mock.call(mock.ANY, 'aki', novadb_instance['kernel_id']),
             mock.call(mock.ANY, 'ari', novadb_instance['ramdisk_id'])],
            any_order=True)

    @mock.patch('cinderclient.v1.client.Client')
    @mock.patch('ec2api.api.instance.novadb')
    def test_format_instance_bdm(self, novadb, cinder):
        cinder = cinder.return_value
        cinder.volumes.get.return_value = (
            mock.Mock(status='attached', attachments={'device': 'fake'}))
        id_os_instance_1 = fakes.random_os_id()
        id_os_instance_2 = fakes.random_os_id()
        novadb.block_device_mapping_get_all_by_instance.side_effect = (
            fakes.get_by_2nd_arg_getter({
                id_os_instance_1: [{'device_name': '/dev/sdb1',
                                    'delete_on_termination': False,
                                    'snapshot_id': '1',
                                    'volume_id': '2',
                                    'no_device': False},
                                   {'device_name': '/dev/sdb2',
                                    'delete_on_termination': False,
                                    'snapshot_id': None,
                                    'volume_id': '3',
                                    'volume_size': 1,
                                    'no_device': False},
                                   {'device_name': '/dev/sdb3',
                                    'delete_on_termination': True,
                                    'snapshot_id': '4',
                                    'volume_id': '5',
                                    'no_device': False},
                                   {'device_name': '/dev/sdb4',
                                    'delete_on_termination': False,
                                    'snapshot_id': '6',
                                    'volume_id': '7',
                                    'no_device': False},
                                   {'device_name': '/dev/sdb5',
                                    'delete_on_termination': False,
                                    'snapshot_id': '8',
                                    'volume_id': '9',
                                    'volume_size': 0,
                                    'no_device': False},
                                   {'device_name': '/dev/sdb6',
                                    'delete_on_termination': False,
                                    'snapshot_id': '10',
                                    'volume_id': '11',
                                    'volume_size': 1,
                                    'no_device': False},
                                   {'device_name': '/dev/sdb7',
                                    'snapshot_id': None,
                                    'volume_id': None,
                                    'no_device': True},
                                   {'device_name': '/dev/sdb8',
                                    'snapshot_id': None,
                                    'volume_id': None,
                                    'virtual_name': 'swap',
                                    'no_device': False},
                                   {'device_name': '/dev/sdb9',
                                    'snapshot_id': None,
                                    'volume_id': None,
                                    'virtual_name': 'ephemeral3',
                                    'no_device': False}],
                id_os_instance_2: [{'device_name': 'vda',
                                    'delete_on_termination': False,
                                    'snapshot_id': '1',
                                    'volume_id': '21',
                                    'no_device': False}]}))

        db_volumes_1 = {'2': {'id': 'vol-00000002'},
                        '3': {'id': 'vol-00000003'},
                        '5': {'id': 'vol-00000005'},
                        '7': {'id': 'vol-00000007'},
                        '9': {'id': 'vol-00000009'},
                        '11': {'id': 'vol-0000000b'}}

        fake_context = mock.Mock(service_catalog=[{'type': 'fake'}])

        result = {}
        instance_api._cloud_format_instance_bdm(
            fake_context, id_os_instance_1, '/dev/sdb1', result, db_volumes_1)
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
                        {'deviceName': '/dev/sdb2',
                         'ebs': {'status': 'attached',
                                 'deleteOnTermination': False,
                                 'volumeId': 'vol-00000003',
                                 }},
                        {'deviceName': '/dev/sdb3',
                         'ebs': {'status': 'attached',
                                 'deleteOnTermination': True,
                                 'volumeId': 'vol-00000005',
                                 }},
                        {'deviceName': '/dev/sdb4',
                         'ebs': {'status': 'attached',
                                 'deleteOnTermination': False,
                                 'volumeId': 'vol-00000007',
                                 }},
                        {'deviceName': '/dev/sdb5',
                         'ebs': {'status': 'attached',
                                 'deleteOnTermination': False,
                                 'volumeId': 'vol-00000009',
                                 }},
                        {'deviceName': '/dev/sdb6',
                         'ebs': {'status': 'attached',
                                 'deleteOnTermination': False,
                                 'volumeId': 'vol-0000000b',
                                 }}]},
                orderless_lists=True))

        result = {}
        with mock.patch('ec2api.db.api.IMPL') as db_api:
            db_api.get_items.return_value = [{'id': 'vol-00000015',
                                              'os_id': '21'}]
            instance_api._cloud_format_instance_bdm(
                fake_context, id_os_instance_2, '/dev/sdc1', result)
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

    @mock.patch('cinderclient.v1.client.Client')
    @mock.patch('ec2api.api.instance.novadb')
    def test_format_instance_bdm_while_attaching_volume(self, novadb, cinder):
        cinder = cinder.return_value
        cinder.volumes.get.return_value = (
            mock.Mock(status='attaching'))
        id_os_instance = fakes.random_os_id()
        novadb.block_device_mapping_get_all_by_instance.return_value = (
            [{'device_name': '/dev/sdb1',
              'delete_on_termination': False,
              'snapshot_id': '1',
              'volume_id': '2',
              'no_device': False}])
        fake_context = mock.Mock(service_catalog=[{'type': 'fake'}])

        result = {}
        instance_api._cloud_format_instance_bdm(
            fake_context, id_os_instance, '/dev/vda', result,
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

    @mock.patch('ec2api.api.instance._remove_instances')
    @mock.patch('novaclient.v1_1.client.Client')
    def test_get_os_instances_by_instances(self, nova, remove_instances):
        nova = nova.return_value
        fake_context = mock.Mock(service_catalog=[{'type': 'fake'}])

        def do_check(exactly_flag):
            nova.servers.get.side_effect = [fakes.OS_INSTANCE_1,
                                            nova_exception.NotFound(404),
                                            fakes.OS_INSTANCE_2]
            absent_instance = {'id': fakes.random_ec2_id('i'),
                               'os_id': fakes.random_os_id()}

            params = (fake_context, [fakes.DB_INSTANCE_1, absent_instance,
                                     fakes.DB_INSTANCE_2],
                      exactly_flag)
            if exactly_flag:
                self.assertRaises(exception.InvalidInstanceIDNotFound,
                                  instance_api._get_os_instances_by_instances,
                                  *params)
            else:
                res = instance_api._get_os_instances_by_instances(*params)
                self.assertEqual([fakes.OS_INSTANCE_1, fakes.OS_INSTANCE_2],
                                 res)
            remove_instances.assert_called_once_with(fake_context,
                                                     [absent_instance])
            remove_instances.reset_mock()

        do_check(True)
        do_check(False)

    @mock.patch('ec2api.api.network_interface._detach_network_interface_item')
    @mock.patch('ec2api.api.address._disassociate_address_item')
    @mock.patch('ec2api.db.api.IMPL')
    def test_remove_instances(self, db_api, disassociate_address_item,
                              detach_network_interface_item):
        fake_context = mock.Mock(service_catalog=[{'type': 'fake'}])

        instances = [{'id': fakes.random_ec2_id('i')}
                     for dummy in range(4)]
        network_interfaces = [
            {'id': fakes.random_ec2_id('eni'),
             'instance_id': inst['id'],
             'delete_on_termination': num in (0, 1, 4, 6)}
            for num, inst in enumerate(itertools.chain(
                  *(zip(instances[:3], instances[:3]) +
                    [[{'id': fakes.random_ec2_id('i')}] * 2])))]
        network_interfaces.extend({'id': fakes.random_ec2_id('eni')}
                                  for dummy in range(2))
        addresses = [{'id': fakes.random_ec2_id('eipalloc'),
                      'network_interface_id': eni['id']}
                     for eni in network_interfaces[::2]]
        addresses.extend({'id': fakes.random_ec2_id('eipalloc')}
                         for dummy in range(2))

        instances_to_remove = instances[:2] + [instances[3]]
        network_interfaces_of_removed_instances = {
            instances[0]['id']: network_interfaces[0:2],
            instances[1]['id']: network_interfaces[2:4],
            instances[3]['id']: []}
        network_interfaces_to_delete = [network_interfaces[0],
                                        network_interfaces[1]]
        network_interfaces_to_detach = [network_interfaces[2],
                                        network_interfaces[3]]
        addresses_to_dissassociate = [addresses[0]]

        db_api.get_items.side_effect = fakes.get_db_api_get_items(
            *(network_interfaces + addresses))

        def check_calls():
            for eni in network_interfaces_to_detach:
                detach_network_interface_item.assert_any_call(fake_context,
                                                              eni)
            for eni in network_interfaces_to_delete:
                db_api.delete_item.assert_any_call(fake_context, eni['id'])
            for addr in addresses_to_dissassociate:
                disassociate_address_item.assert_any_call(fake_context, addr)
            detach_network_interface_item.reset_mock()
            db_api.reset_mock()
            disassociate_address_item.reset_mock()

        instance_api._remove_instances(fake_context, instances_to_remove)
        check_calls()

        instance_api._remove_instances(fake_context, instances_to_remove,
                                       network_interfaces_of_removed_instances)
        check_calls()

    @mock.patch('ec2api.api.instance.novadb')
    def test_is_ebs_instance(self, novadb):
        context = mock.Mock(service_catalog=[{'type': 'fake'}])
        os_instance = fakes.OSInstance(fakes.random_os_id())

        novadb.instance_get_by_uuid.return_value = {}
        novadb.block_device_mapping_get_all_by_instance.return_value = []
        self.assertFalse(instance_api._is_ebs_instance(context, os_instance))

        novadb.instance_get_by_uuid.return_value = {
            'root_device_name': '/dev/vda'}
        self.assertFalse(instance_api._is_ebs_instance(context, os_instance))

        novadb.block_device_mapping_get_all_by_instance.return_value = [
            {'device_name': '/dev/vda',
             'volume_id': None,
             'snapshot_id': None,
             'no_device': True}]
        self.assertFalse(instance_api._is_ebs_instance(context, os_instance))

        novadb.block_device_mapping_get_all_by_instance.return_value = [
            {'device_name': '/dev/vda',
             'volume_id': fakes.random_ec2_id('vol'),
             'snapshot_id': None,
             'no_device': True}]
        self.assertFalse(instance_api._is_ebs_instance(context, os_instance))

        novadb.block_device_mapping_get_all_by_instance.return_value = [
            {'device_name': '/dev/vda',
             'volume_id': '',
             'snapshot_id': '',
             'no_device': False}]
        self.assertFalse(instance_api._is_ebs_instance(context, os_instance))

        novadb.block_device_mapping_get_all_by_instance.return_value = [
            {'device_name': '/dev/vdb',
             'volume_id': fakes.random_ec2_id('vol'),
             'snapshot_id': '',
             'no_device': False}]
        self.assertFalse(instance_api._is_ebs_instance(context, os_instance))

        novadb.block_device_mapping_get_all_by_instance.return_value = [
            {'device_name': '/dev/vda',
             'volume_id': fakes.random_ec2_id('vol'),
             'snapshot_id': '',
             'no_device': False}]
        self.assertTrue(instance_api._is_ebs_instance(context, os_instance))

        novadb.block_device_mapping_get_all_by_instance.return_value = [
            {'device_name': 'vda',
             'volume_id': fakes.random_ec2_id('vol'),
             'snapshot_id': '',
             'no_device': False}]
        self.assertTrue(instance_api._is_ebs_instance(context, os_instance))

    def test_block_device_strip_dev(self):
        self.assertEqual(
            instance_api._block_device_strip_dev('/dev/sda'), 'sda')
        self.assertEqual(instance_api._block_device_strip_dev('sda'), 'sda')

    def test_block_device_prepend_dev(self):
        mapping = ['/dev/sda', 'sdb', 'sdc', 'sdd', 'sde']
        expected = ['/dev/sda', '/dev/sdb', '/dev/sdc', '/dev/sdd', '/dev/sde']

        for m, e in zip(mapping, expected):
            prepended = instance_api._block_device_prepend_dev(m)
            self.assertEqual(e, prepended)
