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


import collections
import copy
import itertools

import mock

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class InstanceTestCase(base.ApiTestCase):

    # TODO(ft): make negative tests on invalid parameters

    def setUp(self):
        super(InstanceTestCase, self).setUp()
        create_network_interface_patcher = (
            mock.patch('ec2api.api.network_interface.'
                       'create_network_interface'))
        self.create_network_interface = (
            create_network_interface_patcher.start())
        self.addCleanup(create_network_interface_patcher.stop)
        utils_generate_uid_patcher = (
            mock.patch('ec2api.api.instance._utils_generate_uid'))
        self.utils_generate_uid = utils_generate_uid_patcher.start()
        self.addCleanup(utils_generate_uid_patcher.stop)
        novadb_patcher = (mock.patch('ec2api.api.instance.novadb'))
        self.novadb = novadb_patcher.start()
        self.addCleanup(novadb_patcher.stop)

        self.fake_image_class = collections.namedtuple(
            'FakeImage', ['id', 'status', 'properties'])
        self.fake_flavor_class = collections.namedtuple(
            'FakeFlavor', ['name'])
        self.fake_instance_class = collections.namedtuple(
            'FakeInstance', ['id'])

    @mock.patch('ec2api.api.instance._get_vpc_default_security_group_id')
    def test_run_instances(self, _get_vpc_default_security_group_id):
        """Run instance with various network interface settings."""
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(
                {fakes.ID_EC2_SUBNET_1: fakes.DB_SUBNET_1,
                 fakes.ID_EC2_NETWORK_INTERFACE_1:
                    copy.deepcopy(fakes.DB_NETWORK_INTERFACE_1)}))
        self.db_api.get_item_ids.return_value = [
                (fakes.ID_EC2_IMAGE_1, fakes.ID_OS_IMAGE_1)]
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})
        self.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_1})
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE
        self.db_api.add_item.return_value = fakes.DB_INSTANCE_1
        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1

        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        fake_flavor = self.fake_flavor_class('fake_flavor')
        self.nova_flavors.list.return_value = [fake_flavor]
        self.nova_servers.create.return_value = (
            fakes.OSInstance(fakes.ID_OS_INSTANCE_1, {'id': 'fakeFlavorId'},
                 addresses={
                    fakes.ID_EC2_SUBNET_1: [
                        {'addr': fakes.IP_NETWORK_INTERFACE_1,
                         'version': 4,
                         'OS-EXT-IPS:type': 'fixed'}]}))
        self.novadb.instance_get_by_uuid.return_value = fakes.NOVADB_INSTANCE_1
        self.novadb.block_device_mapping_get_all_by_instance.return_value = []
        fake_flavor = self.fake_flavor_class('fake_flavor')
        self.nova_flavors.get.return_value = fake_flavor

        _get_vpc_default_security_group_id.return_value = None

        def do_check(params, new_port=True, delete_on_termination=None):
            params.update({'ImageId': fakes.ID_EC2_IMAGE_1,
                           'InstanceType': 'fake_flavor',
                           'MinCount': '1', 'MaxCount': '1'})
            resp = self.execute('RunInstances', params)
            self.assertEqual(200, resp['status'])
            resp.pop('status')
            delete_port_on_termination = (new_port
                                          if delete_on_termination is None
                                          else delete_on_termination)
            db_attached_eni = fakes.gen_db_network_interface(
                fakes.ID_EC2_NETWORK_INTERFACE_1,
                fakes.ID_OS_PORT_1, fakes.ID_EC2_VPC_1,
                fakes.ID_EC2_SUBNET_1,
                fakes.IP_NETWORK_INTERFACE_1,
                fakes.DESCRIPTION_NETWORK_INTERFACE_1,
                instance_id=fakes.ID_EC2_INSTANCE_1,
                delete_on_termination=delete_port_on_termination)
            eni = fakes.gen_ec2_network_interface(
                fakes.ID_EC2_NETWORK_INTERFACE_1,
                fakes.EC2_SUBNET_1,
                [fakes.IP_NETWORK_INTERFACE_1],
                description=fakes.DESCRIPTION_NETWORK_INTERFACE_1,
                ec2_instance_id=fakes.ID_EC2_INSTANCE_1,
                delete_on_termination=delete_port_on_termination,
                for_instance_output=True)
            expected_reservation = fakes.gen_ec2_reservation(
                fakes.ID_EC2_RESERVATION_1,
                [fakes.gen_ec2_instance(
                    fakes.ID_EC2_INSTANCE_1,
                    private_ip_address=fakes.IP_NETWORK_INTERFACE_1,
                    ec2_network_interfaces=[eni])])
            self.assertThat(resp, matchers.DictMatches(expected_reservation))
            if new_port:
                self.create_network_interface.assert_called_once_with(
                    mock.ANY, fakes.EC2_SUBNET_1['subnetId'])
            self.nova_servers.create.assert_called_once_with(
                'EC2 server', fakes.ID_OS_IMAGE_1, fake_flavor,
                min_count=1, max_count=1,
                kernel_id=None, ramdisk_id=None,
                availability_zone=None,
                block_device_mapping=None,
                security_groups=None,
                nics=[{'port-id': fakes.ID_OS_PORT_1}],
                key_name=None, userdata=None)
            self.db_api.get_item_ids.assert_called_once_with(
                mock.ANY, 'ami', (fakes.ID_EC2_IMAGE_1,))
            self.db_api.update_item.assert_called_once_with(
                mock.ANY, db_attached_eni)
            self.isotime.assert_called_once_with(None, True)
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'i', tools.purge_dict(fakes.DB_INSTANCE_1, ('id',)))

            self.create_network_interface.reset_mock()
            self.nova_servers.reset_mock()
            self.db_api.reset_mock()
            self.isotime.reset_mock()

        do_check({'SubnetId': fakes.EC2_SUBNET_1['subnetId']})

        do_check({'NetworkInterface.1.SubnetId':
                  fakes.EC2_SUBNET_1['subnetId']})

        do_check({'NetworkInterface.1.SubnetId':
                  fakes.EC2_SUBNET_1['subnetId'],
                  'NetworkInterface.1.DeleteOnTermination': 'False'},
                 delete_on_termination=False)

        do_check({'NetworkInterface.1.NetworkInterfaceId':
                  fakes.EC2_NETWORK_INTERFACE_1['networkInterfaceId']},
                 new_port=False)

    @mock.patch('ec2api.api.instance._get_vpc_default_security_group_id')
    # TODO(ft): restore test after finish extraction of Nova EC2 API
    def _test_run_instances_multiple_networks(
                self, _get_vpc_default_security_group_id):
        """Run 2 instances at once on 2 subnets in all combinations."""
        self._build_multiple_data_model()

        self.db_api.add_item.side_effect = [
            {'id': ec2_instance_id,
             'os_id': os_instance_id}
            for ec2_instance_id, os_instance_id in zip(
                self.IDS_EC2_INSTANCE, self.IDS_OS_INSTANCE)]
        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1

        self.glance.images.get.return_value = self.fake_image_class(
                'fake_image_id', 'active', {})
        fake_flavor = self.fake_flavor_class('fake_flavor')
        self.nova_flavors.list.return_value = [fake_flavor]

        _get_vpc_default_security_group_id.return_value = None

        ec2_instances = [
            fakes.gen_ec2_instance(
                ec2_instance_id,
                private_ip_address=None,
                ec2_network_interfaces=eni_pair)
            for ec2_instance_id, eni_pair in zip(
                self.IDS_EC2_INSTANCE,
                zip(*[iter(self.EC2_ATTACHED_ENIS)] * 2))]
        ec2_reservation = fakes.gen_ec2_reservation(fakes.ID_EC2_RESERVATION_1,
                                                    ec2_instances)

        fakes_db_items = dict((eni['id'], eni)
                              for eni in self.DB_DETACHED_ENIS)
        fakes_db_items.update({
            fakes.ID_EC2_SUBNET_1: fakes.DB_SUBNET_1,
            fakes.ID_EC2_SUBNET_2: fakes.DB_SUBNET_2})
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(fakes_db_items))
        self.create_network_interface.side_effect = (
            [{'networkInterface': eni}
             for eni in self.EC2_DETACHED_ENIS])
        self.nova_servers.create.side_effect = [
            self.fake_instance_class(os_instance_id)
            for os_instance_id in self.IDS_OS_INSTANCE]
        self.neutron.list_ports.return_value = (
            {'ports': self.OS_DETACHED_PORTS + [self.OS_FAKE_PORT]})
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE

        resp = self.execute(
            'RunInstances',
            {'ImageId': 'ami-00000001',
             'InstanceType': 'fake_flavor',
             'MinCount': '2',
             'MaxCount': '2',
             'NetworkInterface.1.SubnetId': fakes.ID_EC2_SUBNET_1,
             'NetworkInterface.2.SubnetId': fakes.ID_EC2_SUBNET_2,
             'NetworkInterface.2.DeleteOnTermination': 'False'})

        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.assertThat(resp, matchers.DictMatches(ec2_reservation))

        self.create_network_interface.assert_has_calls([
            mock.call(mock.ANY, ec2_subnet_id)
            for ec2_subnet_id in self.IDS_EC2_SUBNET_BY_PORT])
        self.nova_servers.create.assert_has_calls([
            mock.call(
                'EC2 server', 'fake_image_id', fake_flavor,
                min_count=1, max_count=1,
                kernel_id=None, ramdisk_id=None,
                availability_zone=None,
                block_device_mapping=None,
                security_groups=None,
                nics=[{'port-id': port_id}
                      for port_id in port_ids],
                key_name=None, userdata=None)
            for port_ids in zip(*[iter(self.IDS_OS_PORT)] * 2)])
        self.db_api.update_item.assert_has_calls([
            mock.call(mock.ANY, eni)
            for eni in self.DB_ATTACHED_ENIS])
        self.isotime.assert_called_once_with(None, True)
        self.db_api.add_item.assert_has_calls([
            mock.call(
                mock.ANY, 'i', {'os_id': os_instance_id})
            for os_instance_id in self.IDS_OS_INSTANCE])

    @mock.patch('ec2api.api.network_interface.delete_network_interface')
    def test_run_instances_rollback(self, delete_network_interface):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(
                {fakes.ID_EC2_SUBNET_1: fakes.DB_SUBNET_1,
                 fakes.ID_EC2_NETWORK_INTERFACE_1:
                    copy.deepcopy(fakes.DB_NETWORK_INTERFACE_1)}))
        self.db_api.get_item_ids.return_value = [
                (fakes.ID_EC2_IMAGE_1, fakes.ID_OS_IMAGE_1)]
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})
        self.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_1})
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE
        self.db_api.add_item.return_value = fakes.DB_INSTANCE_1
        self.utils_generate_uid.return_value = fakes.ID_EC2_RESERVATION_1

        self.glance.images.get.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        fake_flavor = self.fake_flavor_class('fake_flavor')
        self.nova_flavors.list.return_value = [fake_flavor]
        self.nova_servers.create.return_value = (
            fakes.OSInstance(fakes.ID_OS_INSTANCE_1, {'id': 'fakeFlavorId'},
                 image={'id': fakes.ID_OS_IMAGE_1},
                 addresses={
                    fakes.ID_EC2_SUBNET_1: [
                        {'addr': fakes.IP_NETWORK_INTERFACE_1,
                         'version': 4,
                         'OS-EXT-IPS:type': 'fixed'}]}))
        self.db_api.update_item.side_effect = Exception()

        def do_check(params, new_port=True, delete_on_termination=None):
            params.update({'ImageId': fakes.ID_EC2_IMAGE_1,
                           'InstanceType': 'fake_flavor',
                           'MinCount': '1', 'MaxCount': '1'})
            self.execute('RunInstances', params)

            # TODO(ft): check sequence of calling
            # neutron update port must be the first
            if new_port:
                delete_network_interface.assert_called_once_with(
                    mock.ANY,
                    network_interface_id=fakes.ID_EC2_NETWORK_INTERFACE_1)
            else:
                self.neutron.update_port.assert_called_once_with(
                    fakes.ID_OS_PORT_1,
                    {'port': {'device_id': '',
                              'device_owner': ''}})
            self.nova_servers.delete.assert_called_once_with(
                fakes.ID_OS_INSTANCE_1)
            self.db_api.delete_item.assert_called_once_with(
                mock.ANY, fakes.ID_EC2_INSTANCE_1)

            delete_network_interface.reset_mock()
            self.neutron.reset_mock()
            self.nova_servers.reset_mock()
            self.db_api.reset_mock()

        do_check({'SubnetId': fakes.EC2_SUBNET_1['subnetId']})

        do_check({'NetworkInterface.1.SubnetId':
                  fakes.EC2_SUBNET_1['subnetId']})

        do_check({'NetworkInterface.1.SubnetId':
                  fakes.EC2_SUBNET_1['subnetId'],
                  'NetworkInterface.1.DeleteOnTermination': 'False'},
                 delete_on_termination=False)

        do_check({'NetworkInterface.1.NetworkInterfaceId':
                  fakes.EC2_NETWORK_INTERFACE_1['networkInterfaceId']},
                 new_port=False)

    @mock.patch('ec2api.api.address._disassociate_address_item')
    @mock.patch('ec2api.api.network_interface.detach_network_interface')
    def test_terminate_instances(self, detach_network_interface,
                                 dissassociate_address_item):
        """Terminate 2 instances in one request."""
        self.db_api.get_items_by_ids.return_value = [fakes.DB_INSTANCE_1,
                                                     fakes.DB_INSTANCE_2]
        self.nova_servers.get.side_effect = [fakes.OS_INSTANCE_1,
                                               fakes.OS_INSTANCE_2]
        self.db_api.get_items.side_effect = fakes.get_db_api_get_items(
            {'eni': [copy.deepcopy(fakes.DB_NETWORK_INTERFACE_1),
                     copy.deepcopy(fakes.DB_NETWORK_INTERFACE_2)],
             'eipalloc': [copy.deepcopy(fakes.DB_ADDRESS_1),
                          copy.deepcopy(fakes.DB_ADDRESS_2)]})

        instance1_delete_patcher = mock.patch.object(fakes.OS_INSTANCE_1,
                                                     'delete')
        instance1_delete = instance1_delete_patcher.start()
        self.addCleanup(instance1_delete.stop)
        instance2_delete_patcher = mock.patch.object(fakes.OS_INSTANCE_2,
                                                     'delete')
        instance2_delete = instance2_delete_patcher.start()
        self.addCleanup(instance2_delete.stop)
        instance1_get_patcher = mock.patch.object(fakes.OS_INSTANCE_1, 'get')
        instance1_get = instance1_get_patcher.start()
        self.addCleanup(instance1_get.stop)
        instance2_get_patcher = mock.patch.object(fakes.OS_INSTANCE_2, 'get')
        instance2_get = instance2_get_patcher.start()
        self.addCleanup(instance2_get.stop)

        resp = self.execute('TerminateInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                             'InstanceId.2': fakes.ID_EC2_INSTANCE_2})

        self.assertEqual(200, resp['status'])
        resp.pop('status')
        fake_state_change = {'previousState': {'code': 0,
                                               'name': 'pending'},
                             'currentState': {'code': 0,
                                              'name': 'pending'}}
        self.assertThat(resp, matchers.DictMatches(
            {'instancesSet': [tools.update_dict(
                                    {'instanceId': fakes.ID_EC2_INSTANCE_1},
                                    fake_state_change),
                              tools.update_dict(
                                    {'instanceId': fakes.ID_EC2_INSTANCE_2},
                                    fake_state_change)]}))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, 'i',
            set([fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2]))
        self.assertEqual(2, self.db_api.get_items.call_count)
        self.db_api.get_items.assert_any_call(mock.ANY, 'eni')
        self.db_api.get_items.assert_any_call(mock.ANY, 'eipalloc')
        detach_network_interface.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_NETWORK_INTERFACE_2_ATTACH)
        self.nova_servers.get.assert_any_call(fakes.ID_OS_INSTANCE_1)
        self.nova_servers.get.assert_any_call(fakes.ID_OS_INSTANCE_2)
        self.assertEqual(0, dissassociate_address_item.call_count)
        self.assertEqual(2, self.db_api.delete_item.call_count)
        for inst_id in (fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2):
            self.db_api.delete_item.assert_any_call(mock.ANY, inst_id)
        instance1_delete.assert_called_once_with()
        instance2_delete.assert_called_once_with()
        instance1_get.assert_called_once_with()
        instance2_get.assert_called_once_with()

    # TODO(ft): restore test after finish extraction of Nova EC2 API
    def _test_terminate_instances_multiple_networks(self):
        """Terminate an instance with various combinations of ports."""
        self._build_multiple_data_model()

        ec2_terminate_instances_result = {
            'instancesSet': [{'instanceId': fakes.ID_EC2_INSTANCE_1,
                              'fakeKey': 'fakeValue'},
                             {'instanceId': fakes.ID_EC2_INSTANCE_2,
                              'fakeKey': 'fakeValue'}]}

        def do_check(mock_port_list=[], mock_eni_list=[],
                     updated_ports=[], deleted_ports=[]):
            self.neutron.list_ports.return_value = {'ports': mock_port_list}
            self.db_api.get_items.return_value = (
                copy.deepcopy(mock_eni_list) + [self.DB_FAKE_ENI])

            resp = self.execute('TerminateInstances',
                                {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                                 'InstanceId.2': fakes.ID_EC2_INSTANCE_2})

            self.assertEqual(200, resp['status'])
            resp.pop('status')
            self.assertThat(resp, matchers.DictMatches(
                ec2_terminate_instances_result))
            self._assert_list_ports_is_called_with_filter(self.IDS_OS_INSTANCE)
            self.assertEqual(len(updated_ports),
                             self.neutron.update_port.call_count)
            self.assertEqual(len(updated_ports),
                             self.db_api.update_item.call_count)
            for port in updated_ports:
                self.neutron.update_port.assert_any_call(
                    port['os_id'],
                    {'port': {'device_id': '',
                              'device_owner': ''}})
                self.db_api.update_item.assert_any_call(
                    mock.ANY,
                    port)
            self.assertEqual(len(deleted_ports) + 2,
                             self.db_api.delete_item.call_count)
            for port in deleted_ports:
                self.db_api.delete_item.assert_any_call(
                    mock.ANY,
                    port['id'])
            for inst_id in (fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2):
                self.db_api.delete_item.assert_any_call(mock.ANY, inst_id)

            self.neutron.list_ports.reset_mock()
            self.neutron.update_port.reset_mock()
            self.db_api.delete_item.reset_mock()
            self.db_api.update_item.reset_mock()

        # NOTE(ft): 2 instances; the first has 2 correct ports;
        # the second has the first port attached by EC2 API but later detached
        # by OpenStack and the second port created through EC2 API but
        # attached by OpenStack only
        do_check(
            mock_port_list=[
                self.OS_ATTACHED_PORTS[0], self.OS_ATTACHED_PORTS[1],
                self.OS_ATTACHED_PORTS[3]],
            mock_eni_list=[
                self.DB_ATTACHED_ENIS[0], self.DB_ATTACHED_ENIS[1],
                self.DB_ATTACHED_ENIS[2], self.DB_DETACHED_ENIS[3]],
            updated_ports=[self.DB_DETACHED_ENIS[1]],
            deleted_ports=[self.DB_ATTACHED_ENIS[0],
                           self.DB_ATTACHED_ENIS[2]])

        # NOTE(ft): 2 instances: the first has the first port attached by
        # OpenStack only, EC2 layer of OpenStack displays its IP address as
        # IP address of the instance, the second port is attached correctly;
        # the second instance has one port created and attached by OpenStack
        # only
        do_check(
            mock_port_list=[
                self.OS_ATTACHED_PORTS[0], self.OS_ATTACHED_PORTS[1],
                self.OS_ATTACHED_PORTS[3]],
            mock_eni_list=[self.DB_ATTACHED_ENIS[1]],
            updated_ports=[self.DB_DETACHED_ENIS[1]],
            deleted_ports=[])

    @mock.patch('ec2api.api.instance.security_group_api.'
                '_format_security_groups_ids_names')
    def test_describe_instances(self, format_security_groups_ids_names):
        """Describe 2 instances, one of which is vpc instance."""
        self.neutron.list_ports.return_value = {'ports': [fakes.OS_PORT_2]}
        self.db_api.get_items.side_effect = (
            lambda _, kind: [fakes.DB_NETWORK_INTERFACE_1,
                             fakes.DB_NETWORK_INTERFACE_2]
            if kind == 'eni' else
            [fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2]
            if kind == 'eipalloc' else
            [fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2]
            if kind == 'i' else
            [fakes.DB_IMAGE_1, fakes.DB_IMAGE_2]
            if kind == 'ami' else [])
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})
        self.nova_servers.list.return_value = [fakes.OS_INSTANCE_1,
                                               fakes.OS_INSTANCE_2]
        instance_get_by_uuid = fakes.get_db_api_get_item_by_id({
            fakes.ID_OS_INSTANCE_1: fakes.NOVADB_INSTANCE_1,
            fakes.ID_OS_INSTANCE_2: fakes.NOVADB_INSTANCE_2})
        self.novadb.instance_get_by_uuid.side_effect = (
            lambda context, item_id:
                instance_get_by_uuid(context, None, item_id))
        fake_flavor = self.fake_flavor_class('fake_flavor')
        self.nova_flavors.get.return_value = fake_flavor
        format_security_groups_ids_names.return_value = {}
        self.novadb.block_device_mapping_get_all_by_instance.return_value = []

        resp = self.execute('DescribeInstances', {})

        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.assertThat(resp, matchers.DictMatches(
            {'reservationSet': [fakes.EC2_RESERVATION_1,
                                fakes.EC2_RESERVATION_2]},
            orderless_lists=True))

    # TODO(ft): restore test after finish extraction of Nova EC2 API
    def _test_describe_instances_mutliple_networks(self):
        """Describe 2 instances with various combinations of network."""
        self._build_multiple_data_model()
        ips_instance = [fakes.IP_FIRST_SUBNET_1, fakes.IP_FIRST_SUBNET_2]

        def do_check(separate_reservations=False, mock_port_list=[],
                     mock_eni_list=[], ec2_enis_by_instance=[],
                     is_instance_ip_in_vpc_by_instance=[True, True]):
            def gen_reservation_set(instances):
                if separate_reservations:
                    return [fakes.gen_ec2_reservation(
                                fakes.ID_EC2_RESERVATION_1, [instances[0]]),
                            fakes.gen_ec2_reservation(
                                fakes.ID_EC2_RESERVATION_2, [instances[1]])]
                else:
                    return [fakes.gen_ec2_reservation(
                        fakes.ID_EC2_RESERVATION_1, [instances[0],
                                                     instances[1]])]

            instances = [fakes.gen_ec2_instance(inst_id, private_ip_address=ip)
                         for inst_id, ip in zip(
                self.IDS_EC2_INSTANCE, ips_instance)]
            reservation_set = gen_reservation_set([instances[0], instances[1]])

            self.neutron.list_ports.return_value = {'ports': mock_port_list}
            self.db_api.get_items.return_value = (
                mock_eni_list + [self.DB_FAKE_ENI])

            resp = self.execute('DescribeInstances', {})

            self.assertEqual(200, resp['status'])
            resp.pop('status')

            instances = [fakes.gen_ec2_instance(inst_id, private_ip_address=ip,
                                                ec2_network_interfaces=enis,
                                                is_private_ip_in_vpc=ip_in_vpc)
                         for inst_id, ip, enis, ip_in_vpc in zip(
                self.IDS_EC2_INSTANCE, ips_instance,
                ec2_enis_by_instance,
                is_instance_ip_in_vpc_by_instance)]
            reservation_set = gen_reservation_set([instances[0], instances[1]])

            self.assertThat({'reservationSet': reservation_set,
                             'fakeKey': 'fakeValue'},
                            matchers.DictMatches(resp), verbose=True)
            self._assert_list_ports_is_called_with_filter(self.IDS_OS_INSTANCE)

            self.neutron.list_ports.reset_mock()

        # NOTE(ft): 2 instances; the first has 2 correct ports;
        # the second has the first port attached by EC2 API but later detached
        # by OpenStack and the second port created through EC2 API but
        # attached by OpenStack only
        do_check(
            separate_reservations=False,
            mock_port_list=[
                self.OS_ATTACHED_PORTS[0], self.OS_ATTACHED_PORTS[1],
                self.OS_ATTACHED_PORTS[3]],
            mock_eni_list=[
                self.DB_ATTACHED_ENIS[0], self.DB_ATTACHED_ENIS[1],
                self.DB_ATTACHED_ENIS[2], self.DB_DETACHED_ENIS[3]],
            ec2_enis_by_instance=[
                [self.EC2_ATTACHED_ENIS[0], self.EC2_ATTACHED_ENIS[1]],
                None],
            is_instance_ip_in_vpc_by_instance=[True, None])

        # NOTE(ft): 2 instances: the first has the first port attached by
        # OpenStack only, EC2 layer of OpenStack displays its IP address as
        # IP address of the instance, the second port is attached correctly;
        # the second instance has one port created and attached by OpenStack
        # only
        do_check(
            separate_reservations=True,
            mock_port_list=[
                self.OS_ATTACHED_PORTS[0], self.OS_ATTACHED_PORTS[1],
                self.OS_ATTACHED_PORTS[3]],
            mock_eni_list=[self.DB_ATTACHED_ENIS[1]],
            ec2_enis_by_instance=[[self.EC2_ATTACHED_ENIS[1]], None],
            is_instance_ip_in_vpc_by_instance=[False, None])

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

        ids_db_subnet = (fakes.ID_EC2_SUBNET_1, fakes.ID_EC2_SUBNET_2)
        ids_db_subnet_by_port = ids_db_subnet * 2
        ids_ec2_subnet = (fakes.ID_EC2_SUBNET_1, fakes.ID_EC2_SUBNET_2)
        ids_ec2_subnet_by_port = ids_ec2_subnet * 2
        ips = (fakes.IP_FIRST_SUBNET_1, fakes.IP_FIRST_SUBNET_2,
               fakes.IP_LAST_SUBNET_1, fakes.IP_LAST_SUBNET_2)

        ids_db_instance = [fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2]
        ids_db_instance_by_port = list(
            itertools.chain(*map(lambda i: [i] * subnets_count,
                                 ids_db_instance)))
        ids_os_instance = [fakes.ID_OS_INSTANCE_1, fakes.ID_OS_INSTANCE_2]
        ids_os_instance_by_port = list(
            itertools.chain(*map(lambda i: [i] * subnets_count,
                                 ids_os_instance)))
        ids_ec2_instance = [fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2]
        ids_ec2_instance_by_port = list(
            itertools.chain(*map(lambda i: [i] * subnets_count,
                                 ids_ec2_instance)))

        dots_by_port = [True, False] * instances_count
        db_attached_enis = [
            fakes.gen_db_network_interface(
                ec2_id, os_id, fakes.ID_EC2_VPC_1,
                subnet_db_id, ip,
                instance_id=instance_db_id,
                delete_on_termination=dot)
            for ec2_id, os_id, subnet_db_id, ip, instance_db_id, dot in zip(
                ids_ec2_eni,
                ids_os_port,
                ids_db_subnet_by_port,
                ips,
                ids_db_instance_by_port,
                dots_by_port)]
        db_detached_enis = [
            fakes.gen_db_network_interface(
                ec2_id, os_id, fakes.ID_EC2_VPC_1,
                subnet_db_id, ip)
            for ec2_id, os_id, subnet_db_id, ip in zip(
                ids_ec2_eni,
                ids_os_port,
                ids_db_subnet_by_port,
                ips)]
        ec2_attached_enis = [
            fakes.gen_ec2_network_interface(
                db_eni['id'],
                None,  # ec2_subnet
                [db_eni['private_ip_address']],
                ec2_instance_id=ec2_instance_id,
                delete_on_termination=dot,
                for_instance_output=True,
                ec2_subnet_id=ec2_subnet_id,
                ec2_vpc_id=fakes.ID_EC2_VPC_1)
            for db_eni, dot, ec2_subnet_id, ec2_instance_id in zip(
                db_attached_enis,
                dots_by_port,
                ids_ec2_subnet_by_port,
                ids_ec2_instance_by_port)]
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
        os_attached_ports = [
            fakes.gen_os_port(
                os_id, ec2_eni, subnet_os_id,
                [ec2_eni['privateIpAddress']],
                os_instance_id=os_instance_id)
            for os_id, ec2_eni, subnet_os_id, os_instance_id in zip(
                ids_os_port,
                ec2_attached_enis,
                ids_db_subnet_by_port,
                ids_os_instance_by_port)]
        os_detached_ports = [
            fakes.gen_os_port(
                os_id, ec2_eni, subnet_os_id,
                [ec2_eni['privateIpAddress']])
            for os_id, ec2_eni, subnet_os_id in zip(
                ids_os_port,
                ec2_detached_enis,
                ids_db_subnet_by_port)]

        self.IDS_OS_PORT = ids_os_port
        self.IDS_DB_INSTANCE = ids_db_instance
        self.IDS_OS_INSTANCE = ids_os_instance
        self.IDS_EC2_INSTANCE = ids_ec2_instance
        self.IDS_EC2_SUBNET_BY_PORT = ids_ec2_subnet_by_port
        self.OS_ATTACHED_PORTS = os_attached_ports
        self.OS_DETACHED_PORTS = os_detached_ports
        self.DB_ATTACHED_ENIS = db_attached_enis
        self.DB_DETACHED_ENIS = db_detached_enis
        self.EC2_ATTACHED_ENIS = ec2_attached_enis
        self.EC2_DETACHED_ENIS = ec2_detached_enis

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

    def _assert_list_ports_is_called_with_filter(self, instance_ids):
            # NOTE(ft): compare manually due to the order of instance ids in
            # list_ports call depends of values of instance EC2 ids
            # But neither assert_any_called nor matchers.DictMatches can not
            # compare lists excluding the order of elements
        list_ports_calls = self.neutron.list_ports.mock_calls
        self.assertEqual(1, len(list_ports_calls))
        self.assertEqual((), list_ports_calls[0][1])
        list_ports_kwargs = list_ports_calls[0][2]
        self.assertEqual(len(list_ports_kwargs), 1)
        self.assertIn('device_id', list_ports_kwargs)
        self.assertEqual(sorted(instance_ids),
                         sorted(list_ports_kwargs['device_id']))


# TODO(ft): add tests for _get_vpc_default_security_group_id
