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
import itertools

import mock

from ec2api.api import ec2utils
from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers


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

    def test_run_instances(self):
        """Run instance with various network interface settings."""
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(
                {fakes.ID_DB_SUBNET_1: fakes.DB_SUBNET_1,
                 fakes.ID_DB_NETWORK_INTERFACE_1:
                 copy.deepcopy(fakes.DB_NETWORK_INTERFACE_1)}))
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})
        self.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_1})
        self.ec2.run_instances.return_value = (
            fakes.gen_ec2_reservation([fakes.gen_ec2_instance(
                fakes.ID_EC2_INSTANCE_1, private_ip_address=None)]))
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE

        def do_check(params, new_port=True, delete_on_termination=None):
            params.update({'ImageId': 'fake_image',
                           'MinCount': '1', 'MaxCount': '1'})
            resp = self.execute('RunInstances', params)
            self.assertEqual(200, resp['status'])
            resp.pop('status')
            delete_port_on_termination = (new_port
                                          if delete_on_termination is None
                                          else delete_on_termination)
            db_attached_eni = fakes.gen_db_network_interface(
                fakes.ID_DB_NETWORK_INTERFACE_1,
                fakes.ID_OS_PORT_1, fakes.ID_DB_VPC_1,
                fakes.ID_DB_SUBNET_1,
                fakes.IP_NETWORK_INTERFACE_1,
                fakes.DESCRIPTION_NETWORK_INTERFACE_1,
                instance_id=fakes.ID_DB_INSTANCE_1,
                delete_on_termination=delete_port_on_termination)
            eni = fakes.gen_ec2_network_interface(
                fakes.ID_EC2_NETWORK_INTERFACE_1,
                fakes.EC2_SUBNET_1,
                [fakes.IP_NETWORK_INTERFACE_1],
                description=fakes.DESCRIPTION_NETWORK_INTERFACE_1,
                ec2_instance_id=fakes.ID_EC2_INSTANCE_1,
                delete_on_termination=delete_port_on_termination,
                for_instance_output=True)
            expected_reservation = fakes.gen_ec2_reservation([
                fakes.gen_ec2_instance(
                    fakes.ID_EC2_INSTANCE_1, private_ip_address=None,
                    ec2_network_interfaces=[eni])])
            self.assertThat(resp, matchers.DictMatches(expected_reservation))
            if new_port:
                self.create_network_interface.assert_called_once_with(
                    mock.ANY, fakes.EC2_SUBNET_1['subnetId'])
            self.ec2.run_instances.assert_called_once_with(
                image_id='fake_image',
                min_count=1, max_count=1,
                security_group=None,
                network_interface=[
                    {'network_interface_id': fakes.ID_OS_PORT_1}])
            self.db_api.update_item.assert_called_once_with(
                mock.ANY, db_attached_eni)
            self.isotime.assert_called_once_with(None, True)

            self.create_network_interface.reset_mock()
            self.ec2.reset_mock()
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

    def test_run_instances_multiple_networks(self):
        """Run 2 instances at once on 2 subnets in all combinations."""
        self._build_multiple_data_model()

        ec2os_reservations = [
            fakes.gen_ec2_reservation([
                fakes.gen_ec2_instance(ec2_instance_id,
                                       private_ip_address=None)])
            for ec2_instance_id in self.IDS_EC2_INSTANCE]

        ec2_instances = [
            fakes.gen_ec2_instance(
                ec2_instance_id,
                private_ip_address=None,
                ec2_network_interfaces=eni_pair)
            for ec2_instance_id, eni_pair in zip(
                self.IDS_EC2_INSTANCE,
                zip(*[iter(self.EC2_ATTACHED_ENIS)] * 2))]
        ec2_reservation = fakes.gen_ec2_reservation(ec2_instances)

        fakes_db_items = dict((eni['id'], eni)
                              for eni in self.DB_DETACHED_ENIS)
        fakes_db_items.update({
            fakes.ID_DB_SUBNET_1: fakes.DB_SUBNET_1,
            fakes.ID_DB_SUBNET_2: fakes.DB_SUBNET_2})
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(fakes_db_items))
        self.create_network_interface.side_effect = (
            [{'networkInterface': eni}
             for eni in self.EC2_DETACHED_ENIS])
        self.ec2.run_instances.side_effect = (
            [copy.deepcopy(r)
             for r in ec2os_reservations])
        self.neutron.list_ports.return_value = (
            {'ports': self.OS_DETACHED_PORTS + [self.OS_FAKE_PORT]})
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE

        resp = self.execute(
            'RunInstances',
            {'ImageId': 'fake_image',
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
        self.ec2.run_instances.assert_has_calls([
            mock.call(image_id='fake_image',
                      min_count=1, max_count=1,
                      security_group=None,
                      network_interface=[
                          {'network_interface_id': port_id}
                          for port_id in port_ids])
            for port_ids in zip(*[iter(self.IDS_OS_PORT)] * 2)])
        self.db_api.update_item.assert_has_calls([
            mock.call(mock.ANY, eni)
            for eni in self.DB_ATTACHED_ENIS])
        self.isotime.assert_called_once_with(None, True)

    @mock.patch('ec2api.api.network_interface.delete_network_interface')
    @mock.patch('ec2api.api.instance._format_instance')
    def test_run_instances_rollback(self, format_instance,
                                    delete_network_interface):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(
                {fakes.ID_DB_SUBNET_1: fakes.DB_SUBNET_1,
                 fakes.ID_DB_NETWORK_INTERFACE_1:
                 copy.deepcopy(fakes.DB_NETWORK_INTERFACE_1)}))
        self.neutron.list_ports.return_value = (
            {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})
        self.create_network_interface.return_value = (
            {'networkInterface': fakes.EC2_NETWORK_INTERFACE_1})
        self.ec2.run_instances.return_value = (
            fakes.gen_ec2_reservation([fakes.gen_ec2_instance(
                fakes.ID_EC2_INSTANCE_1, private_ip_address=None)]))
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE
        format_instance.side_effect = Exception()

        def do_check(params, new_port=True, delete_on_termination=None):
            params.update({'ImageId': 'fake_image',
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
            self.ec2.terminate_instances.assert_called_once_with(
                instance_id=fakes.ID_EC2_INSTANCE_1)
            self.db_api.update_item.assert_any_call(
                mock.ANY, fakes.DB_NETWORK_INTERFACE_1)

            delete_network_interface.reset_mock()
            self.neutron.reset_mock()
            self.ec2.reset_mock()
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

    def test_terminate_instances(self):
        """Terminate 2 instances in one request."""
        ec2_terminate_instances_result = {
            'instancesSet': [{'instanceId': fakes.ID_EC2_INSTANCE_1,
                              'fakeKey': 'fakeValue'},
                             {'instanceId': fakes.ID_EC2_INSTANCE_2,
                              'fakeKey': 'fakeValue'}]}

        os_instance_ids_dict = {fakes.ID_DB_INSTANCE_1: fakes.ID_OS_INSTANCE_1,
                                fakes.ID_DB_INSTANCE_2: fakes.ID_OS_INSTANCE_2}
        self.get_instance_uuid_from_int_id.side_effect = (
            lambda _, inst_id: os_instance_ids_dict[inst_id])
        self.neutron.list_ports.return_value = {'ports': [fakes.OS_PORT_2]}
        self.db_api.get_items.return_value = (
            [copy.deepcopy(fakes.DB_NETWORK_INTERFACE_1),
             copy.deepcopy(fakes.DB_NETWORK_INTERFACE_2)])
        self.ec2.terminate_instances.return_value = (
            ec2_terminate_instances_result)

        resp = self.execute('TerminateInstances',
                            {'InstanceId.1': fakes.ID_EC2_INSTANCE_1,
                             'InstanceId.2': fakes.ID_EC2_INSTANCE_2})

        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.assertThat(resp, matchers.DictMatches(
            ec2_terminate_instances_result))
        self.get_instance_uuid_from_int_id.assert_any_call(
            mock.ANY, fakes.ID_DB_INSTANCE_1)
        self.get_instance_uuid_from_int_id.assert_any_call(
            mock.ANY, fakes.ID_DB_INSTANCE_2)
        self._assert_list_ports_is_called_with_filter(
            [fakes.ID_OS_INSTANCE_1, fakes.ID_OS_INSTANCE_2])
        self.neutron.update_port.assert_called_once_with(
            fakes.ID_OS_PORT_2,
            {'port': {'device_id': '',
                      'device_owner': ''}})
        self.ec2.terminate_instances.assert_called_once_with(
            instance_id=[fakes.ID_EC2_INSTANCE_1, fakes.ID_EC2_INSTANCE_2])

    def test_terminate_instances_multiple_networks(self):
        """Terminate an instance with various combinations of ports."""
        self._build_multiple_data_model()

        ec2_terminate_instances_result = {
            'instancesSet': [{'instanceId': fakes.ID_EC2_INSTANCE_1,
                              'fakeKey': 'fakeValue'},
                             {'instanceId': fakes.ID_EC2_INSTANCE_2,
                              'fakeKey': 'fakeValue'}]}

        os_instance_ids_dict = {fakes.ID_DB_INSTANCE_1: fakes.ID_OS_INSTANCE_1,
                                fakes.ID_DB_INSTANCE_2: fakes.ID_OS_INSTANCE_2}
        self.get_instance_uuid_from_int_id.side_effect = (
            lambda _, inst_id: os_instance_ids_dict[inst_id])
        self.ec2.terminate_instances.return_value = (
            ec2_terminate_instances_result)

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
            for inst_id in self.IDS_DB_INSTANCE:
                self.get_instance_uuid_from_int_id.assert_any_call(
                    mock.ANY, inst_id)
            self._assert_list_ports_is_called_with_filter(self.IDS_OS_INSTANCE)
            self.ec2.terminate_instances.assert_called_once_with(
                instance_id=self.IDS_EC2_INSTANCE)
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
            self.assertEqual(len(deleted_ports),
                             self.db_api.delete_item.call_count)
            for port in deleted_ports:
                self.db_api.delete_item.assert_any_call(
                    mock.ANY,
                    port['id'])

            self.get_instance_uuid_from_int_id.reset_mock()
            self.neutron.list_ports.reset_mock()
            self.neutron.update_port.reset_mock()
            self.ec2.terminate_instances.reset_mock()
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

    def test_describe_instances(self):
        """Describe 2 instances, one of which is vpc instance."""
        self.ec2.describe_instances.return_value = (
            {'reservationSet': [fakes.EC2OS_RESERVATION_1,
                                fakes.EC2OS_RESERVATION_2],
             'fakeKey': 'fakeValue'})
        self.ec2_inst_id_to_uuid.side_effect = [fakes.ID_OS_INSTANCE_1,
                                                fakes.ID_OS_INSTANCE_2]
        self.neutron.list_ports.return_value = {'ports': [fakes.OS_PORT_2]}
        self.db_api.get_items.side_effect = (
            lambda _, kind: [fakes.DB_NETWORK_INTERFACE_1,
                             fakes.DB_NETWORK_INTERFACE_2]
            if kind == 'eni' else
            [fakes.DB_ADDRESS_1, fakes.DB_ADDRESS_2]
            if kind == 'eipalloc' else [])
        self.neutron.list_floatingips.return_value = (
            {'floatingips': [fakes.OS_FLOATING_IP_1,
                             fakes.OS_FLOATING_IP_2]})

        resp = self.execute('DescribeInstances', {})

        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.ec2.describe_instances.assert_called_once_with(
            instance_id=None, filter=None)
        self.assertThat(resp, matchers.DictMatches(
            {'reservationSet': [fakes.EC2_RESERVATION_1,
                                fakes.EC2_RESERVATION_2],
             'fakeKey': 'fakeValue'}))
        self.ec2_inst_id_to_uuid.assert_any_call(
            mock.ANY,
            fakes.ID_EC2_INSTANCE_1)
        self.ec2_inst_id_to_uuid.assert_any_call(
            mock.ANY,
            fakes.ID_EC2_INSTANCE_2)
        self._assert_list_ports_is_called_with_filter(
            [fakes.ID_OS_INSTANCE_1, fakes.ID_OS_INSTANCE_2])

    def test_describe_instances_mutliple_networks(self):
        """Describe 2 instances with various combinations of network."""
        self._build_multiple_data_model()
        ips_instance = [fakes.IP_FIRST_SUBNET_1, fakes.IP_FIRST_SUBNET_2]

        def do_check(separate_reservations=False, mock_port_list=[],
                     mock_eni_list=[], ec2_enis_by_instance=[],
                     is_instance_ip_in_vpc_by_instance=[True, True]):
            def gen_reservation_set(instances):
                if separate_reservations:
                    return [fakes.gen_ec2_reservation([instances[0]]),
                            fakes.gen_ec2_reservation([instances[1]])]
                else:
                    return [fakes.gen_ec2_reservation([instances[0],
                                                       instances[1]])]

            instances = [fakes.gen_ec2_instance(inst_id, private_ip_address=ip)
                         for inst_id, ip in zip(
                self.IDS_EC2_INSTANCE, ips_instance)]
            reservation_set = gen_reservation_set([instances[0], instances[1]])

            self.ec2.describe_instances.return_value = (
                {'reservationSet': reservation_set,
                 'fakeKey': 'fakeValue'})
            self.ec2_inst_id_to_uuid.side_effect = self.IDS_OS_INSTANCE
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
            self.ec2.describe_instances.assert_called_once_with(
                instance_id=None, filter=None)
            for inst_id in self.IDS_EC2_INSTANCE:
                self.ec2_inst_id_to_uuid.assert_any_call(
                    mock.ANY, inst_id)
            self._assert_list_ports_is_called_with_filter(self.IDS_OS_INSTANCE)

            self.ec2.describe_instances.reset_mock()
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
        ids_db_eni = [fakes.random_db_id() for _ in range(ports_count)]
        ids_os_port = [fakes.random_os_id() for _ in range(ports_count)]

        ids_db_subnet = (fakes.ID_DB_SUBNET_1, fakes.ID_DB_SUBNET_2)
        ids_db_subnet_by_port = ids_db_subnet * 2
        ids_ec2_subnet = (fakes.ID_EC2_SUBNET_1, fakes.ID_EC2_SUBNET_2)
        ids_ec2_subnet_by_port = ids_ec2_subnet * 2
        ips = (fakes.IP_FIRST_SUBNET_1, fakes.IP_FIRST_SUBNET_2,
               fakes.IP_LAST_SUBNET_1, fakes.IP_LAST_SUBNET_2)

        ids_db_instance = [fakes.ID_DB_INSTANCE_1, fakes.ID_DB_INSTANCE_2]
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
                db_id, os_id, fakes.ID_DB_VPC_1,
                subnet_db_id, ip,
                instance_id=instance_db_id,
                delete_on_termination=dot)
            for db_id, os_id, subnet_db_id, ip, instance_db_id, dot in zip(
                ids_db_eni,
                ids_os_port,
                ids_db_subnet_by_port,
                ips,
                ids_db_instance_by_port,
                dots_by_port)]
        db_detached_enis = [
            fakes.gen_db_network_interface(
                db_id, os_id, fakes.ID_DB_VPC_1,
                subnet_db_id, ip)
            for db_id, os_id, subnet_db_id, ip in zip(
                ids_db_eni,
                ids_os_port,
                ids_db_subnet_by_port,
                ips)]
        ec2_attached_enis = [
            fakes.gen_ec2_network_interface(
                ec2utils.get_ec2_id(db_eni['id'], 'eni'),
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
                ec2utils.get_ec2_id(db_eni['id'], 'eni'),
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

        self.IDS_DB_ENI = ids_db_eni
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
            fakes.random_db_id(), fakes.random_os_id(),
            fakes.ID_DB_VPC_1, fakes.ID_DB_SUBNET_2,
            'fake_ip')
        ec2_fake_eni = fakes.gen_ec2_network_interface(
            ec2utils.get_ec2_id(self.DB_FAKE_ENI['id'], 'eni'),
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


class InstanceIntegrationTestCase(base.ApiTestCase):

    def test_run_instances(self):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id(
                {fakes.ID_DB_SUBNET_1: fakes.DB_SUBNET_1,
                 fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                 fakes.ID_DB_NETWORK_INTERFACE_1:
                 fakes.DB_NETWORK_INTERFACE_1}))
        self.db_api.add_item.return_value = fakes.DB_NETWORK_INTERFACE_1
        self.neutron.show_subnet.return_value = {'subnet': fakes.OS_SUBNET_1}
        self.neutron.create_port.return_value = {'port': fakes.OS_PORT_1}
        self.neutron.list_ports.return_value = {'ports': [fakes.OS_PORT_1]}
        self.ec2.run_instances.return_value = (
            fakes.gen_ec2_reservation([fakes.gen_ec2_instance(
                fakes.ID_EC2_INSTANCE_1, private_ip_address=None)]))
        self.isotime.return_value = fakes.TIME_ATTACH_NETWORK_INTERFACE

        resp = self.execute('RunInstances',
                            {'ImageId': 'fake_image',
                             'MinCount': '1', 'MaxCount': '1',
                             'SubnetId': fakes.ID_EC2_SUBNET_1})

        self.assertEqual(200, resp['status'])
