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
from unittest import mock

from novaclient import exceptions as nova_exception
from oslo_cache import core as cache_core
from oslo_config import cfg

from ec2api import exception
from ec2api.metadata import api
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools

CONF = cfg.CONF
FAKE_USER_DATA = u'fake_user_data-' + chr(1071)


class MetadataApiTestCase(base.ApiTestCase):
    # TODO(ft): 'execute' feature isn't used here, but some mocks and
    # fake context are. ApiTestCase should be split to some classes to use
    # its feature optimally

    def setUp(self):
        super(MetadataApiTestCase, self).setUp()
        self.instance_api = self.mock('ec2api.metadata.api.instance_api')

        self.set_mock_db_items(fakes.DB_INSTANCE_1)
        self.instance_api.describe_instances.return_value = {
               'reservationSet': [fakes.EC2_RESERVATION_1]}
        userDataValue = base64.b64encode(FAKE_USER_DATA.encode('utf-8'))
        self.instance_api.describe_instance_attribute.return_value = {
                'instanceId': fakes.ID_EC2_INSTANCE_1,
                'userData': {'value': userDataValue}}
        self.configure(enabled=False, group='cache')
        self._init_cache_region()

        self.fake_context = base.create_context()

    def _init_cache_region(self):
        self.cache_region = cache_core.create_region()
        cache_core.configure_cache_region(CONF, self.cache_region)

    def test_get_version_list(self):
        retval = api.get_version_list()
        self.assertEqual('\n'.join(api.VERSIONS + ['latest']), retval)

    def test_get_instance_and_project_id_by_provider_id(self):
        self.neutron.list_subnets.return_value = {
            'subnets': [fakes.OS_SUBNET_1, fakes.OS_SUBNET_2]}
        self.neutron.list_ports.return_value = {
            'ports': [fakes.OS_PORT_2]}
        self.assertEqual(
            (fakes.ID_OS_INSTANCE_1, fakes.ID_OS_PROJECT),
            api.get_os_instance_and_project_id_by_provider_id(
                self.fake_context, mock.sentinel.provider_id,
                fakes.IP_NETWORK_INTERFACE_2))
        self.neutron.list_subnets.assert_called_with(
            advanced_service_providers=[mock.sentinel.provider_id],
            fields=['network_id'])
        self.neutron.list_ports.assert_called_with(
            fixed_ips=('ip_address=%s' % fakes.IP_NETWORK_INTERFACE_2),
            network_id=[fakes.ID_OS_NETWORK_1, fakes.ID_OS_NETWORK_2],
            fields=['device_id', 'tenant_id'])

        self.neutron.list_ports.return_value = {'ports': []}
        self.assertRaises(exception.EC2MetadataNotFound,
                          api.get_os_instance_and_project_id_by_provider_id,
                          self.fake_context, mock.sentinel.provider_id,
                          fakes.IP_NETWORK_INTERFACE_2)

        self.neutron.list_subnets.return_value = {'subnets': []}
        self.assertRaises(exception.EC2MetadataNotFound,
                          api.get_os_instance_and_project_id_by_provider_id,
                          self.fake_context, mock.sentinel.provider_id,
                          fakes.IP_NETWORK_INTERFACE_2)

    def test_get_version_root(self):
        retval = api.get_metadata_item(self.fake_context, ['2009-04-04'],
                                       fakes.ID_OS_INSTANCE_1,
                                       fakes.IP_NETWORK_INTERFACE_2,
                                       self.cache_region)
        self.assertEqual('meta-data/\nuser-data', retval)

        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context, ['9999-99-99'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
              self.cache_region)

        self.db_api.get_items_ids.assert_called_with(
            self.fake_context, 'i', item_ids=None,
            item_os_ids=(fakes.ID_OS_INSTANCE_1,))
        self.instance_api.describe_instances.assert_called_with(
            self.fake_context, [fakes.ID_EC2_INSTANCE_1])
        self.instance_api.describe_instance_attribute.assert_called_with(
            self.fake_context, fakes.ID_EC2_INSTANCE_1, 'userData')

    def test_invalid_path(self):
        self.assertRaises(exception.EC2MetadataNotFound,
                          api.get_metadata_item, self.fake_context,
                          ['9999-99-99', 'user-data-invalid'],
                          fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
                          self.cache_region)

    def test_mismatch_project_id(self):
        self.fake_context.project_id = fakes.random_os_id()
        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context, ['2009-04-04'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
              self.cache_region)

    def test_non_existing_instance(self):
        self.instance_api.describe_instances.return_value = {
               'reservationSet': []}
        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context, ['2009-04-04'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
              self.cache_region)

    def test_user_data(self):
        retval = api.get_metadata_item(
               self.fake_context, ['2009-04-04', 'user-data'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual(FAKE_USER_DATA, retval)

    def test_no_user_data(self):
        self.instance_api.describe_instance_attribute.return_value = {
                'instanceId': fakes.ID_EC2_INSTANCE_1}
        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context,
              ['2009-04-04', 'user-data'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
              self.cache_region)

    def test_security_groups(self):
        self.instance_api.describe_instances.return_value = {
               'reservationSet': [fakes.EC2_RESERVATION_2]}
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'security-groups'],
               fakes.ID_OS_INSTANCE_2, fakes.IP_NETWORK_INTERFACE_1,
               self.cache_region)
        self.assertEqual('\n'.join(['groupname3']),
                         retval)

    def test_local_hostname(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'local-hostname'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual(fakes.EC2_INSTANCE_1['privateDnsName'], retval)

    def test_local_ipv4(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'local-ipv4'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual(fakes.IP_NETWORK_INTERFACE_2, retval)

    def test_local_ipv4_from_address(self):
        self.instance_api.describe_instances.return_value = {
               'reservationSet': [fakes.EC2_RESERVATION_2]}
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'local-ipv4'],
               fakes.ID_OS_INSTANCE_2, fakes.IP_NETWORK_INTERFACE_1,
               self.cache_region)
        self.assertEqual(fakes.IP_NETWORK_INTERFACE_1, retval)

    def test_pubkey_name(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'public-keys'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual('0=%s' % fakes.NAME_KEY_PAIR, retval)

    def test_pubkey(self):
        self.nova.servers.get.return_value = (
               fakes.OSInstance(fakes.OS_INSTANCE_1))
        self.nova.keypairs.keypair_prefix = 'os_keypairs'
        self.nova.keypairs._get.return_value = (
               fakes.NovaKeyPair(fakes.OS_KEY_PAIR))
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'public-keys', '0', 'openssh-key'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual(fakes.PUBLIC_KEY_KEY_PAIR, retval)
        self.nova.servers.get.assert_called_once_with(fakes.ID_OS_INSTANCE_1)
        self.nova.keypairs._get.assert_called_once_with(
               '/os_keypairs/%s?user_id=%s' % (fakes.NAME_KEY_PAIR,
                                               fakes.ID_OS_USER),
               'keypair')

        self.nova.keypairs._get.side_effect = nova_exception.NotFound(404)
        self.assertRaises(
                exception.EC2MetadataNotFound,
                api.get_metadata_item,
                self.fake_context,
                ['2009-04-04', 'meta-data', 'public-keys', '0', 'openssh-key'],
                fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
                self.cache_region)

    def test_image_type_ramdisk(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'ramdisk-id'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual(fakes.ID_EC2_IMAGE_ARI_1, retval)

    def test_image_type_kernel(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'kernel-id'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual(fakes.ID_EC2_IMAGE_AKI_1, retval)

    def test_check_version(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'block-device-mapping'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertIsNotNone(retval)

        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context,
              ['2007-08-29', 'meta-data', 'block-device-mapping'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
              self.cache_region)

    def test_format_instance_mapping(self):
        retval = api._build_block_device_mappings(
                'fake_context', fakes.EC2_INSTANCE_1, fakes.ID_OS_INSTANCE_1)
        self.assertThat(retval,
                        matchers.DictMatches(
                             {'ami': 'vda',
                              'root': fakes.ROOT_DEVICE_NAME_INSTANCE_1}))

        retval = api._build_block_device_mappings(
                'fake_context', fakes.EC2_INSTANCE_2, fakes.ID_OS_INSTANCE_2)
        expected = {'ami': 'sdb1',
                    'root': fakes.ROOT_DEVICE_NAME_INSTANCE_2}
        expected.update(fakes.EC2_BDM_METADATA_INSTANCE_2)
        self.assertThat(retval,
                        matchers.DictMatches(expected))

    def test_metadata_cache(self):
        self.configure(enabled=True, group='cache')
        self.configure(backend='oslo_cache.dict', group='cache')
        self._init_cache_region()
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'local-ipv4'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual(fakes.IP_NETWORK_INTERFACE_2, retval)
        self.nova.servers.get.assert_called_once_with(fakes.ID_OS_INSTANCE_1)
        self.nova.servers.get.reset_mock()

        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'instance-id'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               self.cache_region)
        self.assertEqual(fakes.ID_EC2_INSTANCE_1, retval)
        self.nova.servers.get.assert_not_called()


class MetadataApiIntegralTestCase(base.ApiTestCase):
    # TODO(ft): 'execute' feature isn't used here, but some mocks and
    # fake context are. ApiTestCase should be split to some classes to use
    # its feature optimally

    @mock.patch('ec2api.metadata.api.cache_core.create_region')
    @mock.patch('ec2api.api.instance.security_group_api')
    @mock.patch('ec2api.api.instance.network_interface_api')
    def test_get_metadata_integral(self, network_interface_api,
                                   security_group_api, create_region):
        fake_context = base.create_context(is_os_admin=True)

        self.set_mock_db_items(
            fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2,
            fakes.DB_IMAGE_1, fakes.DB_IMAGE_2,
            fakes.DB_IMAGE_ARI_1, fakes.DB_IMAGE_AKI_1,
            fakes.DB_VOLUME_1, fakes.DB_VOLUME_2, fakes.DB_VOLUME_3)
        self.nova_admin.servers.list.return_value = [
            fakes.OSInstance_full(fakes.OS_INSTANCE_1),
            fakes.OSInstance_full(fakes.OS_INSTANCE_2)]
        self.nova_admin.servers.get.side_effect = tools.get_by_1st_arg_getter({
            fakes.ID_OS_INSTANCE_1: fakes.OSInstance_full(fakes.OS_INSTANCE_1),
            fakes.ID_OS_INSTANCE_2: fakes.OSInstance_full(fakes.OS_INSTANCE_2)
        })
        self.nova_admin.keypairs._get.return_value = (
               fakes.NovaKeyPair(fakes.OS_KEY_PAIR))
        self.cinder.volumes.list.return_value = [
            fakes.OSVolume(fakes.OS_VOLUME_1),
            fakes.OSVolume(fakes.OS_VOLUME_2),
            fakes.OSVolume(fakes.OS_VOLUME_3)]
        network_interface_api.describe_network_interfaces.side_effect = (
            lambda *args, **kwargs: copy.deepcopy({
                'networkInterfaceSet': [fakes.EC2_NETWORK_INTERFACE_1,
                                        fakes.EC2_NETWORK_INTERFACE_2]}))
        security_group_api.describe_security_groups.return_value = {
            'securityGroupInfo': [fakes.EC2_SECURITY_GROUP_1,
                                  fakes.EC2_SECURITY_GROUP_3]}
        create_region.get.return_value = cache_core.NO_VALUE

        retval = api.get_metadata_item(
               fake_context, ['latest', 'meta-data', 'instance-id'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2,
               create_region)
        self.assertEqual(fakes.ID_EC2_INSTANCE_1, retval)

        retval = api.get_metadata_item(
               fake_context, ['latest', 'meta-data', 'instance-id'],
               fakes.ID_OS_INSTANCE_2, '10.200.1.15',
               create_region)
        self.assertEqual(fakes.ID_EC2_INSTANCE_2, retval)
