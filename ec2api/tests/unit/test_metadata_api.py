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

import mock
from novaclient import exceptions as nova_exception

from ec2api import exception
from ec2api.metadata import api
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers


class MetadataApiTestCase(base.ApiTestCase):
    # TODO(ft): 'execute' feature isn't used here, but some mocks and
    # fake context are. ApiTestCase should be split to some classes to use
    # its feature optimally

    def setUp(self):
        super(MetadataApiTestCase, self).setUp()

        instance_api_patcher = mock.patch('ec2api.metadata.api.instance_api')
        self.instance_api = instance_api_patcher.start()
        self.addCleanup(instance_api_patcher.stop)

        self.set_mock_db_items(fakes.DB_INSTANCE_1)
        self.instance_api.describe_instances.return_value = {
               'reservationSet': [fakes.EC2_RESERVATION_1]}
        self.instance_api.describe_instance_attribute.return_value = {
                'instanceId': fakes.ID_EC2_INSTANCE_1,
                'userData': {'value': base64.b64encode('fake_user_data')}}

        self.fake_context = self._create_context()

    def test_get_version_list(self):
        retval = api.get_version_list()
        self.assertEqual('\n'.join(api.VERSIONS + ['latest']), retval)

    def test_get_instance_and_project_id(self):
        self.nova.servers.list.return_value = [
            fakes.OSInstance(fakes.OS_INSTANCE_1),
            fakes.OSInstance(fakes.OS_INSTANCE_2)]
        self.nova.fixed_ips.get.return_value = mock.Mock(hostname='fake_name')
        self.assertEqual(
            (fakes.ID_OS_INSTANCE_1, fakes.ID_OS_PROJECT),
            api.get_os_instance_and_project_id(self.fake_context,
                                               fakes.IP_NETWORK_INTERFACE_2))
        self.nova.fixed_ips.get.assert_called_with(
                fakes.IP_NETWORK_INTERFACE_2)
        self.nova.servers.list.assert_called_with(
                search_opts={'hostname': 'fake_name',
                             'all_tenants': True})

        def check_raise():
            self.assertRaises(exception.EC2MetadataNotFound,
                              api.get_os_instance_and_project_id,
                              self.fake_context,
                              fakes.IP_NETWORK_INTERFACE_2)

        self.nova.servers.list.return_value = [
            fakes.OSInstance(fakes.OS_INSTANCE_2)]
        check_raise()

        self.nova.fixed_ips.get.side_effect = nova_exception.NotFound('fake')
        self.nova.servers.list.return_value = [
            fakes.OSInstance(fakes.OS_INSTANCE_1),
            fakes.OSInstance(fakes.OS_INSTANCE_2)]
        check_raise()

    def test_get_version_root(self):
        retval = api.get_metadata_item(self.fake_context, ['2009-04-04'],
                                       fakes.ID_OS_INSTANCE_1,
                                       fakes.IP_NETWORK_INTERFACE_2)
        self.assertEqual('meta-data/\nuser-data', retval)

        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context, ['9999-99-99'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)

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
                          fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)

    def test_mismatch_project_id(self):
        self.fake_context.project_id = fakes.random_os_id()
        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context, ['2009-04-04'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)

    def test_non_existing_instance(self):
        self.instance_api.describe_instances.return_value = {
               'reservationSet': []}
        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context, ['2009-04-04'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)

    def test_user_data(self):
        retval = api.get_metadata_item(
               self.fake_context, ['2009-04-04', 'user-data'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)
        self.assertEqual('fake_user_data', retval)

    def test_no_user_data(self):
        self.instance_api.describe_instance_attribute.return_value = {
                'instanceId': fakes.ID_EC2_INSTANCE_1}
        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context,
              ['2009-04-04', 'user-data'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)

    def test_security_groups(self):
        self.instance_api.describe_instances.return_value = {
               'reservationSet': [fakes.EC2_RESERVATION_2]}
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'security-groups'],
               fakes.ID_OS_INSTANCE_2, fakes.IP_NETWORK_INTERFACE_1)
        self.assertEqual('\n'.join([fakes.NAME_DEFAULT_OS_SECURITY_GROUP,
                                    fakes.NAME_OTHER_OS_SECURITY_GROUP]),
                         retval)

    def test_local_hostname(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'local-hostname'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)
        self.assertEqual(fakes.EC2_INSTANCE_1['privateDnsName'], retval)

    def test_local_ipv4(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'local-ipv4'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)
        self.assertEqual(fakes.IP_NETWORK_INTERFACE_2, retval)

    def test_local_ipv4_from_address(self):
        self.instance_api.describe_instances.return_value = {
               'reservationSet': [fakes.EC2_RESERVATION_2]}
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'local-ipv4'],
               fakes.ID_OS_INSTANCE_2, fakes.IP_NETWORK_INTERFACE_1)
        self.assertEqual(fakes.IP_NETWORK_INTERFACE_1, retval)

    def test_pubkey_name(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'public-keys'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)
        self.assertEqual('0=%s' % fakes.NAME_KEY_PAIR, retval)

    @base.skip_not_implemented
    def test_pubkey(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'public-keys', '0', 'openssh-key'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)
        self.assertEqual(fakes.PUBLIC_KEY_KEY_PAIR, retval)

    def test_image_type_ramdisk(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'ramdisk-id'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)
        self.assertEqual(fakes.ID_EC2_IMAGE_ARI_1, retval)

    def test_image_type_kernel(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'kernel-id'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)
        self.assertEqual(fakes.ID_EC2_IMAGE_AKI_1, retval)

    def test_check_version(self):
        retval = api.get_metadata_item(
               self.fake_context,
               ['2009-04-04', 'meta-data', 'block-device-mapping'],
               fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)
        self.assertIsNotNone(retval)

        self.assertRaises(
              exception.EC2MetadataNotFound,
              api.get_metadata_item, self.fake_context,
              ['2007-08-29', 'meta-data', 'block-device-mapping'],
              fakes.ID_OS_INSTANCE_1, fakes.IP_NETWORK_INTERFACE_2)

    def test_format_instance_mapping(self):
        self.instance_api._block_device_strip_dev.return_value = 'vda'
        retval = api._build_block_device_mappings(
                'fake_context', fakes.EC2_INSTANCE_1, fakes.ID_OS_INSTANCE_1)
        self.assertThat(retval,
                        matchers.DictMatches(
                             {'ami': 'vda',
                              'root': fakes.ROOT_DEVICE_NAME_INSTANCE_1}))
        self.instance_api._block_device_strip_dev.assert_called_with(
                fakes.EC2_INSTANCE_1['rootDeviceName'])

        self.instance_api._block_device_strip_dev.return_value = 'sdb1'
        retval = api._build_block_device_mappings(
                'fake_context', fakes.EC2_INSTANCE_2, fakes.ID_OS_INSTANCE_2)
        expected = {'ami': 'sdb1',
                    'root': fakes.ROOT_DEVICE_NAME_INSTANCE_2}
        expected.update(fakes.EC2_BDM_METADATA_INSTANCE_2)
        self.assertThat(retval,
                        matchers.DictMatches(expected))
        self.instance_api._block_device_strip_dev.assert_called_with(
                fakes.EC2_INSTANCE_2['rootDeviceName'])
