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
from oslotest import base as test_base

from ec2api.api import image as image_api
from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class ImageTestCase(base.ApiTestCase):

    @mock.patch('ec2api.api.image._s3_create')
    def test_register_image(self, s3_create):
        s3_create.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        self.db_api.add_item.side_effect = (
            fakes.get_db_api_add_item(fakes.ID_EC2_IMAGE_1))

        resp = self.execute(
            'RegisterImage',
            {'ImageLocation': fakes.LOCATION_IMAGE_1})
        self.assertThat(resp, matchers.DictMatches(
            {'status': 200,
            'imageId': fakes.ID_EC2_IMAGE_1}))

        s3_create.assert_called_once_with(
            mock.ANY,
            {'name': fakes.LOCATION_IMAGE_1,
             'properties': {'image_location': fakes.LOCATION_IMAGE_1}})
        s3_create.reset_mock()

        resp = self.execute(
            'RegisterImage',
            {'ImageLocation': fakes.LOCATION_IMAGE_1,
             'Name': 'an image name'})
        self.assertThat(resp, matchers.DictMatches(
            {'status': 200,
            'imageId': fakes.ID_EC2_IMAGE_1}))

        s3_create.assert_called_once_with(
            mock.ANY,
            {'name': 'an image name',
             'properties': {'image_location': fakes.LOCATION_IMAGE_1}})

    def test_register_image_invalid_parameters(self):
        resp = self.execute('RegisterImage', {})
        self.assertEqual(400, resp['status'])
        self.assertEqual('MissingParameter', resp['Error']['Code'])

    def test_deregister_image(self):
        self._setup_model()

        resp = self.execute('DeregisterImage',
                            {'ImageId': fakes.ID_EC2_IMAGE_1})
        self.assertThat(resp, matchers.DictMatches({'status': 200,
                                                    'return': True}))
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_IMAGE_1)
        self.glance.images.delete.assert_called_once_with(
            fakes.ID_OS_IMAGE_1)

    def test_deregister_image_invalid_parameters(self):
        self._setup_model()

        resp = self.execute('DeregisterImage',
                            {'ImageId': fakes.random_ec2_id('ami')})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidAMIID.NotFound', resp['Error']['Code'])

    def test_describe_images(self):
        self._setup_model()

        resp = self.execute('DescribeImages', {})
        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.assertThat(resp, matchers.DictMatches(
            {'imagesSet': [fakes.EC2_IMAGE_1, fakes.EC2_IMAGE_2]},
            orderless_lists=True))

        self.db_api.get_items_by_ids.assert_any_call(mock.ANY, 'ami', set([]))

        self.db_api.get_items_by_ids = tools.CopyingMock(
            side_effect=self.db_api.get_items_by_ids.side_effect)

        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.ID_EC2_IMAGE_1})
        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.assertThat(resp, matchers.DictMatches(
            {'imagesSet': [fakes.EC2_IMAGE_1]},
            orderless_lists=True))

        self.db_api.get_items_by_ids.assert_any_call(
            mock.ANY, 'ami', set([fakes.ID_EC2_IMAGE_1]))

    def test_describe_images_invalid_parameters(self):
        self._setup_model()

        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.random_ec2_id('ami')})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidAMIID.NotFound', resp['Error']['Code'])

        self.glance.images.list.side_effect = lambda: []

        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.ID_EC2_IMAGE_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidAMIID.NotFound', resp['Error']['Code'])

    def test_describe_image_attributes(self):
        self._setup_model()

        def do_check(attr, ec2_image_id, response):
            self.db_api.reset_mock()
            self.glance.reset_mock()
            resp = self.execute('DescribeImageAttribute',
                                {'ImageId': ec2_image_id,
                                 'Attribute': attr})
            response['status'] = 200
            response['imageId'] = ec2_image_id
            self.assertThat(resp, matchers.DictMatches(response,
                                                       orderless_lists=True))

        do_check('launchPermission',
                 fakes.ID_EC2_IMAGE_2,
                 {'launchPermission': [{'group': 'all'}]})

        do_check('kernel',
                 fakes.ID_EC2_IMAGE_1,
                 {'kernel': {'value': fakes.ID_EC2_IMAGE_AKI_1}})

        do_check('ramdisk',
                 fakes.ID_EC2_IMAGE_1,
                 {'ramdisk': {'value': fakes.ID_EC2_IMAGE_ARI_1}})

        do_check('rootDeviceName',
                 fakes.ID_EC2_IMAGE_1,
                 {'rootDeviceName': fakes.ROOT_DEVICE_NAME_IMAGE_1})

        do_check('rootDeviceName',
                 fakes.ID_EC2_IMAGE_2,
                 {'rootDeviceName': fakes.ROOT_DEVICE_NAME_IMAGE_2})

        do_check('blockDeviceMapping',
                 fakes.ID_EC2_IMAGE_1,
                 {'blockDeviceMapping':
                        fakes.EC2_IMAGE_1['blockDeviceMapping']})

        do_check('blockDeviceMapping',
                 fakes.ID_EC2_IMAGE_2,
                 {'blockDeviceMapping':
                        fakes.EC2_IMAGE_2['blockDeviceMapping']})

    @mock.patch.object(fakes.OSImage, 'update', autospec=True)
    def test_modify_image_attributes(self, osimage_update):
        self._setup_model()

        resp = self.execute('ModifyImageAttribute',
                            {'imageId': fakes.ID_EC2_IMAGE_1,
                             'attribute': 'launchPermission',
                             'operationType': 'add',
                             'userGroup.1': 'all'})
        self.assertThat(resp, matchers.DictMatches({'status': 200,
                                                    'return': True}))
        osimage_update.assert_called_once_with(
                mock.ANY, is_public=True)
        self.assertEqual(fakes.ID_OS_IMAGE_1,
                         osimage_update.call_args[0][0].id)

    def _setup_model(self):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_IMAGE_1: fakes.DB_IMAGE_1,
                fakes.ID_EC2_IMAGE_2: fakes.DB_IMAGE_2}))
        self.db_api.get_items_by_ids.side_effect = (
            fakes.get_db_api_get_items({
                'ami': [fakes.DB_IMAGE_1, fakes.DB_IMAGE_2],
                'ari': [],
                'aki': []}))
        self.db_api.get_items.side_effect = (
            fakes.get_db_api_get_items({
                'snap': [fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2]}))
        self.db_api.get_public_items.return_value = []

        self.db_api.get_item_ids.side_effect = (
            fakes.get_db_api_get_item_by_id({
                (fakes.ID_OS_IMAGE_ARI_1,): [(fakes.ID_EC2_IMAGE_ARI_1,
                                              fakes.ID_OS_IMAGE_ARI_1)],
                (fakes.ID_OS_IMAGE_AKI_1,): [(fakes.ID_EC2_IMAGE_AKI_1,
                                              fakes.ID_OS_IMAGE_AKI_1)],
                (fakes.ID_OS_SNAPSHOT_1,): [(fakes.ID_EC2_SNAPSHOT_1,
                                             fakes.ID_OS_SNAPSHOT_1)],
                (fakes.ID_OS_SNAPSHOT_2,): [(fakes.ID_EC2_SNAPSHOT_2,
                                             fakes.ID_OS_SNAPSHOT_2)],
                (fakes.ID_OS_VOLUME_1,): [(fakes.ID_EC2_VOLUME_1,
                                           fakes.ID_OS_VOLUME_1)],
                (fakes.ID_OS_VOLUME_2,): [(fakes.ID_EC2_VOLUME_2,
                                           fakes.ID_OS_VOLUME_2)]}))

        self.glance.images.list.side_effect = (
            lambda: [fakes.OSImage(fakes.OS_IMAGE_1),
                     fakes.OSImage(fakes.OS_IMAGE_2)])
        self.glance.images.get.side_effect = (
            lambda os_id: (fakes.OSImage(fakes.OS_IMAGE_1)
                           if os_id == fakes.ID_OS_IMAGE_1 else
                           fakes.OSImage(fakes.OS_IMAGE_2)
                           if os_id == fakes.ID_OS_IMAGE_2 else
                           None))


class ImagePrivateTestCase(test_base.BaseTestCase):

    def test_format_image(self):
        image_ids = {fakes.ID_OS_IMAGE_1: fakes.ID_EC2_IMAGE_1,
                     fakes.ID_OS_IMAGE_AKI_1: fakes.ID_EC2_IMAGE_AKI_1,
                     fakes.ID_OS_IMAGE_ARI_1: fakes.ID_EC2_IMAGE_ARI_1}

        os_image = copy.deepcopy(fakes.OS_IMAGE_1)
        os_image['properties'] = {'image_location': 'location'}
        os_image['name'] = None

        image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, fakes.OSImage(os_image),
                None, image_ids)

        self.assertEqual('location', image['imageLocation'])
        self.assertEqual('location', image['name'])

        os_image['properties'] = {}
        os_image['name'] = 'fake_name'

        image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, fakes.OSImage(os_image),
                None, image_ids)

        self.assertEqual('None (fake_name)', image['imageLocation'])
        self.assertEqual('fake_name', image['name'])

    def test_cloud_format_mappings(self):
        properties = {
            'mappings': [
                {'virtual': 'ami', 'device': '/dev/sda'},
                {'virtual': 'root', 'device': 'sda'},
                {'virtual': 'ephemeral0', 'device': 'sdb'},
                {'virtual': 'swap', 'device': 'sdc'},
                {'virtual': 'ephemeral1', 'device': 'sdd'},
                {'virtual': 'ephemeral2', 'device': 'sde'},
                {'virtual': 'ephemeral', 'device': 'sdf'},
                {'virtual': '/dev/sdf1', 'device': 'root'}],
        }
        expected = {
            'blockDeviceMapping': [
                {'virtualName': 'ephemeral0', 'deviceName': '/dev/sdb'},
                {'virtualName': 'swap', 'deviceName': '/dev/sdc'},
                {'virtualName': 'ephemeral1', 'deviceName': '/dev/sdd'},
                {'virtualName': 'ephemeral2', 'deviceName': '/dev/sde'},
            ]
        }

        result = {}
        image_api._cloud_format_mappings('fake_context', properties, result)

        self.assertThat(result,
                        matchers.DictMatches(expected, orderless_lists=True))

    def test_block_device_properties_root_device_name(self):
        root_device0 = '/dev/sda'
        root_device1 = '/dev/sdb'
        mappings = [{'virtual': 'root',
                     'device': root_device0}]

        properties0 = {'mappings': mappings}
        properties1 = {'mappings': mappings,
                       'root_device_name': root_device1}

        self.assertIsNone(
            image_api._block_device_properties_root_device_name({}))
        self.assertEqual(
            image_api._block_device_properties_root_device_name(properties0),
            root_device0)
        self.assertEqual(
            image_api._block_device_properties_root_device_name(properties1),
            root_device1)
