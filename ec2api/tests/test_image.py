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

import mock

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class ImageTestCase(base.ApiTestCase):

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
