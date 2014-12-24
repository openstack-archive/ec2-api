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

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class ImageTestCase(base.ApiTestCase):

    def test_describe_images(self):
        self.db_api.get_items_by_ids.side_effect = (
            fakes.get_db_api_get_items({
                'ami': [fakes.DB_IMAGE_1, fakes.DB_IMAGE_2],
                'ari': [],
                'aki': []}))
        self.db_api.get_public_items.return_value = []
        self.db_api.get_items.side_effect = (
            fakes.get_db_api_get_items({
                'snap': [fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2]}))
        self.db_api.get_item_ids.side_effect = (
            fakes.get_db_api_get_item_by_id({
                (fakes.ID_OS_IMAGE_AKI_1,): [(fakes.ID_EC2_IMAGE_AKI_1,
                                              fakes.ID_OS_IMAGE_AKI_1)],
                (fakes.ID_OS_IMAGE_ARI_1,): [(fakes.ID_EC2_IMAGE_ARI_1,
                                              fakes.ID_OS_IMAGE_ARI_1)],
                (fakes.ID_OS_VOLUME_1,): [(fakes.ID_EC2_VOLUME_1,
                                           fakes.ID_OS_VOLUME_1)],
                (fakes.ID_OS_VOLUME_2,): [(fakes.ID_EC2_VOLUME_2,
                                           fakes.ID_OS_VOLUME_2)]}))
        self.glance.images.list.return_value = [
            copy.deepcopy(fakes.OSImage(fakes.OS_IMAGE_1)),
            copy.deepcopy(fakes.OSImage(fakes.OS_IMAGE_2))]

        resp = self.execute('DescribeImages', {})
        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.assertThat(resp, matchers.DictMatches(
            {'imagesSet': [fakes.EC2_IMAGE_1, fakes.EC2_IMAGE_2]},
            orderless_lists=True))

        self.db_api.get_items_by_ids.assert_any_call(mock.ANY, 'ami', set([]))
        self.glance.images.list.return_value = [
            copy.deepcopy(fakes.OSImage(fakes.OS_IMAGE_1)),
            copy.deepcopy(fakes.OSImage(fakes.OS_IMAGE_2))]

        self.db_api.get_items_by_ids = tools.CopyingMock()
        self.db_api.get_items_by_ids.side_effect = (
            fakes.get_db_api_get_items({
                'ami': [fakes.DB_IMAGE_1],
                'ari': [],
                'aki': []}))

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
        self.db_api.get_items_by_ids.return_value = []
        self.glance.images.list.return_value = []
        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.ID_EC2_IMAGE_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidAMIID.NotFound', resp['Error']['Code'])

        self.db_api.get_items_by_ids.side_effect = (
            fakes.get_db_api_get_items({
                'ami': [fakes.DB_IMAGE_1],
                'ari': [],
                'aki': []}))

        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.ID_EC2_IMAGE_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidAMIID.NotFound', resp['Error']['Code'])
