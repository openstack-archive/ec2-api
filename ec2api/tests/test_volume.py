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


class VolumeTestCase(base.ApiTestCase):

    def test_describe_volumes(self):
        self.cinder.volumes.list.return_value = [
            fakes.CinderVolume(fakes.OS_VOLUME_1),
            fakes.CinderVolume(fakes.OS_VOLUME_2)]

        db_items = [fakes.DB_VOLUME_1, fakes.DB_VOLUME_2]
        self.db_api.get_items.return_value = db_items

        resp = self.execute('DescribeVolumes', {})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'volumeSet': [fakes.EC2_VOLUME_1, fakes.EC2_VOLUME_2]},
            orderless_lists=True))

        self.db_api.get_items.assert_any_call(mock.ANY, 'vol')

        self.db_api.get_items_by_ids.side_effect = (
            lambda context, kind, ids: [fakes.DB_VOLUME_1])
        self.db_api.get_items_by_ids = tools.CopyingMock(
            side_effect=self.db_api.get_items_by_ids.side_effect)

        resp = self.execute('DescribeVolumes',
                            {'VolumeId.1': fakes.ID_EC2_VOLUME_1})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'volumeSet': [fakes.EC2_VOLUME_1]},
            orderless_lists=True))

        self.db_api.get_items_by_ids.assert_any_call(
            mock.ANY, 'vol', set([fakes.ID_EC2_VOLUME_1]))

    def test_describe_volumes_invalid_parameters(self):
        self.cinder.volumes.list.return_value = [
            fakes.CinderVolume(fakes.OS_VOLUME_1),
            fakes.CinderVolume(fakes.OS_VOLUME_2)]

        resp = self.execute('DescribeVolumes',
                            {'VolumeId.1': fakes.random_ec2_id('vol')})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidVolume.NotFound', resp['Error']['Code'])

        self.cinder.volumes.list.side_effect = lambda: []

        resp = self.execute('DescribeVolumes',
                            {'VolumeId.1': fakes.ID_EC2_VOLUME_1})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidVolume.NotFound', resp['Error']['Code'])

    def test_create_volume(self):
        self.cinder.volumes.create.return_value = (
            fakes.CinderVolume(fakes.OS_VOLUME_1))
        self.db_api.add_item.side_effect = (
            fakes.get_db_api_add_item(fakes.ID_EC2_VOLUME_1))

        resp = self.execute(
            'CreateVolume',
            {'AvailabilityZone': fakes.VOLUME_AVAILABILITY_ZONE})
        self.assertEqual(200, resp['http_status_code'])
        self.assertThat(fakes.EC2_VOLUME_1, matchers.DictMatches(
            tools.purge_dict(resp, {'http_status_code'})))
        self.cinder.volumes.create.assert_called_once(mock.ANY)
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'vol',
            tools.purge_dict(fakes.DB_VOLUME_1, ('id',)))

    def test_format_volume_maps_status(self):
        fake_volume = fakes.CinderVolume(fakes.OS_VOLUME_1)
        self.cinder.volumes.list.return_value = [fake_volume]
        self.db_api.get_items.return_value = [fakes.DB_VOLUME_1]

        fake_volume.status = 'creating'
        resp = self.execute('DescribeVolumes', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('creating', resp['volumeSet'][0]['status'])

        fake_volume.status = 'attaching'
        resp = self.execute('DescribeVolumes', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('in-use', resp['volumeSet'][0]['status'])

        fake_volume.status = 'detaching'
        resp = self.execute('DescribeVolumes', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('in-use', resp['volumeSet'][0]['status'])

        fake_volume.status = 'banana'
        resp = self.execute('DescribeVolumes', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('banana', resp['volumeSet'][0]['status'])
