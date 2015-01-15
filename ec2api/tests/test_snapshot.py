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


class SnapshotTestCase(base.ApiTestCase):

    def test_describe_snapshots(self):
        self.cinder.volume_snapshots.list.return_value = [
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_1),
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_2)]

        self.db_api.get_items.side_effect = (
            fakes.get_db_api_get_items({
                'snap': [fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2],
                'vol': [fakes.DB_VOLUME_2]}))

        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'snapshotSet': [fakes.EC2_SNAPSHOT_1, fakes.EC2_SNAPSHOT_2]},
            orderless_lists=True))

        self.db_api.get_items.assert_any_call(mock.ANY, 'vol')

        self.db_api.get_items_by_ids.side_effect = (
            lambda context, kind, ids: [fakes.DB_SNAPSHOT_1])
        self.db_api.get_items_by_ids = tools.CopyingMock(
            side_effect=self.db_api.get_items_by_ids.side_effect)

        resp = self.execute('DescribeSnapshots',
                            {'SnapshotId.1': fakes.ID_EC2_SNAPSHOT_1})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'snapshotSet': [fakes.EC2_SNAPSHOT_1]},
            orderless_lists=True))

        self.db_api.get_items_by_ids.assert_any_call(
            mock.ANY, 'snap', set([fakes.ID_EC2_SNAPSHOT_1]))

    def test_describe_snapshots_invalid_parameters(self):
        self.cinder.volume_snapshots.list.return_value = [
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_1),
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_2)]

        resp = self.execute('DescribeSnapshots',
                            {'SnapshotId.1': fakes.random_ec2_id('snap')})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidSnapshot.NotFound', resp['Error']['Code'])

        self.cinder.volume_snapshots.list.side_effect = lambda: []

        resp = self.execute('DescribeSnapshots',
                            {'SnapshotId.1': fakes.ID_EC2_SNAPSHOT_1})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('InvalidSnapshot.NotFound', resp['Error']['Code'])

    def test_create_snapshot_from_volume(self):
        self.cinder.volume_snapshots.create.return_value = (
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_1))
        self.db_api.add_item.side_effect = (
            fakes.get_db_api_add_item(fakes.ID_EC2_SNAPSHOT_1))
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_VOLUME_2: fakes.DB_VOLUME_2}))
        self.cinder.volumes.get.side_effect = (
            lambda vol_id: (fakes.CinderVolume(fakes.OS_VOLUME_2)
               if vol_id == fakes.ID_OS_VOLUME_2
               else None))

        resp = self.execute(
            'CreateSnapshot',
            {'VolumeId': fakes.ID_EC2_VOLUME_2})
        self.assertEqual(200, resp['http_status_code'])
        self.assertThat(fakes.EC2_SNAPSHOT_1, matchers.DictMatches(
            tools.purge_dict(resp, {'http_status_code'})))
        self.cinder.volume_snapshots.create.assert_called_once(mock.ANY)
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'snap',
            tools.purge_dict(fakes.DB_SNAPSHOT_1, ('id',)))

        self.cinder.volume_snapshots.create.assert_called_once_with(
            fakes.ID_OS_VOLUME_2, force=True, display_description=None)

    def test_format_snapshot_maps_status(self):
        fake_snapshot = fakes.OSSnapshot(fakes.OS_SNAPSHOT_1)
        self.cinder.volume_snapshots.list.return_value = [fake_snapshot]
        self.db_api.get_items.side_effect = (
            fakes.get_db_api_get_items({
                'snap': [fakes.DB_SNAPSHOT_1],
                'vol': [fakes.DB_VOLUME_2]}))

        fake_snapshot.status = 'new'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('pending', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'creating'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('pending', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'available'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('completed', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'active'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('completed', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'deleting'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('pending', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'error'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('error', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'banana'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual('banana', resp['snapshotSet'][0]['status'])
