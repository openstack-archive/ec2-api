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

from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class SnapshotTestCase(base.ApiTestCase):

    def test_describe_snapshots(self):
        self.cinder.volume_snapshots.list.return_value = [
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_1),
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_2)]

        self.set_mock_db_items(fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2,
                               fakes.DB_VOLUME_2)

        resp = self.execute('DescribeSnapshots', {})
        self.assertThat(resp, matchers.DictMatches(
            {'snapshotSet': [fakes.EC2_SNAPSHOT_1, fakes.EC2_SNAPSHOT_2]},
            orderless_lists=True))

        self.db_api.get_items.assert_any_call(mock.ANY, 'vol')

        self.db_api.get_items_by_ids = tools.CopyingMock(
            return_value=[fakes.DB_SNAPSHOT_1])
        resp = self.execute('DescribeSnapshots',
                            {'SnapshotId.1': fakes.ID_EC2_SNAPSHOT_1})
        self.assertThat(resp, matchers.DictMatches(
            {'snapshotSet': [fakes.EC2_SNAPSHOT_1]},
            orderless_lists=True))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_SNAPSHOT_1]))

        self.check_filtering(
            'DescribeSnapshots', 'snapshotSet',
            [
             # TODO(ft): declare a constant for the description in fakes
             ('description', 'fake description'),
             ('owner-id', fakes.ID_OS_PROJECT),
             ('progress', '100%'),
             ('snapshot-id', fakes.ID_EC2_SNAPSHOT_1),
             ('start-time', fakes.TIME_CREATE_SNAPSHOT_2),
             ('status', 'completed'),
             ('volume-id', fakes.ID_EC2_VOLUME_2),
             # TODO(ft): declare a constant for the volume size in fakes
             ('volume-size', 1)
            ])
        self.check_tag_support(
            'DescribeSnapshots', 'snapshotSet',
            fakes.ID_EC2_SNAPSHOT_1, 'snapshotId')

    def test_describe_snapshots_auto_remove(self):
        self.cinder.volume_snapshots.list.return_value = []

        self.set_mock_db_items(fakes.DB_SNAPSHOT_1, fakes.DB_VOLUME_2)

        resp = self.execute('DescribeSnapshots', {})
        self.assertThat(resp, matchers.DictMatches(
            {'snapshotSet': []},
            orderless_lists=True))

        self.db_api.get_items.assert_any_call(mock.ANY, 'vol')
        self.db_api.get_items.assert_any_call(mock.ANY, 'snap')
        self.db_api.delete_item.assert_any_call(mock.ANY,
                                                fakes.ID_EC2_SNAPSHOT_1)

    def test_describe_snapshots_invalid_parameters(self):
        self.cinder.volume_snapshots.list.return_value = [
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_1),
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_2)]

        self.assert_execution_error(
            'InvalidSnapshot.NotFound', 'DescribeSnapshots',
            {'SnapshotId.1': fakes.random_ec2_id('snap')})

        self.cinder.volume_snapshots.list.side_effect = lambda: []

        self.assert_execution_error(
            'InvalidSnapshot.NotFound', 'DescribeSnapshots',
            {'SnapshotId.1': fakes.ID_EC2_SNAPSHOT_1})

    def test_create_snapshot_from_volume(self):
        self.cinder.volume_snapshots.create.return_value = (
            fakes.OSSnapshot(fakes.OS_SNAPSHOT_1))
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_SNAPSHOT_1))
        self.set_mock_db_items(fakes.DB_VOLUME_2)
        self.cinder.volumes.get.side_effect = (
            lambda vol_id: (
                fakes.OSVolume(fakes.OS_VOLUME_2)
                if vol_id == fakes.ID_OS_VOLUME_2
                else None))

        resp = self.execute(
            'CreateSnapshot',
            {'VolumeId': fakes.ID_EC2_VOLUME_2})
        self.assertThat(fakes.EC2_SNAPSHOT_1, matchers.DictMatches(resp))
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'snap',
            tools.purge_dict(fakes.DB_SNAPSHOT_1, ('id',)))

        self.cinder.volume_snapshots.create.assert_called_once_with(
            fakes.ID_OS_VOLUME_2, force=True)

    def test_format_snapshot_maps_status(self):
        fake_snapshot = fakes.OSSnapshot(fakes.OS_SNAPSHOT_1)
        self.cinder.volume_snapshots.list.return_value = [fake_snapshot]
        self.set_mock_db_items(fakes.DB_SNAPSHOT_1, fakes.DB_VOLUME_2)

        fake_snapshot.status = 'new'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual('pending', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'creating'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual('pending', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'available'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual('completed', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'active'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual('completed', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'deleting'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual('pending', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'error'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual('error', resp['snapshotSet'][0]['status'])

        fake_snapshot.status = 'banana'
        resp = self.execute('DescribeSnapshots', {})
        self.assertEqual('banana', resp['snapshotSet'][0]['status'])
