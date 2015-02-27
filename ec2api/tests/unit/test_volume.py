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


class VolumeTestCase(base.ApiTestCase):

    def test_describe_volumes(self):
        self.cinder.volumes.list.return_value = [
            fakes.CinderVolume(fakes.OS_VOLUME_1),
            fakes.CinderVolume(fakes.OS_VOLUME_2),
            fakes.CinderVolume(fakes.OS_VOLUME_3)]

        self.db_api.get_items.side_effect = (
            fakes.get_db_api_get_items({
                'vol': [fakes.DB_VOLUME_1, fakes.DB_VOLUME_2],
                'i': [fakes.DB_INSTANCE_1, fakes.DB_INSTANCE_2],
                'snap': [fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2]}))
        self.db_api.add_item.side_effect = (
            fakes.get_db_api_add_item(fakes.ID_EC2_VOLUME_3))

        resp = self.execute('DescribeVolumes', {})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'volumeSet': [fakes.EC2_VOLUME_1, fakes.EC2_VOLUME_2,
                           fakes.EC2_VOLUME_3]},
            orderless_lists=True))

        self.db_api.get_items.assert_any_call(mock.ANY, 'vol')

        self.db_api.get_items_by_ids = tools.CopyingMock(
            return_value=[fakes.DB_VOLUME_1])
        resp = self.execute('DescribeVolumes',
                            {'VolumeId.1': fakes.ID_EC2_VOLUME_1})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'volumeSet': [fakes.EC2_VOLUME_1]},
            orderless_lists=True))
        self.db_api.get_items_by_ids.assert_any_call(
            mock.ANY, set([fakes.ID_EC2_VOLUME_1]))

        self.check_filtering(
            'DescribeVolumes', 'volumeSet',
            [('availability-zone', fakes.NAME_AVAILABILITY_ZONE),
             ('create-time', fakes.TIME_CREATE_VOLUME_2),
             # TODO(ft): support filtering by a number value
             # NOTE(ft): declare a constant for the volume size in fakes
             # ('size', 1),
             ('snapshot-id', fakes.ID_EC2_SNAPSHOT_1),
             ('status', 'available'),
             ('volume-id', fakes.ID_EC2_VOLUME_1)])
        self.check_tag_support(
            'DescribeVolumes', 'volumeSet',
            fakes.ID_EC2_VOLUME_1, 'volumeId')

    def test_describe_volumes_auto_remove(self):
        self.cinder.volumes.list.return_value = []
        self.db_api.get_items.side_effect = (
            fakes.get_db_api_get_items({
                'vol': [fakes.DB_VOLUME_1, fakes.DB_VOLUME_2],
                'i': [],
                'snap': []}))
        resp = self.execute('DescribeVolumes', {})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertThat(resp, matchers.DictMatches(
            {'volumeSet': []}))

        self.db_api.delete_item.assert_any_call(
            mock.ANY, fakes.ID_EC2_VOLUME_1)
        self.db_api.delete_item.assert_any_call(
            mock.ANY, fakes.ID_EC2_VOLUME_2)

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
            {'AvailabilityZone': fakes.NAME_AVAILABILITY_ZONE})
        self.assertEqual(200, resp['http_status_code'])
        self.assertThat(fakes.EC2_VOLUME_1, matchers.DictMatches(
            tools.purge_dict(resp, {'http_status_code'})))
        self.cinder.volumes.create.assert_called_once(mock.ANY)
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'vol',
            tools.purge_dict(fakes.DB_VOLUME_1, ('id',)))

        self.cinder.volumes.create.assert_called_once_with(
            None, snapshot_id=None, volume_type=None,
            availability_zone=fakes.NAME_AVAILABILITY_ZONE)

    def test_create_volume_from_snapshot(self):
        self.cinder.volumes.create.return_value = (
            fakes.CinderVolume(fakes.OS_VOLUME_3))
        self.db_api.add_item.side_effect = (
            fakes.get_db_api_add_item(fakes.ID_EC2_VOLUME_3))
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_SNAPSHOT_1: fakes.DB_SNAPSHOT_1}))

        resp = self.execute(
            'CreateVolume',
            {'AvailabilityZone': fakes.NAME_AVAILABILITY_ZONE,
             'SnapshotId': fakes.ID_EC2_SNAPSHOT_1})
        self.assertEqual(200, resp['http_status_code'])
        self.assertThat(fakes.EC2_VOLUME_3, matchers.DictMatches(
            tools.purge_dict(resp, {'http_status_code'})))
        self.cinder.volumes.create.assert_called_once(mock.ANY)
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'vol',
            tools.purge_dict(fakes.DB_VOLUME_3, ('id',)))

        self.cinder.volumes.create.assert_called_once_with(
            None, snapshot_id=fakes.ID_OS_SNAPSHOT_1, volume_type=None,
            availability_zone=fakes.NAME_AVAILABILITY_ZONE)

    def test_delete_volume(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_VOLUME_1
        resp = self.execute('DeleteVolume',
                            {'VolumeId': fakes.ID_EC2_VOLUME_1})
        self.assertEqual(200, resp['http_status_code'])
        resp.pop('http_status_code')
        self.assertEqual({'return': True}, resp)
        self.cinder.volumes.delete.assert_called_once_with(
            fakes.ID_OS_VOLUME_1)
        self.assertFalse(self.db_api.delete_item.called)

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

    def test_attach_volume(self):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_INSTANCE_2: fakes.DB_INSTANCE_2,
                fakes.ID_EC2_VOLUME_3: fakes.DB_VOLUME_3}))
        os_volume = fakes.CinderVolume(fakes.OS_VOLUME_3)
        os_volume.attachments.append({'device': '/dev/vdf',
                                      'server_id': fakes.ID_OS_INSTANCE_2})
        os_volume.status = 'attaching'
        self.cinder.volumes.get.return_value = os_volume

        resp = self.execute('AttachVolume',
                            {'VolumeId': fakes.ID_EC2_VOLUME_3,
                             'InstanceId': fakes.ID_EC2_INSTANCE_2,
                             'Device': '/dev/vdf'})
        self.assertEqual({'http_status_code': 200,
                          'device': '/dev/vdf',
                          'instanceId': fakes.ID_EC2_INSTANCE_2,
                          'status': 'attaching',
                          'volumeId': fakes.ID_EC2_VOLUME_3},
                         resp)
        self.nova_volumes.create_server_volume.assert_called_once_with(
            fakes.ID_OS_INSTANCE_2, fakes.ID_OS_VOLUME_3, '/dev/vdf')

    @mock.patch.object(fakes.CinderVolume, 'get', autospec=True)
    def test_detach_volume(self, os_volume_get):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_INSTANCE_2: fakes.DB_INSTANCE_2,
                fakes.ID_EC2_VOLUME_2: fakes.DB_VOLUME_2}))
        self.db_api.get_items.return_value = [fakes.DB_INSTANCE_1,
                                              fakes.DB_INSTANCE_2]
        os_volume = fakes.CinderVolume(fakes.OS_VOLUME_2)
        self.cinder.volumes.get.return_value = os_volume
        os_volume_get.side_effect = (
            lambda vol: setattr(vol, 'status', 'detaching'))

        resp = self.execute('DetachVolume',
                            {'VolumeId': fakes.ID_EC2_VOLUME_2})
        self.assertEqual({'http_status_code': 200,
                          'device': os_volume.attachments[0]['device'],
                          'instanceId': fakes.ID_EC2_INSTANCE_2,
                          'status': 'detaching',
                          'volumeId': fakes.ID_EC2_VOLUME_2},
                         resp)
        self.nova_volumes.delete_server_volume.assert_called_once_with(
            fakes.ID_OS_INSTANCE_2, fakes.ID_OS_VOLUME_2)
        self.cinder.volumes.get.assert_called_once_with(fakes.ID_OS_VOLUME_2)

    def test_detach_volume_invalid_parameters(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_VOLUME_1
        self.cinder.volumes.get.return_value = (
            fakes.CinderVolume(fakes.OS_VOLUME_1))

        resp = self.execute('DetachVolume',
                            {'VolumeId': fakes.ID_EC2_VOLUME_1})
        self.assertEqual(400, resp['http_status_code'])
        self.assertEqual('IncorrectState', resp['Error']['Code'])
