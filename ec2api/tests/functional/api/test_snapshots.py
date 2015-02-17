# Copyright 2014 OpenStack Foundation
# All Rights Reserved.
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

import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class SnapshotTest(base.EC2TestCase):

    def test_create_delete_snapshot(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_vol = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        desc = 'test snapshot'
        kwargs = {
            'VolumeId': volume_id,
            'Description': desc
        }
        resp, data = self.client.CreateSnapshot(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        snapshot_id = data['SnapshotId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSnapshot,
                                            SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        self.assertEqual(desc, data['Description'])
        self.assertEqual(volume_id, data['VolumeId'])
        self.assertEqual(1, data['VolumeSize'])
        self.assertNotEmpty(data.get('State', ''))
        if 'Encrypted' in data:
            self.assertFalse(data['Encrypted'])
        self.assertIsNotNone(data['StartTime'])

        resp, data = self.client.DeleteSnapshot(SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_snapshot_waiter().wait_delete(snapshot_id)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vol)
        self.get_volume_waiter().wait_delete(volume_id)

    def test_describe_snapshots(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_vol = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        desc = 'test snapshot'
        kwargs = {
            'VolumeId': volume_id,
            'Description': desc
        }
        resp, data = self.client.CreateSnapshot(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        snapshot_id = data['SnapshotId']
        ownerId = data['OwnerId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSnapshot,
                                            SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        self.assertEqual(desc, data['Description'])
        self.assertEqual(volume_id, data['VolumeId'])
        self.assertEqual(1, data['VolumeSize'])
        self.assertNotEmpty(data.get('State', ''))
        if 'Encrypted' in data:
            self.assertFalse(data['Encrypted'])
        self.assertIsNotNone(data['StartTime'])

        resp, data = self.client.DescribeSnapshots(SnapshotIds=[snapshot_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Snapshots']))
        data = data['Snapshots'][0]
        self.assertEqual(snapshot_id, data['SnapshotId'])
        self.assertEqual(desc, data['Description'])
        self.assertEqual(volume_id, data['VolumeId'])
        self.assertEqual(1, data['VolumeSize'])
        self.assertNotEmpty(data.get('State', ''))
        if 'Encrypted' in data:
            self.assertFalse(data['Encrypted'])
        self.assertIsNotNone(data['StartTime'])

        resp, data = self.client.DescribeSnapshots(OwnerIds=[ownerId])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        data = [s for s in data['Snapshots'] if s['SnapshotId'] == snapshot_id]
        self.assertEqual(1, len(data))

        resp, data = self.client.DeleteSnapshot(SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_snapshot_waiter().wait_delete(snapshot_id)

        resp, data = self.client.DescribeSnapshots(SnapshotIds=[snapshot_id])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidSnapshot.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vol)
        self.get_volume_waiter().wait_delete(volume_id)

    def test_create_volume_from_snapshot(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_vol = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)
        vol1 = data

        desc = 'test snapshot'
        kwargs = {
            'VolumeId': volume_id,
            'Description': desc
        }
        resp, data = self.client.CreateSnapshot(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        snapshot_id = data['SnapshotId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSnapshot,
                                            SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        kwargs = {
            'SnapshotId': snapshot_id,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id2 = data['VolumeId']
        clean_vol2 = self.addResourceCleanUp(self.client.DeleteVolume,
                                             VolumeId=volume_id2)
        self.get_volume_waiter().wait_available(volume_id2)

        self.assertNotEqual(volume_id, volume_id2)
        self.assertEqual(vol1['Size'], data['Size'])
        self.assertEqual(snapshot_id, data['SnapshotId'])

        resp, data = self.client.DescribeVolumes(
            Filters=[{'Name': 'snapshot-id', 'Values': [snapshot_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Volumes']))
        self.assertEqual(volume_id2, data['Volumes'][0]['VolumeId'])

        resp, data = self.client.DeleteSnapshot(SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_snapshot_waiter().wait_delete(snapshot_id)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vol)
        self.get_volume_waiter().wait_delete(volume_id)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id2)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vol2)
        self.get_volume_waiter().wait_delete(volume_id2)

    def test_create_increased_volume_from_snapshot(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_vol = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)
        vol1 = data

        desc = 'test snapshot'
        kwargs = {
            'VolumeId': volume_id,
            'Description': desc
        }
        resp, data = self.client.CreateSnapshot(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        snapshot_id = data['SnapshotId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSnapshot,
                                            SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        kwargs = {
            'Size': 2,
            'SnapshotId': snapshot_id,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id2 = data['VolumeId']
        clean_vol2 = self.addResourceCleanUp(self.client.DeleteVolume,
                                             VolumeId=volume_id2)
        self.get_volume_waiter().wait_available(volume_id2)

        self.assertNotEqual(volume_id, volume_id2)
        self.assertEqual(2, data['Size'])
        self.assertEqual(snapshot_id, data['SnapshotId'])

        resp, data = self.client.DeleteSnapshot(SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_snapshot_waiter().wait_delete(snapshot_id)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vol)
        self.get_volume_waiter().wait_delete(volume_id)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id2)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vol2)
        self.get_volume_waiter().wait_delete(volume_id2)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Openstack can't delete volume with snapshots")
    def test_delete_volume_with_snapshots(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_vol = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        desc = 'test snapshot'
        kwargs = {
            'VolumeId': volume_id,
            'Description': desc
        }
        resp, data = self.client.CreateSnapshot(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        snapshot_id = data['SnapshotId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSnapshot,
                                            SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vol)
        self.get_volume_waiter().wait_delete(volume_id)

        resp, data = self.client.DeleteSnapshot(SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_snapshot_waiter().wait_delete(snapshot_id)
