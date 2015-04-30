# Copyright 2015 OpenStack Foundation
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

from oslo_log import log
from tempest_lib.common.utils import data_utils

from ec2api.tests.functional import base
from ec2api.tests.functional import config
from ec2api.tests.functional.scenario import base as scenario_base

CONF = config.CONF
LOG = log.getLogger(__name__)


class TagsPagingTest(scenario_base.BaseScenarioTest):

    # NOTE(andrey-mp): limit for tags for one resource in amazon
    TAGS_COUNT = 10

    def _create_volume_and_tags(self):
        data = self.client.create_volume(
            Size=1, AvailabilityZone=CONF.aws.aws_zone)
        volume_id = data['VolumeId']
        self.addResourceCleanUp(self.client.delete_volume, VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        keys = list()
        for dummy in xrange(0, self.TAGS_COUNT):
            key = data_utils.rand_name('key')
            value = 'aaa' if dummy < 6 else 'bbb'
            data = self.client.create_tags(Resources=[volume_id],
                Tags=[{'Key': key, 'Value': value}])
            keys.append(key)

        return volume_id, keys

    def test_simple_tags_paging_with_many_results(self):
        volume_id = self._create_volume_and_tags()[0]

        data = self.client.describe_tags(MaxResults=500,
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]}])
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])
        self.assertEqual(self.TAGS_COUNT, len(data['Tags']))

    def test_simple_tags_paging_with_min_results(self):
        volume_id = self._create_volume_and_tags()[0]

        data = self.client.describe_tags(
            MaxResults=5,
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]},
                     {'Name': 'tag-value', 'Values': ['aaa']}])
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])

    def test_tags_paging_second_page_only_with_token(self):
        volume_id = self._create_volume_and_tags()[0]

        data = self.client.describe_tags(
            MaxResults=5,
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]},
                     {'Name': 'tag-value', 'Values': ['aaa']}])
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])
        data = self.client.describe_tags(
            NextToken=data['NextToken'],
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]},
                     {'Name': 'tag-value', 'Values': ['aaa']}])
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])

    def test_tags_paging_with_const_filter(self):
        volume_id = self._create_volume_and_tags()[0]

        data = self.client.describe_tags(
            MaxResults=5,
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]},
                     {'Name': 'tag-value', 'Values': ['aaa']}])
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])
        data = self.client.describe_tags(
            MaxResults=5, NextToken=data['NextToken'],
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]},
                     {'Name': 'tag-value', 'Values': ['aaa']}])
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])

    def test_tags_paging_with_differenet_filters(self):
        volume_id = self._create_volume_and_tags()[0]

        data = self.client.describe_tags(
            MaxResults=5,
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]},
                     {'Name': 'tag-value', 'Values': ['aaa']}])
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])
        data = self.client.describe_tags(
            MaxResults=5, NextToken=data['NextToken'],
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]}])
        self.assertNotEmpty(data['Tags'])
        self.assertLess(1, len(data['Tags']))

    def test_tags_paging_with_tags_deletion(self):
        volume_id, keys = self._create_volume_and_tags()

        data = self.client.describe_tags(MaxResults=5,
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]}])
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])
        for key in keys:
            self.client.delete_tags(Resources=[volume_id], Tags=[{'Key': key}])
        data = self.client.describe_tags(
            MaxResults=5, NextToken=data['NextToken'],
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]}])
        self.assertNotIn('NextToken', data)
        self.assertEmpty(data['Tags'])

    def test_invalid_max_results(self):
        self.assertRaises('InvalidParameterValue',
            self.client.describe_tags, MaxResults=4)

        # NOTE(andrey-mp): value more than 1000 in not invalid
        # but amazon returns 1000 elements
        self.client.describe_tags(MaxResults=1100)


class VolumesPagingTest(scenario_base.BaseScenarioTest):

    VOLUMES_COUNT = 6

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(VolumesPagingTest, cls).setUpClass()
        zone = CONF.aws.aws_zone
        cls.ids = list()
        for dummy in xrange(0, cls.VOLUMES_COUNT):
            data = cls.client.create_volume(Size=1, AvailabilityZone=zone)
            volume_id = data['VolumeId']
            cls.addResourceCleanUpStatic(cls.client.delete_volume,
                                         VolumeId=volume_id)
            cls.ids.append(volume_id)
        for volume_id in cls.ids:
            cls.get_volume_waiter().wait_available(volume_id)

    def test_simple_volumes_paging_with_many_results(self):
        data = self.client.describe_volumes(MaxResults=500)
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])
        self.assertLessEqual(self.VOLUMES_COUNT, len(data['Volumes']))

    def test_simple_volumes_paging_with_min_results(self):
        data = self.client.describe_volumes(MaxResults=5)
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])

    def test_volumes_paging_second_page(self):
        data = self.client.describe_volumes(MaxResults=5)
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])
        data = self.client.describe_volumes(
            MaxResults=5, NextToken=data['NextToken'])
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])

    def test_invalid_paging(self):
        self.assertRaises('InvalidParameterValue',
            self.client.describe_volumes, MaxResults=4)

        self.assertRaises('InvalidParameterCombination',
            self.client.describe_volumes,
            MaxResults=5, VolumeIds=[self.ids[0]])

    def test_volumes_paging_with_filters(self):
        data = self.client.describe_volumes(MaxResults=5,
            Filters=[{'Name': 'volume-id', 'Values': [self.ids[0]]}])
        self.assertNotEmpty(data['Volumes'])
        if 'NextToken' in data:
            # Amazon way
            data = self.client.describe_volumes(
                MaxResults=5, NextToken=data['NextToken'],
                Filters=[{'Name': 'volume-id', 'Values': [self.ids[0]]}])
            self.assertNotIn('NextToken', data)
            self.assertEmpty(data['Volumes'])

        data = self.client.describe_volumes(MaxResults=5,
            Filters=[{'Name': 'volume-id', 'Values': ['vol-*']}])
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])
        data = self.client.describe_volumes(
            MaxResults=5, NextToken=data['NextToken'],
            Filters=[{'Name': 'volume-id', 'Values': ['vol-*']}])
        self.assertNotEmpty(data['Volumes'])


class SnapshotPagingTest(scenario_base.BaseScenarioTest):

    SNAPSHOTS_COUNT = 6

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(SnapshotPagingTest, cls).setUpClass()
        zone = CONF.aws.aws_zone

        data = cls.client.create_volume(Size=1, AvailabilityZone=zone)
        volume_id = data['VolumeId']
        cls.addResourceCleanUpStatic(cls.client.delete_volume,
                                     VolumeId=volume_id)
        cls.get_volume_waiter().wait_available(volume_id)

        cls.ids = list()
        for dummy in xrange(0, cls.SNAPSHOTS_COUNT):
            data = cls.client.create_snapshot(VolumeId=volume_id)
            snapshot_id = data['SnapshotId']
            cls.addResourceCleanUpStatic(cls.client.delete_snapshot,
                                         SnapshotId=snapshot_id)
            cls.ids.append(snapshot_id)
        for snapshot_id in cls.ids:
            cls.get_snapshot_waiter().wait_available(snapshot_id,
                                                     final_set=('completed'))

    def test_simple_snapshots_paging_with_many_results(self):
        data = self.client.describe_snapshots(MaxResults=500)
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Snapshots'])
        self.assertLessEqual(self.SNAPSHOTS_COUNT, len(data['Snapshots']))

    def test_simple_snapshots_paging_with_min_results(self):
        data = self.client.describe_snapshots(MaxResults=5)
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Snapshots'])

    def test_snapshots_paging_second_page(self):
        data = self.client.describe_snapshots(MaxResults=5)
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Snapshots'])
        data = self.client.describe_snapshots(
            MaxResults=5, NextToken=data['NextToken'])
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Snapshots'])

    def test_invalid_paging(self):
        self.assertRaises('InvalidParameterValue',
            self.client.describe_snapshots, MaxResults=4)

        self.assertRaises('InvalidParameterCombination',
            self.client.describe_snapshots,
            MaxResults=5, SnapshotIds=[self.ids[0]])


class InstancePagingTest(scenario_base.BaseScenarioTest):

    RESERVATIONS_COUNT = 2
    INSTANCES_IN_RESERVATIONS_COUNT = 3

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(InstancePagingTest, cls).setUpClass()
        if not CONF.aws.image_id:
            raise cls.skipException('aws image_id does not provided')

        cls.ids = list()
        kwargs = {
            'ImageId': CONF.aws.image_id,
            'InstanceType': CONF.aws.instance_type,
            'Placement': {'AvailabilityZone': CONF.aws.aws_zone},
            'MinCount': cls.INSTANCES_IN_RESERVATIONS_COUNT,
            'MaxCount': cls.INSTANCES_IN_RESERVATIONS_COUNT
        }
        for dummy in xrange(0, cls.RESERVATIONS_COUNT):
            data = cls.client.run_instances(*[], **kwargs)
            for instance in data['Instances']:
                cls.ids.append(instance['InstanceId'])

        cls.addResourceCleanUpStatic(cls.client.terminate_instances,
                                     InstanceIds=cls.ids)
        for instance_id in cls.ids:
            cls.get_instance_waiter().wait_available(instance_id,
                                                     final_set=('running'))

    def test_simple_instances_paging_with_many_results(self):
        data = self.client.describe_instances(MaxResults=500)
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Reservations'])
        self.assertEqual(self.RESERVATIONS_COUNT, len(data['Reservations']))
        count = self.RESERVATIONS_COUNT * self.INSTANCES_IN_RESERVATIONS_COUNT
        self.assertEqual(count, self._count_instances(data))

    def test_simple_instances_paging_with_min_results(self):
        max_results = 5
        data = self.client.describe_instances(MaxResults=max_results)
        self.assertIn('NextToken', data)
        self.assertEqual(max_results, self._count_instances(data))

    def test_instances_paging_second_page(self):
        max_results = 5
        data = self.client.describe_instances(MaxResults=max_results)
        self.assertIn('NextToken', data)
        self.assertEqual(max_results, self._count_instances(data))
        data = self.client.describe_instances(
            MaxResults=max_results, NextToken=data['NextToken'])
        self.assertNotIn('NextToken', data)
        self.assertLess(0, self._count_instances(data))

    def test_invalid_paging(self):
        self.assertRaises('InvalidParameterValue',
            self.client.describe_instances, MaxResults=4)

        self.assertRaises('InvalidParameterCombination',
            self.client.describe_instances,
            MaxResults=5, InstanceIds=[self.ids[0]])

    def _count_instances(self, data):
        count = 0
        for reservation in data['Reservations']:
            count += len(reservation['Instances'])
        return count
