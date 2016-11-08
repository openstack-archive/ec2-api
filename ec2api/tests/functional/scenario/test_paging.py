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

import time

import botocore.exceptions
from oslo_log import log
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from ec2api.tests.functional import base
from ec2api.tests.functional import config
from ec2api.tests.functional.scenario import base as scenario_base

CONF = config.CONF
LOG = log.getLogger(__name__)


class TagsPagingTest(scenario_base.BaseScenarioTest):

    # NOTE(andrey-mp): limit for tags for one resource in amazon
    TAGS_COUNT = 10

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(TagsPagingTest, cls).setUpClass()
        if 'amazon' in CONF.aws.ec2_url:
            raise cls.skipException('Paging is broken in Amazon.')

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

    @decorators.idempotent_id('8df6e612-07cd-466d-99de-9f37954a6c9a')
    def test_simple_tags_paging_with_many_results(self):
        volume_id = self._create_volume_and_tags()[0]

        data = self.client.describe_tags(MaxResults=500,
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]}])
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])
        self.assertEqual(self.TAGS_COUNT, len(data['Tags']))

    @decorators.idempotent_id('683883d5-9a94-43f2-a1eb-d193db0e44e9')
    def test_simple_tags_paging_with_min_results(self):
        volume_id = self._create_volume_and_tags()[0]

        data = self.client.describe_tags(
            MaxResults=5,
            Filters=[{'Name': 'resource-id', 'Values': [volume_id]},
                     {'Name': 'tag-value', 'Values': ['aaa']}])
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Tags'])

    @decorators.idempotent_id('1db8cc5a-d0b3-4e5f-b411-d84cfa4f21e0')
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

    @decorators.idempotent_id('a4d7b315-9616-4f9e-85b7-0f892e09a9a2')
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

    @decorators.idempotent_id('ad4b793a-8231-4d30-8c26-43736b7b71e4')
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
        self.assertLessEqual(1, len(data['Tags']))

    @decorators.idempotent_id('ec6d68bb-37f3-4c5c-b4c5-000d73fbc1bf')
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

    @decorators.idempotent_id('37eb0597-998f-4744-8462-d56e5599dcd8')
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
        if 'amazon' in CONF.aws.ec2_url:
            raise cls.skipException('Paging is broken in Amazon.')

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

    @decorators.idempotent_id('d44ea940-d9ae-42a4-b3ce-add296a1678c')
    def test_simple_volumes_paging_with_many_results(self):
        data = self.client.describe_volumes(MaxResults=500)
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])
        self.assertLessEqual(self.VOLUMES_COUNT, len(data['Volumes']))

    @decorators.idempotent_id('9780c871-ee90-411c-b6ec-1e2f1785926b')
    def test_simple_volumes_paging_with_min_results(self):
        data = self.client.describe_volumes(MaxResults=5)
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])

    @decorators.idempotent_id('692684c4-62bc-457a-899a-07cc5382c9ab')
    def test_volumes_paging_second_page(self):
        data = self.client.describe_volumes(MaxResults=5)
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])
        data = self.client.describe_volumes(
            MaxResults=5, NextToken=data['NextToken'])
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Volumes'])

    @decorators.idempotent_id('83183fac-bb9b-4c36-8d23-84ed55c57015')
    def test_invalid_paging(self):
        self.assertRaises('InvalidParameterValue',
            self.client.describe_volumes, MaxResults=4)

        self.assertRaises('InvalidParameterCombination',
            self.client.describe_volumes,
            MaxResults=5, VolumeIds=[self.ids[0]])

    @decorators.idempotent_id('2a777d78-9f0b-4ab0-a841-73dbaafae0dd')
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
        if 'amazon' in CONF.aws.ec2_url:
            raise cls.skipException('Paging is broken in Amazon.')

        zone = CONF.aws.aws_zone

        data = cls.client.create_volume(Size=1, AvailabilityZone=zone)
        volume_id = data['VolumeId']
        cls.addResourceCleanUpStatic(cls.client.delete_volume,
                                     VolumeId=volume_id)
        cls.get_volume_waiter().wait_available(volume_id)

        def _create_snapshot():
            try:
                return cls.client.create_snapshot(VolumeId=volume_id)
            except botocore.exceptions.ClientError as e:
                code = (e.response.get('ResponseMetadata', {})
                                  .get('HTTPStatusCode'))
                if not code or code != 500:
                    raise

        waiter = base.EC2Waiter(_create_snapshot)
        cls.ids = list()
        while len(cls.ids) < cls.SNAPSHOTS_COUNT:
            time.sleep(10)
            data = waiter.wait_for_result()
            snapshot_id = data['SnapshotId']
            cls.addResourceCleanUpStatic(cls.client.delete_snapshot,
                                         SnapshotId=snapshot_id)
            cls.get_snapshot_waiter().wait_available(snapshot_id,
                                                     final_set=('completed'))
            cls.ids.append(snapshot_id)

    @decorators.idempotent_id('f44729b1-42d7-4f18-b5e0-f8dc2a03e624')
    def test_simple_snapshots_paging_with_many_results(self):
        data = self.client.describe_snapshots(MaxResults=500,
                                              OwnerIds=['self'])
        self.assertNotEmpty(data['Snapshots'])
        count = 0
        for s in data['Snapshots']:
            if s['SnapshotId'] in self.ids:
                count += 1
        self.assertEqual(self.SNAPSHOTS_COUNT, count)

    @decorators.idempotent_id('3146c81d-84c0-4817-9318-328f92bece7f')
    def test_simple_snapshots_paging_with_min_results(self):
        data = self.client.describe_snapshots(MaxResults=5, OwnerIds=['self'])
        self.assertIn('NextToken', data)
        self.assertNotEmpty(data['Snapshots'])

    @decorators.idempotent_id('fef90b60-0a46-4802-a822-98ccb58ff18c')
    def test_snapshots_paging(self):
        count = 0
        max_results = 5
        kwargs = {'MaxResults': max_results, 'OwnerIds': ['self']}
        while True:
            data = self.client.describe_snapshots(*[], **kwargs)
            self.assertGreaterEqual(max_results, len(data['Snapshots']))
            for s in data['Snapshots']:
                if s['SnapshotId'] in self.ids:
                    count += 1
            if 'NextToken' not in data:
                break
            kwargs['NextToken'] = data['NextToken']

        self.assertEqual(self.SNAPSHOTS_COUNT, count)

    @decorators.idempotent_id('8379d875-2979-4573-858f-2fd331ae992c')
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
        if 'amazon' in CONF.aws.ec2_url:
            raise cls.skipException('Paging is broken in Amazon.')
        if not CONF.aws.image_id:
            raise cls.skipException('aws image_id does not provided')

        cls.ids = list()
        cls.reservation_ids = list()
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
            cls.reservation_ids.append(data['ReservationId'])

        cls.addResourceCleanUpStatic(cls.client.terminate_instances,
                                     InstanceIds=cls.ids)
        for instance_id in cls.ids:
            cls.get_instance_waiter().wait_available(instance_id,
                                                     final_set=('running'))

    @decorators.idempotent_id('703da498-c73f-4fd1-a2be-2feddb5292d0')
    def test_simple_instances_paging_with_many_results(self):
        data = self.client.describe_instances(MaxResults=500)
        self.assertNotIn('NextToken', data)
        self.assertNotEmpty(data['Reservations'])
        rcount = 0
        for r in data['Reservations']:
            if r['ReservationId'] in self.reservation_ids:
                rcount += 1
        self.assertEqual(self.RESERVATIONS_COUNT, rcount)
        count = self.RESERVATIONS_COUNT * self.INSTANCES_IN_RESERVATIONS_COUNT
        instances = set()
        self._collect_own_instances(data, instances)
        self.assertEqual(count, len(instances))

    @decorators.idempotent_id('f494a2a8-6d75-4ef4-ae15-ac4fd1269107')
    def test_simple_instances_paging_with_min_results(self):
        max_results = 5
        data = self.client.describe_instances(MaxResults=max_results)
        self.assertIn('NextToken', data)
        self.assertEqual(max_results, self._count_instances(data))

    @decorators.idempotent_id('429802be-d599-4732-a310-3ffe8274df54')
    def test_instances_paging(self):
        max_results = 5
        kwargs = {'MaxResults': max_results}
        instances = set()
        while True:
            data = self.client.describe_instances(*[], **kwargs)
            self.assertGreaterEqual(max_results, self._count_instances(data))
            self._collect_own_instances(data, instances)
            if 'NextToken' not in data:
                break
            kwargs['NextToken'] = data['NextToken']

        count = self.RESERVATIONS_COUNT * self.INSTANCES_IN_RESERVATIONS_COUNT
        self.assertEqual(count, len(instances))

    @decorators.idempotent_id('061d564d-6d3a-44a8-bec9-9dba04f6f362')
    def test_invalid_paging(self):
        self.assertRaises('InvalidParameterValue',
            self.client.describe_instances, MaxResults=4)

        self.assertRaises('InvalidParameterCombination',
            self.client.describe_instances,
            MaxResults=5, InstanceIds=[self.ids[0]])

    def _collect_own_instances(self, data, instances):
        for reservation in data['Reservations']:
            for instance in reservation['Instances']:
                if instance['InstanceId'] in self.ids:
                    instances.add(instance['InstanceId'])

    def _count_instances(self, data):
        count = 0
        for reservation in data['Reservations']:
            count += len(reservation['Instances'])
        return count
