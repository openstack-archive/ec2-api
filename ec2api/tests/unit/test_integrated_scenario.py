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

from ec2api.api import image as image_api
from ec2api.api import instance as instance_api
from ec2api.api import snapshot as snapshot_api
from ec2api.api import volume as volume_api
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes


class DBItemsAutoCreationTestCase(base.DbTestCase):

    def setUp(self):
        super(DBItemsAutoCreationTestCase, self).setUp()
        self.mock_all_os()
        self.context = base.create_context()

    def assert_image_project(self, expected_project_id, image_id):
        if expected_project_id:
            context = mock.NonCallableMock(project_id=expected_project_id)
        else:
            context = self.context
        image_item = db_api.get_item_by_id(context, image_id)
        if expected_project_id:
            self.assertIsNotNone(image_item)
        else:
            self.assertIsNone(image_item)

    def test_describe_new_instance_then_its_volume(self):
        os_instance_id = fakes.random_os_id()
        os_volume_id = fakes.random_os_id()
        os_instance = {
            'id': os_instance_id,
            'flavor': {'id': 'fake'},
            'volumes_attached': [{'id': os_volume_id}],
        }
        os_volume = {
            'id': os_volume_id,
            'status': 'in-use',
            'attachments': [{'device': '/dev/vdb',
                             'server_id': os_instance_id}],
        }
        self.nova_admin.servers.list.return_value = [
            fakes.OSInstance_full(os_instance)]
        self.cinder.volumes.list.return_value = [
            fakes.OSVolume(os_volume)]

        reservations = instance_api.describe_instances(self.context)
        instance = reservations['reservationSet'][0]['instancesSet'][0]
        volume_id = instance['blockDeviceMapping'][0]['ebs']['volumeId']
        volume_api.describe_volumes(self.context, [volume_id])

    def _test_describe_new_images(self, image_project_id=None,
                                  aki_image_project_id=None,
                                  with_id_mapping=False):
        os_image_id = fakes.random_os_id()
        os_aki_image_id = fakes.random_os_id()
        os_image = {
            'id': os_image_id,
            'owner': image_project_id,
            'is_public': True,
            'container_format': 'ami',
            'properties': {
                'kernel_id': os_aki_image_id,
            },
        }
        os_aki_image = {
            'id': os_aki_image_id,
            'owner': aki_image_project_id,
            'is_public': True,
            'container_format': 'aki',
        }
        self.glance.images.list.return_value = (
            [fakes.OSImage(os_image), fakes.OSImage(os_aki_image)]
            if with_id_mapping else
            [fakes.OSImage(os_aki_image), fakes.OSImage(os_image)])

        images = image_api.describe_images(self.context)
        image = next(i for i in images['imagesSet']
                     if i['imageType'] == 'machine')
        aki_image = next(i for i in images['imagesSet']
                         if i['imageType'] == 'kernel')
        self.assertEqual(image_project_id, image['imageOwnerId'])
        self.assert_image_project(
            (image_project_id
             if image_project_id == fakes.ID_OS_PROJECT else
             None),
            image['imageId'])
        self.assertEqual(aki_image_project_id, aki_image['imageOwnerId'])
        self.assert_image_project(
            (aki_image_project_id
             if aki_image_project_id == fakes.ID_OS_PROJECT else
             None),
            aki_image['imageId'])

    def test_describe_new_alien_images(self):
        alien_project_id = fakes.random_os_id()
        self._test_describe_new_images(
            image_project_id=alien_project_id,
            aki_image_project_id=alien_project_id,
            with_id_mapping=False)

    def test_describe_new_local_images(self):
        self._test_describe_new_images(
            image_project_id=fakes.ID_OS_PROJECT,
            aki_image_project_id=fakes.ID_OS_PROJECT,
            with_id_mapping=False)

    def test_describe_new_local_ami_alien_aki_images(self):
        alien_project_id = fakes.random_os_id()
        self._test_describe_new_images(
            image_project_id=fakes.ID_OS_PROJECT,
            aki_image_project_id=alien_project_id,
            with_id_mapping=False)

    def test_describe_new_alien_ami_local_aki_images(self):
        alien_project_id = fakes.random_os_id()
        self._test_describe_new_images(
            image_project_id=alien_project_id,
            aki_image_project_id=fakes.ID_OS_PROJECT,
            with_id_mapping=False)

    def test_describe_new_alien_images_with_mappings(self):
        alien_project_id = fakes.random_os_id()
        self._test_describe_new_images(
            image_project_id=alien_project_id,
            aki_image_project_id=alien_project_id,
            with_id_mapping=True)

    def test_describe_new_local_images_with_mappings(self):
        self._test_describe_new_images(
            image_project_id=fakes.ID_OS_PROJECT,
            aki_image_project_id=fakes.ID_OS_PROJECT,
            with_id_mapping=True)

    def test_describe_new_local_ami_alien_aki_images_with_mappings(self):
        alien_project_id = fakes.random_os_id()
        self._test_describe_new_images(
            image_project_id=fakes.ID_OS_PROJECT,
            aki_image_project_id=alien_project_id,
            with_id_mapping=True)

    def test_describe_new_alien_ami_local_aki_images_with_mappings(self):
        alien_project_id = fakes.random_os_id()
        self._test_describe_new_images(
            image_project_id=alien_project_id,
            aki_image_project_id=fakes.ID_OS_PROJECT,
            with_id_mapping=True)

    def _get_new_ebs_image(self, image_project_id=None,
                           bdm_image_project_id=None):
        os_image_id = fakes.random_os_id()
        os_snapshot_id = fakes.random_os_id()
        os_bdm_image_id = fakes.random_os_id()
        os_image = {
            'id': os_image_id,
            'owner': image_project_id,
            'is_public': True,
            'container_format': 'ami',
            'properties': {
                'bdm_v2': True,
                'block_device_mapping': [{'device_name': '/dev/vds',
                                          'source_type': 'snapshot',
                                          'destination_type': 'volume',
                                          'snapshot_id': os_snapshot_id}],
            },
        }
        if os_bdm_image_id:
            os_image['properties']['block_device_mapping'].append({
                'device_name': '/dev/vdi',
                'source_type': 'image',
                'destination_type': 'volume',
                'image_id': os_bdm_image_id,
                'size': 100})
        os_snapshot = {
            'id': os_snapshot_id,
        }
        os_bdm_image = {
            'id': os_bdm_image_id,
            'owner': bdm_image_project_id,
            'is_public': True,
        }
        os_images = [fakes.OSImage(os_image)]
        if bdm_image_project_id:
            os_images.append(fakes.OSImage(os_bdm_image))
        self.glance.images.list.return_value = os_images
        self.cinder.volume_snapshots.list.return_value = (
            [fakes.OSSnapshot(os_snapshot)]
            if image_project_id == fakes.ID_OS_PROJECT else
            [])

        images = image_api.describe_images(self.context)
        return next(i for i in images['imagesSet']
                    if i['blockDeviceMapping'])

    def _find_snapshot_id_in_bdm(self, image, device_name):
        return next(bdm['ebs']['snapshotId']
                    for bdm in image['blockDeviceMapping']
                    if bdm['deviceName'] == device_name)

    def test_describe_new_local_snapshot_from_new_image(self):
        image = self._get_new_ebs_image(image_project_id=fakes.ID_OS_PROJECT)
        snapshot_id = self._find_snapshot_id_in_bdm(image, '/dev/vds')
        snapshot_api.describe_snapshots(self.context, [snapshot_id])

    def test_describe_new_alien_snapshot_from_new_image(self):
        image = self._get_new_ebs_image(image_project_id=fakes.random_os_id())
        snapshot_id = self._find_snapshot_id_in_bdm(image, '/dev/vds')
        self.assertRaises(exception.InvalidSnapshotNotFound,
                          snapshot_api.describe_snapshots,
                          self.context, [snapshot_id])

    def test_describe_new_local_bdm_image_from_local_image(self):
        image = self._get_new_ebs_image(
            image_project_id=fakes.ID_OS_PROJECT,
            bdm_image_project_id=fakes.ID_OS_PROJECT)
        image_id = self._find_snapshot_id_in_bdm(image, '/dev/vdi')
        image_api.describe_images(self.context, image_id=[image_id])
        self.assert_image_project(fakes.ID_OS_PROJECT, image_id)

    def test_describe_new_alien_bdm_image_from_new_local_image(self):
        alien_project_id = fakes.random_os_id()
        image = self._get_new_ebs_image(
            image_project_id=fakes.ID_OS_PROJECT,
            bdm_image_project_id=alien_project_id)
        image_id = self._find_snapshot_id_in_bdm(image, '/dev/vdi')
        image_api.describe_images(self.context, image_id=[image_id])
        self.assert_image_project(None, image_id)

    def test_describe_new_alien_bdm_image_from_new_alien_image(self):
        alien_project_id = fakes.random_os_id()
        image = self._get_new_ebs_image(
            image_project_id=alien_project_id,
            bdm_image_project_id=alien_project_id)
        image_id = self._find_snapshot_id_in_bdm(image, '/dev/vdi')
        image_api.describe_images(self.context, image_id=[image_id])
        self.assert_image_project(None, image_id)

    def _test_describe_new_instance_then_its_image(self, image_project_id):
        os_instance_id = fakes.random_os_id()
        os_image_id = fakes.random_os_id()
        os_instance = {
            'id': os_instance_id,
            'flavor': {'id': 'fake'},
            'image': {'id': os_image_id},
        }
        os_image = {
            'id': os_image_id,
            'owner': image_project_id,
            'is_public': True,
        }
        self.nova_admin.servers.list.return_value = [
            fakes.OSInstance_full(os_instance)]
        self.glance.images.list.return_value = [fakes.OSImage(os_image)]

        reservations = instance_api.describe_instances(self.context)
        instance = reservations['reservationSet'][0]['instancesSet'][0]
        image_id = instance['imageId']
        image = (image_api.describe_images(self.context, image_id=[image_id])
                 ['imagesSet'][0])
        self.assertEqual(image_id, image['imageId'])
        self.assertEqual(image_project_id, image['imageOwnerId'])
        expected_project_id = (fakes.ID_OS_PROJECT
                               if image_project_id == fakes.ID_OS_PROJECT else
                               None)
        self.assert_image_project(expected_project_id, image['imageId'])

    def test_describe_new_instance_then_its_local_image(self):
        self._test_describe_new_instance_then_its_image(fakes.ID_OS_PROJECT)

    def test_describe_new_instance_then_its_alien_image(self):
        self._test_describe_new_instance_then_its_image(fakes.random_os_id())

    def test_describe_new_instance_then_its_alien_image_attribute(self):
        os_instance_id = fakes.random_os_id()
        os_image_id = fakes.random_os_id()
        alien_project_id = fakes.random_os_id()
        os_instance = {
            'id': os_instance_id,
            'flavor': {'id': 'fake'},
            'image': {'id': os_image_id},
        }
        os_image = {
            'id': os_image_id,
            'owner': alien_project_id,
            'is_public': True,
        }
        self.nova_admin.servers.list.return_value = [
            fakes.OSInstance_full(os_instance)]
        self.glance.images.get.return_value = fakes.OSImage(os_image)

        reservations = instance_api.describe_instances(self.context)
        instance = reservations['reservationSet'][0]['instancesSet'][0]
        image_id = instance['imageId']

        # NOTE(ft): ensure that InvalidAMIID.NotFound is not raised
        self.assertRaises(exception.AuthFailure,
                          image_api.describe_image_attribute,
                          self.context, image_id, 'description')
