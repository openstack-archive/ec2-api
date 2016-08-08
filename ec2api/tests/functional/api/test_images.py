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

from tempest.lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class ImageTest(base.EC2TestCase):

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_check_ebs_image_type(self):
        image_id = CONF.aws.ebs_image_id
        data = self.client.describe_images(ImageIds=[image_id])
        self.assertEqual(1, len(data['Images']))
        image = data['Images'][0]
        self.assertEqual("ebs", image['RootDeviceType'],
                         "Image is not EBS image")

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_check_ebs_image_volume_properties(self):
        image_id = CONF.aws.ebs_image_id
        data = self.client.describe_images(ImageIds=[image_id])
        self.assertEqual(1, len(data['Images']))
        image = data['Images'][0]
        self.assertTrue(image['RootDeviceName'])
        self.assertTrue(image['BlockDeviceMappings'])
        device_name = image['RootDeviceName']
        bdm = image['BlockDeviceMappings']
        bdm = [v for v in bdm if v['DeviceName'] == device_name]
        self.assertEqual(1, len(bdm))
        bdm = bdm[0]
        self.assertIn('Ebs', bdm)
        ebs = bdm['Ebs']
        self.assertIsNotNone(ebs.get('SnapshotId'))
        self.assertIsNotNone(ebs.get('DeleteOnTermination'))
        self.assertIsNotNone(ebs.get('VolumeSize'))
        if CONF.aws.run_incompatible_tests:
            self.assertIsNotNone(ebs.get('Encrypted'))
            self.assertFalse(ebs.get('Encrypted'))
            self.assertIsNotNone(ebs.get('VolumeType'))

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_describe_image_with_filters(self):
        image_id = CONF.aws.ebs_image_id
        data = self.client.describe_images(ImageIds=[image_id])
        self.assertEqual(1, len(data['Images']))

        data = self.client.describe_images(
            # NOTE(ft): limit output to prevent timeout over AWS
            Filters=[{'Name': 'image-type', 'Values': ['kernel', 'ramdisk']}])
        if len(data['Images']) < 2:
            self.skipTest("Insufficient images to check filters")
        data = self.client.describe_images(
            Filters=[{'Name': 'image-id', 'Values': [image_id]}])
        self.assertEqual(1, len(data['Images']))
        self.assertEqual(image_id, data['Images'][0]['ImageId'])

    @testtools.skipUnless(CONF.aws.image_id, "Image id is not defined")
    def test_check_image_operations_negative(self):
        # NOTE(andrey-mp): image_id is a public image created by admin
        image_id = CONF.aws.image_id

        self.assertRaises('InvalidRequest',
            self.client.describe_image_attribute,
            ImageId=image_id, Attribute='unsupported')

        self.assertRaises('AuthFailure',
            self.client.describe_image_attribute,
            ImageId=image_id, Attribute='description')

        self.assertRaises('InvalidParameterCombination',
            self.client.modify_image_attribute,
            ImageId=image_id, Attribute='unsupported')

        self.assertRaises('InvalidParameter',
            self.client.modify_image_attribute,
            ImageId=image_id, Attribute='blockDeviceMapping')

        self.assertRaises('InvalidParameterCombination',
            self.client.modify_image_attribute,
            ImageId=image_id)

        self.assertRaises('AuthFailure',
            self.client.modify_image_attribute,
            ImageId=image_id, Description={'Value': 'fake'})

        self.assertRaises('AuthFailure',
            self.client.modify_image_attribute,
            ImageId=image_id, LaunchPermission={'Add': [{'Group': 'all'}]})

        self.assertRaises('MissingParameter',
            self.client.modify_image_attribute,
            ImageId=image_id, Attribute='description')

        self.assertRaises('InvalidParameterCombination',
            self.client.modify_image_attribute,
            ImageId=image_id, Attribute='launchPermission')

        self.assertRaises('InvalidRequest',
            self.client.reset_image_attribute,
            ImageId=image_id, Attribute='fake')

        self.assertRaises('AuthFailure',
            self.client.reset_image_attribute,
            ImageId=image_id, Attribute='launchPermission')

        self.assertRaises('AuthFailure',
            self.client.deregister_image,
            ImageId=image_id)

    @testtools.skipUnless(CONF.aws.image_id, 'image id is not defined')
    def test_create_image_from_non_ebs_instance(self):
        image_id = CONF.aws.image_id
        data = self.client.describe_images(ImageIds=[image_id])
        image = data['Images'][0]
        if 'RootDeviceType' in image and 'ebs' in image['RootDeviceType']:
            raise self.skipException('image_id should not be EBS image.')

        instance_id = self.run_instance(ImageId=image_id)

        def _rollback(fn_data):
            self.client.deregister_image(ImageId=fn_data['ImageId'])

        self.assertRaises('InvalidParameterValue',
            self.client.create_image, rollback_fn=_rollback,
            InstanceId=instance_id, Name='name', Description='desc')

        data = self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    def _create_image(self, name, desc, extra_run_instance_args={}):
        image_id = CONF.aws.ebs_image_id
        data = self.client.describe_images(ImageIds=[image_id])
        image = data['Images'][0]
        self.assertTrue('RootDeviceType' in image
                        and 'ebs' in image['RootDeviceType'])

        instance_id = self.run_instance(ImageId=image_id,
                                        **extra_run_instance_args)
        instance = self.get_instance(instance_id)
        for bdm in instance.get('BlockDeviceMappings', []):
            if 'Ebs' in bdm:
                self.addResourceCleanUp(self.client.delete_volume,
                                        VolumeId=bdm['Ebs']['VolumeId'])

        data = self.client.create_image(InstanceId=instance_id,
                                             Name=name, Description=desc)
        image_id = data['ImageId']
        image_clean = self.addResourceCleanUp(self.client.deregister_image,
                                              ImageId=image_id)
        self.get_image_waiter().wait_available(image_id)

        data = self.client.describe_images(ImageIds=[image_id])
        for bdm in data['Images'][0].get('BlockDeviceMappings', []):
            if 'Ebs' in bdm and 'SnapshotId' in bdm['Ebs']:
                snapshot_id = bdm['Ebs']['SnapshotId']
                self.addResourceCleanUp(self.client.delete_snapshot,
                                        SnapshotId=snapshot_id)

        data = self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

        return image_id, image_clean

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_create_image_from_ebs_instance(self):
        name = data_utils.rand_name('image')
        desc = data_utils.rand_name('description')
        image_id, image_clean = self._create_image(name, desc)

        data = self.client.describe_images(ImageIds=[image_id])
        self.assertEqual(1, len(data['Images']))
        image = data['Images'][0]

        self.assertIsNotNone(image['CreationDate'])
        self.assertEqual("ebs", image['RootDeviceType'])
        self.assertFalse(image['Public'])
        self.assertEqual(name, image['Name'])
        self.assertEqual(desc, image['Description'])
        self.assertEqual('machine', image['ImageType'])
        self.assertNotEmpty(image['BlockDeviceMappings'])
        for bdm in image['BlockDeviceMappings']:
            self.assertIn('DeviceName', bdm)

        data = self.client.deregister_image(ImageId=image_id)
        self.cancelResourceCleanUp(image_clean)

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_check_simple_image_attributes(self):
        name = data_utils.rand_name('image')
        desc = data_utils.rand_name('desc for image')
        image_id, image_clean = self._create_image(name, desc)

        data = self.client.describe_image_attribute(
            ImageId=image_id, Attribute='kernel')
        self.assertIn('KernelId', data)

        data = self.client.describe_image_attribute(
            ImageId=image_id, Attribute='ramdisk')
        self.assertIn('RamdiskId', data)

        # description
        data = self.client.describe_image_attribute(
            ImageId=image_id, Attribute='description')
        self.assertIn('Description', data)
        self.assertIn('Value', data['Description'])
        self.assertEqual(desc, data['Description']['Value'])

        def _modify_description(**kwargs):
            self.client.modify_image_attribute(ImageId=image_id, **kwargs)
            data = self.client.describe_image_attribute(
                ImageId=image_id, Attribute='description')
            self.assertEqual(new_desc, data['Description']['Value'])

        new_desc = data_utils.rand_name('new desc')
        _modify_description(Attribute='description', Value=new_desc)
        _modify_description(Description={'Value': new_desc})

        data = self.client.deregister_image(ImageId=image_id)
        self.cancelResourceCleanUp(image_clean)

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_check_bdm_in_image(self):
        image_id = CONF.aws.ebs_image_id
        data = self.client.describe_images(ImageIds=[image_id])
        root_device_name = data['Images'][0]['RootDeviceName']
        device_name_prefix = base.get_device_name_prefix(root_device_name)
        device_name = device_name_prefix + 'h'

        name = data_utils.rand_name('image')
        desc = data_utils.rand_name('description')
        image_id, image_clean = self._create_image(
            name, desc,
            extra_run_instance_args={
                'BlockDeviceMappings': [{'DeviceName': device_name,
                                         'Ebs': {'VolumeSize': 1}}]})

        data = self.client.describe_images(ImageIds=[image_id])
        image = data['Images'][0]

        for bdm in image['BlockDeviceMappings']:
            self.assertTrue('DeviceName', bdm)

        data = self.client.deregister_image(ImageId=image_id)
        self.cancelResourceCleanUp(image_clean)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        'By default glance is configured as "publicize_image": "role:admin"')
    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        'skip due to bug #1439819')
    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_check_launch_permission_attribute(self):
        name = data_utils.rand_name('image')
        desc = data_utils.rand_name('desc for image')
        image_id, image_clean = self._create_image(name, desc)

        # launch permission
        data = self.client.describe_image_attribute(
            ImageId=image_id, Attribute='launchPermission')
        self.assertIn('LaunchPermissions', data)
        self.assertEmpty(data['LaunchPermissions'])

        def _modify_launch_permission(**kwargs):
            self.client.modify_image_attribute(ImageId=image_id, **kwargs)
            data = self.client.describe_image_attribute(
                ImageId=image_id, Attribute='launchPermission')
            self.assertIn('LaunchPermissions', data)
            self.assertNotEmpty(data['LaunchPermissions'])
            self.assertIn('Group', data['LaunchPermissions'][0])
            self.assertEqual('all', data['LaunchPermissions'][0]['Group'])
            data = self.client.describe_images(ImageIds=[image_id])
            self.assertTrue(data['Images'][0]['Public'])

            self.client.reset_image_attribute(
                ImageId=image_id, Attribute='launchPermission')
            data = self.client.describe_image_attribute(
                ImageId=image_id, Attribute='launchPermission')
            self.assertEmpty(data['LaunchPermissions'])
            data = self.client.describe_images(ImageIds=[image_id])
            self.assertFalse(data['Images'][0]['Public'])

        _modify_launch_permission(Attribute='launchPermission',
                                  OperationType='add', UserGroups=['all'])
        _modify_launch_permission(LaunchPermission={'Add': [{'Group': 'all'}]})

        data = self.client.deregister_image(ImageId=image_id)
        self.cancelResourceCleanUp(image_clean)


class ImageRegisterTest(base.EC2TestCase):

    valid_image_state = set(('available', 'pending', 'failed'))

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(ImageRegisterTest, cls).setUpClass()
        cls.image_location = CONF.aws.ami_image_location
        if not cls.image_location:
            raise cls.skipException('Image materials are not ready in S3')

    def test_register_get_deregister_ami_image(self):
        image_name = data_utils.rand_name("ami-name")
        data = self.client.register_image(
            Name=image_name, ImageLocation=self.image_location)
        image_id = data['ImageId']
        image_clean = self.addResourceCleanUp(self.client.deregister_image,
                                              ImageId=image_id)
        self.assertEqual(image_id[0:3], "ami")

        data = self.client.describe_images(ImageIds=[image_id])
        self.assertEqual(1, len(data['Images']))
        image = data['Images'][0]
        self.assertEqual(image_name, image['Name'])
        self.assertEqual(image_id, image['ImageId'])
        self.assertIn(image['State'], self.valid_image_state)

        self.get_image_waiter().wait_available(image_id)

        self.client.deregister_image(ImageId=image_id)
        self.cancelResourceCleanUp(image_clean)
        self.get_image_waiter().wait_delete(image_id)
