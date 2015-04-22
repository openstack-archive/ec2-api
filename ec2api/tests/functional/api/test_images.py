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

from tempest_lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class ImageTest(base.EC2TestCase):

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_check_ebs_image_type(self):
        image_id = CONF.aws.ebs_image_id
        resp, data = self.client.DescribeImages(ImageIds=[image_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Images']))
        image = data['Images'][0]
        self.assertEqual("ebs", image['RootDeviceType'],
                         "Image is not EBS image")

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_check_ebs_image_volume_properties(self):
        image_id = CONF.aws.ebs_image_id
        resp, data = self.client.DescribeImages(ImageIds=[image_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
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
        if CONF.aws.run_incompatible_tests:
            self.assertIsNotNone(ebs.get('DeleteOnTermination'))
            self.assertIsNotNone(ebs.get('Encrypted'))
            self.assertFalse(ebs.get('Encrypted'))
            self.assertIsNotNone(ebs.get('VolumeSize'))
            self.assertIsNotNone(ebs.get('VolumeType'))

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_describe_image_with_filters(self):
        image_id = CONF.aws.ebs_image_id
        resp, data = self.client.DescribeImages(ImageIds=[image_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Images']))

        resp, data = self.client.DescribeImages(
            # NOTE(ft): limit output to prevent timeout over AWS
            Filters=[{'Name': 'image-type', 'Values': ['kernel', 'ramdisk']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        if len(data['Images']) < 2:
            self.skipTest("Insufficient images to check filters")
        resp, data = self.client.DescribeImages(
            Filters=[{'Name': 'image-id', 'Values': [image_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Images']))
        self.assertEqual(image_id, data['Images'][0]['ImageId'])

    def test_check_image_operations_negative(self):
        # NOTE(andrey-mp): image_id is a public image created by admin
        image_id = CONF.aws.image_id

        resp, data = self.client.DescribeImageAttribute(
            ImageId=CONF.aws.image_id, Attribute='unsupported')
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidRequest', data['Error']['Code'])

        resp, data = self.client.DescribeImageAttribute(
            ImageId=CONF.aws.image_id, Attribute='description')
        self.assertEqual(400, resp.status_code)
        self.assertEqual('AuthFailure', data['Error']['Code'])

        resp, data = self.client.ModifyImageAttribute(
            ImageId=CONF.aws.image_id, Attribute='unsupported')
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterCombination', data['Error']['Code'])

        resp, data = self.client.ModifyImageAttribute(
            ImageId=CONF.aws.image_id, Attribute='blockDeviceMapping')
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameter', data['Error']['Code'])

        resp, data = self.client.ModifyImageAttribute(
            ImageId=CONF.aws.image_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterCombination', data['Error']['Code'])

        resp, data = self.client.ModifyImageAttribute(
            ImageId=image_id, Description={'Value': 'fake'})
        self.assertEqual(400, resp.status_code)
        self.assertEqual('AuthFailure', data['Error']['Code'])

        resp, data = self.client.ModifyImageAttribute(
            ImageId=image_id, LaunchPermission={'Add': [{'Group': 'all'}]})
        self.assertEqual(400, resp.status_code)
        self.assertEqual('AuthFailure', data['Error']['Code'])

        resp, data = self.client.ModifyImageAttribute(
            ImageId=image_id, Attribute='description')
        self.assertEqual(400, resp.status_code)
        self.assertEqual('MissingParameter', data['Error']['Code'])

        resp, data = self.client.ModifyImageAttribute(
            ImageId=image_id, Attribute='launchPermission')
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterCombination', data['Error']['Code'])

        resp, data = self.client.ResetImageAttribute(
            ImageId=image_id, Attribute='fake')
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidRequest', data['Error']['Code'])

        resp, data = self.client.ResetImageAttribute(
            ImageId=image_id, Attribute='launchPermission')
        self.assertEqual(400, resp.status_code)
        self.assertEqual('AuthFailure', data['Error']['Code'])

        resp, data = self.client.DeregisterImage(ImageId=image_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('AuthFailure', data['Error']['Code'])

    @testtools.skipUnless(CONF.aws.image_id, 'image id is not defined')
    def test_create_image_from_non_ebs_instance(self):
        image_id = CONF.aws.image_id
        resp, data = self.client.DescribeImages(ImageIds=[image_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        image = data['Images'][0]
        if 'RootDeviceType' in image and 'ebs' in image['RootDeviceType']:
            raise self.skipException('image_id should not be EBS image.')

        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=CONF.aws.instance_type,
            Placement={'AvailabilityZone': CONF.aws.aws_zone},
            MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Instances']))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.CreateImage(InstanceId=instance_id,
                                             Name='name', Description='desc')
        if resp.status_code == 200:
            image_id = data['ImageId']
            self.addResourceCleanUp(self.client.DeregisterImage,
                                    ImageId=image_id)
            self.get_image_waiter().wait_available(image_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    def _create_image(self, name, desc):
        image_id = CONF.aws.ebs_image_id
        resp, data = self.client.DescribeImages(ImageIds=[image_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        image = data['Images'][0]
        self.assertTrue('RootDeviceType' in image
                        and 'ebs' in image['RootDeviceType'])

        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=CONF.aws.instance_type,
            Placement={'AvailabilityZone': CONF.aws.aws_zone},
            MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Instances']))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.CreateImage(InstanceId=instance_id,
                                             Name=name, Description=desc)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        image_id = data['ImageId']
        image_clean = self.addResourceCleanUp(self.client.DeregisterImage,
                                              ImageId=image_id)
        self.get_image_waiter().wait_available(image_id)

        resp, data = self.client.DescribeImages(ImageIds=[image_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        for bdm in data['Images'][0].get('BlockDeviceMappings', []):
            if 'Ebs' in bdm and 'SnapshotId' in bdm['Ebs']:
                snapshot_id = bdm['Ebs']['SnapshotId']
                kwargs = {'SnapshotIds': [snapshot_id]}
                resp, data = self.client.DescribeSnapshots(**kwargs)
                if resp.status_code == 200:
                    volume_id = data['Snapshots'][0].get('VolumeId')
                    if volume_id:
                        self.addResourceCleanUp(self.client.DeleteVolume,
                                                VolumeId=volume_id)
                self.addResourceCleanUp(self.client.DeleteSnapshot,
                                        SnapshotId=snapshot_id)

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        return image_id, image_clean

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          'skip due to bug #1439819')
    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_create_image_from_ebs_instance(self):
        name = data_utils.rand_name('image')
        desc = data_utils.rand_name('')
        image_id, image_clean = self._create_image(name, desc)

        resp, data = self.client.DescribeImages(ImageIds=[image_id])
        self.assertEqual(200, resp.status_code,
                         base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Images']))
        image = data['Images'][0]

        self.assertEqual("ebs", image['RootDeviceType'])
        self.assertFalse(image['Public'])
        self.assertEqual(name, image['Name'])
        self.assertEqual(desc, image['Description'])
        self.assertEqual('machine', image['ImageType'])
        self.assertNotEmpty(image['BlockDeviceMappings'])
        for bdm in image['BlockDeviceMappings']:
            self.assertIn('DeviceName', bdm)

        resp, data = self.client.DeregisterImage(ImageId=image_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(image_clean)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          'skip due to bug #1439819')
    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_check_simple_image_attributes(self):
        name = data_utils.rand_name('image')
        desc = data_utils.rand_name('desc for image')
        image_id, image_clean = self._create_image(name, desc)

        resp, data = self.client.DescribeImageAttribute(
            ImageId=image_id, Attribute='kernel')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('KernelId', data)

        resp, data = self.client.DescribeImageAttribute(
            ImageId=image_id, Attribute='ramdisk')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('RamdiskId', data)

        # description
        resp, data = self.client.DescribeImageAttribute(
            ImageId=image_id, Attribute='description')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('Description', data)
        self.assertIn('Value', data['Description'])
        self.assertEqual(desc, data['Description']['Value'])

        def _modify_description(**kwargs):
            resp, data = self.client.ModifyImageAttribute(
                ImageId=image_id, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            resp, data = self.client.DescribeImageAttribute(
                ImageId=image_id, Attribute='description')
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(new_desc, data['Description']['Value'])

        new_desc = data_utils.rand_name('new desc')
        _modify_description(Attribute='description', Value=new_desc)
        _modify_description(Description={'Value': new_desc})

        resp, data = self.client.DeregisterImage(ImageId=image_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
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
        resp, data = self.client.DescribeImageAttribute(
            ImageId=image_id, Attribute='launchPermission')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('LaunchPermissions', data)
        self.assertEmpty(data['LaunchPermissions'])

        def _modify_launch_permission(**kwargs):
            resp, data = self.client.ModifyImageAttribute(
                ImageId=image_id, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            resp, data = self.client.DescribeImageAttribute(
                ImageId=image_id, Attribute='launchPermission')
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertIn('LaunchPermissions', data)
            self.assertNotEmpty(data['LaunchPermissions'])
            self.assertIn('Group', data['LaunchPermissions'][0])
            self.assertEqual('all', data['LaunchPermissions'][0]['Group'])
            resp, data = self.client.DescribeImages(ImageIds=[image_id])
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertTrue(data['Images'][0]['Public'])

            resp, data = self.client.ResetImageAttribute(
                ImageId=image_id, Attribute='launchPermission')
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            resp, data = self.client.DescribeImageAttribute(
                ImageId=image_id, Attribute='launchPermission')
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEmpty(data['LaunchPermissions'])
            resp, data = self.client.DescribeImages(ImageIds=[image_id])
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertFalse(data['Images'][0]['Public'])

        _modify_launch_permission(Attribute='launchPermission',
                                  OperationType='add', UserGroups=['all'])
        _modify_launch_permission(LaunchPermission={'Add': [{'Group': 'all'}]})

        resp, data = self.client.DeregisterImage(ImageId=image_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(image_clean)
