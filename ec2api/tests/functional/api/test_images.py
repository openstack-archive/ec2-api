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


class ImageTest(base.EC2TestCase):

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Openstack doesn't report right RootDeviceType")
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
        if len(data['Images']) < 2:
            self.skipTest("Insufficient images to check filters")
        resp, data = self.client.DescribeImages(
            Filters=[{'Name': 'image-id', 'Values': [image_id]}])
        self.assertEqual(1, len(data['Images']))
        self.assertEqual(image_id, data['Images'][0]['ImageId'])
