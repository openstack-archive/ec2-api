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


class VolumeTest(base.EC2TestCase):

    def test_create_delete_volume(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        data = self.client.create_volume(*[], **kwargs)
        volume_id = data['VolumeId']
        res_clean = self.addResourceCleanUp(self.client.delete_volume,
                                            VolumeId=volume_id)

        self.get_volume_waiter().wait_available(volume_id)

        if CONF.aws.run_incompatible_tests:
            self.assertEqual('standard', data['VolumeType'])
        self.assertEqual(1, data['Size'])
        if 'Encrypted' in data:
            self.assertFalse(data['Encrypted'])
        self.assertIsNotNone(data['CreateTime'])
        self.assertEqual(CONF.aws.aws_zone, data['AvailabilityZone'])

        self.client.delete_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_volume_waiter().wait_delete(volume_id)

        self.assertRaises('InvalidVolume.NotFound',
                          self.client.describe_volumes,
                          VolumeIds=[volume_id])

        self.assertRaises('InvalidVolume.NotFound',
                          self.client.delete_volume,
                          VolumeId=volume_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Encryption is not implemented")
    def test_create_encrypted_volume(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone,
            'Encrypted': True,
        }
        data = self.client.create_volume(*[], **kwargs)
        volume_id = data['VolumeId']
        res_clean = self.addResourceCleanUp(self.client.delete_volume,
                                            VolumeId=volume_id)

        self.get_volume_waiter().wait_available(volume_id)

        self.assertTrue(data['Encrypted'])

        self.client.delete_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_volume_waiter().wait_delete(volume_id)

    def test_describe_volumes(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        data = self.client.create_volume(*[], **kwargs)
        volume_id = data['VolumeId']
        res_clean = self.addResourceCleanUp(self.client.delete_volume,
                                            VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        data = self.client.create_volume(*[], **kwargs)
        volume_id_ext = data['VolumeId']
        res_clean_ext = self.addResourceCleanUp(self.client.delete_volume,
                                                VolumeId=volume_id_ext)
        self.get_volume_waiter().wait_available(volume_id_ext)

        data = self.client.describe_volumes(VolumeIds=[volume_id])
        self.assertEqual(1, len(data['Volumes']))

        volume = data['Volumes'][0]
        self.assertEqual(volume_id, volume['VolumeId'])
        if CONF.aws.run_incompatible_tests:
            self.assertEqual('standard', volume['VolumeType'])
        self.assertEqual(1, volume['Size'])
        if 'Encrypted' in volume:
            self.assertFalse(volume['Encrypted'])

        self.client.delete_volume(VolumeId=volume_id_ext)
        self.cancelResourceCleanUp(res_clean_ext)
        self.get_volume_waiter().wait_delete(volume_id_ext)

        self.client.delete_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_volume_waiter().wait_delete(volume_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Volume statuses are not implemented")
    def test_describe_volume_status(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        data = self.client.create_volume(*[], **kwargs)
        volume_id = data['VolumeId']
        res_clean = self.addResourceCleanUp(self.client.delete_volume,
                                            VolumeId=volume_id)

        self.get_volume_waiter().wait_available(volume_id)

        data = self.client.describe_volume_status(VolumeIds=[volume_id])
        self.assertEqual(1, len(data['VolumeStatuses']))

        volume_status = data['VolumeStatuses'][0]
        self.assertIn('Actions', volume_status)
        self.assertIn('Events', volume_status)
        self.assertIn('VolumeStatus', volume_status)

        self.client.delete_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_volume_waiter().wait_delete(volume_id)

    @testtools.skipUnless(CONF.aws.ebs_image_id, "ebs image id is not defined")
    def test_attach_detach_volume(self):
        clean_dict = {}
        instance_id = self.run_instance(ImageId=CONF.aws.ebs_image_id,
                                        clean_dict=clean_dict)
        clean_i = clean_dict['instance']

        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        data = self.client.create_volume(*[], **kwargs)
        volume_id = data['VolumeId']
        clean_v = self.addResourceCleanUp(self.client.delete_volume,
                                          VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/sdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        self.client.attach_volume(*[], **kwargs)
        clean_vi = self.addResourceCleanUp(self.client.detach_volume,
                                           VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        # reorder cleanups to avoid error on volume delete
        self.cancelResourceCleanUp(clean_i)
        clean_i = self.addResourceCleanUp(self.client.terminate_instances,
                                          InstanceIds=[instance_id])

        data = self.client.describe_volumes(VolumeIds=[volume_id])
        self.assertEqual(1, len(data['Volumes']))
        volume = data['Volumes'][0]
        self.assertEqual('in-use', volume['State'])
        self.assertEqual(1, len(volume['Attachments']))
        attachment = volume['Attachments'][0]
        self.assertFalse(attachment['DeleteOnTermination'])
        self.assertIsNotNone(attachment['Device'])
        self.assertEqual(instance_id, attachment['InstanceId'])
        self.assertEqual(volume_id, attachment['VolumeId'])

        data = self.client.describe_instances(InstanceIds=[instance_id])
        self.assertEqual(1, len(data.get('Reservations', [])))
        self.assertEqual(1, len(data['Reservations'][0].get('Instances', [])))
        bdms = data['Reservations'][0]['Instances'][0]['BlockDeviceMappings']
        self.assertNotEmpty(bdms)
        self.assertIn('DeviceName', bdms[0])
        self.assertIn('Ebs', bdms[0])

        # stop instance to prevent 'busy' state of detached volume
        data = self.client.stop_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('stopped'))

        self.client.detach_volume(VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_delete(volume_id)
        self.cancelResourceCleanUp(clean_vi)

        data = self.client.describe_volumes(VolumeIds=[volume_id])
        self.assertEqual(1, len(data['Volumes']))
        volume = data['Volumes'][0]
        self.assertEqual('available', volume['State'])
        self.assertEqual(0, len(volume['Attachments']))

        self.client.delete_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_attaching_stage(self):
        clean_dict = {}
        instance_id = self.run_instance(ImageId=CONF.aws.ebs_image_id,
                                        clean_dict=clean_dict)
        clean_i = clean_dict['instance']

        data = self.client.create_volume(
            AvailabilityZone=CONF.aws.aws_zone, Size=1)
        volume_id = data['VolumeId']
        clean_v = self.addResourceCleanUp(self.client.delete_volume,
                                          VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        device_name = '/dev/xvdh'
        kwargs = {
            'Device': device_name,
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        data = self.client.attach_volume(*[], **kwargs)
        clean_vi = self.addResourceCleanUp(self.client.detach_volume,
                                           VolumeId=volume_id)
        self.assertEqual('attaching', data['State'])

        if CONF.aws.run_incompatible_tests:
            bdt = self.get_instance_bdm(instance_id, device_name)
            self.assertIsNotNone(bdt)
            self.assertEqual('attaching', bdt['Ebs']['Status'])

        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        # reorder cleanups to avoid error on volume delete
        self.cancelResourceCleanUp(clean_i)
        clean_i = self.addResourceCleanUp(self.client.terminate_instances,
                                          InstanceIds=[instance_id])

        # stop instance to prevent 'busy' state of detached volume
        data = self.client.stop_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('stopped'))

        self.client.detach_volume(VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_delete(volume_id)
        self.cancelResourceCleanUp(clean_vi)

        self.client.delete_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Volume statuses are not implemented")
    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_delete_detach_attached_volume(self):
        instance_id = self.run_instance(ImageId=CONF.aws.ebs_image_id)

        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        data = self.client.create_volume(*[], **kwargs)
        volume_id = data['VolumeId']
        clean_v = self.addResourceCleanUp(self.client.delete_volume,
                                          VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/sdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        self.client.attach_volume(*[], **kwargs)
        clean_vi = self.addResourceCleanUp(self.client.detach_volume,
                                           VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        self.assertRaises('VolumeInUse',
                          self.client.attach_volume,
                          **kwargs)

        kwargs['Device'] = '/dev/sdi'
        self.assertRaises('VolumeInUse',
                          self.client.attach_volume,
                          **kwargs)

        self.assertRaises('VolumeInUse',
                          self.client.delete_volume,
                          VolumeId=volume_id)

        # stop instance to prevent 'busy' state of detached volume
        data = self.client.stop_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('stopped'))

        self.client.detach_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(clean_vi)
        self.get_volume_attachment_waiter().wait_delete(volume_id)

        self.assertRaises('IncorrectState',
                          self.client.detach_volume,
                          VolumeId=volume_id)

        self.client.delete_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

        self.assertRaises('InvalidVolume.NotFound',
                          self.client.detach_volume,
                          VolumeId=volume_id)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_volume_auto_termination_swithed_off(self):
        instance_id = self.run_instance()

        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        data = self.client.create_volume(*[], **kwargs)
        volume_id = data['VolumeId']
        clean_v = self.addResourceCleanUp(self.client.delete_volume,
                                          VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/sdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        self.client.attach_volume(*[], **kwargs)
        self.addResourceCleanUp(self.client.detach_volume, VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

        data = self.client.describe_volumes(VolumeIds=[volume_id])
        self.assertEqual(1, len(data['Volumes']))
        volume = data['Volumes'][0]
        self.assertEqual('available', volume['State'])
        if 'Attachments' in volume:
            self.assertEqual(0, len(volume['Attachments']))

        self.client.delete_volume(VolumeId=volume_id)
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "modify_instance_attribute is not implemented")
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_volume_auto_termination_swithed_on(self):
        instance_id = self.run_instance()

        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        data = self.client.create_volume(*[], **kwargs)
        volume_id = data['VolumeId']
        self.addResourceCleanUp(self.client.delete_volume, VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/sdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        self.client.attach_volume(*[], **kwargs)
        self.addResourceCleanUp(self.client.detach_volume, VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        kwargs = {
            'InstanceId': instance_id,
            'BlockDeviceMappings': [{'DeviceName': '/dev/sdh',
                                     'Ebs': {'VolumeId': volume_id,
                                             'DeleteOnTermination': True}}],
        }
        self.client.modify_instance_attribute(*[], **kwargs)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

        # volume should be deleted by the Cloud
        self.get_volume_waiter().wait_delete(volume_id)
