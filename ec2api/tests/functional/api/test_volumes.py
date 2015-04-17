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
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        res_clean = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)

        self.get_volume_waiter().wait_available(volume_id)

        if CONF.aws.run_incompatible_tests:
            self.assertEqual('standard', data['VolumeType'])
        self.assertEqual(1, data['Size'])
        if 'Encrypted' in data:
            self.assertFalse(data['Encrypted'])
        if 'SnapshotId' in data:
            self.assertIsNone(data['SnapshotId'])
        self.assertIsNotNone(data['CreateTime'])
        self.assertEqual(CONF.aws.aws_zone, data['AvailabilityZone'])

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_volume_waiter().wait_delete(volume_id)

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidVolume.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidVolume.NotFound', data['Error']['Code'])

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Encryption is not implemented")
    def test_create_encrypted_volume(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone,
            'Encrypted': True,
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        res_clean = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)

        self.get_volume_waiter().wait_available(volume_id)

        self.assertTrue(data['Encrypted'])

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_volume_waiter().wait_delete(volume_id)

    def test_describe_volumes(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        res_clean = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id_ext = data['VolumeId']
        res_clean_ext = self.addResourceCleanUp(self.client.DeleteVolume,
                                                VolumeId=volume_id_ext)
        self.get_volume_waiter().wait_available(volume_id_ext)

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['Volumes']))

        volume = data['Volumes'][0]
        self.assertEqual(volume_id, volume['VolumeId'])
        if CONF.aws.run_incompatible_tests:
            self.assertEqual('standard', volume['VolumeType'])
        self.assertEqual(1, volume['Size'])
        if 'Encrypted' in volume:
            self.assertFalse(volume['Encrypted'])
        if 'SnapshotId' in volume:
            self.assertIsNone(volume['SnapshotId'])

        resp, data = self.client.DeleteVolume(VolumeId=volume_id_ext)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_ext)
        self.get_volume_waiter().wait_delete(volume_id_ext)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_volume_waiter().wait_delete(volume_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Volume statuses are not implemented")
    def test_describe_volume_status(self):
        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        res_clean = self.addResourceCleanUp(self.client.DeleteVolume,
                                            VolumeId=volume_id)

        self.get_volume_waiter().wait_available(volume_id)

        resp, data = self.client.DescribeVolumeStatus(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['VolumeStatuses']))

        volume_status = data['VolumeStatuses'][0]
        self.assertIn('Actions', volume_status)
        self.assertIn('Events', volume_status)
        self.assertIn('VolumeStatus', volume_status)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_volume_waiter().wait_delete(volume_id)

    def test_attach_detach_volume(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        kwargs = {
            'ImageId': image_id,
            'InstanceType': instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'Placement': {'AvailabilityZone': CONF.aws.aws_zone}
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        clean_i = self.addResourceCleanUp(self.client.TerminateInstances,
                                          InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_v = self.addResourceCleanUp(self.client.DeleteVolume,
                                          VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/sdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        resp, data = self.client.AttachVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        clean_vi = self.addResourceCleanUp(self.client.DetachVolume,
                                           VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['Volumes']))
        volume = data['Volumes'][0]
        self.assertEqual('in-use', volume['State'])
        self.assertEqual(1, len(volume['Attachments']))
        attachment = volume['Attachments'][0]
        if CONF.aws.run_incompatible_tests:
            self.assertFalse(attachment['DeleteOnTermination'])
        self.assertIsNotNone(attachment['Device'])
        self.assertEqual(instance_id, attachment['InstanceId'])
        self.assertEqual(volume_id, attachment['VolumeId'])

        resp, data = self.client.DescribeInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data.get('Reservations', [])))
        self.assertEqual(1, len(data['Reservations'][0].get('Instances', [])))
        bdms = data['Reservations'][0]['Instances'][0]['BlockDeviceMappings']
        self.assertNotEmpty(bdms)
        self.assertIn('DeviceName', bdms[0])
        self.assertIn('Ebs', bdms[0])

        resp, data = self.client.DetachVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vi)
        self.get_volume_attachment_waiter().wait_delete(volume_id)

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['Volumes']))
        volume = data['Volumes'][0]
        self.assertEqual('available', volume['State'])
        self.assertEqual(0, len(volume['Attachments']))

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

    def test_attaching_stage(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        kwargs = {
            'ImageId': image_id,
            'InstanceType': instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'Placement': {'AvailabilityZone': CONF.aws.aws_zone}
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        clean_i = self.addResourceCleanUp(self.client.TerminateInstances,
                                          InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.CreateVolume(
            AvailabilityZone=CONF.aws.aws_zone, Size=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_v = self.addResourceCleanUp(self.client.DeleteVolume,
                                          VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/vdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        resp, data = self.client.AttachVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        clean_vi = self.addResourceCleanUp(self.client.DetachVolume,
                                           VolumeId=volume_id)
        self.assertEqual('attaching', data['State'])

        if CONF.aws.run_incompatible_tests:
            bdt = self.get_instance_bdm(instance_id, '/dev/vdh')
            self.assertIsNotNone(bdt)
            self.assertEqual('attaching', bdt['Ebs']['Status'])

        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        resp, data = self.client.DetachVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vi)
        self.get_volume_attachment_waiter().wait_delete(volume_id)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Volume statuses are not implemented")
    def test_delete_detach_attached_volume(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        kwargs = {
            'ImageId': image_id,
            'InstanceType': instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'Placement': {'AvailabilityZone': CONF.aws.aws_zone}
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        clean_i = self.addResourceCleanUp(self.client.TerminateInstances,
                                          InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_v = self.addResourceCleanUp(self.client.DeleteVolume,
                                          VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/sdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        resp, data = self.client.AttachVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        clean_vi = self.addResourceCleanUp(self.client.DetachVolume,
                                           VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        resp, data = self.client.AttachVolume(*[], **kwargs)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('VolumeInUse', data['Error']['Code'])

        kwargs['Device'] = '/dev/sdi'
        resp, data = self.client.AttachVolume(*[], **kwargs)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('VolumeInUse', data['Error']['Code'])

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('VolumeInUse', data['Error']['Code'])

        resp, data = self.client.DetachVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vi)
        self.get_volume_attachment_waiter().wait_delete(volume_id)

        resp, data = self.client.DetachVolume(VolumeId=volume_id)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('IncorrectState', data['Error']['Code'])

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

        resp, data = self.client.DetachVolume(VolumeId=volume_id)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidVolume.NotFound', data['Error']['Code'])

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

    def test_volume_auto_termination_swithed_off(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        kwargs = {
            'ImageId': image_id,
            'InstanceType': instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'Placement': {'AvailabilityZone': CONF.aws.aws_zone}
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        clean_i = self.addResourceCleanUp(self.client.TerminateInstances,
                                          InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        clean_v = self.addResourceCleanUp(self.client.DeleteVolume,
                                          VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/sdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        resp, data = self.client.AttachVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DetachVolume, VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['Volumes']))
        volume = data['Volumes'][0]
        self.assertEqual('available', volume['State'])
        if 'Attachments' in volume:
            self.assertEqual(0, len(volume['Attachments']))

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "ModifyInstanceAttribute is not implemented")
    def test_volume_auto_termination_swithed_on(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        kwargs = {
            'ImageId': image_id,
            'InstanceType': instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'Placement': {'AvailabilityZone': CONF.aws.aws_zone}
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        clean_i = self.addResourceCleanUp(self.client.TerminateInstances,
                                          InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        kwargs = {
            'Size': 1,
            'AvailabilityZone': CONF.aws.aws_zone
        }
        resp, data = self.client.CreateVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id = data['VolumeId']
        self.addResourceCleanUp(self.client.DeleteVolume, VolumeId=volume_id)
        self.get_volume_waiter().wait_available(volume_id)

        kwargs = {
            'Device': '/dev/sdh',
            'InstanceId': instance_id,
            'VolumeId': volume_id,
        }
        resp, data = self.client.AttachVolume(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DetachVolume, VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        kwargs = {
            'InstanceId': instance_id,
            'BlockDeviceMappings': [{'DeviceName': '/dev/sdh',
                                     'Ebs': {'VolumeId': volume_id,
                                             'DeleteOnTermination': True}}],
        }
        resp, data = self.client.ModifyInstanceAttribute(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidVolume.NotFound', data['Error']['Code'])
