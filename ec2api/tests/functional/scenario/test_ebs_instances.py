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

import math

from oslo_log import log
from tempest_lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


def _get_device_name_prefix(device_name):
    dev_num_pos = 0
    while '0' <= device_name[dev_num_pos - 1] <= '9':
        dev_num_pos -= 1
    return device_name[:dev_num_pos - 1]


class EC2_EBSInstanceTuneBDM(base.EC2TestCase):
    """Test change root device attributes at instance launch."""
    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(EC2_EBSInstanceTuneBDM, cls).setUpClass()
        if not CONF.aws.ebs_image_id:
            raise cls.skipException('aws EBS image does not provided')
        cls.image_id = CONF.aws.ebs_image_id
        cls.zone = CONF.aws.aws_zone

        resp, data = cls.client.DescribeImages(ImageIds=[cls.image_id])
        cls.assertResultStatic(resp, data)
        assert 1 == len(data['Images'])
        image = data['Images'][0]
        cls.root_device_name = image['RootDeviceName']
        bdm = image['BlockDeviceMappings']
        bdm = [v for v in bdm if v['DeviceName'] == cls.root_device_name]
        assert 1 == len(bdm)
        ebs = bdm[0]['Ebs']
        cls.root_device_size = ebs.get('VolumeSize')
        if not cls.root_device_size:
            snapshotId = ebs.get('SnapshotId')
            resp, data = cls.client.DescribeSnapshots(SnapshotIds=[snapshotId])
            cls.assertResultStatic(resp, data)
            assert 1 == len(data['Snapshots'])
            cls.root_device_size = data['Snapshots'][0]['VolumeSize']

    @testtools.skipUnless(
        CONF.aws.run_incompatible_tests,
        "Error from nova: "
        "Invalid input for field/attribute 0. ...")
    def test_launch_ebs_instance_with_persistent_root_device(self):
        """

        Launch EBS-backed instance with left root device after termination
        """
        instance_type = CONF.aws.instance_type
        resp, data = self.client.RunInstances(
            ImageId=self.image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1,
            BlockDeviceMappings=[{'DeviceName': self.root_device_name,
                                  'Ebs': {'DeleteOnTermination': False}}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        bdt = self.get_instance_bdm(instance_id, self.root_device_name)
        self.assertIsNotNone(bdt)
        volume_id = bdt['Ebs'].get('VolumeId')
        res_clean_vol = self.addResourceCleanUp(self.client.DeleteVolume,
                                                VolumeId=volume_id)

        self.assertIsNotNone(volume_id)
        self.assertFalse(bdt['Ebs']['DeleteOnTermination'])

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Volumes']))

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        self.get_volume_waiter().wait_available(volume_id)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_vol)
        self.get_volume_waiter().wait_delete(volume_id)

    @testtools.skipUnless(
        CONF.aws.run_incompatible_tests,
        "Error from nova: "
        "Invalid input for field/attribute 0. ...")
    def test_launch_ebs_instance_with_resized_root_device(self):
        """Launch EBS-backed instance with resizing root device."""
        new_size = int(math.ceil(self.root_device_size * 1.1))

        instance_type = CONF.aws.instance_type
        resp, data = self.client.RunInstances(
            ImageId=self.image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1,
            BlockDeviceMappings=[{'DeviceName': self.root_device_name,
                                  'Ebs': {'VolumeSize': new_size}}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        bdt = self.get_instance_bdm(instance_id, self.root_device_name)
        self.assertIsNotNone(bdt)
        volume_id = bdt['Ebs'].get('VolumeId')
        self.assertIsNotNone(volume_id)
        self.assertTrue(bdt['Ebs']['DeleteOnTermination'])

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Volumes']))
        volume = data['Volumes'][0]
        self.assertEqual(new_size, volume['Size'])

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(
        CONF.aws.run_incompatible_tests,
        "Error from nova: "
        "Invalid input for field/attribute 0. ...")
    def test_launch_ebs_instance_with_creating_blank_volume(self):
        """Launch instance with creating blank volume."""
        device_name_prefix = _get_device_name_prefix(self.root_device_name)
        device_name = device_name_prefix + 'd'

        instance_type = CONF.aws.instance_type
        resp, data = self.client.RunInstances(
            ImageId=self.image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1,
            BlockDeviceMappings=[{'DeviceName': device_name,
                                  'Ebs': {'VolumeSize': 1}}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        bdt = self.get_instance_bdm(instance_id, device_name)
        self.assertIsNotNone(bdt)
        volume_id = bdt['Ebs'].get('VolumeId')
        self.assertIsNotNone(volume_id)
        self.assertTrue(bdt['Ebs']['DeleteOnTermination'])

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Volumes']))
        volume = data['Volumes'][0]
        self.assertEqual(1, volume['Size'])

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)


class EC2_EBSInstanceAttaching(base.EC2TestCase):
    """

    Launch instance with two attached volumes. One at first free slot (xxdb,
    other at some free slot (xxdh). Use full device name for the first and
    short device name for the second. Check used device names.
    Detach devices and  reattach their back with same names. Check used device
    names again.
    Detach devices and attach their in next slots (xxdc and xxdi). First with
    full name, and second with short. Check useed device names.
    Sometimes this test case failed in AWS because volumes get attach state
    'busy'. Then it's need to give a pause and rerun test case.
    Some dublicate tests are hidden to less output information.
    """
    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(EC2_EBSInstanceAttaching, cls).setUpClass()

        if not CONF.aws.run_incompatible_tests:
            raise cls.skipException('Decsribe returns full device name while '
                                    'we boot with short name.')

        if not CONF.aws.ebs_image_id:
            raise cls.skipException('aws EBS image does not provided')
        cls.image_id = CONF.aws.ebs_image_id
        cls.zone = CONF.aws.aws_zone

        resp, data = cls.client.DescribeImages(ImageIds=[cls.image_id])
        cls.assertResultStatic(resp, data)
        assert 1 == len(data['Images'])
        image = data['Images'][0]
        root_device_name = image['RootDeviceName']

        device_name_prefix = _get_device_name_prefix(root_device_name)
        cls.full_device_name_prefix = device_name_prefix
        cls.short_device_name_prefix = device_name_prefix[len("/dev/"):]

        resp, data = cls.client.CreateVolume(AvailabilityZone=cls.zone,
                                             Size=1)
        cls.assertResultStatic(resp, data)
        cls.volume_id = data['VolumeId']
        cls.addResourceCleanUpStatic(cls.client.DeleteVolume,
                                     VolumeId=cls.volume_id)
        cls.get_volume_waiter().wait_available(cls.volume_id)

        resp, data = cls.client.CreateSnapshot(VolumeId=cls.volume_id)
        cls.assertResultStatic(resp, data)
        cls.snapshot_id = data['SnapshotId']
        cls.addResourceCleanUpStatic(cls.client.DeleteSnapshot,
                                     SnapshotId=cls.snapshot_id)
        cls.get_snapshot_waiter().wait_available(cls.snapshot_id,
                                                 final_set=('completed'))

        instance_type = CONF.aws.instance_type
        cls.device1_name = cls.full_device_name_prefix + "d"
        cls.device2_name = cls.short_device_name_prefix + "h"
        resp, data = cls.client.RunInstances(
            ImageId=cls.image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': cls.zone}, MinCount=1, MaxCount=1,
            BlockDeviceMappings=[{'DeviceName': cls.device1_name,
                                  'Ebs': {'SnapshotId': cls.snapshot_id,
                                          'DeleteOnTermination': True}},
                                 {'DeviceName': cls.device2_name,
                                  'Ebs': {'SnapshotId': cls.snapshot_id,
                                          'DeleteOnTermination': True}}])
        cls.assertResultStatic(resp, data)
        instance_id = data['Instances'][0]['InstanceId']
        cls.instance_id = instance_id
        cls.addResourceCleanUpStatic(cls.client.TerminateInstances,
                                     InstanceIds=[instance_id])
        cls.get_instance_waiter().wait_available(instance_id,
                                                 final_set=('running'))

        resp, data = cls.client.DescribeInstances(InstanceIds=[instance_id])
        cls.assertResultStatic(resp, data)
        assert 1 == len(data.get('Reservations', []))
        instances = data['Reservations'][0].get('Instances', [])
        assert 1 == len(instances)
        instance = instances[0]
        bdms = instance['BlockDeviceMappings']
        for bdt in bdms:
            if bdt['DeviceName'] == cls.device1_name:
                cls.volume_id1 = bdt['Ebs']['VolumeId']
            if bdt['DeviceName'] == cls.device2_name:
                cls.volume_id2 = bdt['Ebs']['VolumeId']
        assert cls.volume_id1
        assert cls.volume_id2

    @classmethod
    def tearDownClass(cls):
        super(EC2_EBSInstanceAttaching, cls).tearDownClass()
        # NOTE(andrey-mp): Amazon resets flag DeleteOnTermination after
        # reattaching volume, so we need delete them manually
        for volume_id in [cls.volume_id1, cls.volume_id2]:
            try:
                cls.cleanUpItem(cls.client.DeleteVolume, [],
                                {'VolumeId': volume_id})
            except BaseException:
                LOG.exception('EBSInstanceAttaching.tearDownClass failure')

    def _test_attaching(self, volume_id, device_name, device_prefix,
                        new_device_name_letter):
        resp, data = self.client.DetachVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        clean_v = self.addResourceCleanUp(self.client.DeleteVolume,
                                          VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_delete(volume_id)

        bdt = self.get_instance_bdm(self.instance_id, device_name)
        self.assertIsNone(bdt)

        resp, data = self.client.AttachVolume(InstanceId=self.instance_id,
                                              VolumeId=volume_id,
                                              Device=device_name)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['Volumes']))
        self.assertEqual('in-use', data['Volumes'][0]['State'])

        bdt = self.get_instance_bdm(self.instance_id, device_name)
        self.assertIsNotNone(bdt)

        resp, data = self.client.DetachVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        clean_v = self.addResourceCleanUp(self.client.DeleteVolume,
                                          VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_delete(volume_id)

        bdt = self.get_instance_bdm(self.instance_id, device_name)
        self.assertIsNone(bdt)

        new_device_name = device_prefix + new_device_name_letter
        resp, data = self.client.AttachVolume(InstanceId=self.instance_id,
                                              VolumeId=volume_id,
                                              Device=new_device_name)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_attachment_waiter().wait_available(
            volume_id, final_set=('attached'))

        resp, data = self.client.DescribeVolumes(VolumeIds=[volume_id])
        self.assertEqual(200, resp.status_code)
        self.assertEqual(1, len(data['Volumes']))
        self.assertEqual('in-use', data['Volumes'][0]['State'])

        bdt = self.get_instance_bdm(self.instance_id, new_device_name)
        self.assertIsNotNone(bdt)

    def test_attaching_by_full_name(self):
        """Attach and reattach device by full name."""
        self._test_attaching(self.volume_id1, self.device1_name,
                             self.full_device_name_prefix, "e")

    def test_attaching_by_short_name(self):
        """Attach and reattach device by short name."""
        self._test_attaching(self.volume_id2, self.device2_name,
                             self.short_device_name_prefix, "i")


class EC2_EBSInstanceSnapshot(base.EC2TestCase):
    """

    Launch EBS-backed image, snapshot root device, register image,
    and launch another instance from the image
    (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/
    instance-launch-snapshot.html)
    """
    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(EC2_EBSInstanceSnapshot, cls).setUpClass()
        if not CONF.aws.ebs_image_id:
            raise cls.skipException('aws EBS image does not provided')
        cls.image_id = CONF.aws.ebs_image_id
        cls.zone = CONF.aws.aws_zone

    def test_create_ebs_instance_snapshot(self):
        """Create snapshot of EBS-backed instance and check it."""

        instance_type = CONF.aws.instance_type
        resp, data = self.client.RunInstances(
            ImageId=self.image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))
        instance = self.get_instance(instance_id)

        bdt = self.get_instance_bdm(instance_id, None)
        self.assertIsNotNone(bdt)
        volume_id = bdt['Ebs'].get('VolumeId')
        self.assertIsNotNone(volume_id)

        resp, data = self.client.StopInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('stopped'))

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        resp, data = self.client.CreateSnapshot(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        snapshot_id = data['SnapshotId']
        clean_s = self.addResourceCleanUp(self.client.DeleteSnapshot,
                                          SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        kwargs = {
            'Name': data_utils.rand_name('ebs-ami'),
            'RootDeviceName': instance['RootDeviceName'],
            'BlockDeviceMappings': [{'DeviceName': instance['RootDeviceName'],
                                     'Ebs': {'SnapshotId': snapshot_id,
                                             'DeleteOnTermination': True}}]
        }
        if 'Architecture' in instance:
            kwargs['Architecture'] = instance['Architecture']
        if 'KernelId' in instance:
            kwargs['KernelId'] = instance['KernelId']
        if 'RamdiskId' in instance:
            kwargs['RamdiskId'] = instance['RamdiskId']
        resp, data = self.client.RegisterImage(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        image_id = data['ImageId']
        clean_i = self.addResourceCleanUp(self.client.DeregisterImage,
                                          ImageId=image_id)
        self.get_image_waiter().wait_available(image_id)

        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        # NOTE(andrey-mp): if instance will run then test will pass

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        resp, data = self.client.DeregisterImage(ImageId=image_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_i)

        resp, data = self.client.DeleteSnapshot(SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_s)


class EC2_EBSInstanceResizeRootDevice(base.EC2TestCase):
    """

    Launch EBS-backed instance, stop instance, detach root volume, snapshot it,
    create volume from snapshot with increased size, attach new root volume,
    start instance
    (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-expand-volume.html)
    """
    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(EC2_EBSInstanceResizeRootDevice, cls).setUpClass()
        if not CONF.aws.ebs_image_id:
            raise cls.skipException('aws EBS image does not provided')
        cls.image_id = CONF.aws.ebs_image_id
        cls.zone = CONF.aws.aws_zone

    @testtools.skipUnless(
        CONF.aws.run_incompatible_tests,
        "Error from nova: "
        "Unexpected Forbidden raised: Can't detach root device volume")
    def test_resize_root_ebs_device(self):
        """Resize root device of launched instance."""
        instance_type = CONF.aws.instance_type
        resp, data = self.client.RunInstances(
            ImageId=self.image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance = data['Instances'][0]
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        bdt = self.get_instance_bdm(instance_id, None)
        self.assertIsNotNone(bdt)
        volume_id = bdt['Ebs'].get('VolumeId')
        self.assertIsNotNone(volume_id)

        resp, data = self.client.StopInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('stopped'))

        resp, data = self.client.DetachVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        clean_v = self.addResourceCleanUp(self.client.DeleteVolume,
                                          VolumeId=volume_id)
        self.get_volume_attachment_waiter().wait_delete(volume_id)

        resp, data = self.client.CreateSnapshot(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        snapshot_id = data['SnapshotId']
        clean_s = self.addResourceCleanUp(self.client.DeleteSnapshot,
                                          SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        new_size = int(math.ceil(data['VolumeSize'] * 1.1))
        resp, data = self.client.CreateVolume(AvailabilityZone=self.zone,
                                              Size=new_size,
                                              SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        volume_id2 = data['VolumeId']
        clean_v2 = self.addResourceCleanUp(self.client.DeleteVolume,
                                           VolumeId=volume_id2)
        self.get_volume_waiter().wait_available(volume_id2)

        resp, data = self.client.DeleteSnapshot(SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_s)

        resp, data = self.client.DeleteVolume(VolumeId=volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_v)
        self.get_volume_waiter().wait_delete(volume_id)

        resp, data = self.client.AttachVolume(
            InstanceId=instance_id, VolumeId=volume_id2,
            Device=instance['RootDeviceName'])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.get_volume_attachment_waiter().wait_available(
            volume_id2, final_set=('attached'))

        # NOTE(andrey-mp): move this cleanup operation to the end of trash
        self.cancelResourceCleanUp(res_clean)
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])

        resp, data = self.client.StartInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        # NOTE(andrey-mp): if instance will run then test will pass

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        self.client.DeleteVolume(VolumeId=volume_id)
        self.cancelResourceCleanUp(clean_v2)
