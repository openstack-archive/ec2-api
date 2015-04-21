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

from oslo_log import log
from tempest_lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class InstanceTest(base.EC2TestCase):

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(InstanceTest, cls).setUpClass()
        if not CONF.aws.image_id:
            raise cls.skipException('aws image_id does not provided')
        cls.zone = CONF.aws.aws_zone

    def test_create_delete_instance(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.assertEqual(1, len(data['Instances']))
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.DescribeInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        reservations = data.get('Reservations', [])
        self.assertNotEmpty(reservations)
        instances = reservations[0].get('Instances', [])
        self.assertEqual(1, len(instances))

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        # NOTE(andrey-mp): There is difference between Openstack and Amazon.
        # Amazon returns instance in 'terminated' state some time after
        # instance deletion. But Openstack doesn't return such instance.

    def test_create_idempotent_instance(self):
        client_token = data_utils.rand_name('t')
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1,
            ClientToken=client_token)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.assertEqual(1, len(data['Instances']))
        reservation_id = data['ReservationId']
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1,
            ClientToken=client_token)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        # NOTE(andrey-mp): if idempotent run will fail this will terminate
        # second instance
        self.addResourceCleanUp(self.client.TerminateInstances,
            InstanceIds=[data['Instances'][0]['InstanceId']])

        self.assertEqual(1, len(data['Instances']))
        self.assertEqual(reservation_id, data['ReservationId'])
        self.assertEqual(instance_id, data['Instances'][0]['InstanceId'])

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    def test_describe_instances_filter(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        # NOTE(andrey-mp): by real id
        resp, data = self.client.DescribeInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self._assert_instance(data, instance_id)
        instances = data['Reservations'][0]['Instances']
        private_dns = instances[0]['PrivateDnsName']
        private_ip = instances[0]['PrivateIpAddress']

        # NOTE(andrey-mp): by fake id
        resp, data = self.client.DescribeInstances(InstanceIds=['i-0'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidInstanceID.NotFound', data['Error']['Code'])

        # NOTE(andrey-mp): by private ip
        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'private-ip-address', 'Values': ['1.2.3.4']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Reservations']))

        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'private-ip-address', 'Values': [private_ip]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self._assert_instance(data, instance_id)

        # NOTE(andrey-mp): by private dns
        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'private-dns-name', 'Values': ['fake.com']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Reservations']))

        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'private-dns-name', 'Values': [private_dns]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self._assert_instance(data, instance_id)

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    def _assert_instance(self, data, instance_id):
        reservations = data.get('Reservations', [])
        self.assertNotEmpty(reservations)
        instances = reservations[0].get('Instances', [])
        self.assertNotEmpty(instances)
        self.assertEqual(instance_id, instances[0]['InstanceId'])

    def test_get_password_data_and_console_output(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.GetPasswordData(InstanceId=instance_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(instance_id, data['InstanceId'])
        self.assertIsNotNone(data['Timestamp'])
        self.assertIn('PasswordData', data)

        waiter = base.EC2Waiter(self.client.GetConsoleOutput)
        waiter.wait_no_exception(InstanceId=instance_id)

        resp, data = self.client.GetConsoleOutput(InstanceId=instance_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(instance_id, data['InstanceId'])
        self.assertIsNotNone(data['Timestamp'])
        self.assertIn('Output', data)

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    def test_stop_instance(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.StopInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        if CONF.aws.run_incompatible_tests:
            instances = data['StoppingInstances']
            self.assertEqual(1, len(instances))
            instance = instances[0]
            self.assertEqual(instance_id, instance['InstanceId'])
            self.assertEqual('running', instance['PreviousState']['Name'])
            self.assertEqual('stopping', instance['CurrentState']['Name'])

        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('stopped'))

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "Openstack doesn't assign public ip automatically for new instance")
    def test_public_ip_is_assigned(self):
        """Is public IP assigned to launched instnace?"""
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Instances']))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        instance = self.get_instance(instance_id)
        self.assertIsNotNone(instance.get('PublicIpAddress'))
        self.assertIsNotNone(instance.get('PrivateIpAddress'))
        self.assertNotEqual(instance.get('PublicIpAddress'),
                            instance.get('PrivateIpAddress'))

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    def test_describe_instance_attributes(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type,
            Placement={'AvailabilityZone': self.zone}, MinCount=1, MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.assertEqual(1, len(data['Instances']))
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        if CONF.aws.run_incompatible_tests:
            resp, data = self.client.DescribeInstanceAttribute(
                InstanceId=instance_id, Attribute='blockDeviceMapping')
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            bdms = data.get('BlockDeviceMappings', [])
            self.assertNotEmpty(bdms)
            self.assertEqual(1, len(bdms))
            self.assertIn('DeviceName', bdms[0])
            self.assertIn('Ebs', bdms[0])

        resp, data = self.client.DescribeInstanceAttribute(
            InstanceId=instance_id, Attribute='disableApiTermination')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('DisableApiTermination', data)
        self.assertIn('Value', data['DisableApiTermination'])
        self.assertFalse(data['DisableApiTermination']['Value'])

        resp, data = self.client.DescribeInstanceAttribute(
            InstanceId=instance_id, Attribute='groupSet')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('Groups', data)
        self.assertNotEmpty(data['Groups'], data)
        self.assertTrue('GroupId' in data['Groups'][0]
                        or 'GroupName' in data['Groups'][0])
        self.assertTrue(data['Groups'][0].get('GroupId')
                        or data['Groups'][0].get('GroupName'))

        resp, data = self.client.DescribeInstanceAttribute(
            InstanceId=instance_id, Attribute='instanceType')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('InstanceType', data)
        self.assertIn('Value', data['InstanceType'])
        self.assertEqual(instance_type, data['InstanceType']['Value'])

        resp, data = self.client.DescribeInstanceAttribute(
            InstanceId=instance_id, Attribute='kernel')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('KernelId', data)

        resp, data = self.client.DescribeInstanceAttribute(
            InstanceId=instance_id, Attribute='ramdisk')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('RamdiskId', data)

        resp, data = self.client.DescribeInstanceAttribute(
            InstanceId=instance_id, Attribute='rootDeviceName')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('RootDeviceName', data)
        self.assertIn('Value', data['RootDeviceName'])
        self.assertTrue(data['RootDeviceName']['Value'])

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "Error from nova: "
        "Invalid input for field/attribute 0. ...")
    def test_launch_instance_with_creating_blank_volume(self):
        """Launch instance with creating blank volume."""
        device_name = '/dev/xvdh'
        instance_type = CONF.aws.instance_type
        resp, data = self.client.RunInstances(
            ImageId=CONF.aws.image_id, InstanceType=instance_type,
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
