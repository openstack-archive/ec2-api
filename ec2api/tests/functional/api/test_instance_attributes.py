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

import time

from oslo_log import log
from tempest.lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class InstanceAttributeTest(base.EC2TestCase):

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    def test_describe_instance_attributes(self):
        instance_id = self.run_instance(ImageId=CONF.aws.ebs_image_id)

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='blockDeviceMapping')
        bdms = data.get('BlockDeviceMappings', [])
        self.assertNotEmpty(bdms)
        self.assertEqual(1, len(bdms))
        self.assertIn('DeviceName', bdms[0])
        self.assertIn('Ebs', bdms[0])

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='disableApiTermination')
        self.assertIn('DisableApiTermination', data)
        self.assertIn('Value', data['DisableApiTermination'])
        self.assertFalse(data['DisableApiTermination']['Value'])

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='groupSet')
        self.assertIn('Groups', data)
        self.assertNotEmpty(data['Groups'], data)
        self.assertTrue('GroupId' in data['Groups'][0]
                        or 'GroupName' in data['Groups'][0])
        self.assertTrue(data['Groups'][0].get('GroupId')
                        or data['Groups'][0].get('GroupName'))

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='instanceType')
        self.assertIn('InstanceType', data)
        self.assertIn('Value', data['InstanceType'])
        self.assertEqual(CONF.aws.instance_type, data['InstanceType']['Value'])

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='kernel')
        self.assertIn('KernelId', data)

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='ramdisk')
        self.assertIn('RamdiskId', data)

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='rootDeviceName')
        self.assertIn('RootDeviceName', data)
        self.assertIn('Value', data['RootDeviceName'])
        self.assertTrue(data['RootDeviceName']['Value'])

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_disable_api_termination_attribute(self):
        instance_id = self.run_instance(DisableApiTermination=True)
        res_clean = self.addResourceCleanUp(
            self.client.modify_instance_attribute,
            InstanceId=instance_id,
            DisableApiTermination={'Value': False})

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='disableApiTermination')
        self.assertIn('DisableApiTermination', data)
        self.assertIn('Value', data['DisableApiTermination'])
        self.assertTrue(data['DisableApiTermination']['Value'])

        data = self.client.modify_instance_attribute(InstanceId=instance_id,
            Attribute='disableApiTermination', Value='False')
        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='disableApiTermination')
        self.assertFalse(data['DisableApiTermination']['Value'])

        data = self.client.modify_instance_attribute(InstanceId=instance_id,
            Attribute='disableApiTermination', Value='True')
        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='disableApiTermination')
        self.assertTrue(data['DisableApiTermination']['Value'])

        self.assertRaises('OperationNotPermitted',
                          self.client.terminate_instances,
                          InstanceIds=[instance_id])

        data = self.client.modify_instance_attribute(InstanceId=instance_id,
            DisableApiTermination={'Value': False})
        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='disableApiTermination')
        self.assertFalse(data['DisableApiTermination']['Value'])

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_instance_attributes_negative(self):
        instance_id = self.run_instance()

        self.assertRaises('InvalidParameterValue',
            self.client.describe_instance_attribute,
            InstanceId=instance_id, Attribute='fake_attribute')
        self.assertRaises('InvalidInstanceID.NotFound',
            self.client.describe_instance_attribute,
            InstanceId='i-0', Attribute='disableApiTermination')
        if base.TesterStateHolder().get_ec2_enabled():
            self.assertRaises('InvalidParameterCombination',
                self.client.describe_instance_attribute,
                InstanceId=instance_id, Attribute='sourceDestCheck')

        self.assertRaises('InvalidParameterValue',
            self.client.modify_instance_attribute,
            InstanceId=instance_id, Attribute='fake_attribute')
        self.assertRaises('MissingParameter',
            self.client.modify_instance_attribute,
            InstanceId=instance_id, Attribute='disableApiTermination')
        self.assertRaises('InvalidParameterCombination',
            self.client.modify_instance_attribute,
            InstanceId=instance_id)
        self.assertRaises('InvalidParameterCombination',
            self.client.modify_instance_attribute,
            InstanceId=instance_id, Attribute='disableApiTermination',
            Value='True', DisableApiTermination={'Value': False})

        ex_str = ('InvalidParameterCombination'
                  if base.TesterStateHolder().get_ec2_enabled() else
                  'InvalidGroup.NotFound')
        self.assertRaises(ex_str,
            self.client.modify_instance_attribute,
            InstanceId=instance_id, Groups=['sg-0'])
        if base.TesterStateHolder().get_ec2_enabled():
            self.assertRaises('InvalidParameterCombination',
                self.client.modify_instance_attribute,
                InstanceId=instance_id, Attribute='sourceDestCheck',
                Value='False')

        self.assertRaises('InvalidParameterValue',
            self.client.reset_instance_attribute,
            InstanceId=instance_id, Attribute='fake_attribute')
        self.assertRaises('InvalidParameterValue',
            self.client.reset_instance_attribute,
            InstanceId=instance_id, Attribute='disableApiTermination')
        self.assertRaises('InvalidParameterValue',
            self.client.reset_instance_attribute,
            InstanceId='i-0', Attribute='disableApiTermination')
        self.assertRaises('InvalidParameterValue',
            self.client.reset_instance_attribute,
            InstanceId=instance_id, Attribute='groupSet')
        self.assertRaises('InvalidParameterValue',
            self.client.reset_instance_attribute,
            InstanceId=instance_id, Attribute='instanceType')

        if base.TesterStateHolder().get_ec2_enabled():
            self.assertRaises('InvalidParameterCombination',
                self.client.reset_instance_attribute,
                InstanceId=instance_id, Attribute='sourceDestCheck')

        self.assertRaises('IncorrectInstanceState',
            self.client.modify_instance_attribute,
            InstanceId=instance_id, Attribute='instanceType',
            Value=CONF.aws.instance_type)
        self.assertRaises('IncorrectInstanceState',
            self.client.modify_instance_attribute,
            InstanceId=instance_id,
            InstanceType={'Value': CONF.aws.instance_type})

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_attributes_for_multiple_interfaces_negative(self):
        vpc_id, subnet_id = self.create_vpc_and_subnet('10.30.0.0/24')

        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        data = self.client.create_security_group(VpcId=vpc_id, GroupName=name,
                                                 Description=desc)
        group_id = data['GroupId']
        self.addResourceCleanUp(self.client.delete_security_group,
                                GroupId=group_id)
        time.sleep(2)
        data = self.client.create_network_interface(SubnetId=subnet_id,
            Groups=[group_id])
        ni_id2 = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.delete_network_interface,
                                NetworkInterfaceId=ni_id2)
        self.get_network_interface_waiter().wait_available(ni_id2)

        instance_id = self.run_instance(SubnetId=subnet_id)

        kwargs = {
            'DeviceIndex': 2,
            'InstanceId': instance_id,
            'NetworkInterfaceId': ni_id2
        }
        data = self.client.attach_network_interface(*[], **kwargs)

        self.assertRaises('InvalidInstanceID',
            self.client.describe_instance_attribute,
            InstanceId=instance_id, Attribute='groupSet')
        self.assertRaises('InvalidInstanceID',
            self.client.modify_instance_attribute,
            InstanceId=instance_id, Groups=['sg-0'])

        self.assertRaises('InvalidInstanceID',
            self.client.describe_instance_attribute,
            InstanceId=instance_id, Attribute='sourceDestCheck')
        self.assertRaises('InvalidInstanceID',
            self.client.modify_instance_attribute,
            InstanceId=instance_id, SourceDestCheck={'Value': False})
        self.assertRaises('InvalidInstanceID',
            self.client.reset_instance_attribute,
            InstanceId=instance_id, Attribute='sourceDestCheck')

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_group_set_attribute(self):
        vpc_id, subnet_id = self.create_vpc_and_subnet('10.30.0.0/24')

        instance_id = self.run_instance(SubnetId=subnet_id)

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='groupSet')
        self.assertIn('Groups', data)
        self.assertEqual(1, len(data['Groups']))
        default_group_id = data['Groups'][0]['GroupId']

        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        data = self.client.create_security_group(VpcId=vpc_id, GroupName=name,
                                                 Description=desc)
        group_id = data['GroupId']
        self.addResourceCleanUp(self.client.delete_security_group,
                                GroupId=group_id)
        time.sleep(2)

        try:
            data = self.client.modify_instance_attribute(
                InstanceId=instance_id, Groups=[group_id])
            data = self.client.describe_instance_attribute(
                InstanceId=instance_id, Attribute='groupSet')
            self.assertIn('Groups', data)
            self.assertEqual(1, len(data['Groups']))
            self.assertNotEqual(default_group_id, data['Groups'][0]['GroupId'])

            self.assertRaises('DependencyViolation',
                self.client.delete_security_group,
                GroupId=group_id)
        finally:
            self.client.modify_instance_attribute(InstanceId=instance_id,
                Groups=[default_group_id])

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='groupSet')
        self.assertIn('Groups', data)
        self.assertEqual(1, len(data['Groups']))
        self.assertEqual(default_group_id, data['Groups'][0]['GroupId'])

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_source_dest_check_attribute(self):
        vpc_id, subnet_id = self.create_vpc_and_subnet('10.30.0.0/24')

        instance_id = self.run_instance(SubnetId=subnet_id)

        def do_check(value):
            data = self.client.describe_instance_attribute(
                InstanceId=instance_id, Attribute='sourceDestCheck')
            self.assertIn('SourceDestCheck', data)
            self.assertEqual(value, data['SourceDestCheck'].get('Value'))

        do_check(True)

        self.client.modify_instance_attribute(
            InstanceId=instance_id, Attribute='sourceDestCheck',
            Value='False')
        do_check(False)

        self.client.reset_instance_attribute(
            InstanceId=instance_id, Attribute='sourceDestCheck')
        do_check(True)

        self.client.modify_instance_attribute(
            InstanceId=instance_id, Attribute='sourceDestCheck',
            Value='False')
        do_check(False)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @testtools.skipUnless(CONF.aws.ebs_image_id, "EBS image id is not defined")
    @testtools.skipUnless(CONF.aws.instance_type_alt,
                          "Alternative instance type is not defined")
    @testtools.skipUnless(CONF.aws.instance_type_alt != CONF.aws.instance_type,
                          "Alternative instance type is not defined")
    def test_instance_type_attribute(self):
        instance_id = self.run_instance(ImageId=CONF.aws.ebs_image_id)

        self.client.stop_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('stopped'))
        instance = self.get_instance(instance_id)
        self.assertEqual(CONF.aws.instance_type, instance['InstanceType'])

        self.client.modify_instance_attribute(
            InstanceId=instance_id, Attribute='instanceType',
            Value=CONF.aws.instance_type)
        instance = self.get_instance(instance_id)
        self.assertEqual(CONF.aws.instance_type, instance['InstanceType'])

        self.client.modify_instance_attribute(
            InstanceId=instance_id,
            InstanceType={'Value': CONF.aws.instance_type_alt})
        instance = self.get_instance(instance_id)
        self.assertEqual(CONF.aws.instance_type_alt, instance['InstanceType'])

        self.client.start_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        instance = self.get_instance(instance_id)
        self.assertEqual(CONF.aws.instance_type_alt, instance['InstanceType'])

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)
