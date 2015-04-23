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

import botocore.exceptions
from oslo_log import log
from tempest_lib.common.utils import data_utils

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF

LOG = log.getLogger(__name__)


class NetworkInterfaceTest(base.EC2TestCase):

    VPC_CIDR = '10.7.0.0/20'
    vpc_id = None
    SUBNET_CIDR = '10.7.0.0/28'
    subnet_id = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(NetworkInterfaceTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

        data = cls.client.create_vpc(CidrBlock=cls.VPC_CIDR)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.addResourceCleanUpStatic(cls.client.delete_vpc, VpcId=cls.vpc_id)
        cls.get_vpc_waiter().wait_available(cls.vpc_id)

        aws_zone = CONF.aws.aws_zone
        data = cls.client.create_subnet(VpcId=cls.vpc_id,
                                             CidrBlock=cls.SUBNET_CIDR,
                                             AvailabilityZone=aws_zone)
        cls.subnet_id = data['Subnet']['SubnetId']
        cls.addResourceCleanUpStatic(cls.client.delete_subnet,
                                     SubnetId=cls.subnet_id)
        cls.get_subnet_waiter().wait_available(cls.subnet_id)

    def _wait_assignment(self, ni_id, data):
        # NOTE(andrey-mp): Amazon don't do it quickly and there is no way
        # to wait this request
        time.sleep(5)

    def test_delete_subnet_with_network_interface(self):
        data = self.client.create_subnet(VpcId=self.vpc_id,
                                              CidrBlock='10.7.1.0/28')
        subnet_id = data['Subnet']['SubnetId']
        res_clean_subnet = self.addResourceCleanUp(self.client.delete_subnet,
                                                   SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        kwargs = {
            'SubnetId': subnet_id,
            'Description': data_utils.rand_name('ni')
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean_ni = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        self.assertRaises('DependencyViolation',
                          self.client.delete_subnet,
                          SubnetId=subnet_id)

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean_ni)
        self.get_network_interface_waiter().wait_delete(ni_id)

        data = self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(res_clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

    def test_create_network_interface(self):
        kwargs = {
            'SubnetId': self.subnet_id,
            'Description': data_utils.rand_name('ni')
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        ni = data['NetworkInterface']
        self.assertEqual(self.vpc_id, ni['VpcId'])
        self.assertEqual(self.subnet_id, ni['SubnetId'])
        self.assertEqual(kwargs['Description'], ni['Description'])

        self.assertNotEmpty(ni.get('Groups'))
        self.assertEqual('default', ni['Groups'][0]['GroupName'])

        address = ni.get('PrivateIpAddress')
        self.assertIsNotNone(address)
        addresses = ni.get('PrivateIpAddresses')
        self.assertIsNotNone(addresses)
        self.assertEqual(1, len(addresses))
        self.assertTrue(addresses[0]['Primary'])
        self.assertEqual(address, addresses[0]['PrivateIpAddress'])

        self.assertIsNotNone(ni.get('MacAddress'))
        self.assertIsNotNone(ni.get('OwnerId'))
        self.assertIsNotNone(ni.get('RequesterManaged'))
        self.assertIsNotNone(ni.get('SourceDestCheck'))

        self.get_network_interface_waiter().wait_available(ni_id)

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

        self.assertRaises('InvalidNetworkInterfaceID.NotFound',
                          self.client.describe_network_interfaces,
                          NetworkInterfaceIds=[ni_id])

    # TODO(andrey-mp): add creation with addresses

    def test_create_max_network_interface(self):
        # NOTE(andrey-mp): wait some time while all ports will be deleted
        # for this subnet(that are deleting after previous test)
        time.sleep(5)

        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count_before = data['Subnets'][0]['AvailableIpAddressCount']
        kwargs = {
            'SubnetId': self.subnet_id,
        }
        addresses = []
        while True:
            try:
                data = self.client.create_network_interface(*[], **kwargs)
            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                self.assertEqual('NetworkInterfaceLimitExceeded', error_code)
                break
            ni_id = data['NetworkInterface']['NetworkInterfaceId']
            res_clean = self.addResourceCleanUp(
                self.client.delete_network_interface,
                NetworkInterfaceId=ni_id)
            addresses.append((ni_id, res_clean))

        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count_after = data['Subnets'][0]['AvailableIpAddressCount']
        # NOTE(andrey-mp): This is strange but Amazon can't create last NI
        # and Openstack can
        self.assertIn(count_after, [0, 1])
        self.assertEqual(len(addresses), count_before - count_after)

        for addr in addresses:
            kwargs = {
                'NetworkInterfaceId': addr[0],
            }
            data = self.client.delete_network_interface(*[], **kwargs)
            self.cancelResourceCleanUp(addr[1])
            self.get_network_interface_waiter().wait_delete(addr[0])

    def test_unassign_primary_addresses(self):
        kwargs = {
            'SubnetId': self.subnet_id,
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        primary_address = data['NetworkInterface'].get('PrivateIpAddress')
        self.get_network_interface_waiter().wait_available(ni_id)

        self.assertRaises('InvalidParameterValue',
                          self.client.unassign_private_ip_addresses,
                          NetworkInterfaceId=ni_id,
                          PrivateIpAddresses=[primary_address])

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    def test_assign_unassign_private_addresses_by_count(self):
        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count = data['Subnets'][0]['AvailableIpAddressCount']
        kwargs = {
            'SubnetId': self.subnet_id,
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        data = self.client.assign_private_ip_addresses(
            NetworkInterfaceId=ni_id,
            SecondaryPrivateIpAddressCount=2)
        self._wait_assignment(ni_id, data)

        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count_after = data['Subnets'][0]['AvailableIpAddressCount']
        self.assertEqual(count - 3, count_after)

        data = self.client.describe_network_interfaces(
            NetworkInterfaceIds=[ni_id])

        addresses = []
        for addr in data['NetworkInterfaces'][0]['PrivateIpAddresses']:
            if not addr['Primary']:
                addresses.append(addr['PrivateIpAddress'])
        self.assertEqual(2, len(addresses))

        data = self.client.unassign_private_ip_addresses(
            NetworkInterfaceId=ni_id,
            PrivateIpAddresses=addresses)
        self._wait_assignment(ni_id, data)

        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count_after = data['Subnets'][0]['AvailableIpAddressCount']
        self.assertEqual(count - 1, count_after)

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    def test_assign_unassign_private_addresses_by_addresses(self):
        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count = data['Subnets'][0]['AvailableIpAddressCount']
        kwargs = {
            'SubnetId': self.subnet_id,
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        addresses = ['10.7.0.10', '10.7.0.11']
        data = self.client.assign_private_ip_addresses(
            NetworkInterfaceId=ni_id,
            PrivateIpAddresses=addresses)
        self._wait_assignment(ni_id, data)

        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count_after = data['Subnets'][0]['AvailableIpAddressCount']
        # NOTE(Alex): Amazon misses 1 IP address by some reason.
        self.assertIn(count_after, [count - 3, count - 4])

        data = self.client.describe_network_interfaces(
            NetworkInterfaceIds=[ni_id])

        assigned_addresses = []
        for addr in data['NetworkInterfaces'][0]['PrivateIpAddresses']:
            if not addr['Primary']:
                self.assertIn(addr['PrivateIpAddress'], addresses)
                assigned_addresses.append(addr['PrivateIpAddress'])
        self.assertEqual(2, len(assigned_addresses))

        data = self.client.unassign_private_ip_addresses(
            NetworkInterfaceId=ni_id,
            PrivateIpAddresses=addresses)
        self._wait_assignment(ni_id, data)

        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count_after = data['Subnets'][0]['AvailableIpAddressCount']
        self.assertIn(count_after, [count - 1, count - 2])

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    def test_network_interface_attribute(self):
        desc = data_utils.rand_name('ni')
        kwargs = {
            'SubnetId': self.subnet_id,
            'Description': desc
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id,
            Attribute='description')
        self.assertEqual(desc, data['Description']['Value'])

        new_desc = data_utils.rand_name('new-ni')
        kwargs = {
            'NetworkInterfaceId': ni_id,
            'Description': {'Value': new_desc}
        }
        data = self.client.modify_network_interface_attribute(*[], **kwargs)

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id,
            Attribute='description')
        self.assertEqual(new_desc, data['Description']['Value'])

        kwargs = {
            'NetworkInterfaceId': ni_id,
            'SourceDestCheck': {'Value': False}
        }
        data = self.client.modify_network_interface_attribute(*[], **kwargs)

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id,
            Attribute='sourceDestCheck')
        self.assertEqual(False, data['SourceDestCheck']['Value'])

        # NOTE(andrey-mp): ResetNetworkInterfaceAttribute had inadequate json
        # scheme in botocore.

        kwargs = {
            'NetworkInterfaceId': ni_id,
            'SourceDestCheck': {'Value': True}
        }
        data = self.client.modify_network_interface_attribute(*[], **kwargs)

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id,
            Attribute='sourceDestCheck')
        self.assertEqual(True, data['SourceDestCheck']['Value'])

        kwargs = {
            'NetworkInterfaceId': ni_id,
            'Attachment': {
                'AttachmentId': 'fake'
            }
        }
        self.assertRaises('MissingParameter',
                          self.client.modify_network_interface_attribute,
                          **kwargs)

        kwargs = {
            'NetworkInterfaceId': ni_id,
            'Attachment': {
                'AttachmentId': 'eni-attach-ffffffff',
                'DeleteOnTermination': True
            }
        }
        self.assertRaises('InvalidAttachmentID.NotFound',
                          self.client.modify_network_interface_attribute,
                          **kwargs)

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    def test_attach_network_interface(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        kwargs = {
            'SubnetId': self.subnet_id,
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.delete_network_interface,
                                NetworkInterfaceId=ni_id)
        ni = data['NetworkInterface']
        address = ni.get('PrivateIpAddress')
        self.assertIsNotNone(address)
        self.get_network_interface_waiter().wait_available(ni_id)

        data = self.client.run_instances(
            ImageId=image_id, InstanceType=instance_type, MinCount=1,
            MaxCount=1, SubnetId=self.subnet_id)
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.terminate_instances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        # NOTE(andrey-mp): Amazon can't attach to device index = 0
        kwargs = {
            'DeviceIndex': 0,
            'InstanceId': instance_id,
            'NetworkInterfaceId': ni_id
        }
        self.assertRaises('InvalidParameterValue',
                          self.client.attach_network_interface,
                          **kwargs)

        kwargs = {
            'DeviceIndex': 2,
            'InstanceId': instance_id,
            'NetworkInterfaceId': ni_id
        }
        data = self.client.attach_network_interface(*[], **kwargs)
        attachment_id = data['AttachmentId']

        instance = self.get_instance(instance_id)
        nis = instance.get('NetworkInterfaces', [])
        self.assertEqual(2, len(nis))
        ids = [nis[0]['Attachment']['AttachmentId'],
               nis[1]['Attachment']['AttachmentId']]
        self.assertIn(attachment_id, ids)

        self.assertRaises('InvalidParameterValue',
                          self.client.delete_network_interface,
                          NetworkInterfaceId=ni_id)

        kwargs = {
            'AttachmentId': attachment_id,
        }
        data = self.client.detach_network_interface(*[], **kwargs)

        data = self.client.terminate_instances(InstanceIds=[instance_id])
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    def test_network_interfaces_are_not_deleted_on_termination(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        data = self.client.run_instances(
            ImageId=image_id, InstanceType=instance_type, MinCount=1,
            MaxCount=1, SubnetId=self.subnet_id)
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.terminate_instances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        instance = self.get_instance(instance_id)
        nis = instance.get('NetworkInterfaces', [])
        self.assertEqual(1, len(nis))
        self.assertTrue(nis[0]['Attachment']['DeleteOnTermination'])
        ni_id = nis[0]['NetworkInterfaceId']
        attachment_id = nis[0]['Attachment']['AttachmentId']

        kwargs = {
            'NetworkInterfaceId': ni_id,
            'Attachment': {
                'AttachmentId': attachment_id,
                'DeleteOnTermination': False,
            }
        }
        data = self.client.modify_network_interface_attribute(*[], **kwargs)
        clean_ni = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)

        kwargs = {
            'SubnetId': self.subnet_id,
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id2 = data['NetworkInterface']['NetworkInterfaceId']
        clean_ni2 = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id2)
        self.get_network_interface_waiter().wait_available(ni_id2)
        kwargs = {
            'DeviceIndex': 2,
            'InstanceId': instance_id,
            'NetworkInterfaceId': ni_id2
        }
        data = self.client.attach_network_interface(*[], **kwargs)
        attachment_id = data['AttachmentId']

        instance = self.get_instance(instance_id)
        nis = instance.get('NetworkInterfaces', [])
        self.assertEqual(2, len(nis))
        ni = nis[0]
        if ni['Attachment']['AttachmentId'] != attachment_id:
            ni = nis[1]
        self.assertEqual(attachment_id, ni['Attachment']['AttachmentId'])
        self.assertFalse(ni['Attachment']['DeleteOnTermination'])

        data = self.client.terminate_instances(InstanceIds=[instance_id])
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        self.get_network_interface_waiter().wait_available(ni_id)
        self.get_network_interface_waiter().wait_available(ni_id2)

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(clean_ni)
        self.get_network_interface_waiter().wait_delete(ni_id)

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id2)
        self.cancelResourceCleanUp(clean_ni2)
        self.get_network_interface_waiter().wait_delete(ni_id2)

    def test_network_interfaces_are_deleted_on_termination(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        data = self.client.run_instances(
            ImageId=image_id, InstanceType=instance_type, MinCount=1,
            MaxCount=1, SubnetId=self.subnet_id)
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.terminate_instances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        instance = self.get_instance(instance_id)
        nis = instance.get('NetworkInterfaces', [])
        self.assertEqual(1, len(nis))
        self.assertTrue(nis[0]['Attachment']['DeleteOnTermination'])
        ni_id = nis[0]['NetworkInterfaceId']

        kwargs = {
            'SubnetId': self.subnet_id,
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id2 = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.delete_network_interface,
                                NetworkInterfaceId=ni_id2)
        self.get_network_interface_waiter().wait_available(ni_id2)
        kwargs = {
            'DeviceIndex': 2,
            'InstanceId': instance_id,
            'NetworkInterfaceId': ni_id2
        }
        data = self.client.attach_network_interface(*[], **kwargs)
        attachment_id = data['AttachmentId']

        kwargs = {
            'NetworkInterfaceId': ni_id2,
            'Attachment': {
                'AttachmentId': attachment_id,
                'DeleteOnTermination': True,
            }
        }
        data = self.client.modify_network_interface_attribute(*[], **kwargs)

        data = self.client.terminate_instances(InstanceIds=[instance_id])
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        self.get_network_interface_waiter().wait_delete(ni_id)
        self.get_network_interface_waiter().wait_delete(ni_id2)
