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
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
import testtools

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

    @decorators.idempotent_id('d03f49b1-a77e-439b-96e2-5e152b968863')
    def test_delete_subnet_with_network_interface(self):
        data = self.client.create_subnet(VpcId=self.vpc_id,
                                              CidrBlock='10.7.1.0/28')
        subnet_id = data['Subnet']['SubnetId']
        res_clean_subnet = self.addResourceCleanUp(self.client.delete_subnet,
                                                   SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        data = self.client.create_network_interface(SubnetId=subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean_ni = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)
        time.sleep(2)

        self.assertRaises('DependencyViolation',
                          self.client.delete_subnet,
                          SubnetId=subnet_id)

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean_ni)
        self.get_network_interface_waiter().wait_delete(ni_id)

        self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(res_clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

    @decorators.idempotent_id('e19e450d-5c24-47b1-9814-4a65a78e5a31')
    def test_create_network_interface(self):
        desc = data_utils.rand_name('ni')
        data = self.client.create_network_interface(SubnetId=self.subnet_id,
                                                    Description=desc)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        ni = data['NetworkInterface']
        self.assertEqual(self.vpc_id, ni['VpcId'])
        self.assertEqual(self.subnet_id, ni['SubnetId'])
        self.assertEqual(desc, ni['Description'])

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

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

        self.assertRaises('InvalidNetworkInterfaceID.NotFound',
                          self.client.describe_network_interfaces,
                          NetworkInterfaceIds=[ni_id])

    # TODO(andrey-mp): add creation with addresses

    @decorators.idempotent_id('61e16648-7736-4647-b618-27d3f4f0c9c6')
    def test_create_max_network_interface(self):
        # NOTE(andrey-mp): wait some time while all ports will be deleted
        # for this subnet(that are deleting after previous test)
        time.sleep(5)

        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count_before = data['Subnets'][0]['AvailableIpAddressCount']
        addresses = []
        while True:
            try:
                data = self.client.create_network_interface(
                    SubnetId=self.subnet_id)
            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                self.assertEqual('InsufficientFreeAddressesInSubnet',
                                 error_code, e.message)
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
            self.client.delete_network_interface(NetworkInterfaceId=addr[0])
            self.cancelResourceCleanUp(addr[1])
            self.get_network_interface_waiter().wait_delete(addr[0])

    @decorators.idempotent_id('8c174e5f-e377-4bf2-9315-b868a8199c17')
    def test_unassign_primary_addresses(self):
        data = self.client.create_network_interface(SubnetId=self.subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        primary_address = data['NetworkInterface'].get('PrivateIpAddress')
        self.get_network_interface_waiter().wait_available(ni_id)

        self.assertRaises('InvalidParameterValue',
                          self.client.unassign_private_ip_addresses,
                          NetworkInterfaceId=ni_id,
                          PrivateIpAddresses=[primary_address])

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    @decorators.idempotent_id('de0d0375-d99a-476c-939a-0e15c4e431a8')
    def test_assign_unassign_private_addresses_by_count(self):
        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count = data['Subnets'][0]['AvailableIpAddressCount']
        data = self.client.create_network_interface(SubnetId=self.subnet_id)
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

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    @decorators.idempotent_id('5d7bda42-d23e-4cbf-9e66-8ca052ac28ff')
    def test_assign_unassign_private_addresses_by_addresses(self):
        data = self.client.describe_subnets(SubnetIds=[self.subnet_id])
        count = data['Subnets'][0]['AvailableIpAddressCount']
        data = self.client.create_network_interface(SubnetId=self.subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        ni = self.client.describe_network_interfaces(
            NetworkInterfaceIds=[ni_id])['NetworkInterfaces']
        ni_addr = ni[0]['PrivateIpAddresses'][0]['PrivateIpAddress']

        # add two more addresses to interface.
        # check that they does not equal to current.
        addresses = []
        for i in range(10, 13):
            addr = '10.7.0.%d' % i
            if addr != ni_addr:
                addresses.append(addr)
            if len(addresses) >= 2:
                break
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

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    @decorators.idempotent_id('0c514bb4-5800-4db0-9032-0aa3ab998612')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_attach_network_interface(self):
        data = self.client.create_network_interface(SubnetId=self.subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.delete_network_interface,
                                NetworkInterfaceId=ni_id)
        ni = data['NetworkInterface']
        address = ni.get('PrivateIpAddress')
        self.assertIsNotNone(address)
        self.get_network_interface_waiter().wait_available(ni_id)

        instance_id = self.run_instance(SubnetId=self.subnet_id)

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

        self.client.detach_network_interface(AttachmentId=attachment_id)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @decorators.idempotent_id('381c9995-bc83-4e7e-b716-25a451660ace')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_network_interfaces_are_not_deleted_on_termination(self):
        instance_id = self.run_instance(SubnetId=self.subnet_id)

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
        self.client.modify_network_interface_attribute(*[], **kwargs)
        clean_ni = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)

        data = self.client.create_network_interface(SubnetId=self.subnet_id)
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

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

        self.get_network_interface_waiter().wait_available(ni_id)
        self.get_network_interface_waiter().wait_available(ni_id2)

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(clean_ni)
        self.get_network_interface_waiter().wait_delete(ni_id)

        self.client.delete_network_interface(NetworkInterfaceId=ni_id2)
        self.cancelResourceCleanUp(clean_ni2)
        self.get_network_interface_waiter().wait_delete(ni_id2)

    @decorators.idempotent_id('de910bc7-008a-40c2-b4b2-4587a489fc1c')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_network_interfaces_are_deleted_on_termination(self):
        instance_id = self.run_instance(SubnetId=self.subnet_id)

        instance = self.get_instance(instance_id)
        nis = instance.get('NetworkInterfaces', [])
        self.assertEqual(1, len(nis))
        self.assertTrue(nis[0]['Attachment']['DeleteOnTermination'])
        ni_id = nis[0]['NetworkInterfaceId']

        data = self.client.create_network_interface(SubnetId=self.subnet_id)
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
        self.client.modify_network_interface_attribute(*[], **kwargs)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

        self.get_network_interface_waiter().wait_delete(ni_id)
        self.get_network_interface_waiter().wait_delete(ni_id2)

    @decorators.idempotent_id('028eb864-59e9-4ed6-a062-9d5de9eba652')
    def test_network_interface_attribute_description(self):
        desc = data_utils.rand_name('ni')
        data = self.client.create_network_interface(
            SubnetId=self.subnet_id, Description=desc)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id, Attribute='description')
        self.assertEqual(desc, data['Description']['Value'])

        new_desc = data_utils.rand_name('new-ni')
        self.client.modify_network_interface_attribute(
            NetworkInterfaceId=ni_id, Description={'Value': new_desc})

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id, Attribute='description')
        self.assertEqual(new_desc, data['Description']['Value'])

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    @decorators.idempotent_id('9428b5e6-42f2-495f-a535-df53d1fcf4af')
    def test_network_interface_attribute_source_dest_check(self):
        data = self.client.create_network_interface(SubnetId=self.subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        self.client.modify_network_interface_attribute(
            NetworkInterfaceId=ni_id, SourceDestCheck={'Value': False})

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id, Attribute='sourceDestCheck')
        self.assertFalse(data['SourceDestCheck']['Value'])

        # NOTE(andrey-mp): ResetNetworkInterfaceAttribute had inadequate json
        # scheme in botocore and doesn't work against Amazon.

        self.client.modify_network_interface_attribute(
            NetworkInterfaceId=ni_id, SourceDestCheck={'Value': True})

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id, Attribute='sourceDestCheck')
        self.assertEqual(True, data['SourceDestCheck']['Value'])

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    @decorators.idempotent_id('19d25f59-5b32-4314-b4da-7c8f679b7a96')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_network_interface_attribute_attachment(self):
        instance_id = self.run_instance(SubnetId=self.subnet_id)

        instance = self.get_instance(instance_id)
        nis = instance.get('NetworkInterfaces', [])
        self.assertEqual(1, len(nis))
        self.assertTrue(nis[0]['Attachment']['DeleteOnTermination'])
        ni_id = nis[0]['NetworkInterfaceId']

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id, Attribute='attachment')
        self.assertIn('Attachment', data)
        self.assertTrue(data['Attachment'].get('AttachmentId'))
        self.assertTrue(data['Attachment'].get('DeleteOnTermination'))
        self.assertEqual(0, data['Attachment'].get('DeviceIndex'))
        self.assertEqual(instance_id, data['Attachment'].get('InstanceId'))
        self.assertEqual('attached', data['Attachment'].get('Status'))

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @decorators.idempotent_id('74967cd0-155f-4cfe-994e-2c6803dad04c')
    def test_network_interface_attribute_empty_attachment(self):
        data = self.client.create_network_interface(SubnetId=self.subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id, Attribute='attachment')
        self.assertNotIn('Attachment', data)

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    @decorators.idempotent_id('a55f1169-d302-4166-b74e-e84a0d79129c')
    def test_network_interface_attribute_group_set(self):
        data = self.client.create_network_interface(SubnetId=self.subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        data = self.client.describe_network_interface_attribute(
            NetworkInterfaceId=ni_id, Attribute='groupSet')
        self.assertIn('Groups', data)
        self.assertEqual(1, len(data['Groups']))
        self.assertEqual('default', data['Groups'][0]['GroupName'])

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

    @decorators.idempotent_id('7832976f-27cb-405e-ab05-466b102d86f8')
    def test_instance_attributes_negative(self):
        data = self.client.create_network_interface(SubnetId=self.subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        self.assertRaises('InvalidParameterCombination',
            self.client.describe_network_interface_attribute,
            NetworkInterfaceId=ni_id)
        self.assertRaises('InvalidParameterValue',
            self.client.describe_network_interface_attribute,
            NetworkInterfaceId=ni_id, Attribute='fake')
        self.assertRaises('InvalidNetworkInterfaceID.NotFound',
            self.client.describe_network_interface_attribute,
            NetworkInterfaceId='eni-0', Attribute='description')

        self.assertRaises('InvalidParameterCombination',
            self.client.modify_network_interface_attribute,
            NetworkInterfaceId=ni_id)
        self.assertRaises('MissingParameter',
            self.client.modify_network_interface_attribute,
            NetworkInterfaceId=ni_id,
            Attachment={'AttachmentId': 'fake'})
        self.assertRaises('InvalidAttachmentID.NotFound',
            self.client.modify_network_interface_attribute,
            NetworkInterfaceId=ni_id,
            Attachment={'AttachmentId': 'eni-attach-0',
                        'DeleteOnTermination': True})
        self.assertRaises('InvalidGroup.NotFound',
            self.client.modify_network_interface_attribute,
            NetworkInterfaceId=ni_id, Groups=['sg-0'])
        self.assertRaises('InvalidParameterCombination',
            self.client.modify_network_interface_attribute,
            NetworkInterfaceId=ni_id, Description={})

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)
