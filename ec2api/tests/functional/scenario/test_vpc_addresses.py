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
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config
from ec2api.tests.functional.scenario import base as scenario_base

CONF = config.CONF
LOG = log.getLogger(__name__)


class VpcAddressTest(scenario_base.BaseScenarioTest):

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_auto_diassociate_address(self):
        vpc_id, subnet_id = self.create_vpc_and_subnet('10.3.0.0/20')
        ni_id1 = self.create_network_interface(subnet_id)
        gw_id = self.create_and_attach_internet_gateway(vpc_id)
        self.prepare_route(vpc_id, gw_id)
        alloc_id1, public_ip1 = self.allocate_address(True)
        alloc_id2, _ = self.allocate_address(True)

        data = self.client.create_network_interface(SubnetId=subnet_id)
        ni_id2 = data['NetworkInterface']['NetworkInterfaceId']
        clean_ni2 = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id2)
        self.get_network_interface_waiter().wait_available(ni_id2)

        kwargs = {
            'ImageId': CONF.aws.image_id,
            'InstanceType': CONF.aws.instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'NetworkInterfaces': [
                {'NetworkInterfaceId': ni_id1, 'DeviceIndex': 0}]
        }
        data = self.client.run_instances(*[], **kwargs)
        instance_id = data['Instances'][0]['InstanceId']
        clean_i = self.addResourceCleanUp(self.client.terminate_instances,
                                          InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))
        data = self.client.attach_network_interface(DeviceIndex=1,
            InstanceId=instance_id, NetworkInterfaceId=ni_id2)
        attachment_id = data['AttachmentId']

        # There are multiple interfaces attached to instance 'i-5310c5af'.
        # Please specify an interface ID for the operation instead.
        self.assertRaises('InvalidInstanceID',
            self.client.associate_address,
            InstanceId=instance_id, AllocationId=alloc_id1)

        # The networkInterface ID 'eni-ffffffff' does not exist
        self.assertRaises('InvalidNetworkInterfaceID.NotFound',
            self.client.associate_address,
            AllocationId=alloc_id1, NetworkInterfaceId='eni-ffffffff')

        # NOTE(andrey-mp): Amazon needs only network interface if several
        # present in instance. Error will be there if instance is passed.
        data = self.client.associate_address(
            AllocationId=alloc_id1, NetworkInterfaceId=ni_id1)
        assoc_id1 = data['AssociationId']
        clean_aa1 = self.addResourceCleanUp(self.client.disassociate_address,
                                            AssociationId=assoc_id1)
        self.get_address_assoc_waiter().wait_available(
            {'AllocationId': alloc_id1})

        instance = self.get_instance(instance_id)
        nis = instance.get('NetworkInterfaces', [])
        self.assertEqual(2, len(nis))
        for ni in nis:
            if ni['NetworkInterfaceId'] == ni_id1:
                self.assertIsNotNone(ni.get('Association'))
                self.assertEqual(public_ip1, ni['Association']['PublicIp'])
            elif ni['NetworkInterfaceId'] == ni_id2:
                self.assertIsNone(ni.get('Association'))
            else:
                self.assertTrue(False, 'Unknown interface found: ' + str(ni))

        data = self.client.describe_network_interfaces(
            NetworkInterfaceIds=[ni_id1, ni_id2])
        self.assertEqual(2, len(data['NetworkInterfaces']))
        self.assertEqual('in-use', data['NetworkInterfaces'][0]['Status'])
        self.assertEqual('in-use', data['NetworkInterfaces'][1]['Status'])

        # NOTE(andrery-mp): associate second address and set delete on
        # termination to True for interface
        data = self.client.associate_address(
            AllocationId=alloc_id2, NetworkInterfaceId=ni_id2)
        assoc_id2 = data['AssociationId']
        clean_aa2 = self.addResourceCleanUp(self.client.disassociate_address,
                                            AssociationId=assoc_id2)
        self.get_address_assoc_waiter().wait_available(
            {'AllocationId': alloc_id2})

        kwargs = {
            'NetworkInterfaceId': ni_id2,
            'Attachment': {
                'AttachmentId': attachment_id,
                'DeleteOnTermination': True,
            }
        }
        self.client.modify_network_interface_attribute(*[], **kwargs)

        # NOTE(andrey-mp): cleanup
        time.sleep(3)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

        self.assertRaises('InvalidNetworkInterfaceID.NotFound',
            self.client.describe_network_interfaces,
            NetworkInterfaceIds=[ni_id2])
        self.cancelResourceCleanUp(clean_ni2)
        self.cancelResourceCleanUp(clean_aa2)

        data = self.client.describe_network_interfaces(
            NetworkInterfaceIds=[ni_id1])
        self.assertEqual(1, len(data['NetworkInterfaces']))
        self.assertEqual('available', data['NetworkInterfaces'][0]['Status'])
        ni = data['NetworkInterfaces'][0]
        self.assertIsNotNone(ni.get('Association'))
        self.assertEqual(public_ip1, ni['Association']['PublicIp'])

        data = self.client.describe_addresses(AllocationIds=[alloc_id1,
                                                             alloc_id2])
        for address in data['Addresses']:
            if address['AllocationId'] == alloc_id1:
                self.assertIsNotNone(address.get('AssociationId'))
            elif address['AllocationId'] == alloc_id2:
                self.assertIsNone(address.get('AssociationId'))

        self.client.disassociate_address(AssociationId=assoc_id1)
        self.cancelResourceCleanUp(clean_aa1)
        self.get_address_assoc_waiter().wait_delete(
            {'AllocationId': alloc_id1})
