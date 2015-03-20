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

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class VpcAddressTest(base.EC2TestCase):

    @base.skip_without_vpc()
    def test_auto_diassociate_address(self):
        image_id = CONF.aws.image_id
        aws_zone = CONF.aws.aws_zone
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        base_net = '10.3.0.0'
        resp, data = self.client.CreateVpc(CidrBlock=base_net + '/20')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        clean_vpc = self.addResourceCleanUp(self.client.DeleteVpc,
                                            VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        cidr = base_net + '/24'
        resp, data = self.client.CreateSubnet(VpcId=vpc_id, CidrBlock=cidr,
                                              AvailabilityZone=aws_zone)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        clean_subnet = self.addResourceCleanUp(self.client.DeleteSubnet,
                                               SubnetId=subnet_id)

        resp, data = self.client.CreateNetworkInterface(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ni_id1 = data['NetworkInterface']['NetworkInterfaceId']
        clean_ni1 = self.addResourceCleanUp(self.client.DeleteNetworkInterface,
                                            NetworkInterfaceId=ni_id1)
        self.get_network_interface_waiter().wait_available(ni_id1)

        resp, data = self.client.CreateNetworkInterface(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ni_id2 = data['NetworkInterface']['NetworkInterfaceId']
        clean_ni2 = self.addResourceCleanUp(self.client.DeleteNetworkInterface,
                                            NetworkInterfaceId=ni_id2)
        self.get_network_interface_waiter().wait_available(ni_id2)

        kwargs = {
            'ImageId': CONF.aws.image_id,
            'InstanceType': CONF.aws.instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'NetworkInterfaces': [
                {'NetworkInterfaceId': ni_id1, 'DeviceIndex': 0}]
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        clean_i = self.addResourceCleanUp(self.client.TerminateInstances,
                                          InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))
        resp, data = self.client.AttachNetworkInterface(DeviceIndex=1,
            InstanceId=instance_id, NetworkInterfaceId=ni_id2)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        attachment_id = data['AttachmentId']

        resp, data = self.client.AllocateAddress(Domain='vpc')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        alloc_id1 = data['AllocationId']
        public_ip1 = data['PublicIp']
        clean_a1 = self.addResourceCleanUp(self.client.ReleaseAddress,
                                           AllocationId=alloc_id1)
        resp, data = self.client.AllocateAddress(Domain='vpc')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        alloc_id2 = data['AllocationId']
        clean_a2 = self.addResourceCleanUp(self.client.ReleaseAddress,
                                           AllocationId=alloc_id2)

        # Create internet gateway
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        clean_ig = self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                           InternetGatewayId=gw_id)
        resp, data = self.client.AttachInternetGateway(VpcId=vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        clean_aig = self.addResourceCleanUp(self.client.DetachInternetGateway,
                                            VpcId=vpc_id,
                                            InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        # There are multiple interfaces attached to instance 'i-5310c5af'.
        # Please specify an interface ID for the operation instead.
        resp, data = self.client.AssociateAddress(InstanceId=instance_id,
                                                  AllocationId=alloc_id1)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidInstanceID', data['Error']['Code'])

        # The networkInterface ID 'eni-ffffffff' does not exist
        resp, data = self.client.AssociateAddress(
            AllocationId=alloc_id1, NetworkInterfaceId='eni-ffffffff')
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidNetworkInterfaceID.NotFound',
                         data['Error']['Code'])

        # NOTE(andrey-mp): Amazon needs only network interface if several
        # present in instance. Error will be there if instance is passed.
        resp, data = self.client.AssociateAddress(
            AllocationId=alloc_id1, NetworkInterfaceId=ni_id1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        assoc_id1 = data['AssociationId']
        clean_aa1 = self.addResourceCleanUp(self.client.DisassociateAddress,
                                           AssociationId=assoc_id1)

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

        resp, data = self.client.DescribeNetworkInterfaces(
            NetworkInterfaceIds=[ni_id1, ni_id2])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(2, len(data['NetworkInterfaces']))
        self.assertEqual('in-use', data['NetworkInterfaces'][0]['Status'])
        self.assertEqual('in-use', data['NetworkInterfaces'][1]['Status'])

        # NOTE(andrery-mp): associate second address and set delete on
        # termination to True for interface
        resp, data = self.client.AssociateAddress(
            AllocationId=alloc_id2, NetworkInterfaceId=ni_id2)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        assoc_id2 = data['AssociationId']
        clean_aa2 = self.addResourceCleanUp(self.client.DisassociateAddress,
                                            AssociationId=assoc_id2)

        kwargs = {
            'NetworkInterfaceId': ni_id2,
            'Attachment': {
                'AttachmentId': attachment_id,
                'DeleteOnTermination': True,
            }
        }
        resp, data = self.client.ModifyNetworkInterfaceAttribute(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        # NOTE(andrey-mp): cleanup
        time.sleep(3)

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_i)
        self.get_instance_waiter().wait_delete(instance_id)

        resp, data = self.client.DescribeNetworkInterfaces(
            NetworkInterfaceIds=[ni_id2])
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidNetworkInterfaceID.NotFound',
                         data['Error']['Code'])
        self.cancelResourceCleanUp(clean_ni2)
        self.cancelResourceCleanUp(clean_aa2)

        resp, data = self.client.DescribeNetworkInterfaces(
            NetworkInterfaceIds=[ni_id1])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['NetworkInterfaces']))
        self.assertEqual('available', data['NetworkInterfaces'][0]['Status'])
        ni = data['NetworkInterfaces'][0]
        self.assertIsNotNone(ni.get('Association'))
        self.assertEqual(public_ip1, ni['Association']['PublicIp'])

        resp, data = self.client.DescribeAddresses(AllocationIds=[alloc_id1,
                                                                  alloc_id2])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        for address in data['Addresses']:
            if address['AllocationId'] == alloc_id1:
                self.assertIsNotNone(address.get('AssociationId'))
            elif address['AllocationId'] == alloc_id2:
                self.assertIsNone(address.get('AssociationId'))

        resp, data = self.client.DisassociateAddress(AssociationId=assoc_id1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_aa1)

        resp, data = self.client.DetachInternetGateway(VpcId=vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_aig)

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_ig)

        resp, data = self.client.ReleaseAddress(AllocationId=alloc_id1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_a1)
        resp, data = self.client.ReleaseAddress(AllocationId=alloc_id2)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_a2)

        resp, data = self.client.DeleteNetworkInterface(
            NetworkInterfaceId=ni_id1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_ni1)
        self.get_network_interface_waiter().wait_delete(ni_id1)

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_vpc)
        self.get_vpc_waiter().wait_delete(vpc_id)
