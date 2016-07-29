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
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class AddressTest(base.EC2TestCase):

    @base.skip_without_vpc()
    def test_create_delete_vpc_address(self):
        kwargs = {
            'Domain': 'vpc',
        }
        data = self.client.allocate_address(*[], **kwargs)
        id = data['AllocationId']
        res_clean = self.addResourceCleanUp(self.client.release_address,
                                            AllocationId=id)
        self.assertEqual('vpc', data['Domain'])

        data = self.client.release_address(AllocationId=id)
        self.cancelResourceCleanUp(res_clean)

    @base.skip_without_ec2()
    def test_create_delete_standard_address(self):
        data = self.client.allocate_address()
        ip = data['PublicIp']
        res_clean = self.addResourceCleanUp(self.client.release_address,
                                            PublicIp=ip)

        data = self.client.release_address(PublicIp=ip)
        self.cancelResourceCleanUp(res_clean)

    @base.skip_without_vpc()
    def test_invalid_delete_vpc_address(self):
        kwargs = {
            'Domain': 'vpc',
        }
        data = self.client.allocate_address(*[], **kwargs)
        ip = data['PublicIp']
        id = data['AllocationId']
        res_clean = self.addResourceCleanUp(self.client.release_address,
                                            AllocationId=id)
        self.assertEqual('vpc', data['Domain'])

        self.assertRaises('InvalidParameterCombination',
            self.client.release_address,
            PublicIp=ip, AllocationId=id)

        self.assertRaises('InvalidParameterValue',
            self.client.release_address,
            PublicIp=ip)

        data = self.client.release_address(AllocationId=id)
        self.cancelResourceCleanUp(res_clean)

        if CONF.aws.run_incompatible_tests:
            self.assertRaises('AuthFailure',
                self.client.release_address,
                PublicIp=ip)

        self.assertRaises('InvalidAllocationID.NotFound',
            self.client.release_address,
            AllocationId=id)

        kwargs = {
            "AllocationId": 'eipalloc-00000000',
        }
        self.assertRaises('InvalidAllocationID.NotFound',
            self.client.release_address,
            **kwargs)

        if CONF.aws.run_incompatible_tests:
            self.assertRaises('InvalidParameterValue',
                self.client.release_address,
                PublicIp='ip')

    def test_invalid_create_address(self):
        kwargs = {
            'Domain': 'invalid',
        }
        try:
            data = self.client.allocate_address(*[], **kwargs)
            allocation_id = data.get('AllocationId')
            if allocation_id:
                self.client.release_address(AllocationId=allocation_id)
            else:
                public_ip = data.get('PublicIp')
                self.client.release_address(PublicIp=public_ip)
        except botocore.exceptions.ClientError as e:
            self.assertEqual('InvalidParameterValue',
                             e.response['Error']['Code'])

    @base.skip_without_vpc()
    def test_describe_vpc_addresses(self):
        kwargs = {
            'Domain': 'vpc',
        }
        data = self.client.allocate_address(*[], **kwargs)
        ip = data['PublicIp']
        id = data['AllocationId']
        res_clean = self.addResourceCleanUp(self.client.release_address,
                                            AllocationId=id)

        data = self.client.describe_addresses(*[], **{})
        for address in data['Addresses']:
            if address.get('AllocationId') == id:
                self.assertEqual('vpc', address['Domain'])
                self.assertEqual(ip, address['PublicIp'])
                break
        else:
            self.fail('Created address could not be found')

        kwargs = {
            'PublicIps': [ip],
        }
        data = self.client.describe_addresses(*[], **kwargs)
        self.assertEqual(1, len(data['Addresses']))
        self.assertEqual(id, data['Addresses'][0]['AllocationId'])

        kwargs = {
            'AllocationIds': [id],
        }
        data = self.client.describe_addresses(*[], **kwargs)
        self.assertEqual(1, len(data['Addresses']))
        self.assertEqual(ip, data['Addresses'][0]['PublicIp'])

        kwargs = {
            'PublicIps': ['invalidIp'],
        }
        self.assertRaises('InvalidParameterValue',
            self.client.describe_addresses,
            **kwargs)

        kwargs = {
            'AllocationIds': ['eipalloc-00000000'],
        }
        self.assertRaises('InvalidAllocationID.NotFound',
            self.client.describe_addresses,
            **kwargs)

        kwargs = {
            'Domain': 'vpc',
        }
        data = self.client.allocate_address(*[], **kwargs)
        id2 = data['AllocationId']
        res_clean2 = self.addResourceCleanUp(self.client.release_address,
                                             AllocationId=id2)

        kwargs = {
            'PublicIps': [ip],
            'AllocationIds': [id2],
        }
        data = self.client.describe_addresses(*[], **kwargs)
        self.assertEqual(2, len(data['Addresses']))

        # NOTE(andrey-mp): wait abit before releasing
        time.sleep(3)

        self.client.release_address(AllocationId=id)
        self.cancelResourceCleanUp(res_clean)

        self.client.release_address(AllocationId=id2)
        self.cancelResourceCleanUp(res_clean2)

    @base.skip_without_ec2()
    def test_describe_standard_addresses(self):
        data = self.client.allocate_address(*[], **{})
        ip = data['PublicIp']
        res_clean = self.addResourceCleanUp(self.client.release_address,
                                            PublicIp=ip)

        data = self.client.describe_addresses(*[], **{})
        for address in data['Addresses']:
            if address['PublicIp'] == ip:
                self.assertEqual('standard', address['Domain'])
                break
        else:
            self.fail('Created address could not be found')

        kwargs = {
            'PublicIps': [ip],
        }
        data = self.client.describe_addresses(*[], **kwargs)
        self.assertEqual(1, len(data['Addresses']))
        self.assertEqual(ip, data['Addresses'][0]['PublicIp'])

        kwargs = {
            'PublicIps': ['invalidIp'],
        }
        self.assertRaises('InvalidParameterValue',
            self.client.describe_addresses,
            PublicIps=['invalidIp'])

        # NOTE(andrey-mp): wait abit before releasing
        time.sleep(3)

        self.client.release_address(PublicIp=ip)
        self.cancelResourceCleanUp(res_clean)

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_associate_disassociate_vpc_addresses(self):
        aws_zone = CONF.aws.aws_zone

        base_net = '10.3.0.0'
        data = self.client.create_vpc(CidrBlock=base_net + '/20')
        vpc_id = data['Vpc']['VpcId']
        clean_vpc = self.addResourceCleanUp(self.client.delete_vpc,
                                            VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        cidr = base_net + '/24'
        data = self.client.create_subnet(VpcId=vpc_id, CidrBlock=cidr,
                                         AvailabilityZone=aws_zone)
        subnet_id = data['Subnet']['SubnetId']
        clean_subnet = self.addResourceCleanUp(self.client.delete_subnet,
                                               SubnetId=subnet_id)

        instance_id = self.run_instance(SubnetId=subnet_id)

        data = self.client.allocate_address(Domain='vpc')
        alloc_id = data['AllocationId']
        clean_a = self.addResourceCleanUp(self.client.release_address,
                                          AllocationId=alloc_id)

        self.assertRaises('Gateway.NotAttached',
            self.client.associate_address,
            InstanceId=instance_id, AllocationId=alloc_id)

        # Create internet gateway and try to associate again
        data = self.client.create_internet_gateway()
        gw_id = data['InternetGateway']['InternetGatewayId']
        clean_ig = self.addResourceCleanUp(self.client.delete_internet_gateway,
                                           InternetGatewayId=gw_id)
        data = self.client.attach_internet_gateway(VpcId=vpc_id,
                                                   InternetGatewayId=gw_id)
        clean_aig = self.addResourceCleanUp(
            self.client.detach_internet_gateway,
            VpcId=vpc_id,
            InternetGatewayId=gw_id)

        self.prepare_route(vpc_id, gw_id)

        data = self.client.associate_address(InstanceId=instance_id,
                                             AllocationId=alloc_id)
        assoc_id = data['AssociationId']
        clean_aa = self.addResourceCleanUp(self.client.disassociate_address,
                                           AssociationId=assoc_id)
        self.get_address_assoc_waiter().wait_available(
            {'AllocationId': alloc_id})

        kwargs = {
            'AllocationIds': [alloc_id],
        }
        data = self.client.describe_addresses(*[], **kwargs)
        self.assertEqual(instance_id, data['Addresses'][0]['InstanceId'])

        data = self.client.disassociate_address(AssociationId=assoc_id)
        self.cancelResourceCleanUp(clean_aa)
        self.get_address_assoc_waiter().wait_delete({'AllocationId': alloc_id})

        # NOTE(andrey-mp): cleanup
        time.sleep(3)

        self.client.detach_internet_gateway(VpcId=vpc_id,
                                            InternetGatewayId=gw_id)
        self.cancelResourceCleanUp(clean_aig)

        self.client.delete_internet_gateway(InternetGatewayId=gw_id)
        self.cancelResourceCleanUp(clean_ig)

        self.client.release_address(AllocationId=alloc_id)
        self.cancelResourceCleanUp(clean_a)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

        self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(clean_vpc)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    # skip this test for nova network due to bug #1607350
    @base.skip_without_vpc()
    # this is a correct skip
    @base.skip_without_ec2()
    def test_associate_disassociate_standard_addresses(self):
        instance_id = self.run_instance()

        data = self.client.allocate_address(*[], **{})
        ip = data['PublicIp']
        clean_a = self.addResourceCleanUp(self.client.release_address,
                                          PublicIp=ip)

        data = self.client.associate_address(InstanceId=instance_id,
                                             PublicIp=ip)
        clean_aa = self.addResourceCleanUp(self.client.disassociate_address,
                                           PublicIp=ip)
        self.get_address_assoc_waiter().wait_available({'PublicIp': ip})

        kwargs = {
            'PublicIps': [ip],
        }
        data = self.client.describe_addresses(*[], **kwargs)
        self.assertEqual(instance_id, data['Addresses'][0]['InstanceId'])

        data = self.client.disassociate_address(PublicIp=ip)
        self.cancelResourceCleanUp(clean_aa)
        self.get_address_assoc_waiter().wait_delete({'PublicIp': ip})

        time.sleep(3)

        data = self.client.release_address(PublicIp=ip)
        self.cancelResourceCleanUp(clean_a)

        data = self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @base.skip_without_vpc()
    def test_disassociate_not_associated_vpc_addresses(self):
        aws_zone = CONF.aws.aws_zone

        base_net = '10.3.0.0'
        data = self.client.create_vpc(CidrBlock=base_net + '/20')
        vpc_id = data['Vpc']['VpcId']
        clean_vpc = self.addResourceCleanUp(self.client.delete_vpc,
                                            VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        cidr = base_net + '/24'
        data = self.client.create_subnet(VpcId=vpc_id, CidrBlock=cidr,
                                              AvailabilityZone=aws_zone)
        subnet_id = data['Subnet']['SubnetId']
        clean_subnet = self.addResourceCleanUp(self.client.delete_subnet,
                                               SubnetId=subnet_id)

        data = self.client.allocate_address(Domain='vpc')
        alloc_id = data['AllocationId']
        ip = data['PublicIp']
        clean_a = self.addResourceCleanUp(self.client.release_address,
                                          AllocationId=alloc_id)

        assoc_id = 'eipassoc-00000001'
        self.assertRaises('InvalidAssociationID.NotFound',
            self.client.disassociate_address,
            AssociationId=assoc_id)

        self.assertRaises('InvalidParameterValue',
            self.client.disassociate_address,
            PublicIp=ip)

        self.client.release_address(AllocationId=alloc_id)
        self.cancelResourceCleanUp(clean_a)

        self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(clean_vpc)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @base.skip_without_ec2()
    def test_disassociate_not_associated_standard_addresses(self):
        data = self.client.allocate_address(Domain='standard')
        ip = data['PublicIp']
        clean_a = self.addResourceCleanUp(self.client.release_address,
                                          PublicIp=ip)

        data = self.client.disassociate_address(PublicIp=ip)

        data = self.client.release_address(PublicIp=ip)
        self.cancelResourceCleanUp(clean_a)

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          'preliminary address association is not supported')
    def test_preliminary_associate_address(self):
        # NOTE(ft): AWS can associate an address to a subnet IP if the subnet
        # has no internet access
        vpc_id, subnet_id = self.create_vpc_and_subnet('10.3.0.0/20')
        self.create_and_attach_internet_gateway(vpc_id)
        data = self.client.allocate_address(Domain='vpc')
        alloc_id = data['AllocationId']
        self.addResourceCleanUp(self.client.release_address,
                                AllocationId=alloc_id)

        data = self.client.create_network_interface(SubnetId=subnet_id)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.delete_network_interface,
                                NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        data = self.client.associate_address(
            AllocationId=alloc_id, NetworkInterfaceId=ni_id)
        assoc_id = data['AssociationId']
        self.addResourceCleanUp(self.client.disassociate_address,
                                AssociationId=assoc_id)
