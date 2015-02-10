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

from tempest_lib.openstack.common import log
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class AddressTest(base.EC2TestCase):

    @testtools.skipUnless(CONF.aws.run_incompatible_tests, "VPC is disabled")
    def test_create_delete_vpc_address(self):
        kwargs = {
            'Domain': 'vpc',
        }
        resp, data = self.client.AllocateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        id = data['AllocationId']
        res_clean = self.addResourceCleanUp(self.client.ReleaseAddress,
                                            AllocationId=id)
        self.assertEqual('vpc', data['Domain'])

        resp, data = self.client.ReleaseAddress(AllocationId=id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_create_delete_standard_address(self):
        resp, data = self.client.AllocateAddress()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ip = data['PublicIp']
        res_clean = self.addResourceCleanUp(self.client.ReleaseAddress,
                                            PublicIp=ip)

        resp, data = self.client.ReleaseAddress(PublicIp=ip)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests, "VPC is disabled")
    def test_invalid_delete_vpc_address(self):
        kwargs = {
            'Domain': 'vpc',
        }
        resp, data = self.client.AllocateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ip = data['PublicIp']
        id = data['AllocationId']
        res_clean = self.addResourceCleanUp(self.client.ReleaseAddress,
                                            AllocationId=id)
        self.assertEqual('vpc', data['Domain'])

        resp, data = self.client.ReleaseAddress(PublicIp=ip, AllocationId=id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterCombination', data['Error']['Code'])

        resp, data = self.client.ReleaseAddress(PublicIp=ip)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        resp, data = self.client.ReleaseAddress(AllocationId=id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        if CONF.aws.run_incompatible_tests:
            resp, data = self.client.ReleaseAddress(PublicIp=ip)
            self.assertEqual(400, resp.status_code)
            self.assertEqual('AuthFailure', data['Error']['Code'])

        resp, data = self.client.ReleaseAddress(AllocationId=id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidAllocationID.NotFound', data['Error']['Code'])

        kwargs = {
            "AllocationId": 'eipalloc-00000000',
        }
        resp, data = self.client.ReleaseAddress(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidAllocationID.NotFound', data['Error']['Code'])

        if CONF.aws.run_incompatible_tests:
            resp, data = self.client.ReleaseAddress(PublicIp='ip')
            self.assertEqual(400, resp.status_code)
            self.assertEqual('InvalidParameterValue', data['Error']['Code'])

    def test_invalid_create_address(self):
        kwargs = {
            'Domain': 'invalid',
        }
        resp, data = self.client.AllocateAddress(*[], **kwargs)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.ReleaseAddress,
                                    AllocationId=data['AllocationId'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

    @testtools.skipUnless(CONF.aws.run_incompatible_tests, "VPC is disabled")
    def test_describe_vpc_addresses(self):
        resp, data = self.client.DescribeAddresses(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        start_count = len(data['Addresses'])

        kwargs = {
            'Domain': 'vpc',
        }
        resp, data = self.client.AllocateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ip = data['PublicIp']
        id = data['AllocationId']
        res_clean = self.addResourceCleanUp(self.client.ReleaseAddress,
                                            AllocationId=id)

        resp, data = self.client.DescribeAddresses(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(start_count + 1, len(data['Addresses']))
        for address in data['Addresses']:
            if address['AllocationId'] == id:
                self.assertEqual('vpc', address['Domain'])
                self.assertEqual(ip, address['PublicIp'])
                break
        else:
            self.fail('Created address could not be found')

        kwargs = {
            'PublicIps': [ip],
        }
        resp, data = self.client.DescribeAddresses(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Addresses']))
        self.assertEqual(id, data['Addresses'][0]['AllocationId'])

        kwargs = {
            'AllocationIds': [id],
        }
        resp, data = self.client.DescribeAddresses(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Addresses']))
        self.assertEqual(ip, data['Addresses'][0]['PublicIp'])

        kwargs = {
            'PublicIps': ['invalidIp'],
        }
        resp, data = self.client.DescribeAddresses(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        kwargs = {
            'AllocationIds': ['eipalloc-00000000'],
        }
        resp, data = self.client.DescribeAddresses(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidAllocationID.NotFound', data['Error']['Code'])

        kwargs = {
            'Domain': 'vpc',
        }
        resp, data = self.client.AllocateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        id2 = data['AllocationId']
        res_clean2 = self.addResourceCleanUp(self.client.ReleaseAddress,
                                             AllocationId=id2)

        kwargs = {
            'PublicIps': [ip],
            'AllocationIds': [id2],
        }
        resp, data = self.client.DescribeAddresses(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(2, len(data['Addresses']))

        # NOTE(andrey-mp): wait abit before releasing
        time.sleep(3)

        resp, data = self.client.ReleaseAddress(AllocationId=id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.ReleaseAddress(AllocationId=id2)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean2)

    def test_describe_standard_addresses(self):
        resp, data = self.client.DescribeAddresses(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        start_count = len(data['Addresses'])

        resp, data = self.client.AllocateAddress(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ip = data['PublicIp']
        res_clean = self.addResourceCleanUp(self.client.ReleaseAddress,
                                            PublicIp=ip)

        resp, data = self.client.DescribeAddresses(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(start_count + 1, len(data['Addresses']))
        for address in data['Addresses']:
            if address['PublicIp'] == ip:
                self.assertEqual('standard', address['Domain'])
                break
        else:
            self.fail('Created address could not be found')

        kwargs = {
            'PublicIps': [ip],
        }
        resp, data = self.client.DescribeAddresses(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Addresses']))
        self.assertEqual(ip, data['Addresses'][0]['PublicIp'])

        kwargs = {
            'PublicIps': ['invalidIp'],
        }
        resp, data = self.client.DescribeAddresses(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        # NOTE(andrey-mp): wait abit before releasing
        time.sleep(3)

        resp, data = self.client.ReleaseAddress(PublicIp=ip)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests, "VPC is disabled")
    def test_associate_disassociate_vpc_addresses(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        aws_zone = CONF.aws.aws_zone
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        resp, data = self.client.CreateVpc(CidrBlock='10.2.0.0/20')
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        cidr = '10.2.0.0/24'
        resp, data = self.client.CreateSubnet(VpcId=vpc_id, CidrBlock=cidr,
                                              AvailabilityZone=aws_zone)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        self.addResourceCleanUp(self.client.DeleteSubnet,
                                SubnetId=subnet_id)

        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type, MinCount=1,
            MaxCount=1, SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        self.addResourceCleanUp(self.client.TerminateInstances,
                                InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        kwargs = {
            'Domain': 'vpc',
        }
        resp, data = self.client.AllocateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        alloc_id = data['AllocationId']
        self.addResourceCleanUp(self.client.ReleaseAddress,
                                AllocationId=alloc_id)

        resp, data = self.client.AssociateAddress(InstanceId=instance_id,
                                                  AllocationId=alloc_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('Gateway.NotAttached', data['Error']['Code'])

        # Create internet gateway and try to associate again
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                InternetGatewayId=gw_id)
        resp, data = self.client.AttachInternetGateway(VpcId=vpc_id,
                                                       InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DetachInternetGateway,
                                VpcId=vpc_id,
                                InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.AssociateAddress(InstanceId=instance_id,
                                                  AllocationId=alloc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        association_id = data['AssociationId']

        resp, data = self.client.DescribeAddresses(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(instance_id, data['Addresses'][0]['InstanceId'])

        kwargs = {
            "AssociationId": association_id,
        }
        resp, data = self.client.DisassociateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DescribeAddresses(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIsNone(data['Addresses'][0].get('InstanceId'))

    def test_associate_disassociate_standard_addresses(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws image_id does not provided')

        resp, data = self.client.RunInstances(ImageId=image_id,
                                              InstanceType=instance_type,
                                              MinCount=1,
                                              MaxCount=1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        self.addResourceCleanUp(self.client.TerminateInstances,
                                InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.AllocateAddress(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ip = data['PublicIp']
        self.addResourceCleanUp(self.client.ReleaseAddress,
                                PublicIp=ip)

        resp, data = self.client.AssociateAddress(InstanceId=instance_id,
                                                  PublicIp=ip)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DescribeAddresses(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(instance_id, data['Addresses'][0]['InstanceId'])

        resp, data = self.client.DisassociateAddress(PublicIp=ip)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DescribeAddresses(*[], **{})
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIsNone(data['Addresses'][0].get('InstanceId'))
