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
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class InstanceInVPCTest(base.EC2TestCase):

    VPC_CIDR = '10.16.0.0/20'
    vpc_id = None
    SUBNET_CIDR = '10.16.0.0/24'
    subnet_id = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(InstanceInVPCTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')
        if not CONF.aws.image_id:
            raise cls.skipException('aws image_id does not provided')

        resp, data = cls.client.CreateVpc(CidrBlock=cls.VPC_CIDR)
        cls.assertResultStatic(resp, data)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.addResourceCleanUpStatic(cls.client.DeleteVpc, VpcId=cls.vpc_id)
        cls.get_vpc_waiter().wait_available(cls.vpc_id)

        aws_zone = CONF.aws.aws_zone
        resp, data = cls.client.CreateSubnet(VpcId=cls.vpc_id,
                                             CidrBlock=cls.SUBNET_CIDR,
                                             AvailabilityZone=aws_zone)
        cls.assertResultStatic(resp, data)
        cls.subnet_id = data['Subnet']['SubnetId']
        cls.addResourceCleanUpStatic(cls.client.DeleteSubnet,
                                     SubnetId=cls.subnet_id)
        cls.get_subnet_waiter().wait_available(cls.subnet_id)

    def test_create_delete_instance(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id

        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type, MinCount=1,
            MaxCount=1, SubnetId=self.subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.DescribeInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        reservations = data.get('Reservations', [])
        self.assertNotEmpty(reservations)
        instances = reservations[0].get('Instances', [])
        self.assertNotEmpty(instances)
        instance = instances[0]
        self.assertEqual(self.vpc_id, instance['VpcId'])
        self.assertEqual(self.subnet_id, instance['SubnetId'])
        if CONF.aws.run_incompatible_tests:
            self.assertTrue(instance['SourceDestCheck'])
        self.assertEqual(1, len(instance['NetworkInterfaces']))
        ni = instance['NetworkInterfaces'][0]
        self.assertIsNone(ni['Description'])
        self.assertEqual(1, len(ni['Groups']))
        self.assertIsNotNone(ni['MacAddress'])
        self.assertIsNotNone(ni['PrivateIpAddress'])
        self.assertTrue(ni['SourceDestCheck'])
        self.assertEqual('in-use', ni['Status'])
        self.assertEqual(self.vpc_id, ni['VpcId'])
        self.assertEqual(self.subnet_id, ni['SubnetId'])

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        # NOTE(andrey-mp): There is difference between Openstack and Amazon.
        # Amazon returns instance in 'terminated' state some time after
        # instance deletion. But Openstack doesn't return such instance.

    def test_describe_instances_filter(self):
        instance_type = CONF.aws.instance_type
        image_id = CONF.aws.image_id

        resp, data = self.client.RunInstances(
            ImageId=image_id, InstanceType=instance_type, MinCount=1,
            MaxCount=1, SubnetId=self.subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        resp, data = self.client.DescribeInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assert_instance(data, instance_id)
        instances = data['Reservations'][0]['Instances']
        private_dns = instances[0]['PrivateDnsName']
        private_ip = instances[0]['PrivateIpAddress']

        # NOTE(andrey-mp): by private ip
        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'private-ip-address', 'Values': ['1.2.3.4']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Reservations']))

        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'private-ip-address', 'Values': [private_ip]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assert_instance(data, instance_id)

        # NOTE(andrey-mp): by private dns
        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'private-dns-name', 'Values': ['fake.com']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Reservations']))

        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'private-dns-name', 'Values': [private_dns]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assert_instance(data, instance_id)

        # NOTE(andrey-mp): by subnet id
        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'subnet-id', 'Values': ['subnet-0']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Reservations']))

        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'subnet-id', 'Values': [self.subnet_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assert_instance(data, instance_id)

        # NOTE(andrey-mp): by vpc id
        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'vpc-id', 'Values': ['vpc-0']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Reservations']))

        resp, data = self.client.DescribeInstances(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assert_instance(data, instance_id)

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    def assert_instance(self, data, instance_id):
        reservations = data.get('Reservations', [])
        self.assertNotEmpty(reservations)
        instances = reservations[0].get('Instances', [])
        self.assertNotEmpty(instances)
        self.assertEqual(instance_id, instances[0]['InstanceId'])

    @testtools.skipUnless(
        CONF.aws.run_incompatible_tests,
        "Amazon can create instance with several network interfaces in"
        "one subnet. Openstack can't do it without additional configuration."
        "Worked only from Juno with parameter in config - "
        "nova.conf/neutron/allow_duplicate_networks = True")
    def test_create_instance_with_two_interfaces(self):
        kwargs = {
            'SubnetId': self.subnet_id,
        }
        resp, data = self.client.CreateNetworkInterface(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ni_id1 = data['NetworkInterface']['NetworkInterfaceId']
        clean_ni1 = self.addResourceCleanUp(self.client.DeleteNetworkInterface,
                                            NetworkInterfaceId=ni_id1)
        self.get_network_interface_waiter().wait_available(ni_id1)

        kwargs = {
            'SubnetId': self.subnet_id,
        }
        resp, data = self.client.CreateNetworkInterface(*[], **kwargs)
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
            'NetworkInterfaces': [{'NetworkInterfaceId': ni_id1,
                                   'DeviceIndex': 0},
                                  {'NetworkInterfaceId': ni_id2,
                                   'DeviceIndex': 2}]
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        instance = self.get_instance(instance_id)
        nis = instance.get('NetworkInterfaces', [])
        self.assertEqual(2, len(nis))

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

        self.get_network_interface_waiter().wait_available(ni_id1)
        self.get_network_interface_waiter().wait_available(ni_id2)

        resp, data = self.client.DeleteNetworkInterface(
            NetworkInterfaceId=ni_id2)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_ni2)
        self.get_network_interface_waiter().wait_delete(ni_id2)

        resp, data = self.client.DeleteNetworkInterface(
            NetworkInterfaceId=ni_id1)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(clean_ni1)
        self.get_network_interface_waiter().wait_delete(ni_id1)

    def test_create_instance_with_private_ip(self):
        ip = '10.16.0.12'

        kwargs = {
            'ImageId': CONF.aws.image_id,
            'InstanceType': CONF.aws.instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'SubnetId': self.subnet_id,
            'PrivateIpAddress': ip
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.TerminateInstances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        instance = self.get_instance(instance_id)
        self.assertEqual(ip, instance['PrivateIpAddress'])

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    def test_create_instance_with_invalid_params(self):
        kwargs = {
            'ImageId': CONF.aws.image_id,
            'InstanceType': CONF.aws.instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'PrivateIpAddress': '10.16.1.2'
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        if resp.status_code == 200:
            self.addResourceCleanUp(
                self.client.TerminateInstances,
                InstanceIds=[data['Instances'][0]['InstanceId']])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterCombination', data['Error']['Code'])

        kwargs = {
            'ImageId': CONF.aws.image_id,
            'InstanceType': CONF.aws.instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'SubnetId': self.subnet_id,
            'PrivateIpAddress': '10.16.1.12'
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        if resp.status_code == 200:
            self.addResourceCleanUp(
                self.client.TerminateInstances,
                InstanceIds=[data['Instances'][0]['InstanceId']])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        kwargs = {
            'SubnetId': self.subnet_id,
        }
        resp, data = self.client.CreateNetworkInterface(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ni_id1 = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.DeleteNetworkInterface,
                                NetworkInterfaceId=ni_id1)
        self.get_network_interface_waiter().wait_available(ni_id1)

        kwargs = {
            'SubnetId': self.subnet_id,
        }
        resp, data = self.client.CreateNetworkInterface(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ni_id2 = data['NetworkInterface']['NetworkInterfaceId']
        self.addResourceCleanUp(self.client.DeleteNetworkInterface,
                                NetworkInterfaceId=ni_id2)
        self.get_network_interface_waiter().wait_available(ni_id2)

        # NOTE(andrey-mp): A network interface may not specify a network
        # interface ID and delete on termination as true
        kwargs = {
            'ImageId': CONF.aws.image_id,
            'InstanceType': CONF.aws.instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'NetworkInterfaces': [{'NetworkInterfaceId': ni_id1,
                                   'DeviceIndex': 0,
                                   'DeleteOnTermination': True}]
        }
        resp, data = self.client.RunInstances(*[], **kwargs)
        if resp.status_code == 200:
            self.addResourceCleanUp(
                self.client.TerminateInstances,
                InstanceIds=[data['Instances'][0]['InstanceId']])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterCombination', data['Error']['Code'])

        if CONF.aws.run_incompatible_tests:
            # NOTE(andrey-mp): Each network interface requires a device index.
            kwargs = {
                'ImageId': CONF.aws.image_id,
                'InstanceType': CONF.aws.instance_type,
                'MinCount': 1,
                'MaxCount': 1,
                'NetworkInterfaces': [{'NetworkInterfaceId': ni_id1},
                                      {'NetworkInterfaceId': ni_id2}]
            }
            resp, data = self.client.RunInstances(*[], **kwargs)
            if resp.status_code == 200:
                self.addResourceCleanUp(
                    self.client.TerminateInstances,
                    InstanceIds=[data['Instances'][0]['InstanceId']])
            self.assertEqual(400, resp.status_code)
            self.assertEqual('InvalidParameterValue', data['Error']['Code'])
