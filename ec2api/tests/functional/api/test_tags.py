# Copyright 2015 OpenStack Foundation
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

from tempest_lib.common.utils import data_utils

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class TagTest(base.EC2TestCase):

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(TagTest, cls).setUpClass()

        cls.zone = CONF.aws.aws_zone
        resp, data = cls.client.CreateVolume(
            Size=1, AvailabilityZone=cls.zone)
        cls.assertResultStatic(resp, data)
        cls.volume_id = data['VolumeId']
        cls.addResourceCleanUpStatic(cls.client.DeleteVolume,
                                     VolumeId=cls.volume_id)
        cls.get_volume_waiter().wait_available(cls.volume_id)

    def test_create_get_delete_tag(self):
        tag_key = data_utils.rand_name('tag-key')
        resp, data = self.client.CreateTags(Resources=[self.volume_id],
            Tags=[{'Key': tag_key, 'Value': 'fake_value'}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DeleteTags,
                                Resources=[self.volume_id],
                                Tags=[{'Key': tag_key}])

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Tags']))

        resp, data = self.client.DeleteTags(Resources=[self.volume_id],
                                            Tags=[{'Key': tag_key}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Tags']))

    def test_describe_tags(self):
        tag_key = data_utils.rand_name('tag-key')
        resp, data = self.client.CreateTags(Resources=[self.volume_id],
            Tags=[{'Key': tag_key, 'Value': 'fake_value'}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DeleteTags,
                                Resources=[self.volume_id],
                                Tags=[{'Key': tag_key}])

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Tags']))
        tag = data['Tags'][0]
        self.assertEqual('volume', tag.get('ResourceType'))
        self.assertEqual(self.volume_id, tag.get('ResourceId'))
        self.assertEqual(tag_key, tag.get('Key'))
        self.assertEqual('fake_value', tag.get('Value'))

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]},
                     {'Name': 'key', 'Values': [tag_key]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['Tags']))

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'key', 'Values': [tag_key]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn(tag_key, [k.get('Key') for k in data['Tags']])

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'value', 'Values': ['fake_value']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn('fake_value', [k.get('Value') for k in data['Tags']])

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'key', 'Values': ['fake_value']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        items = [k.get('Key') for k in data['Tags']]
        self.assertNotIn(tag_key, items)
        self.assertNotIn('fake_value', items)

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-type', 'Values': ['volume']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn(tag_key, [k.get('Key') for k in data['Tags']])

        resp, data = self.client.DeleteTags(Resources=[self.volume_id],
                                            Tags=[{'Key': tag_key}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['Tags']))

    def _test_tag_resource(self, resource_id, res_type, describe_func):
        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        origin_count = len(data['Tags'])

        tag_key = data_utils.rand_name('tag-key')
        resp, data = self.client.CreateTags(Resources=[resource_id],
            Tags=[{'Key': tag_key, 'Value': 'fake_value'}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.addResourceCleanUp(self.client.DeleteTags,
                                Resources=[resource_id],
                                Tags=[{'Key': tag_key}])

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(origin_count + 1, len(data['Tags']))

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-type', 'Values': [res_type]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertIn(tag_key, [k.get('Key') for k in data['Tags']])

        describe_func(Filters=[{'Name': 'tag-key', 'Values': [tag_key]}])

        resp, data = self.client.DeleteTags(Resources=[resource_id],
                                            Tags=[{'Key': tag_key}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(origin_count, len(data['Tags']))

    def _test_tag_resource_negative(self, resource_id):
        resp, data = self.client.DescribeTags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEmpty(data['Tags'])

        tag_key = data_utils.rand_name('tag-key')
        resp, data = self.client.CreateTags(Resources=[resource_id],
            Tags=[{'Key': tag_key, 'Value': 'fake_value'}])
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteTags,
                                    Resources=[resource_id],
                                    Tags=[{'Key': tag_key}])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidID', data['Error']['Code'])

    def test_tag_image(self):
        image_id = CONF.aws.ebs_image_id
        if not image_id:
            image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws or ebs image_id does not provided')

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeImages(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['Images']))
            self.assertEqual(image_id, data['Images'][0]['ImageId'])

        self._test_tag_resource(image_id, 'image', describe_func)

        resp, data = self.client.DescribeImages(ImageIds=[image_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        image = data['Images'][0]
        if 'KernelId' in image:
            image_id = image['KernelId']
            self._test_tag_resource(image_id, 'image', describe_func)
        if 'RamdiskId' in image:
            image_id = image['RamdiskId']
            self._test_tag_resource(image_id, 'image', describe_func)

    @base.skip_without_vpc()
    def test_tag_dhcp_options(self):
        kwargs = {
            'DhcpConfigurations': [
                {'Key': 'domain-name',
                 'Values': ['my.com']},
            ],
        }
        resp, data = self.client.CreateDhcpOptions(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        options = data['DhcpOptions']
        res_id = options['DhcpOptionsId']
        res_clean = self.addResourceCleanUp(self.client.DeleteDhcpOptions,
                                            DhcpOptionsId=res_id)

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeDhcpOptions(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['DhcpOptions']))
            self.assertEqual(res_id, data['DhcpOptions'][0]['DhcpOptionsId'])

        self._test_tag_resource(res_id, 'dhcp-options', describe_func)

        resp, data = self.client.DeleteDhcpOptions(DhcpOptionsId=res_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_tag_volume(self):
        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeVolumes(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['Volumes']))
            self.assertEqual(self.volume_id, data['Volumes'][0]['VolumeId'])

        self._test_tag_resource(self.volume_id, 'volume', describe_func)

    @base.skip_without_vpc()
    def test_tag_address(self):
        kwargs = {
            'Domain': 'vpc',
        }
        resp, data = self.client.AllocateAddress(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        res_id = data['AllocationId']
        res_clean = self.addResourceCleanUp(self.client.ReleaseAddress,
                                            AllocationId=res_id)
        self.assertEqual('vpc', data['Domain'])

        self._test_tag_resource_negative(res_id)

        resp, data = self.client.ReleaseAddress(AllocationId=res_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_tag_instance(self):
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

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeInstances(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['Reservations']))
            self.assertEqual(1, len(data['Reservations'][0]['Instances']))
            self.assertEqual(instance_id,
                data['Reservations'][0]['Instances'][0]['InstanceId'])

        self._test_tag_resource(instance_id, 'instance', describe_func)

        resp, data = self.client.TerminateInstances(InstanceIds=[instance_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_instance_waiter().wait_delete(instance_id)

    @base.skip_without_vpc()
    def test_tag_internet_gateway(self):
        resp, data = self.client.CreateInternetGateway()
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        gw_id = data['InternetGateway']['InternetGatewayId']
        res_clean = self.addResourceCleanUp(self.client.DeleteInternetGateway,
                                            InternetGatewayId=gw_id)

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeInternetGateways(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['InternetGateways']))
            self.assertEqual(gw_id,
                             data['InternetGateways'][0]['InternetGatewayId'])

        self._test_tag_resource(gw_id, 'internet-gateway', describe_func)

        resp, data = self.client.DeleteInternetGateway(InternetGatewayId=gw_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    @base.skip_without_vpc()
    def test_tag_network_interface(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)

        cidr = '10.1.0.0/24'
        resp, data = self.client.CreateSubnet(VpcId=vpc_id,
                                              CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        subnet_clean = self.addResourceCleanUp(self.client.DeleteSubnet,
                                               SubnetId=subnet_id)

        resp, data = self.client.CreateNetworkInterface(SubnetId=subnet_id,
            Description=data_utils.rand_name('ni'))
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(self.client.DeleteNetworkInterface,
                                            NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeNetworkInterfaces(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['NetworkInterfaces']))
            self.assertEqual(ni_id,
                data['NetworkInterfaces'][0]['NetworkInterfaceId'])

        self._test_tag_resource(ni_id, 'network-interface', describe_func)

        resp, data = self.client.DeleteNetworkInterface(
            NetworkInterfaceId=ni_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(subnet_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @base.skip_without_vpc()
    def test_tag_route_table(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)

        resp, data = self.client.CreateRouteTable(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        rt_id = data['RouteTable']['RouteTableId']
        res_clean = self.addResourceCleanUp(self.client.DeleteRouteTable,
                                            RouteTableId=rt_id)

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeRouteTables(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['RouteTables']))
            self.assertEqual(rt_id, data['RouteTables'][0]['RouteTableId'])

        self._test_tag_resource(rt_id, 'route-table', describe_func)

        resp, data = self.client.DeleteRouteTable(RouteTableId=rt_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @base.skip_without_vpc()
    def test_tag_security_group(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)

        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        resp, data = self.client.CreateSecurityGroup(VpcId=vpc_id,
                                                     GroupName=name,
                                                     Description=desc)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSecurityGroup,
                                            GroupId=group_id)
        time.sleep(2)

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeSecurityGroups(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['SecurityGroups']))
            self.assertEqual(group_id,
                             data['SecurityGroups'][0]['GroupId'])

        self._test_tag_resource(group_id, 'security-group', describe_func)

        resp, data = self.client.DeleteSecurityGroup(GroupId=group_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    def test_tag_snapshot(self):
        resp, data = self.client.CreateSnapshot(VolumeId=self.volume_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        snapshot_id = data['SnapshotId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSnapshot,
                                            SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeSnapshots(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['Snapshots']))
            self.assertEqual(snapshot_id, data['Snapshots'][0]['SnapshotId'])

        self._test_tag_resource(snapshot_id, 'snapshot', describe_func)

        resp, data = self.client.DeleteSnapshot(SnapshotId=snapshot_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_snapshot_waiter().wait_delete(snapshot_id)

    @base.skip_without_vpc()
    def test_tag_subnet(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)

        cidr = '10.1.0.0/24'
        resp, data = self.client.CreateSubnet(VpcId=vpc_id,
                                              CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean = self.addResourceCleanUp(self.client.DeleteSubnet,
                                            SubnetId=subnet_id)

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeSubnets(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['Subnets']))
            self.assertEqual(subnet_id, data['Subnets'][0]['SubnetId'])

        self._test_tag_resource(subnet_id, 'subnet', describe_func)

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @base.skip_without_vpc()
    def test_tag_vpc(self):
        cidr = '10.1.0.0/16'
        resp, data = self.client.CreateVpc(CidrBlock=cidr)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.DeleteVpc, VpcId=vpc_id)

        def describe_func(*args, **kwargs):
            resp, data = self.client.DescribeVpcs(*args, **kwargs)
            self.assertEqual(200, resp.status_code,
                             base.EC2ErrorConverter(data))
            self.assertEqual(1, len(data['Vpcs']))
            self.assertEqual(vpc_id, data['Vpcs'][0]['VpcId'])

        self._test_tag_resource(vpc_id, 'vpc', describe_func)

        resp, data = self.client.DeleteVpc(VpcId=vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)
