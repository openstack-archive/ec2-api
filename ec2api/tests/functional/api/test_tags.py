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

from tempest.lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class TagTest(base.EC2TestCase):

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(TagTest, cls).setUpClass()

        cls.zone = CONF.aws.aws_zone
        data = cls.client.create_volume(
            Size=1, AvailabilityZone=cls.zone)
        cls.volume_id = data['VolumeId']
        cls.addResourceCleanUpStatic(cls.client.delete_volume,
                                     VolumeId=cls.volume_id)
        cls.get_volume_waiter().wait_available(cls.volume_id)

    def test_create_get_delete_tag(self):
        tag_key = data_utils.rand_name('tag-key')
        self.client.create_tags(Resources=[self.volume_id],
            Tags=[{'Key': tag_key, 'Value': 'fake_value'}])
        self.addResourceCleanUp(self.client.delete_tags,
                                Resources=[self.volume_id],
                                Tags=[{'Key': tag_key}])

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]}])
        self.assertEqual(1, len(data['Tags']))

        self.client.delete_tags(Resources=[self.volume_id],
                                Tags=[{'Key': tag_key}])

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]}])
        self.assertEqual(0, len(data['Tags']))

    def test_describe_tags(self):
        tag_key = data_utils.rand_name('tag-key')
        self.client.create_tags(Resources=[self.volume_id],
            Tags=[{'Key': tag_key, 'Value': 'fake_value'}])
        self.addResourceCleanUp(self.client.delete_tags,
                                Resources=[self.volume_id],
                                Tags=[{'Key': tag_key}])

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]}])
        self.assertEqual(1, len(data['Tags']))
        tag = data['Tags'][0]
        self.assertEqual('volume', tag.get('ResourceType'))
        self.assertEqual(self.volume_id, tag.get('ResourceId'))
        self.assertEqual(tag_key, tag.get('Key'))
        self.assertEqual('fake_value', tag.get('Value'))

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]},
                     {'Name': 'key', 'Values': [tag_key]}])
        self.assertEqual(1, len(data['Tags']))

        data = self.client.describe_tags(
            Filters=[{'Name': 'key', 'Values': [tag_key]}])
        self.assertIn(tag_key, [k.get('Key') for k in data['Tags']])

        data = self.client.describe_tags(
            Filters=[{'Name': 'value', 'Values': ['fake_value']}])
        self.assertIn('fake_value', [k.get('Value') for k in data['Tags']])

        data = self.client.describe_tags(
            Filters=[{'Name': 'key', 'Values': ['fake_value']}])
        items = [k.get('Key') for k in data['Tags']]
        self.assertNotIn(tag_key, items)
        self.assertNotIn('fake_value', items)

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-type', 'Values': ['volume']}])
        self.assertIn(tag_key, [k.get('Key') for k in data['Tags']])

        self.client.delete_tags(Resources=[self.volume_id],
                                Tags=[{'Key': tag_key}])

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [self.volume_id]}])
        self.assertEqual(0, len(data['Tags']))

    def _test_tag_resource(self, resource_id, res_type, describe_func):
        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        origin_count = len(data['Tags'])

        tag_key = data_utils.rand_name('tag-key')
        data = self.client.create_tags(Resources=[resource_id],
            Tags=[{'Key': tag_key, 'Value': 'fake_value'}])
        self.addResourceCleanUp(self.client.delete_tags,
                                Resources=[resource_id],
                                Tags=[{'Key': tag_key}])

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        self.assertEqual(origin_count + 1, len(data['Tags']))

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-type', 'Values': [res_type]}])
        self.assertIn(tag_key, [k.get('Key') for k in data['Tags']])

        describe_func(Filters=[{'Name': 'tag-key', 'Values': [tag_key]}])

        self.client.delete_tags(Resources=[resource_id],
                                Tags=[{'Key': tag_key}])

        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        self.assertEqual(origin_count, len(data['Tags']))

    def _test_tag_resource_negative(self, resource_id):
        data = self.client.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
        self.assertEmpty(data['Tags'])

        def _rollback(fn_data):
            self.client.delete_tags(Resources=[resource_id],
                                    Tags=[{'Key': tag_key}])

        tag_key = data_utils.rand_name('tag-key')
        self.assertRaises('InvalidID',
                          self.client.create_tags, rollback_fn=_rollback,
                          Resources=[resource_id],
                          Tags=[{'Key': tag_key, 'Value': 'fake_value'}])

    def test_tag_image(self):
        image_id = CONF.aws.ebs_image_id
        if not image_id:
            image_id = CONF.aws.image_id
        if not image_id:
            raise self.skipException('aws or ebs image_id does not provided')

        def describe_func(*args, **kwargs):
            data = self.client.describe_images(*args, **kwargs)
            self.assertEqual(1, len(data['Images']))
            self.assertEqual(image_id, data['Images'][0]['ImageId'])

        self._test_tag_resource(image_id, 'image', describe_func)

        data = self.client.describe_images(ImageIds=[image_id])
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
        data = self.client.create_dhcp_options(*[], **kwargs)
        options = data['DhcpOptions']
        res_id = options['DhcpOptionsId']
        res_clean = self.addResourceCleanUp(self.client.delete_dhcp_options,
                                            DhcpOptionsId=res_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_dhcp_options(*args, **kwargs)
            self.assertEqual(1, len(data['DhcpOptions']))
            self.assertEqual(res_id, data['DhcpOptions'][0]['DhcpOptionsId'])

        self._test_tag_resource(res_id, 'dhcp-options', describe_func)

        self.client.delete_dhcp_options(DhcpOptionsId=res_id)
        self.cancelResourceCleanUp(res_clean)

    def test_tag_volume(self):
        def describe_func(*args, **kwargs):
            data = self.client.describe_volumes(*args, **kwargs)
            self.assertEqual(1, len(data['Volumes']))
            self.assertEqual(self.volume_id, data['Volumes'][0]['VolumeId'])

        self._test_tag_resource(self.volume_id, 'volume', describe_func)

    @base.skip_without_vpc()
    def test_tag_address(self):
        kwargs = {
            'Domain': 'vpc',
        }
        data = self.client.allocate_address(*[], **kwargs)
        res_id = data['AllocationId']
        res_clean = self.addResourceCleanUp(self.client.release_address,
                                            AllocationId=res_id)
        self.assertEqual('vpc', data['Domain'])

        self._test_tag_resource_negative(res_id)

        self.client.release_address(AllocationId=res_id)
        self.cancelResourceCleanUp(res_clean)

    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_tag_instance(self):
        instance_id = self.run_instance()

        def describe_func(*args, **kwargs):
            data = self.client.describe_instances(*args, **kwargs)
            self.assertEqual(1, len(data['Reservations']))
            self.assertEqual(1, len(data['Reservations'][0]['Instances']))
            self.assertEqual(instance_id,
                data['Reservations'][0]['Instances'][0]['InstanceId'])

        self._test_tag_resource(instance_id, 'instance', describe_func)

        self.client.terminate_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_delete(instance_id)

    @base.skip_without_vpc()
    def test_tag_internet_gateway(self):
        data = self.client.create_internet_gateway()
        gw_id = data['InternetGateway']['InternetGatewayId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_internet_gateway, InternetGatewayId=gw_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_internet_gateways(*args, **kwargs)
            self.assertEqual(1, len(data['InternetGateways']))
            self.assertEqual(gw_id,
                             data['InternetGateways'][0]['InternetGatewayId'])

        self._test_tag_resource(gw_id, 'internet-gateway', describe_func)

        self.client.delete_internet_gateway(InternetGatewayId=gw_id)
        self.cancelResourceCleanUp(res_clean)

    @base.skip_without_vpc()
    def test_tag_network_interface(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(
            self.client.delete_vpc, VpcId=vpc_id)

        cidr = '10.1.0.0/24'
        data = self.client.create_subnet(VpcId=vpc_id,
                                        CidrBlock=cidr)
        subnet_id = data['Subnet']['SubnetId']
        subnet_clean = self.addResourceCleanUp(self.client.delete_subnet,
                                               SubnetId=subnet_id)

        data = self.client.create_network_interface(SubnetId=subnet_id,
            Description=data_utils.rand_name('ni'))
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean = self.addResourceCleanUp(
            self.client.delete_network_interface, NetworkInterfaceId=ni_id)
        self.get_network_interface_waiter().wait_available(ni_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_network_interfaces(*args, **kwargs)
            self.assertEqual(1, len(data['NetworkInterfaces']))
            self.assertEqual(ni_id,
                data['NetworkInterfaces'][0]['NetworkInterfaceId'])

        self._test_tag_resource(ni_id, 'network-interface', describe_func)

        self.client.delete_network_interface(NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_network_interface_waiter().wait_delete(ni_id)

        self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(subnet_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @base.skip_without_vpc()
    def test_tag_route_table(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(
            self.client.delete_vpc, VpcId=vpc_id)

        data = self.client.create_route_table(VpcId=vpc_id)
        rt_id = data['RouteTable']['RouteTableId']
        res_clean = self.addResourceCleanUp(self.client.delete_route_table,
                                            RouteTableId=rt_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_route_tables(*args, **kwargs)
            self.assertEqual(1, len(data['RouteTables']))
            self.assertEqual(rt_id, data['RouteTables'][0]['RouteTableId'])

        self._test_tag_resource(rt_id, 'route-table', describe_func)

        self.client.delete_route_table(RouteTableId=rt_id)
        self.cancelResourceCleanUp(res_clean)

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @base.skip_without_vpc()
    def test_tag_security_group(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(
            self.client.delete_vpc, VpcId=vpc_id)

        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        data = self.client.create_security_group(VpcId=vpc_id,
                                                 GroupName=name,
                                                 Description=desc)
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.delete_security_group,
                                            GroupId=group_id)
        time.sleep(2)

        def describe_func(*args, **kwargs):
            data = self.client.describe_security_groups(*args, **kwargs)
            self.assertEqual(1, len(data['SecurityGroups']))
            self.assertEqual(group_id,
                             data['SecurityGroups'][0]['GroupId'])

        self._test_tag_resource(group_id, 'security-group', describe_func)

        self.client.delete_security_group(GroupId=group_id)
        self.cancelResourceCleanUp(res_clean)

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    def test_tag_snapshot(self):
        data = self.client.create_snapshot(VolumeId=self.volume_id)
        snapshot_id = data['SnapshotId']
        res_clean = self.addResourceCleanUp(self.client.delete_snapshot,
                                            SnapshotId=snapshot_id)
        self.get_snapshot_waiter().wait_available(snapshot_id,
                                                  final_set=('completed'))

        def describe_func(*args, **kwargs):
            data = self.client.describe_snapshots(*args, **kwargs)
            self.assertEqual(1, len(data['Snapshots']))
            self.assertEqual(snapshot_id, data['Snapshots'][0]['SnapshotId'])

        self._test_tag_resource(snapshot_id, 'snapshot', describe_func)

        self.client.delete_snapshot(SnapshotId=snapshot_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_snapshot_waiter().wait_delete(snapshot_id)

    @base.skip_without_vpc()
    def test_tag_subnet(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(
            self.client.delete_vpc, VpcId=vpc_id)

        cidr = '10.1.0.0/24'
        data = self.client.create_subnet(VpcId=vpc_id,
                                        CidrBlock=cidr)
        subnet_id = data['Subnet']['SubnetId']
        res_clean = self.addResourceCleanUp(self.client.delete_subnet,
                                            SubnetId=subnet_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_subnets(*args, **kwargs)
            self.assertEqual(1, len(data['Subnets']))
            self.assertEqual(subnet_id, data['Subnets'][0]['SubnetId'])

        self._test_tag_resource(subnet_id, 'subnet', describe_func)

        self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(res_clean)
        self.get_subnet_waiter().wait_delete(subnet_id)

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @base.skip_without_vpc()
    def test_tag_vpc(self):
        cidr = '10.1.0.0/16'
        data = self.client.create_vpc(CidrBlock=cidr)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(
            self.client.delete_vpc, VpcId=vpc_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_vpcs(*args, **kwargs)
            self.assertEqual(1, len(data['Vpcs']))
            self.assertEqual(vpc_id, data['Vpcs'][0]['VpcId'])

        self._test_tag_resource(vpc_id, 'vpc', describe_func)

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

    @base.skip_without_vpc()
    def test_tag_customer_gateway(self):
        data = self.client.create_customer_gateway(
            Type='ipsec.1', PublicIp='198.51.100.77', BgpAsn=65000)
        cgw_id = data['CustomerGateway']['CustomerGatewayId']
        self.addResourceCleanUp(self.client.delete_customer_gateway,
                                CustomerGatewayId=cgw_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_customer_gateways(*args, **kwargs)
            self.assertEqual(1, len(data['CustomerGateways']))
            self.assertEqual(cgw_id,
                             data['CustomerGateways'][0]['CustomerGatewayId'])

        self._test_tag_resource(cgw_id, 'customer-gateway', describe_func)

    @base.skip_without_vpc()
    def test_tag_vpn_gateway(self):
        data = self.client.create_vpn_gateway(Type='ipsec.1')
        vgw_id = data['VpnGateway']['VpnGatewayId']
        self.addResourceCleanUp(self.client.delete_vpn_gateway,
                                VpnGatewayId=vgw_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_vpn_gateways(*args, **kwargs)
            self.assertEqual(1, len(data['VpnGateways']))
            self.assertEqual(vgw_id,
                             data['VpnGateways'][0]['VpnGatewayId'])

        self._test_tag_resource(vgw_id, 'vpn-gateway', describe_func)

    @base.skip_without_vpc()
    def test_tag_vpn_connection(self):
        data = self.client.create_customer_gateway(
            Type='ipsec.1', PublicIp='198.51.100.77', BgpAsn=65000)
        cgw_id = data['CustomerGateway']['CustomerGatewayId']
        self.addResourceCleanUp(self.client.delete_customer_gateway,
                                CustomerGatewayId=cgw_id)

        data = self.client.create_vpn_gateway(Type='ipsec.1')
        vgw_id = data['VpnGateway']['VpnGatewayId']
        self.addResourceCleanUp(self.client.delete_vpn_gateway,
                                VpnGatewayId=vgw_id)

        data = self.client.create_vpn_connection(
            CustomerGatewayId=cgw_id, VpnGatewayId=vgw_id,
            Options={'StaticRoutesOnly': True}, Type='ipsec.1')
        vpn_id = data['VpnConnection']['VpnConnectionId']
        vpn_clean = self.addResourceCleanUp(self.client.delete_vpn_connection,
                                            VpnConnectionId=vpn_id)

        def describe_func(*args, **kwargs):
            data = self.client.describe_vpn_connections(*args, **kwargs)
            self.assertEqual(1, len(data['VpnConnections']))
            self.assertEqual(vpn_id,
                             data['VpnConnections'][0]['VpnConnectionId'])

        self._test_tag_resource(vpn_id, 'vpn-connection', describe_func)

        self.client.delete_vpn_connection(VpnConnectionId=vpn_id)
        vpn_waiter = self.get_vpn_connection_waiter()
        self.cancelResourceCleanUp(vpn_clean)
        vpn_waiter.wait_delete(vpn_id)
