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

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF
LOG = log.getLogger(__name__)


class RouteTest(base.EC2TestCase):

    VPC_CIDR = '10.14.0.0/20'
    SUBNET_CIDR = '10.14.0.0/24'
    vpc_id = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(RouteTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

        resp, data = cls.client.CreateVpc(CidrBlock=cls.VPC_CIDR)
        cls.assertResultStatic(resp, data)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.addResourceCleanUpStatic(cls.client.DeleteVpc, VpcId=cls.vpc_id)
        cls.get_vpc_waiter().wait_available(cls.vpc_id)

    def test_create_delete_route_table(self):
        resp, data = self.client.CreateRouteTable(VpcId=self.vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        rt_id = data['RouteTable']['RouteTableId']
        res_clean = self.addResourceCleanUp(self.client.DeleteRouteTable,
                                            RouteTableId=rt_id)
        rt = data['RouteTable']
        self.assertEqual(self.vpc_id, rt['VpcId'])
        self.assertEqual(1, len(rt['Routes']))
        route = rt['Routes'][0]
        self.assertEqual(self.VPC_CIDR, route['DestinationCidrBlock'])
        self.assertEqual('active', route['State'])

        resp, data = self.client.DeleteRouteTable(RouteTableId=rt_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.DescribeRouteTables(RouteTableIds=[rt_id])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidRouteTableID.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteRouteTable(RouteTableId=rt_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidRouteTableID.NotFound', data['Error']['Code'])

    def test_describe_route_tables_base(self):
        resp, data = self.client.CreateRouteTable(VpcId=self.vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        rt_id = data['RouteTable']['RouteTableId']
        res_clean = self.addResourceCleanUp(self.client.DeleteRouteTable,
                                            RouteTableId=rt_id)

        # NOTE(andrey-mp): by real id
        resp, data = self.client.DescribeRouteTables(RouteTableIds=[rt_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['RouteTables']))

        # NOTE(andrey-mp): by fake id
        resp, data = self.client.DescribeRouteTables(RouteTableIds=['rtb-0'])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidRouteTableID.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteRouteTable(RouteTableId=rt_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_describe_route_tables_filters(self):
        resp, data = self.client.CreateRouteTable(VpcId=self.vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        rt_id = data['RouteTable']['RouteTableId']
        self.addResourceCleanUp(self.client.DeleteRouteTable,
                                RouteTableId=rt_id)

        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=self.SUBNET_CIDR)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        self.addResourceCleanUp(self.client.DeleteSubnet,
                                SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        resp, data = self.client.AssociateRouteTable(RouteTableId=rt_id,
                                                     SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        assoc_id = data['AssociationId']
        self.addResourceCleanUp(self.client.DisassociateRouteTable,
                                AssociationId=assoc_id)

        # NOTE(andrey-mp): by association_id
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'association.route-table-association-id',
                      'Values': [assoc_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['RouteTables']))

        # NOTE(andrey-mp): by route table id
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'association.route-table-id',
                      'Values': [rt_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['RouteTables']))

        # NOTE(andrey-mp): by subnet id
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'association.subnet-id',
                      'Values': [subnet_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['RouteTables']))

        # NOTE(andrey-mp): by filter real vpc
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertLess(0, len(data['RouteTables']))

        # NOTE(andrey-mp): by filter fake vpc
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'vpc-id', 'Values': ['vpc-0']}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(0, len(data['RouteTables']))

        # NOTE(andrey-mp): by fake filter
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'fake', 'Values': ['fake']}])
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

    def test_associate_disassociate_route_table(self):
        resp, data = self.client.CreateRouteTable(VpcId=self.vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        rt_id = data['RouteTable']['RouteTableId']
        res_clean_rt = self.addResourceCleanUp(self.client.DeleteRouteTable,
                                               RouteTableId=rt_id)

        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=self.SUBNET_CIDR)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean_subnet = self.addResourceCleanUp(self.client.DeleteSubnet,
                                                   SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        resp, data = self.client.AssociateRouteTable(RouteTableId=rt_id,
                                                     SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        assoc_id = data['AssociationId']
        res_clean = self.addResourceCleanUp(self.client.DisassociateRouteTable,
                                            AssociationId=assoc_id)

        resp, data = self.client.DisassociateRouteTable(AssociationId=assoc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

        resp, data = self.client.DeleteRouteTable(RouteTableId=rt_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_rt)

    def test_replace_route_table(self):
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=self.SUBNET_CIDR)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean_subnet = self.addResourceCleanUp(self.client.DeleteSubnet,
                                                   SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        # NOTE(andrey-mp): by vpc id
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['RouteTables']))
        self.assertEqual(1, len(data['RouteTables'][0]['Associations']))
        default_rt_id = data['RouteTables'][0]['RouteTableId']
        main_assoc = data['RouteTables'][0]['Associations'][0]
        self.assertTrue(main_assoc['Main'])
        main_assoc_id = main_assoc['RouteTableAssociationId']

        resp, data = self.client.CreateRouteTable(VpcId=self.vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        rt_id = data['RouteTable']['RouteTableId']
        res_clean_rt = self.addResourceCleanUp(self.client.DeleteRouteTable,
                                               RouteTableId=rt_id)

        resp, data = self.client.ReplaceRouteTableAssociation(
            RouteTableId=rt_id, AssociationId=main_assoc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        assoc_id = data['NewAssociationId']
        res_clean = self.addResourceCleanUp(
            self.client.ReplaceRouteTableAssociation,
            RouteTableId=default_rt_id,
            AssociationId=assoc_id)

        # NOTE(andrey-mp): by vpc id
        resp, data = self.client.DescribeRouteTables(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc_id]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(2, len(data['RouteTables']))
        for rt in data['RouteTables']:
            if rt['RouteTableId'] == rt_id:
                self.assertEqual(1, len(rt['Associations']))
                self.assertTrue(rt['Associations'][0]['Main'])
            else:
                self.assertEmpty(rt.get('Associations', []))

        resp, data = self.client.DeleteRouteTable(RouteTableId=rt_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('DependencyViolation', data['Error']['Code'])

        resp, data = self.client.DisassociateRouteTable(AssociationId=assoc_id)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        resp, data = self.client.ReplaceRouteTableAssociation(
            RouteTableId=default_rt_id,
            AssociationId=assoc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.DeleteRouteTable(RouteTableId=rt_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_rt)

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

    def test_create_delete_route(self):
        resp, data = self.client.CreateSubnet(VpcId=self.vpc_id,
                                              CidrBlock=self.SUBNET_CIDR)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        subnet_id = data['Subnet']['SubnetId']
        res_clean_subnet = self.addResourceCleanUp(self.client.DeleteSubnet,
                                                   SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        kwargs = {
            'SubnetId': subnet_id,
        }
        resp, data = self.client.CreateNetworkInterface(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean_ni = self.addResourceCleanUp(
            self.client.DeleteNetworkInterface,
            NetworkInterfaceId=ni_id)

        resp, data = self.client.CreateRouteTable(VpcId=self.vpc_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        rt_id = data['RouteTable']['RouteTableId']
        res_clean_rt = self.addResourceCleanUp(self.client.DeleteRouteTable,
                                               RouteTableId=rt_id)

        kwargs = {
            'DestinationCidrBlock': self.VPC_CIDR,
            'RouteTableId': rt_id,
            'NetworkInterfaceId': ni_id
        }
        resp, data = self.client.CreateRoute(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        # can create wider route
        kwargs = {
            'DestinationCidrBlock': '10.14.0.0/19',
            'RouteTableId': rt_id,
            'NetworkInterfaceId': ni_id
        }
        resp, data = self.client.CreateRoute(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        # can create to another vpc
        kwargs = {
            'DestinationCidrBlock': '10.15.0.0/20',
            'RouteTableId': rt_id,
            'NetworkInterfaceId': ni_id
        }
        resp, data = self.client.CreateRoute(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DescribeRouteTables(RouteTableIds=[rt_id])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data['RouteTables']))
        self.assertEqual(3, len(data['RouteTables'][0]['Routes']))

        kwargs = {
            'DestinationCidrBlock': '10.15.0.0/24',
            'RouteTableId': rt_id,
        }
        resp, data = self.client.DeleteRoute(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidRoute.NotFound', data['Error']['Code'])

        kwargs = {
            'DestinationCidrBlock': self.VPC_CIDR,
            'RouteTableId': rt_id,
        }
        resp, data = self.client.DeleteRoute(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidParameterValue', data['Error']['Code'])

        kwargs = {
            'DestinationCidrBlock': self.SUBNET_CIDR,
            'RouteTableId': rt_id,
        }
        resp, data = self.client.DeleteRoute(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidRoute.NotFound', data['Error']['Code'])

        kwargs = {
            'DestinationCidrBlock': '10.16.0.0/24',
            'RouteTableId': rt_id,
        }
        resp, data = self.client.DeleteRoute(*[], **kwargs)
        self.assertEqual(400, resp.status_code)
        self.assertEqual('InvalidRoute.NotFound', data['Error']['Code'])

        kwargs = {
            'DestinationCidrBlock': '10.15.0.0/20',
            'RouteTableId': rt_id,
        }
        resp, data = self.client.DeleteRoute(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        kwargs = {
            'DestinationCidrBlock': '10.14.0.0/19',
            'RouteTableId': rt_id,
        }
        resp, data = self.client.DeleteRoute(*[], **kwargs)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

        resp, data = self.client.DeleteRouteTable(RouteTableId=rt_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_rt)

        resp, data = self.client.DeleteNetworkInterface(
            NetworkInterfaceId=ni_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_ni)
        self.get_network_interface_waiter().wait_delete(ni_id)

        resp, data = self.client.DeleteSubnet(SubnetId=subnet_id)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)
