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

        data = cls.client.create_vpc(CidrBlock=cls.VPC_CIDR)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.addResourceCleanUpStatic(cls.client.delete_vpc, VpcId=cls.vpc_id)
        cls.get_vpc_waiter().wait_available(cls.vpc_id)

    def test_create_delete_route_table(self):
        data = self.client.create_route_table(VpcId=self.vpc_id)
        rt_id = data['RouteTable']['RouteTableId']
        res_clean = self.addResourceCleanUp(self.client.delete_route_table,
                                            RouteTableId=rt_id)
        rt = data['RouteTable']
        self.assertEqual(self.vpc_id, rt['VpcId'])
        self.assertEqual(1, len(rt['Routes']))
        route = rt['Routes'][0]
        self.assertEqual(self.VPC_CIDR, route['DestinationCidrBlock'])
        self.assertEqual('active', route['State'])

        data = self.client.delete_route_table(RouteTableId=rt_id)
        self.cancelResourceCleanUp(res_clean)

        self.assertRaises('InvalidRouteTableID.NotFound',
                          self.client.describe_route_tables,
                          RouteTableIds=[rt_id])

        self.assertRaises('InvalidRouteTableID.NotFound',
                          self.client.delete_route_table,
                          RouteTableId=rt_id)

    def test_describe_route_tables_base(self):
        data = self.client.create_route_table(VpcId=self.vpc_id)
        rt_id = data['RouteTable']['RouteTableId']
        res_clean = self.addResourceCleanUp(self.client.delete_route_table,
                                            RouteTableId=rt_id)

        # NOTE(andrey-mp): by real id
        data = self.client.describe_route_tables(RouteTableIds=[rt_id])
        self.assertEqual(1, len(data['RouteTables']))

        # NOTE(andrey-mp): by fake id
        self.assertRaises('InvalidRouteTableID.NotFound',
                          self.client.describe_route_tables,
                          RouteTableIds=['rtb-0'])

        data = self.client.delete_route_table(RouteTableId=rt_id)
        self.cancelResourceCleanUp(res_clean)

    def test_describe_route_tables_filters(self):
        data = self.client.create_route_table(VpcId=self.vpc_id)
        rt_id = data['RouteTable']['RouteTableId']
        self.addResourceCleanUp(self.client.delete_route_table,
                                RouteTableId=rt_id)

        data = self.client.create_subnet(VpcId=self.vpc_id,
                                              CidrBlock=self.SUBNET_CIDR)
        subnet_id = data['Subnet']['SubnetId']
        self.addResourceCleanUp(self.client.delete_subnet,
                                SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        data = self.client.associate_route_table(RouteTableId=rt_id,
                                                     SubnetId=subnet_id)
        assoc_id = data['AssociationId']
        self.addResourceCleanUp(self.client.disassociate_route_table,
                                AssociationId=assoc_id)

        # NOTE(andrey-mp): by association_id
        data = self.client.describe_route_tables(
            Filters=[{'Name': 'association.route-table-association-id',
                      'Values': [assoc_id]}])
        self.assertEqual(1, len(data['RouteTables']))

        # NOTE(andrey-mp): by route table id
        data = self.client.describe_route_tables(
            Filters=[{'Name': 'association.route-table-id',
                      'Values': [rt_id]}])
        self.assertEqual(1, len(data['RouteTables']))

        # NOTE(andrey-mp): by subnet id
        data = self.client.describe_route_tables(
            Filters=[{'Name': 'association.subnet-id',
                      'Values': [subnet_id]}])
        self.assertEqual(1, len(data['RouteTables']))

        # NOTE(andrey-mp): by filter real vpc
        data = self.client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc_id]}])
        self.assertLess(0, len(data['RouteTables']))

        # NOTE(andrey-mp): by filter fake vpc
        data = self.client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': ['vpc-0']}])
        self.assertEqual(0, len(data['RouteTables']))

        # NOTE(andrey-mp): by fake filter
        self.assertRaises('InvalidParameterValue',
                          self.client.describe_route_tables,
                          Filters=[{'Name': 'fake', 'Values': ['fake']}])

    def test_associate_disassociate_route_table(self):
        data = self.client.create_route_table(VpcId=self.vpc_id)
        rt_id = data['RouteTable']['RouteTableId']
        res_clean_rt = self.addResourceCleanUp(self.client.delete_route_table,
                                               RouteTableId=rt_id)

        data = self.client.create_subnet(VpcId=self.vpc_id,
                                         CidrBlock=self.SUBNET_CIDR)
        subnet_id = data['Subnet']['SubnetId']
        res_clean_subnet = self.addResourceCleanUp(self.client.delete_subnet,
                                                   SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        data = self.client.associate_route_table(RouteTableId=rt_id,
                                                 SubnetId=subnet_id)
        assoc_id = data['AssociationId']
        res_clean = self.addResourceCleanUp(
            self.client.disassociate_route_table, AssociationId=assoc_id)

        data = self.client.disassociate_route_table(AssociationId=assoc_id)
        self.cancelResourceCleanUp(res_clean)

        data = self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(res_clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

        data = self.client.delete_route_table(RouteTableId=rt_id)
        self.cancelResourceCleanUp(res_clean_rt)

    def test_replace_route_table(self):
        data = self.client.create_subnet(VpcId=self.vpc_id,
                                         CidrBlock=self.SUBNET_CIDR)
        subnet_id = data['Subnet']['SubnetId']
        res_clean_subnet = self.addResourceCleanUp(self.client.delete_subnet,
                                                   SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        # NOTE(andrey-mp): by vpc id
        data = self.client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc_id]}])
        self.assertEqual(1, len(data['RouteTables']))
        self.assertEqual(1, len(data['RouteTables'][0]['Associations']))
        default_rt_id = data['RouteTables'][0]['RouteTableId']
        main_assoc = data['RouteTables'][0]['Associations'][0]
        self.assertTrue(main_assoc['Main'])
        main_assoc_id = main_assoc['RouteTableAssociationId']

        data = self.client.create_route_table(VpcId=self.vpc_id)
        rt_id = data['RouteTable']['RouteTableId']
        res_clean_rt = self.addResourceCleanUp(self.client.delete_route_table,
                                               RouteTableId=rt_id)

        data = self.client.replace_route_table_association(
            RouteTableId=rt_id, AssociationId=main_assoc_id)
        assoc_id = data['NewAssociationId']
        res_clean = self.addResourceCleanUp(
            self.client.replace_route_table_association,
            RouteTableId=default_rt_id,
            AssociationId=assoc_id)

        # NOTE(andrey-mp): by vpc id
        data = self.client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc_id]}])
        self.assertEqual(2, len(data['RouteTables']))
        for rt in data['RouteTables']:
            if rt['RouteTableId'] == rt_id:
                self.assertEqual(1, len(rt['Associations']))
                self.assertTrue(rt['Associations'][0]['Main'])
            else:
                self.assertEmpty(rt.get('Associations', []))

        self.assertRaises('DependencyViolation',
                          self.client.delete_route_table,
                          RouteTableId=rt_id)

        self.assertRaises('InvalidParameterValue',
                          self.client.disassociate_route_table,
                          AssociationId=assoc_id)

        data = self.client.replace_route_table_association(
            RouteTableId=default_rt_id,
            AssociationId=assoc_id)
        self.cancelResourceCleanUp(res_clean)

        data = self.client.delete_route_table(RouteTableId=rt_id)
        self.cancelResourceCleanUp(res_clean_rt)

        data = self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(res_clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)

    def test_create_delete_route(self):
        data = self.client.create_subnet(VpcId=self.vpc_id,
                                         CidrBlock=self.SUBNET_CIDR)
        subnet_id = data['Subnet']['SubnetId']
        res_clean_subnet = self.addResourceCleanUp(self.client.delete_subnet,
                                                   SubnetId=subnet_id)
        self.get_subnet_waiter().wait_available(subnet_id)

        kwargs = {
            'SubnetId': subnet_id,
        }
        data = self.client.create_network_interface(*[], **kwargs)
        ni_id = data['NetworkInterface']['NetworkInterfaceId']
        res_clean_ni = self.addResourceCleanUp(
            self.client.delete_network_interface,
            NetworkInterfaceId=ni_id)

        data = self.client.create_route_table(VpcId=self.vpc_id)
        rt_id = data['RouteTable']['RouteTableId']
        res_clean_rt = self.addResourceCleanUp(self.client.delete_route_table,
                                               RouteTableId=rt_id)

        kwargs = {
            'DestinationCidrBlock': self.VPC_CIDR,
            'RouteTableId': rt_id,
            'NetworkInterfaceId': ni_id
        }
        self.assertRaises('InvalidParameterValue',
                          self.client.create_route,
                          **kwargs)

        # can create wider route
        kwargs = {
            'DestinationCidrBlock': '10.14.0.0/19',
            'RouteTableId': rt_id,
            'NetworkInterfaceId': ni_id
        }
        data = self.client.create_route(*[], **kwargs)
        # can create to another vpc
        kwargs = {
            'DestinationCidrBlock': '10.15.0.0/20',
            'RouteTableId': rt_id,
            'NetworkInterfaceId': ni_id
        }
        data = self.client.create_route(*[], **kwargs)

        data = self.client.describe_route_tables(RouteTableIds=[rt_id])
        self.assertEqual(1, len(data['RouteTables']))
        self.assertEqual(3, len(data['RouteTables'][0]['Routes']))

        kwargs = {
            'DestinationCidrBlock': '10.15.0.0/24',
            'RouteTableId': rt_id,
        }
        self.assertRaises('InvalidRoute.NotFound',
                          self.client.delete_route,
                          **kwargs)

        kwargs = {
            'DestinationCidrBlock': self.VPC_CIDR,
            'RouteTableId': rt_id,
        }
        self.assertRaises('InvalidParameterValue',
                         self.client.delete_route,
                         **kwargs)

        kwargs = {
            'DestinationCidrBlock': self.SUBNET_CIDR,
            'RouteTableId': rt_id,
        }
        self.assertRaises('InvalidRoute.NotFound',
                          self.client.delete_route,
                          **kwargs)

        kwargs = {
            'DestinationCidrBlock': '10.16.0.0/24',
            'RouteTableId': rt_id,
        }
        self.assertRaises('InvalidRoute.NotFound',
                          self.client.delete_route,
                          **kwargs)

        kwargs = {
            'DestinationCidrBlock': '10.15.0.0/20',
            'RouteTableId': rt_id,
        }
        data = self.client.delete_route(*[], **kwargs)

        kwargs = {
            'DestinationCidrBlock': '10.14.0.0/19',
            'RouteTableId': rt_id,
        }
        data = self.client.delete_route(*[], **kwargs)

        data = self.client.delete_route_table(RouteTableId=rt_id)
        self.cancelResourceCleanUp(res_clean_rt)

        data = self.client.delete_network_interface(
            NetworkInterfaceId=ni_id)
        self.cancelResourceCleanUp(res_clean_ni)
        self.get_network_interface_waiter().wait_delete(ni_id)

        data = self.client.delete_subnet(SubnetId=subnet_id)
        self.cancelResourceCleanUp(res_clean_subnet)
        self.get_subnet_waiter().wait_delete(subnet_id)
