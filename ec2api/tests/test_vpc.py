#    Copyright 2014 Cloudscaling Group, Inc
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


import mock
from neutronclient.common import exceptions as neutron_exception

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class VpcTestCase(base.ApiTestCase):

    def test_create_vpc(self):
        self.neutron.create_router.side_effect = (
            fakes.get_neutron_create('router', fakes.ID_OS_ROUTER_1))
        self.db_api.add_item.side_effect = (
            fakes.get_db_api_add_item({
                'vpc': fakes.ID_DB_VPC_1,
                'rtb': fakes.ID_DB_ROUTE_TABLE_1}))

        def check_response(response):
            self.assertEqual(response['status'], 200)
            self.assertIn('vpc', response)
            vpc = resp['vpc']
            self.assertThat(fakes.EC2_VPC_1, matchers.DictMatches(vpc))
            self.neutron.create_router.assert_called_with({'router': {}})
            self.neutron.update_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_1,
                {'router': {'name': fakes.EC2_VPC_1['vpcId']}})
            self.db_api.add_item.assert_any_call(
                mock.ANY, 'vpc',
                tools.purge_dict(fakes.DB_VPC_1,
                                 ('id', 'vpc_id', 'route_table_id')))
            self.db_api.add_item.assert_any_call(
                mock.ANY, 'rtb',
                tools.purge_dict(fakes.DB_ROUTE_TABLE_1,
                                 ('id',)))
            self.db_api.update_item.assert_called_once_with(
                mock.ANY,
                fakes.DB_VPC_1)

            self.neutron.reset_mock()
            self.db_api.reset_mock()
            self.db_api.update_item.reset_mock()

        resp = self.execute('CreateVpc', {'CidrBlock': fakes.CIDR_VPC_1})
        check_response(resp)

        resp = self.execute('CreateVpc', {'CidrBlock': fakes.CIDR_VPC_1,
                                          'instanceTenancy': 'default'})
        check_response(resp)

    def test_create_vpc_invalid_cidr(self):
        self.neutron.create_router.side_effect = (
            fakes.get_neutron_create('router', fakes.ID_OS_ROUTER_1))
        self.db_api.add_item.side_effect = fakes.get_db_api_add_item(
            fakes.ID_DB_VPC_1)

        def check_response(resp, error_code):
            self.assertEqual(400, resp['status'])
            self.assertEqual(error_code, resp['Error']['Code'])
            self.assertEqual(0, self.neutron.create_router.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        resp = self.execute('CreateVpc', {'CidrBlock': 'bad_cidr'})
        check_response(resp, 'InvalidParameterValue')

        resp = self.execute('CreateVpc', {'CidrBlock': '10.0.0.0/8'})
        check_response(resp, 'InvalidVpc.Range')

    @base.skip_not_implemented
    def test_create_vpc_overlimit(self):
        self.neutron.create_router.side_effect = neutron_exception.Conflict
        self.db_api.add_item.side_effect = fakes.get_db_api_add_item(
            fakes.ID_DB_VPC_1)

        resp = self.execute('CreateVpc', {'CidrBlock': fakes.CIDR_VPC_1})

        self.assertEqual(400, resp['status'])
        self.assertEqual('VpcLimitExceeded', resp['Error']['Code'])
        self.neutron.create_router.assert_called_with({'router': {}})
        self.assertEqual(0, self.db_api.add_item.call_count)

    def test_create_vpc_rollback(self):
        self.neutron.create_router.side_effect = (
            fakes.get_neutron_create('router', fakes.ID_OS_ROUTER_1))
        self.db_api.add_item.side_effect = (
            fakes.get_db_api_add_item({
                'vpc': fakes.ID_DB_VPC_1,
                'rtb': fakes.ID_DB_ROUTE_TABLE_1}))
        self.neutron.update_router.side_effect = Exception()

        self.execute('CreateVpc', {'CidrBlock': fakes.CIDR_VPC_1})

        self.neutron.delete_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_1)
        self.db_api.delete_item.assert_any_call(mock.ANY, fakes.ID_DB_VPC_1)
        self.db_api.delete_item.assert_any_call(mock.ANY,
                                                fakes.ID_DB_ROUTE_TABLE_1)

    def test_delete_vpc(self):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                fakes.ID_DB_ROUTE_TABLE_1: fakes.DB_ROUTE_TABLE_1}))

        resp = self.execute('DeleteVpc', {'VpcId': fakes.ID_EC2_VPC_1})

        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])
        self.neutron.delete_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_1)
        self.db_api.delete_item.assert_any_call(
            mock.ANY,
            fakes.ID_DB_VPC_1)
        self.db_api.delete_item.assert_any_call(
            mock.ANY,
            fakes.ID_DB_ROUTE_TABLE_1)

    def test_delete_vpc_not_found(self):
        self.db_api.get_item_by_id.return_value = None

        resp = self.execute('DeleteVpc', {'VpcId': fakes.ID_EC2_VPC_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidVpcID.NotFound', resp['Error']['Code'])
        self.assertEqual(0, self.neutron.delete_router.call_count)
        self.assertEqual(0, self.db_api.delete_item.call_count)

    def test_delete_vpc_dependency_violation(self):
        def do_check():
            resp = self.execute('DeleteVpc',
                                {'VpcId': fakes.ID_EC2_VPC_1})
            self.assertEqual(400, resp['status'])
            self.assertEqual('DependencyViolation', resp['Error']['Code'])
            self.assertEqual(0, self.neutron.delete_router.call_count)
            self.assertEqual(0, self.db_api.delete_item.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.db_api.get_item_by_id.return_value = fakes.DB_VPC_1
        self.db_api.get_items.side_effect = fakes.get_db_api_get_items(
            {'igw': [fakes.DB_IGW_1],
             'subnet': []})
        do_check()

        self.db_api.get_items.side_effect = fakes.get_db_api_get_items(
            {'igw': [],
             'subnet': [fakes.DB_SUBNET_1]})
        do_check()

    def test_delete_vpc_not_conststent_os_vpc(self):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                fakes.ID_DB_ROUTE_TABLE_1: fakes.DB_ROUTE_TABLE_1}))

        def check_response(resp):
            self.assertEqual(200, resp['status'])
            self.assertEqual(True, resp['return'])
            self.neutron.delete_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_1)
            self.db_api.delete_item.assert_any_call(
                mock.ANY,
                fakes.ID_DB_VPC_1)
            self.db_api.delete_item.assert_any_call(
                mock.ANY,
                fakes.ID_DB_ROUTE_TABLE_1)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.neutron.delete_router.side_effect = neutron_exception.NotFound
        resp = self.execute('DeleteVpc', {'VpcId': fakes.ID_EC2_VPC_1})
        check_response(resp)

        self.neutron.delete_router.side_effect = neutron_exception.Conflict
        resp = self.execute('DeleteVpc', {'VpcId': fakes.ID_EC2_VPC_1})
        check_response(resp)

    def test_delete_vpc_rollback(self):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_DB_VPC_1: fakes.DB_VPC_1,
                fakes.ID_DB_ROUTE_TABLE_1: fakes.DB_ROUTE_TABLE_1}))
        self.neutron.delete_router.side_effect = Exception()

        self.execute('DeleteVpc', {'VpcId': fakes.ID_EC2_VPC_1})

        self.db_api.restore_item.assert_any_call(
            mock.ANY, 'vpc', fakes.DB_VPC_1)
        self.db_api.restore_item.assert_any_call(
            mock.ANY, 'rtb', fakes.DB_ROUTE_TABLE_1)

    def test_describe_vpcs(self):
        self.neutron.list_routers.return_value = (
            {'routers': [fakes.OS_ROUTER_1, fakes.OS_ROUTER_2]})
        self.db_api.get_items.return_value = [fakes.DB_VPC_1, fakes.DB_VPC_2]

        resp = self.execute('DescribeVpcs', {})

        self.assertEqual(200, resp['status'])
        self.assertThat(resp['vpcSet'],
                        matchers.DictListMatches([fakes.EC2_VPC_1,
                                                  fakes.EC2_VPC_2]))
        self.db_api.get_items.assert_called_once_with(mock.ANY, 'vpc')

    def test_describe_vpcs_no_router(self):
        self.neutron.list_routers.return_value = {'routers': []}
        self.db_api.get_items.return_value = [fakes.DB_VPC_1]

        resp = self.execute('DescribeVpcs', {})

        self.assertEqual(200, resp['status'])
        self.assertThat(resp['vpcSet'],
                        matchers.DictListMatches([fakes.EC2_VPC_1]))
        self.db_api.get_items.assert_called_once_with(mock.ANY, 'vpc')
