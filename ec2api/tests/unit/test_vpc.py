# Copyright 2014
# The Cloudscaling Group, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import copy

import mock
from neutronclient.common import exceptions as neutron_exception

from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class VpcTestCase(base.ApiTestCase):

    def test_create_vpc(self):
        self.neutron.create_router.side_effect = (
            tools.get_neutron_create('router', fakes.ID_OS_ROUTER_1))
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item({
                'vpc': fakes.ID_EC2_VPC_1,
                'rtb': fakes.ID_EC2_ROUTE_TABLE_1,
                'sg': fakes.ID_EC2_SECURITY_GROUP_1}))
        self.set_mock_db_items(fakes.DB_VPC_1)
        self.nova.security_groups.create.return_value = (
            fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_1))

        def check_response(response):
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
            tools.get_neutron_create('router', fakes.ID_OS_ROUTER_1))
        self.db_api.add_item.side_effect = tools.get_db_api_add_item(
            fakes.ID_EC2_VPC_1)

        def do_check(args, error_code):
            self.assert_execution_error(error_code, 'CreateVpc', args)
            self.assertEqual(0, self.neutron.create_router.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        do_check({'CidrBlock': 'bad_cidr'}, 'InvalidParameterValue')
        do_check({'CidrBlock': '10.0.0.0/8'}, 'InvalidVpc.Range')

    def test_create_vpc_overlimit(self):
        self.neutron.create_router.side_effect = (
            neutron_exception.OverQuotaClient)
        self.db_api.add_item.side_effect = tools.get_db_api_add_item(
            fakes.ID_EC2_VPC_1)

        self.assert_execution_error('VpcLimitExceeded', 'CreateVpc',
                                    {'CidrBlock': fakes.CIDR_VPC_1})
        self.neutron.create_router.assert_called_with({'router': {}})
        self.assertEqual(0, self.db_api.add_item.call_count)

    @tools.screen_unexpected_exception_logs
    def test_create_vpc_rollback(self):
        self.neutron.create_router.side_effect = (
            tools.get_neutron_create('router', fakes.ID_OS_ROUTER_1))
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item({
                'vpc': fakes.ID_EC2_VPC_1,
                'rtb': fakes.ID_EC2_ROUTE_TABLE_1}))
        self.neutron.update_router.side_effect = Exception()

        self.assert_execution_error(self.ANY_EXECUTE_ERROR, 'CreateVpc',
                                    {'CidrBlock': fakes.CIDR_VPC_1})

        self.neutron.delete_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_1)
        self.db_api.delete_item.assert_any_call(mock.ANY, fakes.ID_EC2_VPC_1)
        self.db_api.delete_item.assert_any_call(mock.ANY,
                                                fakes.ID_EC2_ROUTE_TABLE_1)

    def test_delete_vpc(self):
        self.set_mock_db_items(fakes.DB_VPC_1, fakes.DB_ROUTE_TABLE_1,
                               fakes.DB_SECURITY_GROUP_1)

        resp = self.execute('DeleteVpc', {'VpcId': fakes.ID_EC2_VPC_1})

        self.assertEqual(True, resp['return'])
        self.neutron.delete_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_1)
        self.db_api.delete_item.assert_any_call(
            mock.ANY,
            fakes.ID_EC2_VPC_1)
        self.db_api.delete_item.assert_any_call(
            mock.ANY,
            fakes.ID_EC2_ROUTE_TABLE_1)
        self.db_api.delete_item.assert_any_call(
            mock.ANY,
            fakes.ID_EC2_SECURITY_GROUP_1)

    def test_delete_vpc_not_found(self):
        self.set_mock_db_items()

        self.assert_execution_error('InvalidVpcID.NotFound', 'DeleteVpc',
                                    {'VpcId': fakes.ID_EC2_VPC_1})
        self.assertEqual(0, self.neutron.delete_router.call_count)
        self.assertEqual(0, self.db_api.delete_item.call_count)

    def test_delete_vpc_dependency_violation(self):
        def do_check():
            self.assert_execution_error('DependencyViolation', 'DeleteVpc',
                                        {'VpcId': fakes.ID_EC2_VPC_1})
            self.assertEqual(0, self.neutron.delete_router.call_count)
            self.assertEqual(0, self.db_api.delete_item.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.neutron.list_security_groups.return_value = (
            {'security_groups': [copy.deepcopy(fakes.OS_SECURITY_GROUP_1)]})
        self.set_mock_db_items(fakes.DB_SECURITY_GROUP_1,
                               fakes.DB_IGW_1, fakes.DB_VPC_1, )
        do_check()

        self.neutron.list_security_groups.return_value = (
            {'security_groups': [copy.deepcopy(fakes.OS_SECURITY_GROUP_1)]})
        self.set_mock_db_items(fakes.DB_SECURITY_GROUP_1,
                               fakes.DB_ROUTE_TABLE_1, fakes.DB_ROUTE_TABLE_2,
                               fakes.DB_VPC_1)
        do_check()

        self.set_mock_db_items(fakes.DB_SECURITY_GROUP_1,
                               fakes.DB_SECURITY_GROUP_2, fakes.DB_VPC_1)
        self.neutron.list_security_groups.return_value = (
            {'security_groups': [copy.deepcopy(fakes.OS_SECURITY_GROUP_1),
                                 fakes.OS_SECURITY_GROUP_2]})
        do_check()

        self.neutron.list_security_groups.return_value = (
            {'security_groups': [copy.deepcopy(fakes.OS_SECURITY_GROUP_1)]})
        self.set_mock_db_items(fakes.DB_SECURITY_GROUP_1,
                               fakes.DB_VPN_GATEWAY_1, fakes.DB_VPC_1, )
        do_check()

    def test_delete_vpc_not_conststent_os_vpc(self):
        self.set_mock_db_items(fakes.DB_VPC_1, fakes.DB_ROUTE_TABLE_1)

        def check_response(resp):
            self.assertEqual(True, resp['return'])
            self.neutron.delete_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_1)
            self.db_api.delete_item.assert_any_call(
                mock.ANY,
                fakes.ID_EC2_VPC_1)
            self.db_api.delete_item.assert_any_call(
                mock.ANY,
                fakes.ID_EC2_ROUTE_TABLE_1)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.neutron.delete_router.side_effect = neutron_exception.NotFound
        resp = self.execute('DeleteVpc', {'VpcId': fakes.ID_EC2_VPC_1})
        check_response(resp)

        self.neutron.delete_router.side_effect = neutron_exception.Conflict
        resp = self.execute('DeleteVpc', {'VpcId': fakes.ID_EC2_VPC_1})
        check_response(resp)

    @tools.screen_unexpected_exception_logs
    def test_delete_vpc_rollback(self):
        self.set_mock_db_items(fakes.DB_VPC_1, fakes.DB_ROUTE_TABLE_1)
        self.neutron.delete_router.side_effect = Exception()

        self.assert_execution_error(self.ANY_EXECUTE_ERROR, 'DeleteVpc',
                                    {'VpcId': fakes.ID_EC2_VPC_1})

        self.db_api.restore_item.assert_any_call(
            mock.ANY, 'vpc', fakes.DB_VPC_1)
        self.db_api.restore_item.assert_any_call(
            mock.ANY, 'rtb', fakes.DB_ROUTE_TABLE_1)

    def test_describe_vpcs(self):
        self.neutron.list_routers.return_value = (
            {'routers': [fakes.OS_ROUTER_1, fakes.OS_ROUTER_2]})
        self.set_mock_db_items(fakes.DB_VPC_1, fakes.DB_VPC_2)

        resp = self.execute('DescribeVpcs', {})
        self.assertThat(resp['vpcSet'],
                        matchers.ListMatches([fakes.EC2_VPC_1,
                                              fakes.EC2_VPC_2]))
        self.db_api.get_items.assert_called_once_with(mock.ANY, 'vpc')

        resp = self.execute('DescribeVpcs',
                            {'VpcId.1': fakes.ID_EC2_VPC_1})
        self.assertThat(resp['vpcSet'],
                        matchers.ListMatches([fakes.EC2_VPC_1]))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_VPC_1]))

        self.check_filtering(
            'DescribeVpcs', 'vpcSet',
            [('cidr', fakes.CIDR_VPC_1),
             ('dhcp-options-id', 'default'),
             ('is-default', False),
             ('state', 'available'),
             ('vpc-id', fakes.ID_EC2_VPC_1)])
        self.check_tag_support(
            'DescribeVpcs', 'vpcSet',
            fakes.ID_EC2_VPC_1, 'vpcId')

    def test_describe_vpcs_no_router(self):
        self.neutron.list_routers.return_value = {'routers': []}
        self.set_mock_db_items(fakes.DB_VPC_1)

        resp = self.execute('DescribeVpcs', {})

        self.assertThat(resp['vpcSet'],
                        matchers.ListMatches([fakes.EC2_VPC_1]))
        self.db_api.get_items.assert_called_once_with(mock.ANY, 'vpc')
