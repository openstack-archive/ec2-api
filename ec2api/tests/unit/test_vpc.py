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

import fixtures
import mock
from neutronclient.common import exceptions as neutron_exception

from ec2api.api import vpc as vpc_api
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class VpcTestCase(base.ApiTestCase):

    @mock.patch('ec2api.api.vpc._create_vpc')
    def test_create_vpc(self, create_vpc):
        create_vpc.return_value = fakes.DB_VPC_1

        def check_response(response):
            self.assertIn('vpc', response)
            vpc = resp['vpc']
            self.assertThat(fakes.EC2_VPC_1, matchers.DictMatches(vpc))
            create_vpc.assert_called_once_with(mock.ANY, fakes.CIDR_VPC_1)

            create_vpc.reset_mock()

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
            {'routers': [fakes.OS_ROUTER_DEFAULT,
                         fakes.OS_ROUTER_1, fakes.OS_ROUTER_2]})
        self.set_mock_db_items(fakes.DB_VPC_DEFAULT,
                               fakes.DB_VPC_1, fakes.DB_VPC_2)

        resp = self.execute('DescribeVpcs', {})
        self.assertThat(resp['vpcSet'],
                        matchers.ListMatches([fakes.EC2_VPC_DEFAULT,
                                              fakes.EC2_VPC_1,
                                              fakes.EC2_VPC_2]))

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
        self.set_mock_db_items(fakes.DB_VPC_DEFAULT, fakes.DB_VPC_1)

        resp = self.execute('DescribeVpcs', {})

        self.assertThat(resp['vpcSet'],
                        matchers.ListMatches([fakes.EC2_VPC_DEFAULT,
                                              fakes.EC2_VPC_1]))

    @mock.patch('ec2api.api.vpc._check_and_create_default_vpc')
    def test_describe_vpcs_no_default_vpc(self, check_and_create):
        def mock_check_and_create(context):
            self.set_mock_db_items(fakes.DB_VPC_DEFAULT)
        check_and_create.side_effect = mock_check_and_create

        resp = self.execute('DescribeVpcs', {})
        self.assertEqual(resp['vpcSet'], [fakes.EC2_VPC_DEFAULT])

        check_and_create.assert_called_once_with(mock.ANY)

    def test_describe_vpcs_with_default_vpc(self):
        self.set_mock_db_items(fakes.DB_VPC_DEFAULT)

        resp = self.execute('DescribeVpcs', {})
        self.assertEqual(resp['vpcSet'], [fakes.EC2_VPC_DEFAULT])

        self.db_api.add_item.assert_not_called()


class VpcPrivateTestCase(base.BaseTestCase):

    def setUp(self):
        super(VpcPrivateTestCase, self).setUp()
        self.context = base.create_context()
        self.nova, self.nova_admin = self.mock_nova()
        self.neutron = self.mock_neutron()
        self.db_api = self.mock_db()

    @mock.patch('ec2api.api.route_table.create_route')
    @mock.patch('ec2api.api.subnet.create_subnet')
    @mock.patch('ec2api.api.internet_gateway.attach_internet_gateway')
    @mock.patch('ec2api.api.internet_gateway.create_internet_gateway')
    @mock.patch('ec2api.api.security_group._create_default_security_group')
    @mock.patch('ec2api.api.route_table._create_route_table')
    def test_create_vpc(self, create_route_table,
                        create_default_security_group,
                        create_internet_gateway, attach_internet_gateway,
                        create_subnet, create_route):
        def _prepare_and_check(vpc=None, ec2_vpc=None,
                               route_table=None):
            self.neutron.create_router.side_effect = (
                tools.get_neutron_create('router', vpc['os_id']))
            self.db_api.add_item.side_effect = (
                tools.get_db_api_add_item({'vpc': vpc['id']}))
            self.db_api.set_mock_items(vpc)
            create_route_table.return_value = route_table

            resp = vpc_api._create_vpc(self.context, vpc['cidr_block'],
                                       vpc['is_default'])

            # Check creation of vpc
            self.neutron.create_router.assert_called_with({'router': {}})
            self.neutron.update_router.assert_called_once_with(
                vpc['os_id'],
                {'router': {'name': ec2_vpc['vpcId']}})
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'vpc', tools.purge_dict(
                    vpc, ('id', 'vpc_id', 'route_table_id')))
            self.db_api.update_item.assert_called_once_with(
                mock.ANY, vpc)

            create_route_table.assert_called_once_with(
                mock.ANY, vpc)
            create_default_security_group.assert_called_once_with(
                mock.ANY, vpc)

        _prepare_and_check(vpc=fakes.DB_VPC_1, ec2_vpc=fakes.EC2_VPC_1,
                           route_table=fakes.DB_ROUTE_TABLE_1)

        # checking that no default vpc related stuff is added
        create_internet_gateway.assert_not_called()
        attach_internet_gateway.assert_not_called()
        create_subnet.assert_not_called()
        create_route.assert_not_called()

        self.neutron.reset_mock()
        self.db_api.reset_mock()
        create_route_table.reset_mock()
        create_default_security_group.reset_mock()

        # Creation of default vpc
        create_route_table.return_value = fakes.DB_ROUTE_TABLE_DEFAULT
        create_subnet.return_value = {'subnet': fakes.EC2_SUBNET_DEFAULT}
        create_internet_gateway.return_value = {'internetGateway':
                                                fakes.EC2_IGW_DEFAULT}

        _prepare_and_check(vpc=fakes.DB_VPC_DEFAULT,
                           ec2_vpc=fakes.EC2_VPC_DEFAULT,
                           route_table=fakes.DB_ROUTE_TABLE_DEFAULT)

        create_internet_gateway.assert_called_once_with(mock.ANY)
        attach_internet_gateway.assert_called_once_with(mock.ANY,
            fakes.ID_EC2_IGW_DEFAULT,
            fakes.ID_EC2_VPC_DEFAULT)
        create_subnet.assert_called_once_with(mock.ANY,
            fakes.ID_EC2_VPC_DEFAULT,
            fakes.CIDR_SUBNET_DEFAULT)
        create_route.assert_called_once_with(mock.ANY,
            fakes.ID_EC2_ROUTE_TABLE_DEFAULT,
            '0.0.0.0/0', gateway_id=fakes.ID_EC2_IGW_DEFAULT)

    @mock.patch('ec2api.api.vpc._create_vpc')
    def test_check_and_create_default_vpc(self, create_vpc):
        self.configure(disable_ec2_classic=True)
        vpc_api._check_and_create_default_vpc(self.context)

        create_vpc.assert_called_once_with(mock.ANY, fakes.CIDR_VPC_DEFAULT,
                                           is_default=True)

    @tools.screen_logs('ec2api.api.vpc')
    @mock.patch('ec2api.api.internet_gateway.detach_internet_gateway')
    @mock.patch('ec2api.api.route_table.create_route')
    @mock.patch('ec2api.api.subnet.create_subnet')
    @mock.patch('ec2api.api.internet_gateway.attach_internet_gateway')
    @mock.patch('ec2api.api.internet_gateway.create_internet_gateway')
    @mock.patch('ec2api.api.security_group._create_default_security_group')
    @mock.patch('ec2api.api.route_table._create_route_table')
    def test_create_vpc_rollback(self, create_route_table,
                                 create_default_security_group,
                                 create_internet_gateway,
                                 attach_internet_gateway, create_subnet,
                                 create_route, detach_internet_gateway):
        self.configure(disable_ec2_classic=True)

        self.neutron.create_router.side_effect = (
            tools.get_neutron_create('router', fakes.ID_OS_ROUTER_DEFAULT))

        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item({'vpc': fakes.ID_EC2_VPC_DEFAULT}))

        DB_IGW_DEFAULT_DETACHED = (
            {'id': fakes.ID_EC2_IGW_DEFAULT,
            'os_id': None,
            'vpc_id': None})
        self.db_api.get_item_by_id.side_effect = (
            tools.get_db_api_get_item_by_id(fakes.DB_VPC_DEFAULT,
                                            fakes.DB_SUBNET_DEFAULT,
                                            fakes.DB_SECURITY_GROUP_DEFAULT,
                                            DB_IGW_DEFAULT_DETACHED))
        create_route_table.return_value = fakes.DB_ROUTE_TABLE_DEFAULT
        create_internet_gateway.return_value = {'internetGateway':
                                                fakes.EC2_IGW_DEFAULT}
        create_subnet.return_value = {'subnet': fakes.EC2_SUBNET_DEFAULT}
        create_default_security_group.return_value = (
            fakes.ID_EC2_SECURITY_GROUP_DEFAULT)

        # exception during attaching internet gateway
        create_route.side_effect = Exception()

        vpc_api._check_and_create_default_vpc(self.context)

        detach_internet_gateway.assert_any_call(mock.ANY,
                                                fakes.ID_EC2_IGW_DEFAULT,
                                                fakes.ID_EC2_VPC_DEFAULT)
        self.db_api.delete_item.assert_any_call(mock.ANY,
            fakes.ID_EC2_SUBNET_DEFAULT)
        self.db_api.delete_item.assert_any_call(mock.ANY,
            fakes.ID_EC2_IGW_DEFAULT)
        self.neutron.delete_security_group.assert_any_call(
            fakes.ID_OS_SECURITY_GROUP_DEFAULT)
        self.db_api.delete_item.assert_any_call(mock.ANY,
            fakes.ID_EC2_ROUTE_TABLE_DEFAULT)
        self.db_api.delete_item.assert_any_call(mock.ANY,
            fakes.ID_EC2_VPC_DEFAULT)
        self.neutron.delete_router.assert_called_once_with(
            fakes.ID_OS_ROUTER_DEFAULT)

    @mock.patch('ec2api.api.vpc._create_vpc')
    def test_check_and_create_default_vpc_failed(self, create_vpc):
        self.configure(disable_ec2_classic=True)
        create_vpc.side_effect = Exception()
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as log:
            vpc_api._check_and_create_default_vpc(self.context)
        self.assertTrue(log.output.startswith(
            '[ERROR] Failed to create default vpc'))
