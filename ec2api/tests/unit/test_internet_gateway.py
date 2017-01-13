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


import mock
from neutronclient.common import exceptions as neutron_exception

from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class IgwTestCase(base.ApiTestCase):

    def setUp(self):
        super(IgwTestCase, self).setUp()
        self.DB_IGW_1_DETACHED = fakes.gen_db_igw(fakes.ID_EC2_IGW_1)
        self.DB_IGW_2_ATTACHED = fakes.gen_db_igw(fakes.ID_EC2_IGW_2,
                                                  fakes.ID_EC2_VPC_2)

    def test_create_igw(self):
        self.db_api.add_item.return_value = fakes.DB_IGW_2

        resp = self.execute('CreateInternetGateway', {})

        self.assertIn('internetGateway', resp)
        igw = resp['internetGateway']
        self.assertThat(fakes.EC2_IGW_2, matchers.DictMatches(igw))
        self.db_api.add_item.assert_called_with(
                mock.ANY, 'igw', {})

    def test_attach_igw(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        self.set_mock_db_items(fakes.DB_IGW_1, fakes.DB_IGW_2, fakes.DB_VPC_2,
                               fakes.DB_VPN_GATEWAY_1, fakes.DB_VPN_GATEWAY_2)
        self.neutron.list_networks.return_value = (
                {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})

        def do_check():
            resp = self.execute(
                    'AttachInternetGateway',
                    {'VpcId': fakes.ID_EC2_VPC_2,
                     'InternetGatewayId': fakes.ID_EC2_IGW_2})

            self.assertEqual(True, resp['return'])
            self.db_api.update_item.assert_called_once_with(
                    mock.ANY, self.DB_IGW_2_ATTACHED)

        do_check()
        self.neutron.add_gateway_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_2,
                {'network_id': fakes.ID_OS_PUBLIC_NETWORK})
        self.neutron.list_networks.assert_called_once_with(
                **{'router:external': True,
                   'name': fakes.NAME_OS_PUBLIC_NETWORK})

        # VPN gateway is already attached
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        vgw_2 = tools.update_dict(fakes.DB_VPN_GATEWAY_2,
                                  {'vpc_id': fakes.ID_EC2_VPC_2})
        self.add_mock_db_items(vgw_2)
        do_check()
        self.assertFalse(self.neutron.add_gateway_router.called)

    def test_attach_igw_invalid_parameters(self):
        def do_check(error_code):
            self.assert_execution_error(
                error_code, 'AttachInternetGateway',
                {'VpcId': fakes.ID_EC2_VPC_2,
                 'InternetGatewayId': fakes.ID_EC2_IGW_2})

            self.assertEqual(0, self.neutron.add_gateway_router.call_count)
            self.assertEqual(0, self.db_api.update_item.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.set_mock_db_items(fakes.DB_VPC_2)
        do_check('InvalidInternetGatewayID.NotFound')

        self.set_mock_db_items(fakes.DB_IGW_2)
        do_check('InvalidVpcID.NotFound')

        self.set_mock_db_items(self.DB_IGW_2_ATTACHED, fakes.DB_VPC_2)
        do_check('Resource.AlreadyAssociated')

        self.set_mock_db_items(
            fakes.DB_IGW_2, fakes.DB_VPC_2,
            fakes.gen_db_igw(fakes.ID_EC2_IGW_1, fakes.ID_EC2_VPC_2))
        do_check('InvalidParameterValue')

    @tools.screen_unexpected_exception_logs
    def test_attach_igw_rollback(self):
        self.configure(external_network=fakes.NAME_OS_PUBLIC_NETWORK)
        self.set_mock_db_items(fakes.DB_IGW_1, fakes.DB_IGW_2, fakes.DB_VPC_2)
        self.neutron.list_networks.return_value = (
                {'networks': [{'id': fakes.ID_OS_PUBLIC_NETWORK}]})
        self.neutron.add_gateway_router.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'AttachInternetGateway',
            {'VpcId': fakes.ID_EC2_VPC_2,
             'InternetGatewayId': fakes.ID_EC2_IGW_2})

        self.db_api.update_item.assert_any_call(
                mock.ANY, fakes.DB_IGW_2)

    def test_detach_igw(self):
        self.set_mock_db_items(fakes.DB_IGW_1, fakes.DB_VPC_1)

        def do_check():
            resp = self.execute(
                    'DetachInternetGateway',
                    {'VpcId': fakes.ID_EC2_VPC_1,
                     'InternetGatewayId': fakes.ID_EC2_IGW_1})
            self.assertEqual(True, resp['return'])
            self.db_api.update_item.assert_called_once_with(
                    mock.ANY, self.DB_IGW_1_DETACHED)

        do_check()
        self.neutron.remove_gateway_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_1)

        # VPN gateway is still attached
        self.db_api.reset_mock()
        self.neutron.reset_mock()
        self.add_mock_db_items(fakes.DB_VPN_GATEWAY_1)
        do_check()
        self.assertFalse(self.neutron.remove_gateway_router.called)

    def test_detach_igw_invalid_parameters(self):
        def do_check(error_code):
            self.assert_execution_error(
                error_code, 'DetachInternetGateway',
                {'VpcId': fakes.ID_EC2_VPC_1,
                 'InternetGatewayId': fakes.ID_EC2_IGW_1})

            self.assertEqual(0, self.neutron.remove_gateway_router.call_count)
            self.assertEqual(0, self.db_api.update_item.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.set_mock_db_items(fakes.DB_VPC_1)
        do_check('InvalidInternetGatewayID.NotFound')

        self.set_mock_db_items(fakes.DB_IGW_1)
        do_check('InvalidVpcID.NotFound')

        self.set_mock_db_items(self.DB_IGW_1_DETACHED, fakes.DB_VPC_1)
        do_check('Gateway.NotAttached')

    def test_detach_igw_no_router(self):
        self.set_mock_db_items(fakes.DB_IGW_1, fakes.DB_VPC_1)
        self.neutron.remove_gateway_router.side_effect = (
                neutron_exception.NotFound)

        resp = self.execute(
                'DetachInternetGateway',
                {'VpcId': fakes.ID_EC2_VPC_1,
                 'InternetGatewayId': fakes.ID_EC2_IGW_1})

        self.assertEqual(True, resp['return'])
        self.neutron.remove_gateway_router.assert_called_once_with(
                fakes.ID_OS_ROUTER_1)

    @tools.screen_unexpected_exception_logs
    def test_detach_igw_rollback(self):
        self.set_mock_db_items(fakes.DB_IGW_1, fakes.DB_VPC_1)
        self.neutron.remove_gateway_router.side_effect = Exception()

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'DetachInternetGateway',
            {'VpcId': fakes.EC2_VPC_1['vpcId'],
             'InternetGatewayId': fakes.EC2_IGW_1['internetGatewayId']})

        self.db_api.update_item.assert_any_call(
                mock.ANY, fakes.DB_IGW_1)

    def test_delete_igw(self):
        self.set_mock_db_items(fakes.DB_IGW_2)

        resp = self.execute(
                'DeleteInternetGateway',
                {'InternetGatewayId': fakes.ID_EC2_IGW_2})

        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_called_once_with(mock.ANY,
                                                           fakes.ID_EC2_IGW_2)
        self.db_api.delete_item.assert_called_once_with(mock.ANY,
                                                        fakes.ID_EC2_IGW_2)

    def test_delete_igw_invalid_parameters(self):
        def do_check(error_code):
            self.assert_execution_error(
                error_code, 'DeleteInternetGateway',
                {'InternetGatewayId': fakes.ID_EC2_IGW_1})

            self.assertEqual(0, self.db_api.delete_item.call_count)

            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.set_mock_db_items()
        do_check('InvalidInternetGatewayID.NotFound')

        self.set_mock_db_items(fakes.DB_IGW_1)
        do_check('DependencyViolation')

    def test_describe_igw(self):
        self.set_mock_db_items(fakes.DB_IGW_1, fakes.DB_IGW_2)

        resp = self.execute('DescribeInternetGateways', {})
        self.assertThat(resp['internetGatewaySet'],
                        matchers.ListMatches([fakes.EC2_IGW_1,
                                              fakes.EC2_IGW_2]))

        resp = self.execute('DescribeInternetGateways',
                            {'InternetGatewayId.1': fakes.ID_EC2_IGW_2})
        self.assertThat(resp['internetGatewaySet'],
                        matchers.ListMatches([fakes.EC2_IGW_2]))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_IGW_2]))

        self.check_filtering(
            'DescribeInternetGateways', 'internetGatewaySet',
            [('internet-gateway-id', fakes.ID_EC2_IGW_2),
             ('attachment.state', 'available'),
             ('attachment.vpc-id', fakes.ID_EC2_VPC_1)])
        self.check_tag_support(
            'DescribeInternetGateways', 'internetGatewaySet',
            fakes.ID_EC2_IGW_2, 'internetGatewayId')

    @mock.patch('ec2api.api.ec2utils.check_and_create_default_vpc')
    def test_describe_internet_gateways_no_default_vpc(self, check_and_create):
        self.configure(disable_ec2_classic=True)

        def mock_check_and_create(context):
            self.set_mock_db_items(fakes.DB_VPC_DEFAULT,
                                   fakes.DB_IGW_DEFAULT)
        check_and_create.side_effect = mock_check_and_create

        resp = self.execute('DescribeInternetGateways', {})
        self.assertEqual(resp['internetGatewaySet'],
                         [fakes.EC2_IGW_DEFAULT])

        check_and_create.assert_called_once_with(mock.ANY)
