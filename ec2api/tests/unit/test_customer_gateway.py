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


from unittest import mock

from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class CustomerGatewayTestCase(base.ApiTestCase):

    def test_create_customer_gateway(self):
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_CUSTOMER_GATEWAY_2))

        resp = self.execute('CreateCustomerGateway',
                            {'IpAddress': fakes.IP_CUSTOMER_GATEWAY_ADDRESS_2,
                             'Type': 'ipsec.1'})
        self.assertEqual({'customerGateway': fakes.EC2_CUSTOMER_GATEWAY_2},
                         resp)
        self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'cgw',
                {'ip_address': fakes.IP_CUSTOMER_GATEWAY_ADDRESS_2})

        resp = self.execute('CreateCustomerGateway',
                            {'IpAddress': fakes.IP_CUSTOMER_GATEWAY_ADDRESS_2,
                             'Type': 'ipsec.1',
                             'BgpAsn': '65000'})
        self.assertEqual({'customerGateway': fakes.EC2_CUSTOMER_GATEWAY_2},
                         resp)

    def test_create_customer_gateway_idempotent(self):
        self.set_mock_db_items(fakes.DB_CUSTOMER_GATEWAY_1)

        resp = self.execute('CreateCustomerGateway',
                            {'IpAddress': fakes.IP_CUSTOMER_GATEWAY_ADDRESS_1,
                             'Type': 'ipsec.1'})
        self.assertEqual({'customerGateway': fakes.EC2_CUSTOMER_GATEWAY_1},
                         resp)
        self.assertFalse(self.db_api.add_item.called)

        resp = self.execute('CreateCustomerGateway',
                            {'IpAddress': fakes.IP_CUSTOMER_GATEWAY_ADDRESS_1,
                             'Type': 'ipsec.1',
                             'BgpAsn': '65000'})
        self.assertEqual({'customerGateway': fakes.EC2_CUSTOMER_GATEWAY_1},
                         resp)
        self.assertFalse(self.db_api.add_item.called)

    def test_create_customer_gateway_invalid_parameters(self):
        self.assert_execution_error(
            'Unsupported',
            'CreateCustomerGateway',
            {'IpAddress': fakes.IP_CUSTOMER_GATEWAY_ADDRESS_1,
             'Type': 'ipsec.1',
             'BgpAsn': '456'})

    def test_delete_customer_gateway(self):
        self.set_mock_db_items(fakes.DB_CUSTOMER_GATEWAY_2)

        resp = self.execute(
            'DeleteCustomerGateway',
            {'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_2})

        self.assertEqual({'return': True}, resp)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_CUSTOMER_GATEWAY_2)

    def test_delete_customer_gateway_invalid_parameters(self):
        self.set_mock_db_items()
        self.assert_execution_error(
            'InvalidCustomerGatewayID.NotFound',
            'DeleteCustomerGateway',
            {'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_2})
        self.assertFalse(self.db_api.delete_item.called)

        self.set_mock_db_items(fakes.DB_CUSTOMER_GATEWAY_1,
                               fakes.DB_VPN_CONNECTION_1)
        self.assert_execution_error(
            'IncorrectState',
            'DeleteCustomerGateway',
            {'CustomerGatewayId': fakes.ID_EC2_CUSTOMER_GATEWAY_1})
        self.assertFalse(self.db_api.delete_item.called)

    def test_describe_customer_gateways(self):
        self.set_mock_db_items(fakes.DB_CUSTOMER_GATEWAY_1,
                               fakes.DB_CUSTOMER_GATEWAY_2)

        resp = self.execute('DescribeCustomerGateways', {})
        self.assertThat(resp['customerGatewaySet'],
                        matchers.ListMatches([fakes.EC2_CUSTOMER_GATEWAY_1,
                                              fakes.EC2_CUSTOMER_GATEWAY_2]))

        resp = self.execute(
            'DescribeCustomerGateways',
            {'CustomerGatewayId.1': fakes.ID_EC2_CUSTOMER_GATEWAY_2})
        self.assertThat(
            resp['customerGatewaySet'],
            matchers.ListMatches([fakes.EC2_CUSTOMER_GATEWAY_2]))
        self.db_api.get_items_by_ids.assert_called_once_with(
            mock.ANY, set([fakes.ID_EC2_CUSTOMER_GATEWAY_2]))

        self.check_filtering(
            'DescribeCustomerGateways', 'customerGatewaySet',
            [('bgp-asn', 65000),
             ('customer-gateway-id', fakes.ID_EC2_CUSTOMER_GATEWAY_2),
             ('ip-address', fakes.IP_CUSTOMER_GATEWAY_ADDRESS_2),
             ('state', 'available'),
             ('type', 'ipsec.1')])
        self.check_tag_support(
            'DescribeCustomerGateways', 'customerGatewaySet',
            fakes.ID_EC2_CUSTOMER_GATEWAY_2, 'customerGatewayId')
