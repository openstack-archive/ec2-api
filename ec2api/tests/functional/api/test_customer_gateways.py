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

import botocore.exceptions

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class CustomerGatewayTest(base.EC2TestCase):

    CUSTOMER_GATEWAY_IP = '198.51.100.77'

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(CustomerGatewayTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

    def test_create_delete_customer_gateway(self):
        data = self.client.create_customer_gateway(
            Type='ipsec.1', PublicIp=self.CUSTOMER_GATEWAY_IP, BgpAsn=65000)
        cgw_id = data['CustomerGateway']['CustomerGatewayId']
        cgw_clean = self.addResourceCleanUp(
            self.client.delete_customer_gateway, CustomerGatewayId=cgw_id)
        self.assertEqual(self.CUSTOMER_GATEWAY_IP,
                         data['CustomerGateway']['IpAddress'])

        self.client.delete_customer_gateway(CustomerGatewayId=cgw_id)
        self.cancelResourceCleanUp(cgw_clean)

        try:
            data = self.client.describe_customer_gateways(
                CustomerGatewayIds=[cgw_id])
            self.assertEqual(1, len(data['CustomerGateways']))
            self.assertEqual('deleted', data['CustomerGateways'][0]['State'])
        except botocore.exceptions.ClientError as ex:
            self.assertEqual('InvalidCustomerGatewayID.NotFound',
                             ex.response['Error']['Code'])
