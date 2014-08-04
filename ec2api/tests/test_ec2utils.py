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
import testtools

from ec2api.api import ec2utils
from ec2api import exception
from ec2api.tests import matchers


class EC2UtilsTestCase(testtools.TestCase):

    def test_get_ec2_id(self):
        self.assertEqual('vpc-000004d2',
                         ec2utils.get_ec2_id(0x4d2, 'vpc'))
        self.assertEqual('vpc-000004d2',
                         ec2utils.get_ec2_id(long(0x4d2), 'vpc'))
        self.assertRaises(OverflowError,
                          ec2utils.get_ec2_id, -1, 'vpc')
        self.assertRaises(OverflowError,
                          ec2utils.get_ec2_id, 0x123456789, 'vpc')
        self.assertRaises(TypeError,
                          ec2utils.get_ec2_id, 'fake', 'vpc')
        self.assertRaises(TypeError,
                          ec2utils.get_ec2_id, 1.1, 'vpc')

    @mock.patch('ec2api.db.api.IMPL')
    def test_get_db_item(self, db_api):
        item = {'fake_key': 'fake_value'}
        db_api.get_item_by_id.return_value = item

        def check_normal_flow(db_id, kind, ec2_id):
            item['id'] = db_id
            res = ec2utils.get_db_item('fake_context', kind, ec2_id)
            self.assertThat(res, matchers.DictMatches(item))
            db_api.get_item_by_id.assert_called_once_with('fake_context',
                                                          kind, db_id)
            db_api.reset_mock()

        check_normal_flow(0x001234af, 'vpc', 'vpc-001234af')
        check_normal_flow(0x22, 'igw', 'igw-22')

        def check_not_found(kind, ec2_id, item_id, ex_class):
            self.assertRaises(ex_class,
                              ec2utils.get_db_item,
                              'fake_context', kind, ec2_id)
            db_api.get_item_by_id.assert_called_once_with('fake_context',
                                                          kind, item_id)
            db_api.reset_mock()

        db_api.get_item_by_id.return_value = None
        check_not_found('vpc', 'vpc-22', 0x22,
                        exception.InvalidVpcIDNotFound)
        check_not_found('igw', 'igw-22', 0x22,
                        exception.InvalidInternetGatewayIDNotFound)
        check_not_found('subnet', 'subnet-22', 0x22,
                        exception.InvalidSubnetIDNotFound)

    def test_validate_cidr(self):
        self.assertIsNone(ec2utils.validate_cidr('10.10.0.0/24', 'cidr'))

        def check_raise_invalid_parameter(cidr):
            self.assertRaises(exception.InvalidParameterValue,
                              ec2utils.validate_cidr, cidr, 'cidr')

        check_raise_invalid_parameter('fake')
        check_raise_invalid_parameter('10.10/24')
        check_raise_invalid_parameter('10.10.0.0.0/24')
        check_raise_invalid_parameter('10.10.0.0')
        check_raise_invalid_parameter(' 10.10.0.0/24')
        check_raise_invalid_parameter('10.10.0.0/24 ')
        check_raise_invalid_parameter('.10.10.0.0/24 ')
        check_raise_invalid_parameter('-1.10.0.0/24')
        check_raise_invalid_parameter('10.256.0.0/24')
        check_raise_invalid_parameter('10.10.0.0/33')
        check_raise_invalid_parameter('10.10.0.0/-1')

        def check_raise_invalid_vpc_range(cidr, ex_class):
            self.assertRaises(ex_class,
                              ec2utils.validate_vpc_cidr, cidr,
                              ex_class)

        check_raise_invalid_vpc_range('10.10.0.0/15',
                                      exception.InvalidSubnetRange)
        check_raise_invalid_vpc_range('10.10.0.0/29',
                                      exception.InvalidVpcRange)
