# Copyright 2012 Cloudscaling, Inc.
# All Rights Reserved.
# Copyright 2013 Red Hat, Inc.
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

import datetime

from oslo_utils import timeutils
import testtools

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api import exception
from ec2api.tests.unit import tools


class EC2ValidationTestCase(testtools.TestCase):
    """Test case for various validations."""

    def test_validate_net(self):
        validator = common.Validator()
        validator.ip('10.10.0.0')
        validator.cidr('10.10.0.0/24')
        validator.subnet_cidr('10.10.0.0/24')
        validator.vpc_cidr('10.10.0.0/24')

        def check_raise_invalid_parameter(cidr):
            self.assertRaises(exception.InvalidParameterValue,
                              validator.cidr, cidr)

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

        self.assertRaises(exception.InvalidParameterValue,
                          validator.ip, '10.256.0.0')
        self.assertRaises(exception.InvalidSubnetRange,
                          validator.subnet_cidr, '10.10.0.0/15')
        self.assertRaises(exception.InvalidVpcRange,
                          validator.vpc_cidr, '10.10.0.0/29')

    def test_validate_id(self):
        validator = common.Validator()
        validator.ec2_id('i-00000001')
        validator.i_id('i-00000001')
        validator.ami_id('ami-00000001')
        validator.eni_id('eni-00000001')
        validator.sg_id('sg-00000001')
        validator.subnet_id('subnet-00000001')
        validator.igw_id('igw-00000001')
        validator.rtb_id('rtb-00000001')
        validator.vpc_id('vpc-00000001')
        validator.vol_id('vol-00000001')
        validator.snap_id('snap-00000001')
        validator.dopt_id('dopt-00000001')
        validator.eni_attach_id('eni-attach-00000001')
        validator.eipalloc_id('eipalloc-00000001')
        validator.eipassoc_id('eipassoc-00000001')
        validator.rtbassoc_id('rtbassoc-00000001')
        validator.vgw_id('vgw-00000001')
        validator.cgw_id('cgw-00000001')

        invalid_ids = ['1234', 'a-1111', '', 'i-1111', 'i-rrr', 'foobar']

        def check_raise_invalid_parameters(func):
            for id in invalid_ids:
                self.assertRaises(exception.InvalidParameterValue, func, id)

        check_raise_invalid_parameters(validator.ami_id)
        check_raise_invalid_parameters(validator.eni_id)
        check_raise_invalid_parameters(validator.sg_id)
        check_raise_invalid_parameters(validator.subnet_id)
        check_raise_invalid_parameters(validator.igw_id)
        check_raise_invalid_parameters(validator.rtb_id)
        check_raise_invalid_parameters(validator.vpc_id)
        check_raise_invalid_parameters(validator.vol_id)
        check_raise_invalid_parameters(validator.snap_id)
        check_raise_invalid_parameters(validator.dopt_id)
        check_raise_invalid_parameters(validator.eni_attach_id)
        check_raise_invalid_parameters(validator.eipalloc_id)
        check_raise_invalid_parameters(validator.eipassoc_id)
        check_raise_invalid_parameters(validator.rtbassoc_id)
        check_raise_invalid_parameters(validator.vgw_id)
        check_raise_invalid_parameters(validator.cgw_id)

        invalid_ids = ['1234', 'a-1111', '', 'vpc-1111', 'vpc-rrr', 'foobar']

        check_raise_invalid_parameters(validator.i_id)

        invalid_ids = ['1234', '', 'foobar']

        check_raise_invalid_parameters(validator.ec2_id)

    def test_validate_multi(self):
        validator = common.Validator()
        result_sum = {'value': 0}
        list_to_sum = [1, 2, 3, 4]

        def sum(value):
            # NOTE(Alex) Because nonlocal is only in python 3.0
            result_sum['value'] += value

        validator.multi(list_to_sum, sum)
        self.assertEqual(result_sum['value'], 10)

        self.assertRaises(exception.InvalidParameterValue,
                          validator.multi, 'not a list', sum)

    def test_validate_primitive(self):
        validator = common.Validator()
        validator.int(5)
        validator.bool(True)
        validator.str('str')
        validator.str64('str')
        validator.str255('str')

        def check_raise_validation_error(value, func):
            self.assertRaises(exception.ValidationError,
                              func, value)

        check_raise_validation_error('str', validator.int)
        check_raise_validation_error('str', validator.bool)
        check_raise_validation_error(5, validator.str)
        check_raise_validation_error('x' * 65, validator.str64)
        check_raise_validation_error('x' * 256, validator.str255)

    def test_validate_security_group(self):
        validator = common.Validator(params={})
        validator.security_group_str('name')
        validator.security_group_str('aa #^% -=99')
        validator = common.Validator(params={'vpc_id': 'vpc_id'})
        validator.security_group_str('name')

        def check_raise_validation_error(value):
            self.assertRaises(exception.ValidationError,
                              validator.security_group_str, value)

        validator = common.Validator(params={})
        check_raise_validation_error('aa \t\x01\x02\x7f')
        check_raise_validation_error('x' * 256)

        validator = common.Validator(params={'vpc_id': 'vpc_id'})
        check_raise_validation_error('aa #^% -=99')
        check_raise_validation_error('x' * 256)

    def test_validate_vpn_connection_type(self):
        validator = common.Validator()
        validator.vpn_connection_type('ipsec.1')

        invalid_ids = ['1234', 'a-1111', '', 'vpc-1111', 'vpc-rrr', 'foobar',
                       'ipsec1', 'openvpn', 'pptp', 'l2tp', 'freelan']
        for id in invalid_ids:
            self.assertRaises(exception.InvalidParameterValue,
                              validator.vpn_connection_type, id)


class EC2TimestampValidationTestCase(testtools.TestCase):
    """Test case for EC2 request timestamp validation."""

    def test_validate_ec2_timestamp_valid(self):
        params = {'Timestamp': '2011-04-22T11:29:49Z'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertFalse(expired)

    @tools.screen_all_logs
    def test_validate_ec2_timestamp_old_format(self):
        params = {'Timestamp': '2011-04-22T11:29:49'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertTrue(expired)

    def test_validate_ec2_timestamp_not_set(self):
        params = {}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertFalse(expired)

    def test_validate_ec2_timestamp_ms_time_regex(self):
        result = ec2utils._ms_time_regex.match('2011-04-22T11:29:49.123Z')
        self.assertIsNotNone(result)
        result = ec2utils._ms_time_regex.match('2011-04-22T11:29:49.123456Z')
        self.assertIsNotNone(result)
        result = ec2utils._ms_time_regex.match('2011-04-22T11:29:49.1234567Z')
        self.assertIsNone(result)
        result = ec2utils._ms_time_regex.match('2011-04-22T11:29:49.123')
        self.assertIsNone(result)
        result = ec2utils._ms_time_regex.match('2011-04-22T11:29:49Z')
        self.assertIsNone(result)

    @tools.screen_all_logs
    def test_validate_ec2_timestamp_aws_sdk_format(self):
        params = {'Timestamp': '2011-04-22T11:29:49.123Z'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertFalse(expired)
        expired = ec2utils.is_ec2_timestamp_expired(params, expires=300)
        self.assertTrue(expired)

    @tools.screen_all_logs
    def test_validate_ec2_timestamp_invalid_format(self):
        params = {'Timestamp': '2011-04-22T11:29:49.000P'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertTrue(expired)

    def test_validate_ec2_timestamp_advanced_time(self):

        # EC2 request with Timestamp in advanced time
        timestamp = timeutils.utcnow() + datetime.timedelta(seconds=250)
        params = {'Timestamp': timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")}
        expired = ec2utils.is_ec2_timestamp_expired(params, expires=300)
        self.assertFalse(expired)

    @tools.screen_all_logs
    def test_validate_ec2_timestamp_advanced_time_expired(self):
        timestamp = timeutils.utcnow() + datetime.timedelta(seconds=350)
        params = {'Timestamp': timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")}
        expired = ec2utils.is_ec2_timestamp_expired(params, expires=300)
        self.assertTrue(expired)

    def test_validate_ec2_req_timestamp_not_expired(self):
        params = {'Timestamp': ec2utils.isotime()}
        expired = ec2utils.is_ec2_timestamp_expired(params, expires=15)
        self.assertFalse(expired)

    @tools.screen_all_logs
    def test_validate_ec2_req_timestamp_expired(self):
        params = {'Timestamp': '2011-04-22T12:00:00Z'}
        compare = ec2utils.is_ec2_timestamp_expired(params, expires=300)
        self.assertTrue(compare)

    @tools.screen_all_logs
    def test_validate_ec2_req_expired(self):
        params = {'Expires': ec2utils.isotime()}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertTrue(expired)

    def test_validate_ec2_req_not_expired(self):
        expire = timeutils.utcnow() + datetime.timedelta(seconds=350)
        params = {'Expires': expire.strftime("%Y-%m-%dT%H:%M:%SZ")}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertFalse(expired)

    @tools.screen_all_logs
    def test_validate_Expires_timestamp_invalid_format(self):

        # EC2 request with invalid Expires
        params = {'Expires': '2011-04-22T11:29:49'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertTrue(expired)

    @tools.screen_all_logs
    def test_validate_ec2_req_timestamp_Expires(self):

        # EC2 request with both Timestamp and Expires
        params = {'Timestamp': '2011-04-22T11:29:49Z',
                  'Expires': ec2utils.isotime()}
        self.assertRaises(exception.InvalidRequest,
                          ec2utils.is_ec2_timestamp_expired,
                          params)
