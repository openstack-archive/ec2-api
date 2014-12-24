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

import testtools

from ec2api.api import ec2utils
from ec2api import exception
from ec2api.openstack.common import timeutils


class EC2TimestampValidationTestCase(testtools.TestCase):
    """Test case for EC2 request timestamp validation."""

    def test_validate_ec2_timestamp_valid(self):
        params = {'Timestamp': '2011-04-22T11:29:49Z'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertFalse(expired)

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

    def test_validate_ec2_timestamp_aws_sdk_format(self):
        params = {'Timestamp': '2011-04-22T11:29:49.123Z'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertFalse(expired)
        expired = ec2utils.is_ec2_timestamp_expired(params, expires=300)
        self.assertTrue(expired)

    def test_validate_ec2_timestamp_invalid_format(self):
        params = {'Timestamp': '2011-04-22T11:29:49.000P'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertTrue(expired)

    def test_validate_ec2_timestamp_advanced_time(self):

        # EC2 request with Timestamp in advanced time
        timestamp = timeutils.utcnow() + datetime.timedelta(seconds=250)
        params = {'Timestamp': timeutils.strtime(timestamp,
                                           "%Y-%m-%dT%H:%M:%SZ")}
        expired = ec2utils.is_ec2_timestamp_expired(params, expires=300)
        self.assertFalse(expired)

    def test_validate_ec2_timestamp_advanced_time_expired(self):
        timestamp = timeutils.utcnow() + datetime.timedelta(seconds=350)
        params = {'Timestamp': timeutils.strtime(timestamp,
                                           "%Y-%m-%dT%H:%M:%SZ")}
        expired = ec2utils.is_ec2_timestamp_expired(params, expires=300)
        self.assertTrue(expired)

    def test_validate_ec2_req_timestamp_not_expired(self):
        params = {'Timestamp': timeutils.isotime()}
        expired = ec2utils.is_ec2_timestamp_expired(params, expires=15)
        self.assertFalse(expired)

    def test_validate_ec2_req_timestamp_expired(self):
        params = {'Timestamp': '2011-04-22T12:00:00Z'}
        compare = ec2utils.is_ec2_timestamp_expired(params, expires=300)
        self.assertTrue(compare)

    def test_validate_ec2_req_expired(self):
        params = {'Expires': timeutils.isotime()}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertTrue(expired)

    def test_validate_ec2_req_not_expired(self):
        expire = timeutils.utcnow() + datetime.timedelta(seconds=350)
        params = {'Expires': timeutils.strtime(expire, "%Y-%m-%dT%H:%M:%SZ")}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertFalse(expired)

    def test_validate_Expires_timestamp_invalid_format(self):

        # EC2 request with invalid Expires
        params = {'Expires': '2011-04-22T11:29:49'}
        expired = ec2utils.is_ec2_timestamp_expired(params)
        self.assertTrue(expired)

    def test_validate_ec2_req_timestamp_Expires(self):

        # EC2 request with both Timestamp and Expires
        params = {'Timestamp': '2011-04-22T11:29:49Z',
                  'Expires': timeutils.isotime()}
        self.assertRaises(exception.InvalidRequest,
                          ec2utils.is_ec2_timestamp_expired,
                          params)
