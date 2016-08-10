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

from ec2api.api import availability_zone
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers


class AvailabilityZoneCase(base.ApiTestCase):

    def setUp(self):
        super(AvailabilityZoneCase, self).setUp()
        self.addCleanup(self._reset_engine)

    def _reset_engine(self):
        availability_zone.account_attribute_engine = (
            availability_zone.AccountAttributeEngineNeutron())

    def test_describe_availability_zones(self):
        self.nova.availability_zones.list.return_value = [
            fakes.NovaAvailabilityZone(fakes.OS_AVAILABILITY_ZONE),
            fakes.NovaAvailabilityZone(fakes.OS_AVAILABILITY_ZONE_INTERNAL)]
        resp = self.execute('DescribeAvailabilityZones', {})
        self.assertThat(resp['availabilityZoneInfo'],
                        matchers.ListMatches([fakes.EC2_AVAILABILITY_ZONE]))
        self.nova.availability_zones.list.assert_called_once_with(
            detailed=False)

        self.check_filtering(
            'DescribeAvailabilityZones', 'availabilityZoneInfo',
            [('state', 'available'),
             ('zone-name', fakes.NAME_AVAILABILITY_ZONE)])

    def test_describe_availability_zones_verbose(self):
        self.nova.availability_zones.list.return_value = [
            fakes.NovaAvailabilityZone(fakes.OS_AVAILABILITY_ZONE),
            fakes.NovaAvailabilityZone(fakes.OS_AVAILABILITY_ZONE_INTERNAL)]
        resp = self.execute('DescribeAvailabilityZones',
                            {'zoneName.1': 'verbose'})
        self.assertEqual(len(resp['availabilityZoneInfo']), 7)
        self.nova.availability_zones.list.assert_called_once_with()

    def test_regions(self):
        resp = self.execute('DescribeRegions', {})
        self.assertEqual(resp['regionInfo'][0]['regionName'], 'RegionOne')
        self.assertTrue(resp['regionInfo'][0].get('regionEndpoint')
                        is not None)

    def test_describe_account_attributes(self):
        self.nova.quotas.get.return_value = mock.Mock(instances=77)

        availability_zone.account_attribute_engine = (
            availability_zone.AccountAttributeEngineNeutron())
        resp = self.execute('DescribeAccountAttributes', {})
        self.assertThat(resp['accountAttributeSet'],
                        matchers.ListMatches(
                            [{'attributeName': 'supported-platforms',
                              'attributeValueSet': [
                                  {'attributeValue': 'EC2'},
                                  {'attributeValue': 'VPC'}]},
                             {'attributeName': 'default-vpc',
                              'attributeValueSet': [
                                  {'attributeValue': 'none'}]},
                             {'attributeName': 'max-instances',
                              'attributeValueSet': [
                                  {'attributeValue': 77}]}],
                            orderless_lists=True))
        self.nova.quotas.get.assert_called_once_with(
            fakes.ID_OS_PROJECT, fakes.ID_OS_USER)

        availability_zone.account_attribute_engine = (
            availability_zone.AccountAttributeEngineNova())
        resp = self.execute('DescribeAccountAttributes', {})
        self.assertThat(resp['accountAttributeSet'],
                        matchers.ListMatches(
                            [{'attributeName': 'supported-platforms',
                              'attributeValueSet': [
                                  {'attributeValue': 'EC2'}]},
                             {'attributeName': 'default-vpc',
                              'attributeValueSet': [
                                  {'attributeValue': 'none'}]},
                             {'attributeName': 'max-instances',
                              'attributeValueSet': [
                                  {'attributeValue': 77}]}],
                            orderless_lists=True))

        resp = self.execute('DescribeAccountAttributes',
                            {'AttributeName.1': 'default-vpc',
                             'AttributeName.2': 'max-instances'})
        self.assertThat(resp['accountAttributeSet'],
                        matchers.ListMatches(
                            [{'attributeName': 'default-vpc',
                              'attributeValueSet': [
                                  {'attributeValue': 'none'}]},
                             {'attributeName': 'max-instances',
                              'attributeValueSet': [
                                  {'attributeValue': 77}]}],
                            orderless_lists=True))

        self.assert_execution_error('InvalidParameter',
                                    'DescribeAccountAttributes',
                                    {'AttributeName.1': 'fake'})
