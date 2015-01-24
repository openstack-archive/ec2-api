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

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers


class AvailabilityZoneCase(base.ApiTestCase):

    def test_describe_availability_zones(self):
        self.nova_availability_zones.list.return_value = [
            fakes.NovaAvailabilityZone(fakes.OS_AVAILABILITY_ZONE),
            fakes.NovaAvailabilityZone(fakes.OS_AVAILABILITY_ZONE_INTERNAL)]
        resp = self.execute('DescribeAvailabilityZones', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertThat(resp['availabilityZoneInfo'],
                        matchers.ListMatches([fakes.EC2_AVAILABILITY_ZONE]))
        self.nova_availability_zones.list.assert_called_once()

        self.check_filtering(
            'DescribeAvailabilityZones', 'availabilityZoneInfo',
            [('state', 'available'),
             ('zone-name', fakes.NAME_AVAILABILITY_ZONE)])

    def test_describe_availability_zones_verbose(self):
        self.nova_availability_zones.list.return_value = [
            fakes.NovaAvailabilityZone(fakes.OS_AVAILABILITY_ZONE),
            fakes.NovaAvailabilityZone(fakes.OS_AVAILABILITY_ZONE_INTERNAL)]
        resp = self.execute('DescribeAvailabilityZones',
                            {'zoneName.1': 'verbose'})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual(len(resp['availabilityZoneInfo']), 7)
        self.nova_availability_zones.list.assert_called_once()

    def test_regions(self):
        resp = self.execute('DescribeRegions', {})
        self.assertEqual(200, resp['http_status_code'])
        self.assertEqual(resp['regionInfo'][0]['regionName'], 'nova')
        self.assertTrue(resp['regionInfo'][0].get('regionEndpoint')
                        is not None)
