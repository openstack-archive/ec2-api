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

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class RegionTest(base.EC2TestCase):

    def test_describe_regions(self):
        data = self.client.describe_regions()
        self.assertNotEmpty(data['Regions'])

        region = CONF.aws.aws_region
        if not region:
            return

        regions = [r['RegionName'] for r in data['Regions']]
        self.assertIn(region, regions)

    def test_describe_zones(self):
        data = self.client.describe_availability_zones()
        self.assertNotEmpty(data['AvailabilityZones'])

        region = CONF.aws.aws_region
        if not region:
            return

        # TODO(andrey-mp): add checking of other fields of returned data
