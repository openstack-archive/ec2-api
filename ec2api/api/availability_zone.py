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

from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import common
from ec2api.openstack.common import log as logging
from ec2api import utils


availability_zone_opts = [
    cfg.StrOpt('internal_service_availability_zone',
               default='internal',
               help='The availability_zone to show internal services under'),
    cfg.StrOpt('my_ip',
               default=utils._get_my_ip(),
               help='IP address of this host'),
    cfg.StrOpt('ec2_host',
               default='$my_ip',
               help='The IP address of the EC2 API server'),
    cfg.IntOpt('ec2_port',
               default=8788,
               help='The port of the EC2 API server'),
    cfg.StrOpt('ec2_scheme',
               default='http',
               help='The protocol to use when connecting to the EC2 API '
                    'server (http, https)'),
    cfg.StrOpt('ec2_path',
               default='/services/Cloud',
               help='The path prefix used to call the ec2 API server'),
    cfg.ListOpt('region_list',
                default=[],
                help='List of region=fqdn pairs separated by commas'),
]

CONF = cfg.CONF
CONF.register_opts(availability_zone_opts)
LOG = logging.getLogger(__name__)

"""Availability zones and regions related API implementation
"""


class AvailabilityZoneDescriber(common.UniversalDescriber):

    KIND = 'sg'
    FILTER_MAP = {'state': 'zoneState',
                  'zone-name': 'zoneName'}

    def format(self, item=None, os_item=None):
        return _format_availability_zone(os_item)

    def get_db_items(self):
        return []

    def get_os_items(self):
        nova = clients.nova(self.context)
        zones = nova.availability_zones.list(detailed=False)
        for zone in zones:
            if zone.zoneName == CONF.internal_service_availability_zone:
                zones.remove(zone)
        return zones

    def get_name(self, os_item):
        return os_item.zoneName

    def get_id(self, os_item):
        return ''


def describe_availability_zones(context, zone_name=None, filter=None):
    # NOTE(Alex): Openstack extension, AWS-incompability
    # Checking for 'verbose' in zone_name.
    if zone_name and 'verbose' in zone_name:
        return _describe_verbose(context)

    formatted_availability_zones = AvailabilityZoneDescriber().describe(
        context, names=zone_name, filter=filter)
    return {'availabilityZoneInfo': formatted_availability_zones}


def describe_regions(context, region_name=None, filter=None):
    if CONF.region_list:
        regions = []
        for region in CONF.region_list:
            name, _sep, host = region.partition('=')
            endpoint = '%s://%s:%s%s' % (CONF.ec2_scheme,
                                         host,
                                         CONF.ec2_port,
                                         CONF.ec2_path)
            regions.append({'regionName': name,
                            'regionEndpoint': endpoint})
    else:
        regions = [{'regionName': 'nova',
                    'regionEndpoint': '%s://%s:%s%s' % (CONF.ec2_scheme,
                                                        CONF.ec2_host,
                                                        CONF.ec2_port,
                                                        CONF.ec2_path)}]
    return {'regionInfo': regions}


def _format_availability_zone(zone):
    return {'zoneName': zone.zoneName,
            'zoneState': ('available'
                          if zone.zoneState.get('available')
                          else 'unavailable')
            }


# NOTE(Alex): Openstack extension, AWS-incompability
# The whole function and its result is incompatible with AWS.

def _describe_verbose(context):
    nova = clients.nova(context)
    availability_zones = nova.availability_zones.list()

    formatted_availability_zones = []
    for availability_zone in availability_zones:
        formatted_availability_zones.append(
            _format_availability_zone(availability_zone))
        for host, services in availability_zone.hosts.items():
            formatted_availability_zones.append(
                {'zoneName': '|- %s' % host,
                 'zoneState': ''})
            for service, values in services.items():
                active = ":-)" if values['active'] else "XXX"
                enabled = 'enabled' if values['available'] else 'disabled'
                formatted_availability_zones.append(
                    {'zoneName': '| |- %s' % service,
                     'zoneState': ('%s %s %s' % (enabled, active,
                                                 values['updated_at']))})

    return {'availabilityZoneInfo': formatted_availability_zones}
