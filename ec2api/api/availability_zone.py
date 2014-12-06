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


availability_zone_opts = [
    cfg.StrOpt('internal_service_availability_zone',
               default='internal',
               help='The availability_zone to show internal services under'),
    ]

CONF = cfg.CONF
CONF.register_opts(availability_zone_opts)
LOG = logging.getLogger(__name__)

"""Availability zones and regions related API implementation
"""


FILTER_MAP = {'state': 'zoneState',
              'zone-name': 'zoneName'}


def describe_availability_zones(context, zone_name=None, filter=None):
    # NOTE(Alex): Openstack extension, AWS-incompability
    # Checking for 'verbose' in zone_name.
    if zone_name and 'verbose' in zone_name:
        return _describe_verbose(context)

    nova = clients.nova(context)
    availability_zones = nova.availability_zones.list(detailed=False)

    formatted_availability_zones = common.universal_describe(
        context, _format_availability_zone, 'az',
        os_items=availability_zones, describe_all=not zone_name,
        pre_filter_func=_pre_filter_func,
        filter=filter, filter_map=FILTER_MAP,
        **{'item_name': zone_name})
#     formatted_availability_zones = []
#     for availability_zone in availability_zones:
#         # Hide internal_service_availability_zone
#         if availability_zone.zoneName ==
#                 CONF.internal_service_availability_zone:
#             continue
#         formatted_availability_zone = _format_availability_zone(
#             availability_zone)
#         if not utils.filtered_out(formatted_availability_zones, filter,
#                                   FILTER_MAP):
#             formatted_availability_zones.append(formatted_availability_zone)

    # NOTE(Alex): Openstack extension, AWS-incompability
    return {'availabilityZoneInfo': formatted_availability_zones}


def _pre_filter_func(os_item=None, item_name=[], **kwargs):
    return (item_name and os_item.zoneName not in item_name or
            os_item.zoneName ==
                CONF.internal_service_availability_zone)


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


def _format_availability_zone(os_item, **kwargs):
    return {'zoneName': os_item.zoneName,
            'zoneState': ('available'
                          if os_item.zoneState.get('available')
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
