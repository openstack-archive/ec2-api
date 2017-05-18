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

import functools

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import netutils

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api import clients
from ec2api import exception


availability_zone_opts = [
    cfg.StrOpt('internal_service_availability_zone',
               default='internal',
               help='The availability_zone to show internal services under'),
    cfg.StrOpt('my_ip',
               default=netutils.get_my_ipv4(),
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
               default='/',
               help='The path prefix used to call the ec2 API server'),
    cfg.ListOpt('region_list',
                default=[],
                help='List of region=fqdn pairs separated by commas'),
]

CONF = cfg.CONF
CONF.register_opts(availability_zone_opts)
LOG = logging.getLogger(__name__)

"""Availability zones, regions, account attributes related API implementation
"""


Validator = common.Validator


def get_account_attribute_engine():
    return AccountAttributeEngineNeutron()


class AvailabilityZoneDescriber(common.UniversalDescriber):

    KIND = 'az'
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

    def auto_update_db(self, item, os_item):
        pass


def describe_availability_zones(context, zone_name=None, filter=None):
    # NOTE(Alex): Openstack extension, AWS-incompability
    # Checking for 'verbose' in zone_name.
    if zone_name and 'verbose' in zone_name:
        return _describe_verbose(context)

    formatted_availability_zones = AvailabilityZoneDescriber().describe(
        context, names=zone_name, filter=filter)
    return {'availabilityZoneInfo': formatted_availability_zones}


def describe_regions(context, region_name=None, filter=None):
    # TODO(andrey-mp): collect regions from keystone catalog
    if CONF.region_list:
        regions = []
        for region in CONF.region_list:
            name, _sep, host = region.partition('=')
            if not host:
                host = CONF.ec2_host
            endpoint = '%s://%s:%s%s' % (CONF.ec2_scheme,
                                         host,
                                         CONF.ec2_port,
                                         CONF.ec2_path)
            regions.append({'regionName': name,
                            'regionEndpoint': endpoint})
    else:
        # NOTE(andrey-mp): RegionOne is a default region name that is used
        # in keystone, nova and some other projects
        regions = [{'regionName': 'RegionOne',
                    'regionEndpoint': '%s://%s:%s%s' % (CONF.ec2_scheme,
                                                        CONF.ec2_host,
                                                        CONF.ec2_port,
                                                        CONF.ec2_path)}]
    return {'regionInfo': regions}


def describe_account_attributes(context, attribute_name=None):
    def get_max_instances():
        nova = clients.nova(context)
        quotas = nova.quotas.get(context.project_id, context.user_id)
        return quotas.instances

    attribute_getters = {
        'supported-platforms': (
            account_attribute_engine.get_supported_platforms),
        'default-vpc': functools.partial(
            account_attribute_engine.get_default_vpc, context),
        'max-instances': get_max_instances,
    }

    formatted_attributes = []
    for attribute in (attribute_name or attribute_getters):
        if attribute not in attribute_getters:
            raise exception.InvalidParameter(name=attribute)
        formatted_attributes.append(
            _format_account_attribute(attribute,
                                      attribute_getters[attribute]()))
    return {'accountAttributeSet': formatted_attributes}


def _format_availability_zone(zone):
    return {'zoneName': zone.zoneName,
            'zoneState': ('available'
                          if zone.zoneState.get('available')
                          else 'unavailable')
            }


def _format_account_attribute(attribute, value):
    if not isinstance(value, list):
        value = [value]
    return {'attributeName': attribute,
            'attributeValueSet': [{'attributeValue': val} for val in value]}


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


class AccountAttributeEngineNeutron(object):

    def get_supported_platforms(self):
        if CONF.disable_ec2_classic:
            return ['VPC']
        else:
            return ['EC2', 'VPC']

    def get_default_vpc(self, context):
        if CONF.disable_ec2_classic:
            default_vpc = ec2utils.check_and_create_default_vpc(context)
            if default_vpc:
                return default_vpc['id']
        return 'none'


account_attribute_engine = get_account_attribute_engine()
