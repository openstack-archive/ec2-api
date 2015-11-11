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


from neutronclient.common import exceptions as neutron_exception
from oslo_config import cfg
from oslo_log import log as logging

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import internet_gateway as internet_gateway_api
from ec2api.api import route_table as route_table_api
from ec2api.api import security_group as security_group_api
from ec2api.api import subnet as subnet_api
from ec2api.api import vpn_gateway as vpn_gateway_api
from ec2api import clients
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""VPC-object related API implementation
"""


Validator = common.Validator


def create_vpc(context, cidr_block, instance_tenancy='default'):
    neutron = clients.neutron(context)
    with common.OnCrashCleaner() as cleaner:
        os_router_body = {'router': {}}
        try:
            os_router = neutron.create_router(os_router_body)['router']
        except neutron_exception.OverQuotaClient:
            raise exception.VpcLimitExceeded()
        cleaner.addCleanup(neutron.delete_router, os_router['id'])
        vpc = db_api.add_item(context, 'vpc',
                              {'os_id': os_router['id'],
                               'cidr_block': cidr_block})
        cleaner.addCleanup(db_api.delete_item, context, vpc['id'])
        route_table = route_table_api._create_route_table(context, vpc)
        cleaner.addCleanup(route_table_api._delete_route_table,
                           context, route_table['id'])
        vpc['route_table_id'] = route_table['id']
        db_api.update_item(context, vpc)
        neutron.update_router(os_router['id'], {'router': {'name': vpc['id']}})
        security_group_api._create_default_security_group(context, vpc)
    return {'vpc': _format_vpc(vpc)}


def delete_vpc(context, vpc_id):
    vpc = ec2utils.get_db_item(context, vpc_id)
    subnets = subnet_api.describe_subnets(
        context,
        filter=[{'name': 'vpc-id', 'value': [vpc_id]}])['subnetSet']
    internet_gateways = internet_gateway_api.describe_internet_gateways(
        context,
        filter=[{'name': 'attachment.vpc-id',
                 'value': [vpc['id']]}])['internetGatewaySet']
    route_tables = route_table_api.describe_route_tables(
        context,
        filter=[{'name': 'vpc-id', 'value': [vpc['id']]}])['routeTableSet']
    security_groups = security_group_api.describe_security_groups(
        context,
        filter=[{'name': 'vpc-id',
                 'value': [vpc['id']]}])['securityGroupInfo']
    vpn_gateways = vpn_gateway_api.describe_vpn_gateways(
        context,
        filter=[{'name': 'attachment.vpc-id',
                 'value': [vpc['id']]}])['vpnGatewaySet']
    if (subnets or internet_gateways or len(route_tables) > 1 or
            len(security_groups) > 1 or vpn_gateways):
        msg = _("The vpc '%(vpc_id)s' has dependencies and "
                "cannot be deleted.")
        msg = msg % {'vpc_id': vpc['id']}
        raise exception.DependencyViolation(msg)

    neutron = clients.neutron(context)
    with common.OnCrashCleaner() as cleaner:
        db_api.delete_item(context, vpc['id'])
        cleaner.addCleanup(db_api.restore_item, context, 'vpc', vpc)
        route_table_api._delete_route_table(context, vpc['route_table_id'],
                                            cleaner=cleaner)
        if len(security_groups) > 0:
            security_group_api.delete_security_group(
                context, group_id=security_groups[0]['groupId'],
                delete_default=True)
        try:
            neutron.delete_router(vpc['os_id'])
        except neutron_exception.Conflict as ex:
            LOG.warning(_('Failed to delete router %(os_id)s during deleting '
                          'VPC %(id)s. Reason: %(reason)s'),
                        {'id': vpc['id'],
                         'os_id': vpc['os_id'],
                         'reason': ex.message})
        except neutron_exception.NotFound:
            pass

    return True


class VpcDescriber(common.TaggableItemsDescriber,
                   common.NonOpenstackItemsDescriber):

    KIND = 'vpc'
    FILTER_MAP = {'cidr': 'cidrBlock',
                  'dhcp-options-id': 'dhcpOptionsId',
                  'is-default': 'isDefault',
                  'state': 'state',
                  'vpc-id': 'vpcId'}

    def format(self, item=None, os_item=None):
        return _format_vpc(item)


def describe_vpcs(context, vpc_id=None, filter=None):
    formatted_vpcs = VpcDescriber().describe(
        context, ids=vpc_id, filter=filter)
    return {'vpcSet': formatted_vpcs}


def _format_vpc(vpc):
    return {'vpcId': vpc['id'],
            'state': "available",
            'cidrBlock': vpc['cidr_block'],
            'isDefault': False,
            'dhcpOptionsId': vpc.get('dhcp_options_id', 'default'),
            }
