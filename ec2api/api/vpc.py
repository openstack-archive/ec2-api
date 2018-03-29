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
from oslo_concurrency import lockutils
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

synchronized = lockutils.synchronized_with_prefix('ec2api-')


"""VPC-object related API implementation
"""


Validator = common.Validator

DEFAULT_VPC_CIDR_BLOCK = '172.31.0.0/16'
DEFAULT_SUBNET_CIDR_BLOCK = '172.31.0.0/20'


def create_vpc(context, cidr_block, instance_tenancy='default'):
    vpc = _create_vpc(context, cidr_block)
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
            LOG.warning('Failed to delete router %(os_id)s during deleting '
                        'VPC %(id)s. Reason: %(reason)s',
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
    _check_and_create_default_vpc(context)
    formatted_vpcs = VpcDescriber().describe(
        context, ids=vpc_id, filter=filter)
    return {'vpcSet': formatted_vpcs}


def _create_vpc(context, cidr_block, is_default=False):
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
                               'cidr_block': cidr_block,
                               'is_default': is_default})
        cleaner.addCleanup(db_api.delete_item, context, vpc['id'])
        route_table = route_table_api._create_route_table(context, vpc)
        cleaner.addCleanup(route_table_api._delete_route_table,
                           context, route_table['id'])
        vpc['route_table_id'] = route_table['id']
        db_api.update_item(context, vpc)
        neutron.update_router(os_router['id'], {'router': {'name': vpc['id']}})
        sg_id = security_group_api._create_default_security_group(context, vpc)
        cleaner.addCleanup(security_group_api.delete_security_group, context,
                           group_id=sg_id, delete_default=True)
        if is_default:
            igw_id = internet_gateway_api.create_internet_gateway(
                context)['internetGateway']['internetGatewayId']
            cleaner.addCleanup(internet_gateway_api.delete_internet_gateway,
                               context, igw_id)
            internet_gateway_api.attach_internet_gateway(context, igw_id,
                                                         vpc['id'])
            cleaner.addCleanup(internet_gateway_api.detach_internet_gateway,
                               context, igw_id, vpc['id'])
            subnet = subnet_api.create_subnet(
                context, vpc['id'],
                DEFAULT_SUBNET_CIDR_BLOCK)['subnet']
            cleaner.addCleanup(subnet_api.delete_subnet, context,
                               subnet['subnetId'])
            route_table_api.create_route(context, route_table['id'],
                                         '0.0.0.0/0', gateway_id=igw_id)
    return vpc


def _check_and_create_default_vpc(context):
    if not CONF.disable_ec2_classic or context.is_os_admin:
        return

    lock_name = 'default-vpc-lock-{}-'.format(context.project_id)

    @synchronized(lock_name, external=True)
    def _check():
        for vpc in db_api.get_items(context, 'vpc'):
            if vpc.get('is_default'):
                return vpc
        try:
            default_vpc = _create_vpc(context, DEFAULT_VPC_CIDR_BLOCK,
                                      is_default=True)
            return default_vpc
        except Exception:
            LOG.exception('Failed to create default vpc')
        return None

    return _check()


ec2utils.set_check_and_create_default_vpc(_check_and_create_default_vpc)


def _format_vpc(vpc):
    return {'vpcId': vpc['id'],
            'state': "available",
            'cidrBlock': vpc['cidr_block'],
            'isDefault': vpc.get('is_default', False),
            'dhcpOptionsId': vpc.get('dhcp_options_id', 'default'),
            }
