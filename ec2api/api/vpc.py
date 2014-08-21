#    Copyright 2014 Cloudscaling Group, Inc
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


from neutronclient.common import exceptions as neutron_exception
from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import ec2utils
from ec2api.api import route_table as route_table_api
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""VPC-object related API implementation
"""


FILTER_MAP = {'cidr': 'cidrBlock',
              'state': 'state',
              'vpc-id': 'vpcId'}


def create_vpc(context, cidr_block, instance_tenancy='default'):
    ec2utils.validate_vpc_cidr(cidr_block, exception.InvalidVpcRange)
    neutron = clients.neutron(context)
    # TODO(Alex): Handle errors like overlimit
    # TODO(ft) dhcp_options_id
    # TODO(ft): refactor to prevent update created objects
    with utils.OnCrashCleaner() as cleaner:
        os_router_body = {'router': {}}
        os_router = neutron.create_router(os_router_body)['router']
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
        vpc_id = ec2utils.get_ec2_id(vpc['id'], 'vpc')
        neutron.update_router(os_router['id'], {'router': {'name': vpc_id}})

    return {'vpc': _format_vpc(vpc)}


def delete_vpc(context, vpc_id):
    vpc = ec2utils.get_db_item(context, 'vpc', vpc_id)
    # TODO(ft): move search by vpc_id to DB api
    if (any(igw.get('vpc_id') == vpc['id']
            for igw in db_api.get_items(context, 'igw')) or
            any(subnet['vpc_id'] == vpc['id']
                for subnet in db_api.get_items(context, 'subnet')) or
            any(rtb['vpc_id'] == vpc['id'] and
                (rtb['id'] != vpc['route_table_id'] or
                 len(rtb['routes']) > 1)
                for rtb in db_api.get_items(context, 'rtb'))):
        msg = _("The vpc '%(vpc_id)s' has dependencies and "
                "cannot be deleted.")
        msg = msg % {'vpc_id': ec2utils.get_ec2_id(vpc['id'], 'vpc')}
        raise exception.DependencyViolation(msg)

    neutron = clients.neutron(context)
    with utils.OnCrashCleaner() as cleaner:
        db_api.delete_item(context, vpc['id'])
        cleaner.addCleanup(db_api.restore_item, context, 'vpc', vpc)
        route_table_api._delete_route_table(context, vpc['route_table_id'],
                                            cleaner=cleaner)
        try:
            neutron.delete_router(vpc['os_id'])
        except neutron_exception.NeutronClientException as ex:
            # TODO(ft): do log error
            # TODO(ft): adjust catched exception classes to catch:
            # the router doesn't exist
            # somewhat plugged to the router
            pass

    return True


def describe_vpcs(context, vpc_id=None, filter=None):
    # TODO(ft): implement filters
    vpcs = ec2utils.get_db_items(context, 'vpc', vpc_id)
    formatted_vpcs = []
    for vpc in vpcs:
        formatted_vpc = _format_vpc(vpc)
        if not utils.filtered_out(formatted_vpc, filter, FILTER_MAP):
            formatted_vpcs.append(formatted_vpc)
    return {'vpcSet': formatted_vpcs}


def _format_vpc(vpc):
    dhcp_options_id = vpc.get('dhcp_options_id', None)
    if dhcp_options_id:
        dhcp_options_id = ec2utils.get_ec2_id(dhcp_options_id, 'dopt')
    else:
        dhcp_options_id = 'default'
    return {'vpcId': ec2utils.get_ec2_id(vpc['id'], 'vpc'),
            'state': "available",
            'cidrBlock': vpc['cidr_block'],
            'isDefault': 'false',
            'dhcpOptionsId': dhcp_options_id
            # 'instanceTenancy': 'default', #TODO(Alex) implement
            }
