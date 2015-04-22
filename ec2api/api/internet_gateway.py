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

"""
Cloud Controller: Implementation of EC2 REST API calls, which are
dispatched to other nodes via AMQP RPC. State is via distributed
datastore.
"""

from neutronclient.common import exceptions as neutron_exception
from oslo_log import log as logging

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _

LOG = logging.getLogger(__name__)

"""Internet gateway related API implementation
"""


Validator = common.Validator


def create_internet_gateway(context):
    igw = db_api.add_item(context, 'igw', {})
    return {'internet_gateway': _format_internet_gateway(igw)}


def attach_internet_gateway(context, internet_gateway_id, vpc_id):
    igw = ec2utils.get_db_item(context, internet_gateway_id)
    if igw.get('vpc_id'):
        msg_params = {'igw_id': igw['id'],
                      'vpc_id': igw['vpc_id']}
        msg = _("resource %(igw_id)s is already attached to "
                "network %(vpc_id)s") % msg_params
        raise exception.ResourceAlreadyAssociated(msg)
    vpc = ec2utils.get_db_item(context, vpc_id)
    # TODO(ft): move search by vpc_id to DB api
    for gw in db_api.get_items(context, 'igw'):
        if gw.get('vpc_id') == vpc['id']:
            msg = _("Network %(vpc_id)s already has an internet gateway "
                    "attached") % {'vpc_id': vpc['id']}
            raise exception.InvalidParameterValue(msg)

    os_public_network = ec2utils.get_os_public_network(context)
    neutron = clients.neutron(context)

    # TODO(ft): set attaching state into db
    with common.OnCrashCleaner() as cleaner:
        _attach_internet_gateway_item(context, igw, vpc['id'])
        cleaner.addCleanup(_detach_internet_gateway_item, context, igw)
        neutron.add_gateway_router(vpc['os_id'],
                                   {'network_id': os_public_network['id']})
    return True


def detach_internet_gateway(context, internet_gateway_id, vpc_id):
    igw = ec2utils.get_db_item(context, internet_gateway_id)
    vpc = ec2utils.get_db_item(context, vpc_id)
    if igw.get('vpc_id') != vpc['id']:
        raise exception.GatewayNotAttached(igw_id=igw['id'],
                                           vpc_id=vpc['id'])

    neutron = clients.neutron(context)
    # TODO(ft): set detaching state into db
    with common.OnCrashCleaner() as cleaner:
        _detach_internet_gateway_item(context, igw)
        cleaner.addCleanup(_attach_internet_gateway_item,
                           context, igw, vpc['id'])
        try:
            neutron.remove_gateway_router(vpc["os_id"])
        except neutron_exception.NotFound:
            pass
    return True


def delete_internet_gateway(context, internet_gateway_id):
    igw = ec2utils.get_db_item(context, internet_gateway_id)
    if igw.get('vpc_id'):
        msg = _("The internetGateway '%(igw_id)s' has dependencies and "
                "cannot be deleted.") % {'igw_id': igw['id']}
        raise exception.DependencyViolation(msg)
    db_api.delete_item(context, igw['id'])
    return True


class InternetGatewayDescriber(common.TaggableItemsDescriber,
                               common.NonOpenstackItemsDescriber):

    KIND = 'igw'
    FILTER_MAP = {'internet-gateway-id': 'internetGatewayId',
                  'attachment.state': ['attachmentSet', 'state'],
                  'attachment.vpc-id': ['attachmentSet', 'vpcId']}

    def format(self, igw):
        return _format_internet_gateway(igw)


def describe_internet_gateways(context, internet_gateway_id=None,
                               filter=None):
    formatted_igws = InternetGatewayDescriber().describe(
            context, ids=internet_gateway_id, filter=filter)
    return {'internetGatewaySet': formatted_igws}


def _format_internet_gateway(igw):
    ec2_igw = {'internetGatewayId': igw['id'],
               'attachmentSet': []}
    if igw.get('vpc_id'):
        # NOTE(ft): AWS actually returns 'available' state rather than
        # documented 'attached' one
        attachment_state = 'available'
        attachment = {'vpcId': igw['vpc_id'],
                      'state': attachment_state}
        ec2_igw['attachmentSet'].append(attachment)
    return ec2_igw


def _attach_internet_gateway_item(context, igw, vpc_id):
    igw['vpc_id'] = vpc_id
    db_api.update_item(context, igw)


def _detach_internet_gateway_item(context, igw):
    igw['vpc_id'] = None
    db_api.update_item(context, igw)
