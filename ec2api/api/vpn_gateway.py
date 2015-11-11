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
from oslo_log import log as logging

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import vpn_connection as vpn_connection_api
from ec2api import clients
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


LOG = logging.getLogger(__name__)


"""VPN gateways related API implementation
"""


Validator = common.Validator


def create_vpn_gateway(context, type, availability_zone=None):
    vpn_gateway = db_api.add_item(context, 'vgw', {})
    return {'vpnGateway': _format_vpn_gateway(vpn_gateway)}


def attach_vpn_gateway(context, vpc_id, vpn_gateway_id):
    vpn_gateway = ec2utils.get_db_item(context, vpn_gateway_id)
    vpc = ec2utils.get_db_item(context, vpc_id)
    if vpn_gateway['vpc_id'] and vpn_gateway['vpc_id'] != vpc['id']:
        raise exception.VpnGatewayAttachmentLimitExceeded()
    attached_vgw = ec2utils.get_attached_gateway(context, vpc['id'], 'vgw')
    if attached_vgw and attached_vgw['id'] != vpn_gateway['id']:
        raise exception.InvalidVpcState(vpc_id=vpc['id'],
                                        vgw_id=attached_vgw['id'])

    subnets = [subnet for subnet in db_api.get_items(context, 'subnet')
               if subnet['vpc_id'] == vpc['id']]
    if not vpn_gateway['vpc_id']:
        external_network_id = None
        if not ec2utils.get_attached_gateway(context, vpc['id'], 'igw'):
            external_network_id = ec2utils.get_os_public_network(context)['id']
        neutron = clients.neutron(context)

        with common.OnCrashCleaner() as cleaner:
            _attach_vpn_gateway_item(context, vpn_gateway, vpc['id'])
            cleaner.addCleanup(_detach_vpn_gateway_item, context, vpn_gateway)

            if external_network_id:
                neutron.add_gateway_router(vpc['os_id'],
                                           {'network_id': external_network_id})
                cleaner.addCleanup(neutron.remove_gateway_router, vpc['os_id'])

            for subnet in subnets:
                _create_subnet_vpnservice(context, neutron, cleaner,
                                          subnet, vpc)
            vpn_connection_api._reset_vpn_connections(
                context, neutron, cleaner, vpn_gateway, subnets=subnets)

    return {'attachment': _format_attachment(vpn_gateway)}


def detach_vpn_gateway(context, vpc_id, vpn_gateway_id):
    vpn_gateway = ec2utils.get_db_item(context, vpn_gateway_id)
    if vpn_gateway['vpc_id'] != vpc_id:
        raise exception.InvalidVpnGatewayAttachmentNotFound(
            vgw_id=vpn_gateway_id, vpc_id=vpc_id)

    vpc = db_api.get_item_by_id(context, vpc_id)
    neutron = clients.neutron(context)
    remove_os_gateway_router = (
        ec2utils.get_attached_gateway(context, vpc_id, 'igw') is None)
    subnets = [subnet for subnet in db_api.get_items(context, 'subnet')
               if subnet['vpc_id'] == vpc['id']]
    with common.OnCrashCleaner() as cleaner:
        _detach_vpn_gateway_item(context, vpn_gateway)
        cleaner.addCleanup(_attach_vpn_gateway_item, context, vpn_gateway,
                           vpc_id)
        vpn_connection_api._stop_gateway_vpn_connections(
            context, neutron, cleaner, vpn_gateway)
        for subnet in subnets:
            _delete_subnet_vpnservice(context, neutron, cleaner, subnet)

        if remove_os_gateway_router:
            try:
                neutron.remove_gateway_router(vpc['os_id'])
            except neutron_exception.NotFound:
                pass

    return True


def delete_vpn_gateway(context, vpn_gateway_id):
    vpn_gateway = ec2utils.get_db_item(context, vpn_gateway_id)
    vpn_connections = db_api.get_items(context, 'vpn')
    if vpn_gateway['vpc_id'] or any(vpn['vpn_gateway_id'] == vpn_gateway['id']
                                    for vpn in vpn_connections):
        raise exception.IncorrectState(reason=_('The VPN gateway is in use.'))
    db_api.delete_item(context, vpn_gateway['id'])
    return True


def describe_vpn_gateways(context, vpn_gateway_id=None, filter=None):
    formatted_vgws = VpnGatewayDescriber().describe(
        context, ids=vpn_gateway_id, filter=filter)
    return {'vpnGatewaySet': formatted_vgws}


class VpnGatewayDescriber(common.TaggableItemsDescriber,
                          common.NonOpenstackItemsDescriber):

    KIND = 'vgw'
    FILTER_MAP = {'attachment.state': ['attachments', 'state'],
                  'attachment.vpc-id': ['attachments', 'vpcId'],
                  'state': 'state',
                  'type': 'type',
                  'vpn-gateway-id': 'vpnGatewayId'}

    def format(self, vpn_gateway):
        return _format_vpn_gateway(vpn_gateway)


def _format_vpn_gateway(vpn_gateway):
    ec2_vgw = {'vpnGatewayId': vpn_gateway['id'],
               'state': 'available',
               'type': 'ipsec.1',
               'attachments': []}
    if vpn_gateway['vpc_id']:
        ec2_vgw['attachments'].append(_format_attachment(vpn_gateway))
    return ec2_vgw


def _format_attachment(vpn_gateway):
    return {'state': 'attached',
            'vpcId': vpn_gateway['vpc_id']}


def _start_vpn_in_subnet(context, neutron, cleaner, subnet, vpc, route_table):
    vpn_gateway = ec2utils.get_attached_gateway(context, vpc['id'], 'vgw')
    if not vpn_gateway:
        return
    _create_subnet_vpnservice(context, neutron, cleaner, subnet, vpc)
    vpn_connection_api._reset_vpn_connections(context, neutron, cleaner,
                                              vpn_gateway, subnets=[subnet],
                                              route_tables=[route_table])


def _stop_vpn_in_subnet(context, neutron, cleaner, subnet):
    os_vpnservice_id = subnet.get('os_vpnservice_id')
    if not os_vpnservice_id:
        return
    for vpn in db_api.get_items(context, 'vpn'):
        vpn_connection_api._delete_subnet_vpn(context, neutron, cleaner,
                                              subnet, vpn)
    _safe_delete_vpnservice(neutron, os_vpnservice_id, subnet['id'])


def _create_subnet_vpnservice(context, neutron, cleaner, subnet, vpc):
    os_vpnservice = {'subnet_id': subnet['os_id'],
                     'router_id': vpc['os_id'],
                     'name': subnet['id']}
    os_vpnservice = neutron.create_vpnservice(
        {'vpnservice': os_vpnservice})['vpnservice']
    cleaner.addCleanup(neutron.delete_vpnservice, os_vpnservice['id'])

    _set_vpnservice_in_subnet_item(context, subnet, os_vpnservice['id'])
    cleaner.addCleanup(_clear_vpnservice_in_subnet_item,
                       context, subnet)


def _delete_subnet_vpnservice(context, neutron, cleaner, subnet):
    os_vpnservice_id = subnet['os_vpnservice_id']
    _clear_vpnservice_in_subnet_item(context, subnet)
    cleaner.addCleanup(_set_vpnservice_in_subnet_item,
                       context, subnet, os_vpnservice_id)
    _safe_delete_vpnservice(neutron, os_vpnservice_id, subnet['id'])


def _safe_delete_vpnservice(neutron, os_vpnservice_id, subnet_id):
    try:
        neutron.delete_vpnservice(os_vpnservice_id)
    except neutron_exception.NotFound:
        pass
    except neutron_exception.Conflict as ex:
        LOG.warning(
            _('Failed to delete vpnservice %(os_id)s for subnet %(id)s. '
              'Reason: %(reason)s'),
            {'id': subnet_id,
             'os_id': os_vpnservice_id,
             'reason': ex.message})


def _attach_vpn_gateway_item(context, vpn_gateway, vpc_id):
    vpn_gateway['vpc_id'] = vpc_id
    db_api.update_item(context, vpn_gateway)


def _detach_vpn_gateway_item(context, vpn_gateway):
    vpn_gateway['vpc_id'] = None
    db_api.update_item(context, vpn_gateway)


def _set_vpnservice_in_subnet_item(context, subnet, os_vpnservice_id):
    subnet['os_vpnservice_id'] = os_vpnservice_id
    db_api.update_item(context, subnet)


def _clear_vpnservice_in_subnet_item(context, subnet):
    del subnet['os_vpnservice_id']
    db_api.update_item(context, subnet)
