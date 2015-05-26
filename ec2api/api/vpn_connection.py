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

import random
import string

from neutronclient.common import exceptions as neutron_exception
from oslo_log import log as logging

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


LOG = logging.getLogger(__name__)


Validator = common.Validator


SHARED_KEY_CHARS = string.ascii_letters + '_.' + string.digits


def create_vpn_connection(context, customer_gateway_id, vpn_gateway_id,
                          type, options=None):
    if not options or options.get('static_routes_only') is not True:
        raise exception.Unsupported('BGP dynamic routing is unsupported')
    customer_gateway = ec2utils.get_db_item(context, customer_gateway_id)
    vpn_gateway = ec2utils.get_db_item(context, vpn_gateway_id)
    vpn_connection = next(
        (vpn for vpn in db_api.get_items(context, 'vpn')
         if vpn['customer_gateway_id'] == customer_gateway_id),
        None)
    if vpn_connection:
        if vpn_connection['vpn_gateway_id'] == vpn_gateway_id:
            return {'vpnConnection': _format_vpn_connection(vpn_connection)}
        else:
            raise exception.InvalidCustomerGatewayDuplicateIpAddress()
    neutron = clients.neutron(context)
    with common.OnCrashCleaner() as cleaner:
        os_ikepolicy = {'ike_version': 'v1',
                        'auth_algorithm': 'sha1',
                        'encryption_algorithm': 'aes-128',
                        'pfs': 'group2',
                        'phase1_negotiation_mode': 'main',
                        'lifetime': {'units': 'seconds',
                                     'value': 28800}}
        os_ikepolicy = neutron.create_ikepolicy(
            {'ikepolicy': os_ikepolicy})['ikepolicy']
        cleaner.addCleanup(neutron.delete_ikepolicy, os_ikepolicy['id'])

        os_ipsecpolicy = {'transform_protocol': 'esp',
                          'auth_algorithm': 'sha1',
                          'encryption_algorithm': 'aes-128',
                          'pfs': 'group2',
                          'encapsulation_mode': 'tunnel',
                          'lifetime': {'units': 'seconds',
                                       'value': 3600}}
        os_ipsecpolicy = neutron.create_ipsecpolicy(
            {'ipsecpolicy': os_ipsecpolicy})['ipsecpolicy']
        cleaner.addCleanup(neutron.delete_ipsecpolicy, os_ipsecpolicy['id'])

        psk = ''.join(random.choice(SHARED_KEY_CHARS) for _x in xrange(32))
        vpn_connection = db_api.add_item(
             context, 'vpn',
             {'customer_gateway_id': customer_gateway['id'],
              'vpn_gateway_id': vpn_gateway['id'],
              'pre_shared_key': psk,
              'os_ikepolicy_id': os_ikepolicy['id'],
              'os_ipsecpolicy_id': os_ipsecpolicy['id'],
              'cidrs': [],
              'os_ipsec_site_connections': {}})
        cleaner.addCleanup(db_api.delete_item, context, vpn_connection['id'])

        neutron.update_ikepolicy(
            os_ikepolicy['id'], {'ikepolicy': {'name': vpn_connection['id']}})
        neutron.update_ipsecpolicy(
            os_ipsecpolicy['id'],
            {'ipsecpolicy': {'name': vpn_connection['id']}})

        _reset_vpn_connections(context, neutron, cleaner,
                               vpn_gateway, vpn_connections=[vpn_connection])

    return {'vpnConnection': _format_vpn_connection(vpn_connection)}


def create_vpn_connection_route(context, vpn_connection_id,
                                destination_cidr_block):
    vpn_connection = ec2utils.get_db_item(context, vpn_connection_id)
    if destination_cidr_block in vpn_connection['cidrs']:
        return True
    neutron = clients.neutron(context)
    vpn_gateway = db_api.get_item_by_id(context, vpn_connection_id)
    with common.OnCrashCleaner() as cleaner:
        _add_cidr_to_vpn_connection_item(context, vpn_connection,
                                         destination_cidr_block)
        cleaner.addCleanup(_remove_cidr_from_vpn_connection_item,
                           context, vpn_connection, destination_cidr_block)

        _reset_vpn_connections(context, neutron, cleaner,
                               vpn_gateway, [vpn_connection])

    return True


def delete_vpn_connection_route(context, vpn_connection_id,
                                destination_cidr_block):
    vpn_connection = ec2utils.get_db_item(context, vpn_connection_id)
    if destination_cidr_block not in vpn_connection['cidrs']:
        raise exception.InvalidRouteNotFound(
            _('The specified route %(destination_cidr_block)s does not exist')
            % {'destination_cidr_block': destination_cidr_block})
    neutron = clients.neutron(context)
    vpn_gateway = db_api.get_item_by_id(context, vpn_connection_id)
    with common.OnCrashCleaner() as cleaner:
        _remove_cidr_from_vpn_connection_item(context, vpn_connection,
                                              destination_cidr_block)
        cleaner.addCleanup(_add_cidr_to_vpn_connection_item,
                           context, vpn_connection, destination_cidr_block)

        _reset_vpn_connections(context, neutron, cleaner,
                               vpn_gateway, [vpn_connection])

    return True


def delete_vpn_connection(context, vpn_connection_id):
    vpn_connection = ec2utils.get_db_item(context, vpn_connection_id)
    with common.OnCrashCleaner() as cleaner:
        db_api.delete_item(context, vpn_connection['id'])
        cleaner.addCleanup(db_api.restore_item, context, 'vpn', vpn_connection)
        neutron = clients.neutron(context)
        _stop_vpn_connection(neutron, vpn_connection)
        try:
            neutron.delete_ipsecpolicy(vpn_connection['os_ipsecpolicy_id'])
        except neutron_exception.Conflict as ex:
            LOG.warning(
                _('Failed to delete ipsecoplicy %(os_id)s during deleting '
                  'VPN connection %(id)s. Reason: %(reason)s'),
                {'id': vpn_connection['id'],
                 'os_id': vpn_connection['os_ipsecpolicy_id'],
                 'reason': ex.message})
        except neutron_exception.NotFound:
            pass
        try:
            neutron.delete_ikepolicy(vpn_connection['os_ikepolicy_id'])
        except neutron_exception.Conflict as ex:
            LOG.warning(
                _('Failed to delete ikepolicy %(os_id)s during deleting '
                  'VPN connection %(id)s. Reason: %(reason)s'),
                {'id': vpn_connection['id'],
                 'os_id': vpn_connection['os_ikepolicy_id'],
                 'reason': ex.message})
        except neutron_exception.NotFound:
            pass
    return True


def describe_vpn_connections(context, vpn_connection_id=None, filter=None):
    formatted_vpn_connections = VpnConnectionDescriber().describe(
        context, ids=vpn_connection_id, filter=filter)
    return {'vpnConnectionSet': formatted_vpn_connections}


class VpnConnectionDescriber(common.TaggableItemsDescriber,
                             common.NonOpenstackItemsDescriber):

    KIND = 'vpn'
    FILTER_MAP = {'customer-gateway-id': 'customerGatewayId',
                  'state': 'state',
                  'option.static-routes-only': ('options', 'staticRoutesOnly'),
                  'route.destination-cidr-block': ['routes',
                                                   'destination_cidr_block'],
                  'type': 'type',
                  'vpn-connection-id': 'vpnConnectionId',
                  'vpn-gateway-id': 'vpnGatewayId'}

    def format(self, vpn_connection):
        return _format_vpn_connection(vpn_connection)


def _format_vpn_connection(vpn_connection):
    return {'vpnConnectionId': vpn_connection['id'],
            'vpnGatewayId': vpn_connection['vpn_gateway_id'],
            'customerGatewayId': vpn_connection['customer_gateway_id'],
            'state': 'available',
            'type': 'ipsec.1',
            'routes': [{'destination_cidr_block': cidr,
                        'state': 'available'}
                       for cidr in vpn_connection['cidrs']],
            'vgwTelemetry': [],
            'options': {'staticRoutesOnly': True}}


def _stop_vpn_connection(neutron, vpn_connection):
    connection_ids = vpn_connection['os_ipsec_site_connections']
    for os_connection_id in connection_ids.itervalues():
        try:
            neutron.delete_ipsec_site_connection(os_connection_id)
        except neutron_exception.NotFound:
            pass


def _stop_gateway_vpn_connections(context, neutron, cleaner, vpn_gateway):
    def undo_vpn_connection(context, vpn_connection, connections_ids):
        vpn_connection['os_ipsec_site_connections'] = connections_ids
        db_api.update_item(context, vpn_connection)

    for vpn_connection in db_api.get_items(context, 'vpn'):
        if vpn_connection['vpn_gateway_id'] == vpn_gateway['id']:
            _stop_vpn_connection(neutron, vpn_connection)

            connection_ids = vpn_connection['os_ipsec_site_connections']
            vpn_connection['os_ipsec_site_connections'] = {}
            db_api.update_item(context, vpn_connection)
            cleaner.addCleanup(undo_vpn_connection, context, vpn_connection,
                               connection_ids)


def _update_vpn_routes(context, neutron, cleaner, route_table, subnets):
    vpn_gateway = ec2utils.get_attached_gateway(
        context, route_table['vpc_id'], 'vgw')
    if not vpn_gateway:
        return
    _reset_vpn_connections(context, neutron, cleaner, vpn_gateway,
                           route_tables=[route_table], subnets=subnets)


def _reset_vpn_connections(context, neutron, cleaner, vpn_gateway,
                           subnets=None, route_tables=None,
                           vpn_connections=None):
    if not vpn_gateway['vpc_id']:
        return
    # TODO(ft): implement search filters in DB api
    vpn_connections = (vpn_connections or
                       [vpn for vpn in db_api.get_items(context, 'vpn')
                        if vpn['vpn_gateway_id'] == vpn_gateway['id']])
    if not vpn_connections:
        return
    subnets = (subnets or
               [subnet for subnet in db_api.get_items(context, 'subnet')
                if subnet['vpc_id'] == vpn_gateway['vpc_id']])
    if not subnets:
        return
    vpc = db_api.get_item_by_id(context, vpn_gateway['vpc_id'])
    customer_gateways = {cgw['id']: cgw
                         for cgw in db_api.get_items(context, 'cgw')}
    route_tables = route_tables or db_api.get_items(context, 'rtb')
    route_tables = {rtb['id']: rtb
                    for rtb in route_tables
                    if rtb['vpc_id'] == vpc['id']}
    route_tables_cidrs = {}
    for subnet in subnets:
        route_table_id = subnet.get('route_table_id', vpc['route_table_id'])
        if route_table_id not in route_tables_cidrs:
            route_tables_cidrs[route_table_id] = (
                _get_route_table_vpn_cidrs(route_tables[route_table_id],
                                           vpn_gateway, vpn_connections))
        cidrs = route_tables_cidrs[route_table_id]
        for vpn_conn in vpn_connections:
            if vpn_conn['id'] in cidrs:
                _set_subnet_vpn(
                    context, neutron, cleaner, subnet, vpn_conn,
                    customer_gateways[vpn_conn['customer_gateway_id']],
                    cidrs[vpn_conn['id']])
            else:
                _delete_subnet_vpn(context, neutron, cleaner, subnet, vpn_conn)


def _set_subnet_vpn(context, neutron, cleaner, subnet, vpn_connection,
                    customer_gateway, cidrs):
    subnets_connections = vpn_connection['os_ipsec_site_connections']
    os_connection_id = subnets_connections.get(subnet['id'])
    if os_connection_id:
        # TODO(ft): restore original peer_cidrs on crash
        neutron.update_ipsec_site_connection(
            os_connection_id,
            {'ipsec_site_connection': {'peer_cidrs': cidrs}})
    else:
        os_connection = {
            'vpnservice_id': subnet['os_vpnservice_id'],
            'ikepolicy_id': vpn_connection['os_ikepolicy_id'],
            'ipsecpolicy_id': vpn_connection['os_ipsecpolicy_id'],
            'peer_address': customer_gateway['ip_address'],
            'peer_cidrs': cidrs,
            'psk': vpn_connection['pre_shared_key'],
            'name': '%s/%s' % (vpn_connection['id'], subnet['id']),
            'peer_id': customer_gateway['ip_address'],
            'mtu': 1387 + 40,  # AWS MSS + 20 byte IP and 20 byte TCP headers
            'initiator': 'response-only',
        }
        os_connection = (neutron.create_ipsec_site_connection(
            {'ipsec_site_connection': os_connection})
            ['ipsec_site_connection'])
        cleaner.addCleanup(neutron.delete_ipsec_site_connection,
                           os_connection['id'])

        _add_subnet_connection_to_vpn_connection_item(
            context, vpn_connection, subnet['id'], os_connection['id'])
        cleaner.addCleanup(_remove_subnet_connection_from_vpn_connection_item,
                           context, vpn_connection, subnet['id'])


def _delete_subnet_vpn(context, neutron, cleaner, subnet, vpn_connection):
    subnets_connections = vpn_connection['os_ipsec_site_connections']
    os_connection_id = subnets_connections.get(subnet['id'])
    if not os_connection_id:
        return

    _remove_subnet_connection_from_vpn_connection_item(
        context, vpn_connection, subnet['id'])
    cleaner.addCleanup(_add_subnet_connection_to_vpn_connection_item,
                       context, vpn_connection, subnet['id'], os_connection_id)
    try:
        neutron.delete_ipsec_site_connection(os_connection_id)
    except neutron_exception.NotFound:
        pass


def _get_route_table_vpn_cidrs(route_table, vpn_gateway, vpn_connections):
    static_cidrs = [route['destination_cidr_block']
                    for route in route_table['routes']
                    if route.get('gateway_id') == vpn_gateway['id']]
    is_propagation_enabled = (
        vpn_gateway['id'] in route_table.get('propagating_gateways', []))
    vpn_cidrs = {}
    for vpn in vpn_connections:
        if is_propagation_enabled:
            cidrs = list(set(static_cidrs + vpn['cidrs']))
        else:
            cidrs = static_cidrs
        if cidrs:
            vpn_cidrs[vpn['id']] = cidrs
    return vpn_cidrs


def _add_cidr_to_vpn_connection_item(context, vpn_connection, cidr):
    vpn_connection['cidrs'].append(cidr)
    db_api.update_item(context, vpn_connection)


def _remove_cidr_from_vpn_connection_item(context, vpn_connection, cidr):
    vpn_connection['cidrs'].remove(cidr)
    db_api.update_item(context, vpn_connection)


def _add_subnet_connection_to_vpn_connection_item(context, vpn_connection,
                                                  subnet_id, os_connection_id):
    vpn_connection['os_ipsec_site_connections'][subnet_id] = os_connection_id
    db_api.update_item(context, vpn_connection)


def _remove_subnet_connection_from_vpn_connection_item(context, vpn_connection,
                                                       subnet_id):
    del vpn_connection['os_ipsec_site_connections'][subnet_id]
    db_api.update_item(context, vpn_connection)
