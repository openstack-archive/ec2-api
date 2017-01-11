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

import collections
import copy

import netaddr
from novaclient import exceptions as nova_exception
import six

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import vpn_connection as vpn_connection_api
from ec2api import clients
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


HOST_TARGET = 'host'
VPN_TARGET = 'vpn'


"""Route tables related API implementation
"""


class Validator(common.Validator):

    def igw_or_vgw_id(self, id):
        self.ec2_id(id, ['igw', 'vgw'])


def create_route_table(context, vpc_id):
    vpc = ec2utils.get_db_item(context, vpc_id)
    route_table = _create_route_table(context, vpc)
    return {'routeTable': _format_route_table(context, route_table,
                                              is_main=False)}


def create_route(context, route_table_id, destination_cidr_block,
                 gateway_id=None, instance_id=None,
                 network_interface_id=None,
                 vpc_peering_connection_id=None):
    return _set_route(context, route_table_id, destination_cidr_block,
                      gateway_id, instance_id, network_interface_id,
                      vpc_peering_connection_id, False)


def replace_route(context, route_table_id, destination_cidr_block,
                  gateway_id=None, instance_id=None,
                  network_interface_id=None,
                  vpc_peering_connection_id=None):
    return _set_route(context, route_table_id, destination_cidr_block,
                      gateway_id, instance_id, network_interface_id,
                      vpc_peering_connection_id, True)


def delete_route(context, route_table_id, destination_cidr_block):
    route_table = ec2utils.get_db_item(context, route_table_id)
    for route_index, route in enumerate(route_table['routes']):
        if route['destination_cidr_block'] != destination_cidr_block:
            continue
        if route.get('gateway_id', 0) is None:
            msg = _('cannot remove local route %(destination_cidr_block)s '
                    'in route table %(route_table_id)s')
            msg = msg % {'route_table_id': route_table_id,
                         'destination_cidr_block': destination_cidr_block}
            raise exception.InvalidParameterValue(msg)
        break
    else:
        raise exception.InvalidRouteNotFound(
            route_table_id=route_table_id,
            destination_cidr_block=destination_cidr_block)
    update_target = _get_route_target(route)
    if update_target == VPN_TARGET:
        vpn_gateway = db_api.get_item_by_id(context, route['gateway_id'])
        if (not vpn_gateway or
                vpn_gateway['vpc_id'] != route_table['vpc_id']):
            update_target = None
    rollback_route_table_state = copy.deepcopy(route_table)
    del route_table['routes'][route_index]
    with common.OnCrashCleaner() as cleaner:
        db_api.update_item(context, route_table)
        cleaner.addCleanup(db_api.update_item, context,
                           rollback_route_table_state)

        if update_target:
            _update_routes_in_associated_subnets(
                context, cleaner, route_table, update_target=update_target)

    return True


def enable_vgw_route_propagation(context, route_table_id, gateway_id):
    route_table = ec2utils.get_db_item(context, route_table_id)
    # NOTE(ft): AWS returns GatewayNotAttached for all invalid cases of
    # gateway_id value
    vpn_gateway = ec2utils.get_db_item(context, gateway_id)
    if vpn_gateway['vpc_id'] != route_table['vpc_id']:
        raise exception.GatewayNotAttached(gw_id=vpn_gateway['id'],
                                           vpc_id=route_table['vpc_id'])
    if vpn_gateway['id'] in route_table.setdefault('propagating_gateways', []):
        return True
    with common.OnCrashCleaner() as cleaner:
        _append_propagation_to_route_table_item(context, route_table,
                                                vpn_gateway['id'])
        cleaner.addCleanup(_remove_propagation_from_route_table_item,
                           context, route_table, vpn_gateway['id'])

        _update_routes_in_associated_subnets(context, cleaner, route_table,
                                             update_target=VPN_TARGET)
    return True


def disable_vgw_route_propagation(context, route_table_id, gateway_id):
    route_table = ec2utils.get_db_item(context, route_table_id)
    if gateway_id not in route_table.get('propagating_gateways', []):
        return True
    vpn_gateway = db_api.get_item_by_id(context, gateway_id)

    with common.OnCrashCleaner() as cleaner:
        _remove_propagation_from_route_table_item(context, route_table,
                                                  gateway_id)
        cleaner.addCleanup(_append_propagation_to_route_table_item,
                           context, route_table, gateway_id)

        if vpn_gateway and vpn_gateway['vpc_id'] == route_table['vpc_id']:
            _update_routes_in_associated_subnets(context, cleaner, route_table,
                                                 update_target=VPN_TARGET)
    return True


def associate_route_table(context, route_table_id, subnet_id):
    route_table = ec2utils.get_db_item(context, route_table_id)
    subnet = ec2utils.get_db_item(context, subnet_id)
    if route_table['vpc_id'] != subnet['vpc_id']:
        msg = _('Route table %(rtb_id)s and subnet %(subnet_id)s belong to '
                'different networks')
        msg = msg % {'rtb_id': route_table_id,
                     'subnet_id': subnet_id}
        raise exception.InvalidParameterValue(msg)
    if 'route_table_id' in subnet:
        msg = _('The specified association for route table %(rtb_id)s '
                'conflicts with an existing association')
        msg = msg % {'rtb_id': route_table_id}
        raise exception.ResourceAlreadyAssociated(msg)

    with common.OnCrashCleaner() as cleaner:
        _associate_subnet_item(context, subnet, route_table['id'])
        cleaner.addCleanup(_disassociate_subnet_item, context, subnet)

        _update_subnet_routes(context, cleaner, subnet, route_table)

    return {'associationId': ec2utils.change_ec2_id_kind(subnet['id'],
                                                         'rtbassoc')}


def replace_route_table_association(context, association_id, route_table_id):
    route_table = ec2utils.get_db_item(context, route_table_id)
    if route_table['vpc_id'] == ec2utils.change_ec2_id_kind(association_id,
                                                            'vpc'):
        vpc = db_api.get_item_by_id(
            context, ec2utils.change_ec2_id_kind(association_id, 'vpc'))
        if vpc is None:
            raise exception.InvalidAssociationIDNotFound(id=association_id)

        rollback_route_table_id = vpc['route_table_id']
        with common.OnCrashCleaner() as cleaner:
            _associate_vpc_item(context, vpc, route_table['id'])
            cleaner.addCleanup(_associate_vpc_item, context, vpc,
                               rollback_route_table_id)

            _update_routes_in_associated_subnets(
                context, cleaner, route_table, default_associations_only=True)
    else:
        subnet = db_api.get_item_by_id(
            context, ec2utils.change_ec2_id_kind(association_id, 'subnet'))
        if subnet is None or 'route_table_id' not in subnet:
            raise exception.InvalidAssociationIDNotFound(id=association_id)
        if subnet['vpc_id'] != route_table['vpc_id']:
            msg = _('Route table association %(rtbassoc_id)s and route table '
                    '%(rtb_id)s belong to different networks')
            msg = msg % {'rtbassoc_id': association_id,
                         'rtb_id': route_table_id}
            raise exception.InvalidParameterValue(msg)

        rollback_route_table_id = subnet['route_table_id']
        with common.OnCrashCleaner() as cleaner:
            _associate_subnet_item(context, subnet, route_table['id'])
            cleaner.addCleanup(_associate_subnet_item, context, subnet,
                               rollback_route_table_id)

            _update_subnet_routes(context, cleaner, subnet, route_table)

    return {'newAssociationId': association_id}


def disassociate_route_table(context, association_id):
    subnet = db_api.get_item_by_id(
        context, ec2utils.change_ec2_id_kind(association_id, 'subnet'))
    if not subnet:
        vpc = db_api.get_item_by_id(
            context, ec2utils.change_ec2_id_kind(association_id, 'vpc'))
        if vpc is None:
            raise exception.InvalidAssociationIDNotFound(id=association_id)
        msg = _('Cannot disassociate the main route table association '
                '%(rtbassoc_id)s') % {'rtbassoc_id': association_id}
        raise exception.InvalidParameterValue(msg)
    if 'route_table_id' not in subnet:
        raise exception.InvalidAssociationIDNotFound(id=association_id)

    rollback_route_table_id = subnet['route_table_id']
    vpc = db_api.get_item_by_id(context, subnet['vpc_id'])
    main_route_table = db_api.get_item_by_id(context, vpc['route_table_id'])
    with common.OnCrashCleaner() as cleaner:
        _disassociate_subnet_item(context, subnet)
        cleaner.addCleanup(_associate_subnet_item, context, subnet,
                           rollback_route_table_id)

        _update_subnet_routes(context, cleaner, subnet, main_route_table)

    return True


def delete_route_table(context, route_table_id):
    route_table = ec2utils.get_db_item(context, route_table_id)
    vpc = db_api.get_item_by_id(context, route_table['vpc_id'])
    _delete_route_table(context, route_table['id'], vpc)
    return True


class RouteTableDescriber(common.TaggableItemsDescriber,
                          common.NonOpenstackItemsDescriber):

    KIND = 'rtb'
    FILTER_MAP = {'association.route-table-association-id': (
                        ['associationSet', 'routeTableAssociationId']),
                  'association.route-table-id': ['associationSet',
                                                 'routeTableId'],
                  'association.subnet-id': ['associationSet', 'subnetId'],
                  'association.main': ['associationSet', 'main'],
                  'route-table-id': 'routeTableId',
                  'route.destination-cidr-block': ['routeSet',
                                                   'destinationCidrBlock'],
                  'route.gateway-id': ['routeSet', 'gatewayId'],
                  'route.instance-id': ['routeSet', 'instanceId'],
                  'route.origin': ['routeSet', 'origin'],
                  'route.state': ['routeSet', 'state'],
                  'vpc-id': 'vpcId'}

    def format(self, route_table):
        return _format_route_table(
            self.context, route_table,
            associated_subnet_ids=self.associations[route_table['id']],
            is_main=(self.vpcs[route_table['vpc_id']]['route_table_id'] ==
                     route_table['id']),
            gateways=self.gateways,
            network_interfaces=self.network_interfaces,
            vpn_connections_by_gateway_id=self.vpn_connections_by_gateway_id)

    def get_db_items(self):
        associations = collections.defaultdict(list)
        for subnet in db_api.get_items(self.context, 'subnet'):
            if 'route_table_id' in subnet:
                associations[subnet['route_table_id']].append(subnet['id'])
        self.associations = associations
        vpcs = db_api.get_items(self.context, 'vpc')
        self.vpcs = {vpc['id']: vpc for vpc in vpcs}
        gateways = (db_api.get_items(self.context, 'igw') +
                    db_api.get_items(self.context, 'vgw'))
        self.gateways = {gw['id']: gw for gw in gateways}
        # TODO(ft): scan route tables to get only used instances and
        # network interfaces to reduce DB and Nova throughput
        network_interfaces = db_api.get_items(self.context, 'eni')
        self.network_interfaces = {eni['id']: eni
                                   for eni in network_interfaces}
        vpn_connections = db_api.get_items(self.context, 'vpn')
        vpns_by_gateway_id = {}
        for vpn in vpn_connections:
            vpns = vpns_by_gateway_id.setdefault(vpn['vpn_gateway_id'], [])
            vpns.append(vpn)
        self.vpn_connections_by_gateway_id = vpns_by_gateway_id
        return super(RouteTableDescriber, self).get_db_items()


def describe_route_tables(context, route_table_id=None, filter=None):
    ec2utils.check_and_create_default_vpc(context)
    formatted_route_tables = RouteTableDescriber().describe(
            context, ids=route_table_id, filter=filter)
    return {'routeTableSet': formatted_route_tables}


def _create_route_table(context, vpc):
    route_table = {'vpc_id': vpc['id'],
                   'routes': [{'destination_cidr_block': vpc['cidr_block'],
                               'gateway_id': None}]}
    route_table = db_api.add_item(context, 'rtb', route_table)
    return route_table


def _delete_route_table(context, route_table_id, vpc=None, cleaner=None):
    def get_associated_subnets():
        return [s for s in db_api.get_items(context, 'subnet')
                if s.get('route_table_id') == route_table_id]

    if (vpc and route_table_id == vpc['route_table_id'] or
            len(get_associated_subnets()) > 0):
        msg = _("The routeTable '%(rtb_id)s' has dependencies and cannot "
                "be deleted.") % {'rtb_id': route_table_id}
        raise exception.DependencyViolation(msg)
    if cleaner:
        route_table = db_api.get_item_by_id(context, route_table_id)
    db_api.delete_item(context, route_table_id)
    if cleaner and route_table:
        cleaner.addCleanup(db_api.restore_item, context, 'rtb', route_table)


def _set_route(context, route_table_id, destination_cidr_block,
               gateway_id, instance_id, network_interface_id,
               vpc_peering_connection_id, do_replace):
    route_table = ec2utils.get_db_item(context, route_table_id)
    vpc = db_api.get_item_by_id(context, route_table['vpc_id'])
    vpc_ipnet = netaddr.IPNetwork(vpc['cidr_block'])
    route_ipnet = netaddr.IPNetwork(destination_cidr_block)
    if route_ipnet in vpc_ipnet:
        msg = _('Cannot create a more specific route for '
                '%(destination_cidr_block)s than local route '
                '%(vpc_cidr_block)s in route table %(rtb_id)s')
        msg = msg % {'rtb_id': route_table_id,
                     'destination_cidr_block': destination_cidr_block,
                     'vpc_cidr_block': vpc['cidr_block']}
        raise exception.InvalidParameterValue(msg)

    obj_param_count = len([p for p in (gateway_id, network_interface_id,
                                       instance_id, vpc_peering_connection_id)
                           if p is not None])
    if obj_param_count != 1:
        msg = _('The request must contain exactly one of gatewayId, '
                'networkInterfaceId, vpcPeeringConnectionId or instanceId')
        if obj_param_count == 0:
            raise exception.MissingParameter(msg)
        else:
            raise exception.InvalidParameterCombination(msg)

    rollabck_route_table_state = copy.deepcopy(route_table)
    if do_replace:
        route_index, old_route = next(
            ((i, r) for i, r in enumerate(route_table['routes'])
             if r['destination_cidr_block'] == destination_cidr_block),
            (None, None))
        if route_index is None:
            msg = _("There is no route defined for "
                    "'%(destination_cidr_block)s' in the route table. "
                    "Use CreateRoute instead.")
            msg = msg % {'destination_cidr_block': destination_cidr_block}
            raise exception.InvalidParameterValue(msg)
        else:
            del route_table['routes'][route_index]

    if gateway_id:
        gateway = ec2utils.get_db_item(context, gateway_id)
        if gateway.get('vpc_id') != route_table['vpc_id']:
            if ec2utils.get_ec2_id_kind(gateway_id) == 'vgw':
                raise exception.InvalidGatewayIDNotFound(id=gateway['id'])
            else:  # igw
                raise exception.InvalidParameterValue(
                    _('Route table %(rtb_id)s and network gateway %(igw_id)s '
                      'belong to different networks') %
                    {'rtb_id': route_table_id,
                     'igw_id': gateway_id})
        route = {'gateway_id': gateway['id']}
    elif network_interface_id:
        network_interface = ec2utils.get_db_item(context, network_interface_id)
        if network_interface['vpc_id'] != route_table['vpc_id']:
            msg = _('Route table %(rtb_id)s and interface %(eni_id)s '
                    'belong to different networks')
            msg = msg % {'rtb_id': route_table_id,
                         'eni_id': network_interface_id}
            raise exception.InvalidParameterValue(msg)
        route = {'network_interface_id': network_interface['id']}
    elif instance_id:
        # TODO(ft): implement search in DB layer
        network_interfaces = [eni for eni in db_api.get_items(context, 'eni')
                              if eni.get('instance_id') == instance_id]
        if len(network_interfaces) == 0:
            msg = _("Invalid value '%(i_id)s' for instance ID. "
                    "Instance is not in a VPC.")
            msg = msg % {'i_id': instance_id}
            raise exception.InvalidParameterValue(msg)
        elif len(network_interfaces) > 1:
            raise exception.InvalidInstanceId(instance_id=instance_id)
        network_interface = network_interfaces[0]
        if network_interface['vpc_id'] != route_table['vpc_id']:
            msg = _('Route table %(rtb_id)s and interface %(eni_id)s '
                    'belong to different networks')
            msg = msg % {'rtb_id': route_table_id,
                         'eni_id': network_interface['id']}
            raise exception.InvalidParameterValue(msg)
        route = {'network_interface_id': network_interface['id']}
    else:
        raise exception.InvalidRequest('Parameter VpcPeeringConnectionId is '
                                       'not supported by this implementation')
    route['destination_cidr_block'] = destination_cidr_block
    update_target = _get_route_target(route)

    if do_replace:
        idempotent_call = False
        old_target = _get_route_target(old_route)
        if old_target != update_target:
            update_target = None
    else:
        old_route = next((r for r in route_table['routes']
                          if r['destination_cidr_block'] ==
                          destination_cidr_block), None)
        idempotent_call = old_route == route
        if old_route and not idempotent_call:
            raise exception.RouteAlreadyExists(
                destination_cidr_block=destination_cidr_block)

    if not idempotent_call:
        route_table['routes'].append(route)

    with common.OnCrashCleaner() as cleaner:
        db_api.update_item(context, route_table)
        cleaner.addCleanup(db_api.update_item, context,
                           rollabck_route_table_state)
        _update_routes_in_associated_subnets(context, cleaner, route_table,
                                             update_target=update_target)

    return True


def _format_route_table(context, route_table, is_main=False,
                        associated_subnet_ids=[],
                        gateways={},
                        network_interfaces={},
                        vpn_connections_by_gateway_id={}):
    vpc_id = route_table['vpc_id']
    ec2_route_table = {
        'routeTableId': route_table['id'],
        'vpcId': vpc_id,
        'routeSet': [],
        'propagatingVgwSet': [
            {'gatewayId': vgw_id}
            for vgw_id in route_table.get('propagating_gateways', [])],
        # NOTE(ft): AWS returns empty tag set for a route table
        # if no tag exists
        'tagSet': [],
    }
    # TODO(ft): refactor to get Nova instances outside of this function
    nova = clients.nova(context)
    for route in route_table['routes']:
        origin = ('CreateRouteTable'
                  if route.get('gateway_id', 0) is None else
                  'CreateRoute')
        ec2_route = {'destinationCidrBlock': route['destination_cidr_block'],
                     'origin': origin}
        if 'gateway_id' in route:
            gateway_id = route['gateway_id']
            if gateway_id is None:
                state = 'active'
                ec2_gateway_id = 'local'
            else:
                gateway = gateways.get(gateway_id)
                state = ('active'
                         if gateway and gateway.get('vpc_id') == vpc_id else
                         'blackhole')
                ec2_gateway_id = gateway_id
            ec2_route.update({'gatewayId': ec2_gateway_id,
                              'state': state})
        else:
            network_interface_id = route['network_interface_id']
            network_interface = network_interfaces.get(network_interface_id)
            instance_id = (network_interface.get('instance_id')
                           if network_interface else
                           None)
            state = 'blackhole'
            if instance_id:
                instance = db_api.get_item_by_id(context, instance_id)
                if instance:
                    try:
                        os_instance = nova.servers.get(instance['os_id'])
                        if os_instance and os_instance.status == 'ACTIVE':
                            state = 'active'
                    except nova_exception.NotFound:
                        pass
                ec2_route.update({'instanceId': instance_id,
                                  'instanceOwnerId': context.project_id})
            ec2_route.update({'networkInterfaceId': network_interface_id,
                              'state': state})
        ec2_route_table['routeSet'].append(ec2_route)

    for vgw_id in route_table.get('propagating_gateways', []):
        vgw = gateways.get(vgw_id)
        if vgw and vgw_id in vpn_connections_by_gateway_id:
            cidrs = set()
            vpn_connections = vpn_connections_by_gateway_id[vgw_id]
            for vpn_connection in vpn_connections:
                cidrs.update(vpn_connection['cidrs'])
            state = 'active' if vgw['vpc_id'] == vpc_id else 'blackhole'
            for cidr in cidrs:
                ec2_route = {'gatewayId': vgw_id,
                             'destinationCidrBlock': cidr,
                             'state': state,
                             'origin': 'EnableVgwRoutePropagation'}
                ec2_route_table['routeSet'].append(ec2_route)

    associations = []
    if is_main:
        associations.append({
            'routeTableAssociationId': ec2utils.change_ec2_id_kind(vpc_id,
                                                                   'rtbassoc'),
            'routeTableId': route_table['id'],
            'main': True})
    for subnet_id in associated_subnet_ids:
        associations.append({
            'routeTableAssociationId': ec2utils.change_ec2_id_kind(subnet_id,
                                                                   'rtbassoc'),
            'routeTableId': route_table['id'],
            'subnetId': subnet_id,
            'main': False})
    if associations:
        ec2_route_table['associationSet'] = associations

    return ec2_route_table


def _update_routes_in_associated_subnets(context, cleaner, route_table,
                                         default_associations_only=None,
                                         update_target=None):
    if default_associations_only:
        appropriate_rtb_ids = (None,)
    else:
        vpc = db_api.get_item_by_id(context, route_table['vpc_id'])
        if vpc['route_table_id'] == route_table['id']:
            appropriate_rtb_ids = (route_table['id'], None)
        else:
            appropriate_rtb_ids = (route_table['id'],)
    neutron = clients.neutron(context)
    subnets = [subnet for subnet in db_api.get_items(context, 'subnet')
               if (subnet['vpc_id'] == route_table['vpc_id'] and
                   subnet.get('route_table_id') in appropriate_rtb_ids)]
    # NOTE(ft): we need to update host routes for both host and vpn target
    # because vpn-related routes are present in host routes as well
    _update_host_routes(context, neutron, cleaner, route_table, subnets)
    if not update_target or update_target == VPN_TARGET:
        vpn_connection_api._update_vpn_routes(context, neutron, cleaner,
                                              route_table, subnets)


def _update_subnet_routes(context, cleaner, subnet, route_table):
    neutron = clients.neutron(context)
    _update_host_routes(context, neutron, cleaner, route_table, [subnet])
    vpn_connection_api._update_vpn_routes(context, neutron, cleaner,
                                          route_table, [subnet])


def _update_host_routes(context, neutron, cleaner, route_table, subnets):
    destinations = _get_active_route_destinations(context, route_table)
    for subnet in subnets:
        # TODO(ft): do list subnet w/ filters instead of show one by one
        os_subnet = neutron.show_subnet(subnet['os_id'])['subnet']
        host_routes, gateway_ip = _get_subnet_host_routes_and_gateway_ip(
            context, route_table, os_subnet['cidr'], destinations)
        neutron.update_subnet(subnet['os_id'],
                              {'subnet': {'host_routes': host_routes,
                                          'gateway_ip': gateway_ip}})
        cleaner.addCleanup(
            neutron.update_subnet, subnet['os_id'],
            {'subnet': {'host_routes': os_subnet['host_routes'],
                        'gateway_ip': os_subnet['gateway_ip']}})


def _get_active_route_destinations(context, route_table):
    vpn_connections = {vpn['vpn_gateway_id']: vpn
                       for vpn in db_api.get_items(context, 'vpn')}
    dst_ids = [route[id_key]
               for route in route_table['routes']
               for id_key in ('gateway_id', 'network_interface_id')
               if route.get(id_key) is not None]
    dst_ids.extend(route_table.get('propagating_gateways', []))
    destinations = {item['id']: item
                    for item in db_api.get_items_by_ids(context, dst_ids)
                    if (item['vpc_id'] == route_table['vpc_id'] and
                        (ec2utils.get_ec2_id_kind(item['id']) != 'vgw' or
                         item['id'] in vpn_connections))}
    for vpn in six.itervalues(vpn_connections):
        if vpn['vpn_gateway_id'] in destinations:
            destinations[vpn['vpn_gateway_id']]['vpn_connection'] = vpn
    return destinations


def _get_subnet_host_routes_and_gateway_ip(context, route_table, cidr_block,
                                           destinations=None):
    if not destinations:
        destinations = _get_active_route_destinations(context, route_table)
    gateway_ip = str(netaddr.IPAddress(
        netaddr.IPNetwork(cidr_block).first + 1))

    def get_nexthop(route):
        if 'gateway_id' in route:
            gateway_id = route['gateway_id']
            if gateway_id and gateway_id not in destinations:
                    return '127.0.0.1'
            return gateway_ip
        network_interface = destinations.get(route['network_interface_id'])
        if not network_interface:
            return '127.0.0.1'
        return network_interface['private_ip_address']

    host_routes = []
    subnet_gateway_is_used = False
    for route in route_table['routes']:
        nexthop = get_nexthop(route)
        cidr = route['destination_cidr_block']
        if cidr == '0.0.0.0/0':
            if nexthop == '127.0.0.1':
                continue
            elif nexthop == gateway_ip:
                subnet_gateway_is_used = True
        host_routes.append({'destination': cidr,
                            'nexthop': nexthop})
    host_routes.extend(
        {'destination': cidr,
         'nexthop': gateway_ip}
        for vgw_id in route_table.get('propagating_gateways', [])
        for cidr in (destinations.get(vgw_id, {}).get('vpn_connection', {}).
                     get('cidrs', [])))

    if not subnet_gateway_is_used:
        # NOTE(andrey-mp): add route to metadata server
        host_routes.append(
            {'destination': '169.254.169.254/32',
             'nexthop': gateway_ip})
        # NOTE(ft): gateway_ip is set to None to allow correct handling
        # of 0.0.0.0/0 route by Neutron.
        gateway_ip = None
    return host_routes, gateway_ip


def _get_route_target(route):
    if ec2utils.get_ec2_id_kind(route.get('gateway_id') or '') == 'vgw':
        return VPN_TARGET
    else:
        return HOST_TARGET


def _associate_subnet_item(context, subnet, route_table_id):
    subnet['route_table_id'] = route_table_id
    db_api.update_item(context, subnet)


def _disassociate_subnet_item(context, subnet):
    subnet.pop('route_table_id')
    db_api.update_item(context, subnet)


def _associate_vpc_item(context, vpc, route_table_id):
    vpc['route_table_id'] = route_table_id
    db_api.update_item(context, vpc)


def _append_propagation_to_route_table_item(context, route_table, gateway_id):
    vgws = route_table.setdefault('propagating_gateways', [])
    vgws.append(gateway_id)
    db_api.update_item(context, route_table)


def _remove_propagation_from_route_table_item(context, route_table,
                                              gateway_id):
    vgws = route_table['propagating_gateways']
    vgws.remove(gateway_id)
    if not vgws:
        del route_table['propagating_gateways']
    db_api.update_item(context, route_table)
