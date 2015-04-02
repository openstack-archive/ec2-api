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

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


Validator = common.Validator


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
    rollback_route_table_state = copy.deepcopy(route_table)
    del route_table['routes'][route_index]
    with common.OnCrashCleaner() as cleaner:
        db_api.update_item(context, route_table)
        cleaner.addCleanup(db_api.update_item, context,
                           rollback_route_table_state)

        _update_routes_in_associated_subnets(context, route_table, cleaner,
                                             rollback_route_table_state)

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

    vpc = db_api.get_item_by_id(context, subnet['vpc_id'])
    main_route_table = db_api.get_item_by_id(context, vpc['route_table_id'])
    with common.OnCrashCleaner() as cleaner:
        _associate_subnet_item(context, subnet, route_table['id'])
        cleaner.addCleanup(_disassociate_subnet_item, context, subnet)

        _update_subnet_host_routes(
            context, subnet, route_table,
            cleaner=cleaner, rollback_route_table_object=main_route_table)

    return {'associationId': ec2utils.change_ec2_id_kind(subnet['id'],
                                                         'rtbassoc')}


def replace_route_table_association(context, association_id, route_table_id):
    route_table = ec2utils.get_db_item(context, route_table_id)
    if route_table['vpc_id'] == ec2utils.change_ec2_id_kind(association_id,
                                                            'vpc'):
        vpc = db_api.get_item_by_id(
            context, ec2utils.change_ec2_id_kind(association_id, 'vpc'))
        if vpc is None:
            raise exception.InvalidAssociationIDNotFound(
                id=association_id)

        rollabck_route_table_object = db_api.get_item_by_id(
            context, vpc['route_table_id'])
        with common.OnCrashCleaner() as cleaner:
            _associate_vpc_item(context, vpc, route_table['id'])
            cleaner.addCleanup(_associate_vpc_item, context, vpc,
                               rollabck_route_table_object['id'])

            # NOTE(ft): this can cause unnecessary update of subnets, which are
            # associated with the route table
            _update_routes_in_associated_subnets(
                context, route_table, cleaner,
                rollabck_route_table_object, is_main=True)
    else:
        subnet = db_api.get_item_by_id(
            context, ec2utils.change_ec2_id_kind(association_id, 'subnet'))
        if subnet is None or 'route_table_id' not in subnet:
            raise exception.InvalidAssociationIDNotFound(
                id=association_id)
        if subnet['vpc_id'] != route_table['vpc_id']:
            msg = _('Route table association %(rtbassoc_id)s and route table '
                    '%(rtb_id)s belong to different networks')
            msg = msg % {'rtbassoc_id': association_id,
                         'rtb_id': route_table_id}
            raise exception.InvalidParameterValue(msg)

        rollabck_route_table_object = db_api.get_item_by_id(
            context, subnet['route_table_id'])
        with common.OnCrashCleaner() as cleaner:
            _associate_subnet_item(context, subnet, route_table['id'])
            cleaner.addCleanup(_associate_subnet_item, context, subnet,
                               rollabck_route_table_object['id'])

            _update_subnet_host_routes(
                context, subnet, route_table, cleaner=cleaner,
                rollback_route_table_object=rollabck_route_table_object)

    return {'newAssociationId': association_id}


def disassociate_route_table(context, association_id):
    subnet = db_api.get_item_by_id(
        context, ec2utils.change_ec2_id_kind(association_id, 'subnet'))
    if not subnet:
        vpc = db_api.get_item_by_id(
            context, ec2utils.change_ec2_id_kind(association_id, 'vpc'))
        if vpc is None:
            raise exception.InvalidAssociationIDNotFound(
                id=association_id)
        msg = _('Cannot disassociate the main route table association '
                '%(rtbassoc_id)s') % {'rtbassoc_id': association_id}
        raise exception.InvalidParameterValue(msg)
    if 'route_table_id' not in subnet:
        raise exception.InvalidAssociationIDNotFound(
            id=association_id)

    rollback_route_table_object = db_api.get_item_by_id(
        context, subnet['route_table_id'])
    vpc = db_api.get_item_by_id(context, subnet['vpc_id'])
    main_route_table = db_api.get_item_by_id(context, vpc['route_table_id'])
    with common.OnCrashCleaner() as cleaner:
        _disassociate_subnet_item(context, subnet)
        cleaner.addCleanup(_associate_subnet_item, context, subnet,
                           rollback_route_table_object['id'])

        _update_subnet_host_routes(
            context, subnet, main_route_table, cleaner=cleaner,
            rollback_route_table_object=rollback_route_table_object)

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
            network_interfaces=self.network_interfaces)

    def get_db_items(self):
        associations = collections.defaultdict(list)
        for subnet in db_api.get_items(self.context, 'subnet'):
            if 'route_table_id' in subnet:
                associations[subnet['route_table_id']].append(subnet['id'])
        self.associations = associations
        vpcs = db_api.get_items(self.context, 'vpc')
        self.vpcs = {vpc['id']: vpc for vpc in vpcs}
        gateways = db_api.get_items(self.context, 'igw')
        self.gateways = {igw['id']: igw for igw in gateways}
        # TODO(ft): scan route tables to get only used instances and
        # network interfaces to reduce DB and Nova throughput
        network_interfaces = db_api.get_items(self.context, 'eni')
        self.network_interfaces = {eni['id']: eni
                                   for eni in network_interfaces}
        return super(RouteTableDescriber, self).get_db_items()


def describe_route_tables(context, route_table_id=None, filter=None):
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
        route_count = len(route_table['routes'])
        route_table['routes'] = [
            r for r in route_table['routes']
            if r['destination_cidr_block'] != destination_cidr_block]
        if route_count == len(route_table['routes']):
            msg = _("There is no route defined for "
                    "'%(destination_cidr_block)s' in the route table. "
                    "Use CreateRoute instead.")
            msg = msg % {'destination_cidr_block': destination_cidr_block}
            raise exception.InvalidParameterValue(msg)

    if gateway_id:
        gateway = ec2utils.get_db_item(context, gateway_id)
        if gateway.get('vpc_id') != route_table['vpc_id']:
            msg = _('Route table %(rtb_id)s and network gateway %(igw_id)s '
                    'belong to different networks')
            msg = msg % {'rtb_id': route_table_id,
                         'igw_id': gateway_id}
            raise exception.InvalidParameterValue(msg)
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

    if do_replace:
        idempotent_call = False
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
        _update_routes_in_associated_subnets(context, route_table, cleaner,
                                             rollabck_route_table_state)

    return True


def _format_route_table(context, route_table, is_main=False,
                        associated_subnet_ids=[],
                        gateways={},
                        network_interfaces={}):
    vpc_id = route_table['vpc_id']
    ec2_route_table = {'routeTableId': route_table['id'],
                       'vpcId': vpc_id,
                       'routeSet': [],
                       # NOTE(ft): AWS returns empty tag set for a route table
                       # if no tag exists
                       'tagSet': []}
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


def _update_routes_in_associated_subnets(context, route_table, cleaner,
                                         rollabck_route_table_object,
                                         is_main=None):
    if is_main is None:
        vpc = db_api.get_item_by_id(context, route_table['vpc_id'])
        is_main = vpc['route_table_id'] == route_table['id']
    if is_main:
        appropriate_rtb_ids = (route_table['id'], None)
    else:
        appropriate_rtb_ids = (route_table['id'],)
    router_objects = _get_router_objects(context, route_table)
    neutron = clients.neutron(context)
    for subnet in db_api.get_items(context, 'subnet'):
        if (subnet['vpc_id'] == route_table['vpc_id'] and
                subnet.get('route_table_id') in appropriate_rtb_ids):
            _update_subnet_host_routes(
                context, subnet, route_table, cleaner=cleaner,
                rollback_route_table_object=rollabck_route_table_object,
                router_objects=router_objects, neutron=neutron)


def _update_subnet_host_routes(context, subnet, route_table, cleaner=None,
                               rollback_route_table_object=None,
                               router_objects=None, neutron=None):
    neutron = neutron or clients.neutron(context)
    os_subnet = neutron.show_subnet(subnet['os_id'])['subnet']
    gateway_ip = str(netaddr.IPAddress(
        netaddr.IPNetwork(os_subnet['cidr']).first + 1))
    host_routes = _get_subnet_host_routes(context, route_table, gateway_ip,
                                          router_objects)
    neutron.update_subnet(subnet['os_id'],
                          {'subnet': {'host_routes': host_routes}})
    if cleaner and rollback_route_table_object:
        cleaner.addCleanup(_update_subnet_host_routes, context, subnet,
                           rollback_route_table_object)


def _get_router_objects(context, route_table):
    return dict((route['gateway_id'],
                 db_api.get_item_by_id(context, route['gateway_id']))
                if route.get('gateway_id') else
                (route['network_interface_id'],
                 db_api.get_item_by_id(context, route['network_interface_id']))
                for route in route_table['routes']
                if route.get('gateway_id') or 'network_interface_id' in route)


def _get_subnet_host_routes(context, route_table, gateway_ip,
                            router_objects=None):
    def get_nexthop(route):
        if 'gateway_id' in route:
            gateway_id = route['gateway_id']
            if gateway_id:
                gateway = (router_objects[route['gateway_id']]
                           if router_objects else
                           db_api.get_item_by_id(context, gateway_id))
                if (not gateway or
                        gateway.get('vpc_id') != route_table['vpc_id']):
                    return '127.0.0.1'
            return gateway_ip
        network_interface = (
            router_objects[route['network_interface_id']]
            if router_objects else
            db_api.get_item_by_id(context, route['network_interface_id']))
        if not network_interface:
            return '127.0.0.1'
        return network_interface['private_ip_address']

    host_routes = [{'destination': route['destination_cidr_block'],
                    'nexthop': get_nexthop(route)}
                   for route in route_table['routes']]
    if not any(r['destination'] == '0.0.0.0/0' for r in host_routes):
        host_routes.append({'destination': '0.0.0.0/0',
                            'nexthop': '127.0.0.1'})

    return host_routes


def _associate_subnet_item(context, subnet, route_table_id):
    subnet['route_table_id'] = route_table_id
    db_api.update_item(context, subnet)


def _disassociate_subnet_item(context, subnet):
    subnet.pop('route_table_id')
    db_api.update_item(context, subnet)


def _associate_vpc_item(context, vpc, route_table_id):
    vpc['route_table_id'] = route_table_id
    db_api.update_item(context, vpc)
