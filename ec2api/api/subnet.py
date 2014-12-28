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


import netaddr
from neutronclient.common import exceptions as neutron_exception
from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import network_interface as network_interface_api
from ec2api.api import route_table as route_table_api
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""Subnet related API implementation
"""


def create_subnet(context, vpc_id, cidr_block,
                  availability_zone=None):
    vpc = ec2utils.get_db_item(context, 'vpc', vpc_id)
    vpc_ipnet = netaddr.IPNetwork(vpc['cidr_block'])
    subnet_ipnet = netaddr.IPNetwork(cidr_block)
    if subnet_ipnet not in vpc_ipnet:
        raise exception.InvalidSubnetRange(cidr_block=cidr_block)

    # TODO(ft):
    # check availability zone
    # choose default availability zone
    gateway_ip = str(netaddr.IPAddress(subnet_ipnet.first + 1))
    # NOTE(Alex): AWS takes 4 first addresses (.1 - .4) but for
    # OpenStack we decided not to support this as compatibility.
    # start_ip = str(netaddr.IPAddress(subnet_ipnet.first + 4))
    # end_ip = str(netaddr.IPAddress(subnet_ipnet.last - 1))
    main_route_table = db_api.get_item_by_id(context, 'rtb',
                                             vpc['route_table_id'])
    host_routes = route_table_api._get_subnet_host_routes(
            context, main_route_table, gateway_ip)
    neutron = clients.neutron(context)
    with utils.OnCrashCleaner() as cleaner:
        os_network_body = {'network': {}}
        os_network = neutron.create_network(os_network_body)['network']
        cleaner.addCleanup(neutron.delete_network, os_network['id'])
        os_subnet_body = {'subnet': {'network_id': os_network['id'],
                                     'ip_version': '4',
                                     'cidr': cidr_block,
                                     # 'allocation_pools': [{'start': start_ip,
                                     #                       'end': end_ip}],
                                     'host_routes': host_routes}}
        os_subnet = neutron.create_subnet(os_subnet_body)['subnet']
        cleaner.addCleanup(neutron.delete_subnet, os_subnet['id'])
        neutron.add_interface_router(vpc['os_id'],
                                     {'subnet_id': os_subnet['id']})
        cleaner.addCleanup(neutron.remove_interface_router,
                           vpc['os_id'], {'subnet_id': os_subnet['id']})
        # TODO(Alex): Handle errors like cidr conflict or overlimit
        # TODO(ft):
        # store availability_zone
        subnet = db_api.add_item(context, 'subnet',
                                 {'os_id': os_subnet['id'],
                                  'vpc_id': vpc['id']})
        cleaner.addCleanup(db_api.delete_item, context, subnet['id'])
        neutron.update_network(os_network['id'],
                               {'network': {'name': subnet['id']}})
        neutron.update_subnet(os_subnet['id'],
                              {'subnet': {'name': subnet['id']}})
    os_ports = neutron.list_ports()['ports']
    return {'subnet': _format_subnet(context, subnet, os_subnet,
                                          os_network, os_ports)}


def delete_subnet(context, subnet_id):
    subnet = ec2utils.get_db_item(context, 'subnet', subnet_id)
    vpc = db_api.get_item_by_id(context, 'vpc', subnet['vpc_id'])
    network_interfaces = network_interface_api.describe_network_interfaces(
        context,
        filter=[{'name': 'subnet-id',
                 'value': [subnet_id]}])['networkInterfaceSet']
    if network_interfaces:
        msg = _("The subnet '%(subnet_id)s' has dependencies and "
                "cannot be deleted.") % {'subnet_id': subnet_id}
        raise exception.DependencyViolation(msg)
    neutron = clients.neutron(context)
    with utils.OnCrashCleaner() as cleaner:
        db_api.delete_item(context, subnet['id'])
        cleaner.addCleanup(db_api.restore_item, context, 'subnet', subnet)
        try:
            if vpc is not None:
                neutron.remove_interface_router(vpc['os_id'],
                                                {'subnet_id': subnet['os_id']})
                cleaner.addCleanup(neutron.add_interface_router,
                                   vpc['os_id'],
                                   {'subnet_id': subnet['os_id']})
            os_subnet = neutron.show_subnet(subnet['os_id'])['subnet']
            neutron.delete_subnet(os_subnet['id'])
            neutron.delete_network(os_subnet['network_id'])
        except neutron_exception.NeutronClientException:
            # TODO(ft): do log error
            # TODO(ft): adjust catched exception classes to catch:
            # the subnet is already unplugged from the router
            # no such router
            # the subnet doesn't exist
            # some ports exist in the subnet
            # the network has other not empty subnets
            pass

    return True


class SubnetDescriber(common.TaggableItemsDescriber):

    KIND = 'subnet'
    FILTER_MAP = {'available-ip-address-count': 'availableIpAddressCount',
                  'cidr': 'cidrBlock',
                  'cidrBlock': 'cidrBlock',
                  'cidr-block': 'cidrBlock',
                  'subnet-id': 'id',
                  'state': 'state',
                  'vpc-id': 'vpcId'}

    def format(self, subnet, os_subnet):
        if not subnet:
            return None
        os_network = next((n for n in self.os_networks
                           if n['id'] == os_subnet['network_id']),
                          None)
        if not os_network:
            self.delete_obsolete_item(subnet)
            return None
        return _format_subnet(self.context, subnet, os_subnet, os_network,
                              self.os_ports)

    def get_name(self, os_item):
        return ''

    def get_os_items(self):
        neutron = clients.neutron(self.context)
        self.os_networks = neutron.list_networks()['networks']
        self.os_ports = neutron.list_ports()['ports']
        return neutron.list_subnets()['subnets']


def describe_subnets(context, subnet_id=None, filter=None):
    formatted_subnets = SubnetDescriber().describe(context, ids=subnet_id,
                                                   filter=filter)
    return {'subnetSet': formatted_subnets}


def _format_subnet(context, subnet, os_subnet, os_network, os_ports):
    status_map = {'ACTIVE': 'available',
                  'BUILD': 'pending',
                  'DOWN': 'available',
                  'ERROR': 'available'}
    range = int(os_subnet['cidr'].split('/')[1])
    # NOTE(Alex) First and last IP addresses are system ones.
    ip_count = pow(2, 32 - range) - 2
    # TODO(Alex): Probably performance-killer. Will have to optimize.
    dhcp_port_accounted = False
    for port in os_ports:
        for fixed_ip in port.get('fixed_ips', []):
            if fixed_ip['subnet_id'] == os_subnet['id']:
                ip_count -= 1
            if port['device_owner'] == 'network:dhcp':
                dhcp_port_accounted = True
    if not dhcp_port_accounted:
        ip_count -= 1
    return {
        'subnetId': subnet['id'],
        'state': status_map.get(os_network['status'], 'available'),
        'vpcId': subnet['vpc_id'],
        'cidrBlock': os_subnet['cidr'],
        'defaultForAz': 'false',
        'mapPublicIpOnLaunch': 'false',
        # 'availabilityZone' = 'nova' # TODO(Alex) implement
        'availableIpAddressCount': ip_count
    }
