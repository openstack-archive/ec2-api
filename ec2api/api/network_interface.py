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

import netaddr
from neutronclient.common import exceptions as neutron_exception
from novaclient import exceptions as nova_exception
from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import dhcp_options
from ec2api.api import ec2utils
from ec2api.api import security_group as security_group_api
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging
from ec2api.openstack.common import timeutils


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""Network interface related API implementation
"""


FILTER_MAP = {'vpc-id': 'vpcId',
              'subnet-id': 'subnetId'}


def create_network_interface(context, subnet_id,
                             private_ip_address=None,
                             private_ip_addresses=None,
                             secondary_private_ip_address_count=None,
                             description=None,
                             security_group_id=None):
    subnet = ec2utils.get_db_item(context, 'subnet', subnet_id)
    if subnet is None:
        raise exception.InvalidSubnetIDNotFound(id=subnet_id)
    neutron = clients.neutron(context)
    os_subnet = neutron.show_subnet(subnet['os_id'])['subnet']
    # NOTE(Alex): Combine and check ip addresses. Neutron will accept
    # ip_address as a parameter for specified address and subnet_id for
    # address to auto-allocate.
    # TODO(Alex): Implement better diagnostics.
    subnet_ipnet = netaddr.IPNetwork(os_subnet['cidr'])
    if not private_ip_addresses:
        private_ip_addresses = []
    if private_ip_address is not None:
        private_ip_addresses.insert(0,
                                    {'private_ip_address': private_ip_address,
                                     'primary': True})
    primary_ip = None
    fixed_ips = []
    for ip in private_ip_addresses:
        ip_address = netaddr.IPAddress(ip['private_ip_address'])
        if ip_address not in subnet_ipnet:
            raise exception.InvalidParameterValue(
                value=str(ip_address),
                parameter='private_ip_addresses',
                reason='IP address is out of the subnet range')
        if ip.get('primary', False):
            if primary_ip is not None:
                raise exception.InvalidParameterValue(
                    value=str(ip_address),
                    parameter='private_ip_addresses',
                    reason='More than one primary ip is supplied')
            else:
                primary_ip = str(ip_address)
                fixed_ips.insert(0, {'ip_address': primary_ip})
        else:
            fixed_ips.append({'ip_address': str(ip_address)})
    if not fixed_ips and not secondary_private_ip_address_count:
        secondary_private_ip_address_count = 1
    if secondary_private_ip_address_count > 0:
        for _i in range(secondary_private_ip_address_count):
            fixed_ips.append({'subnet_id': os_subnet['id']})
    vpc = db_api.get_item_by_id(context, 'vpc', subnet['vpc_id'])
    vpc_id = vpc['id']
    dhcp_options_id = vpc.get('dhcp_options_id', None)
    if not security_group_id:
        default_groups = security_group_api.describe_security_groups(
            context,
            filter=[{'name': 'vpc-id', 'value': [vpc_id]},
                    {'name': 'group-name', 'value': ['Default']}]
            )['securityGroupInfo']
        security_group_id = [default_group['groupId']
                             for default_group in default_groups]
    security_groups = [ec2utils.get_db_item(context, 'sg', ec2_id)
                       for ec2_id in security_group_id]
    if any(security_group['vpc_id'] != vpc['id']
           for security_group in security_groups):
        msg = _('You have specified two resources that belong to '
                'different networks.')
        raise exception.InvalidGroupNotFound(msg)
    os_groups = [security_group['os_id'] for security_group in security_groups]
    with utils.OnCrashCleaner() as cleaner:
        os_port_body = {'port': {'network_id': os_subnet['network_id'],
                                 'security_groups': os_groups}}
        os_port_body['port']['fixed_ips'] = fixed_ips
        try:
            os_port = neutron.create_port(os_port_body)['port']
        except neutron_exception.IpAddressGenerationFailureClient as e:
            raise exception.NetworkInterfaceLimitExceeded(
                        subnet_id=subnet_id)
        except Exception as e:
            raise exception.InvalidParameterValue(
                value=description,
                parameter='network_interface',
                reason=e.message)
        cleaner.addCleanup(neutron.delete_port, os_port['id'])
        if primary_ip is None:
            primary_ip = os_port['fixed_ips'][0]['ip_address']
        network_interface = db_api.add_item(context, 'eni',
                                            {'os_id': os_port['id'],
                                             'vpc_id': subnet['vpc_id'],
                                             'subnet_id': subnet['id'],
                                             'description': description,
                                             'private_ip_address': primary_ip})
        cleaner.addCleanup(db_api.delete_item,
                           context, network_interface['id'])

        network_interface_id = network_interface['id']
        neutron.update_port(os_port['id'],
                            {'port': {'name': network_interface_id}})
        if dhcp_options_id:
            dhcp_options._add_dhcp_opts_to_port(
                context,
                db_api.get_item_by_id(context, 'dopt', dhcp_options_id),
                network_interface,
                os_port)
    security_groups = security_group_api._format_security_groups_ids_names(
        context)
    return {'networkInterface':
            _format_network_interface(context,
                                      network_interface,
                                      os_port,
                                      security_groups=security_groups)}


def delete_network_interface(context, network_interface_id):
    network_interface = ec2utils.get_db_item(context, 'eni',
                                             network_interface_id)
    if 'instance_id' in network_interface:
        msg = _("Network interface '%(eni_id)s' is currently in use.")
        msg = msg % {'eni_id': network_interface_id}
        raise exception.InvalidParameterValue(msg)

    for address in db_api.get_items(context, 'eipalloc'):
        if address.get('network_interface_id') == network_interface['id']:
            address.pop('network_interface_id')
            address.pop('private_ip_address')
            db_api.update_item(context, address)

    neutron = clients.neutron(context)
    with utils.OnCrashCleaner() as cleaner:
        db_api.delete_item(context, network_interface['id'])
        cleaner.addCleanup(db_api.restore_item, context, 'eni',
                           network_interface)
        try:
            neutron.delete_port(network_interface['os_id'])
        except neutron_exception.NeutronClientException:
            # TODO(Alex): do log error
            # TODO(Alex): adjust caught exception classes to catch:
            # the port doesn't exist
            # port is in use
            pass
    return True


def describe_network_interfaces(context, network_interface_id=None,
                                filter=None):
    # TODO(Alex): implement filters
    neutron = clients.neutron(context)
    os_ports = neutron.list_ports()['ports']
    network_interfaces = ec2utils.get_db_items(context, 'eni',
                                               network_interface_id)
    os_floating_ips = neutron.list_floatingips()['floatingips']
    os_floating_ip_ids = set(ip['id'] for ip in os_floating_ips)
    addresses = collections.defaultdict(list)
    for address in db_api.get_items(context, 'eipalloc'):
        if ('network_interface_id' in address and
                address['os_id'] in os_floating_ip_ids):
            addresses[address['network_interface_id']].append(address)
    security_groups = security_group_api._format_security_groups_ids_names(
        context)
    formatted_network_interfaces = []
    for network_interface in network_interfaces:
        os_port = next((p for p in os_ports
                        if p['id'] == network_interface['os_id']), None)
        if not os_port:
            db_api.delete_item(context, network_interface['id'])
            continue
        formatted_network_interface = _format_network_interface(
            context, network_interface, os_port,
            addresses[network_interface['id']],
            security_groups)
        if not utils.filtered_out(formatted_network_interface, filter,
                                  FILTER_MAP):
            formatted_network_interfaces.append(formatted_network_interface)
    return {'networkInterfaceSet': formatted_network_interfaces}


def assign_private_ip_addresses(context, network_interface_id,
                                private_ip_address=None,
                                secondary_private_ip_address_count=None,
                                allow_reassignment=False):
    # TODO(Alex): allow_reassignment is not supported at the moment
    network_interface = ec2utils.get_db_item(context, 'eni',
                                             network_interface_id)
    subnet = ec2utils.get_db_item(context, 'subnet',
                                  network_interface['subnet_id'])
    neutron = clients.neutron(context)
    os_subnet = neutron.show_subnet(subnet['os_id'])['subnet']
    os_port = neutron.show_port(network_interface['os_id'])['port']
    subnet_ipnet = netaddr.IPNetwork(os_subnet['cidr'])
    fixed_ips = os_port['fixed_ips'] or []
    if private_ip_address is not None:
        for ip_address in private_ip_address:
            if ip_address not in subnet_ipnet:
                raise exception.InvalidParameterValue(
                    value=str(ip_address),
                    parameter='private_ip_address',
                    reason='IP address is out of the subnet range')
            fixed_ips.append({'ip_address': str(ip_address)})
    elif secondary_private_ip_address_count > 0:
        for _i in range(secondary_private_ip_address_count):
            fixed_ips.append({'subnet_id': os_subnet['id']})
    os_port = neutron.update_port(os_port['id'],
                                  {'port': {'fixed_ips': fixed_ips}})
    return True


def unassign_private_ip_addresses(context, network_interface_id,
                                  private_ip_address):
    network_interface = ec2utils.get_db_item(context, 'eni',
                                             network_interface_id)
    if network_interface['private_ip_address'] in private_ip_address:
        raise exception.InvalidParameterValue(
                value=str(network_interface['private_ip_address']),
                parameter='private_ip_addresses',
                reason='Primary IP address cannot be unassigned')
    neutron = clients.neutron(context)
    os_port = neutron.show_port(network_interface['os_id'])['port']
    fixed_ips = os_port['fixed_ips'] or []
    new_fixed_ips = [ip for ip in fixed_ips
                     if ip['ip_address'] not in private_ip_address]
    os_port = neutron.update_port(os_port['id'],
                                  {'port': {'fixed_ips': new_fixed_ips}})
    return True


def describe_network_interface_attribute(context, network_interface_id,
                                         attribute):
    network_interface = ec2utils.get_db_item(context, 'eni',
                                             network_interface_id)
    # TODO(Alex): Implement attachments, groupSet

    db_key = attribute if attribute == 'description' else 'source_dest_check'
    default_value = '' if attribute == 'description' else True
    return {'networkInterfaceId': network_interface['id'],
            attribute: {'value': network_interface.get(db_key, default_value)}}


def modify_network_interface_attribute(context, network_interface_id,
                                       description=None,
                                       source_dest_check=None,
                                       security_group_id=None):
    # NOTE(Alex) Later more parameters will appear
    params_count = (int(description is not None) +
        int(source_dest_check is not None) +
        int(security_group_id is not None))
    if params_count != 1:
        raise exception.InvalidParameterCombination(
            'Multiple attributes specified')
    network_interface = ec2utils.get_db_item(context, 'eni',
                                             network_interface_id)
    # TODO(Alex): Implement attachments
    if description is not None:
        network_interface['description'] = description
        db_api.update_item(context, network_interface)
    neutron = clients.neutron(context)
    os_port = neutron.list_ports(id=network_interface['os_id'])['ports'][0]
    if security_group_id is not None:
        os_groups = [ec2utils.get_db_item(context, 'sg', ec2_id)['os_id']
                     for ec2_id in security_group_id]
        os_port = neutron.update_port(os_port['id'],
                                      {'port': {'security_groups': os_groups}})
    if source_dest_check is not None:
        allowed = [] if source_dest_check else [{'ip_address': '0.0.0.0/0'}]
        os_port = neutron.update_port(
            os_port['id'],
            {'port': {'allowed_address_pairs': allowed}})
        network_interface['source_dest_check'] = source_dest_check
        db_api.update_item(context, network_interface)
    return True


def reset_network_interface_attribute(context, network_interface_id,
                                      attribute):
    # TODO(Alex) This is only a stub because it's not supported by
    # Openstack. True will be returned for now in any case.
    # NOTE(Alex) There is a bug in the AWS doc about this method -
    # "sourceDestCheck" should be used instead of "SourceDestCheck".
    # Also aws cli doesn't work with it because it doesn't comply with
    # the API.
    if attribute == 'sourceDestCheck':
        return modify_network_interface_attribute(context,
                                                  network_interface_id,
                                                  source_dest_check=True)
    return True


def attach_network_interface(context, network_interface_id,
                             instance_id, device_index):
    network_interface = ec2utils.get_db_item(context, 'eni',
                                             network_interface_id)
    neutron = clients.neutron(context)
    os_instance_id = ec2utils.ec2_inst_id_to_uuid(context, instance_id)
    # TODO(Alex) Check that the instance is not yet attached to another VPC
    # TODO(Alex) Check that the instance is "our", not created via nova
    # (which means that it doesn't belong to any VPC and can't be attached)
    os_port = neutron.list_ports(id=network_interface['os_id'])['ports'][0]
    nova = clients.nova(context)
    with utils.OnCrashCleaner() as cleaner:
        # TODO(Alex) nova inserts compute:%availability_zone into device_owner
        #                              'device_owner': 'compute:None'}})
        _attach_network_interface_item(context, network_interface,
                                       instance_id)
        cleaner.addCleanup(_detach_network_interface_item, context,
                           network_interface)
        try:
            nova.servers.interface_attach(os_instance_id, os_port['id'],
                                          None, None)
        except nova_exception.ClientException as e:
            raise exception.IncorrectState(reason=e.message)
    return {'attachmentId': ec2utils.change_ec2_id_kind(
                    network_interface['id'], 'eni-attach')}


def detach_network_interface(context, attachment_id, force=None):
    network_interface = db_api.get_item_by_id(
            context, 'eni', ec2utils.change_ec2_id_kind(attachment_id, 'eni'))
    if 'instance_id' not in network_interface:
        raise exception.InvalidAttachmentIDNotFound(id=attachment_id)
    # TODO(Alex) Check that device index is not 0 (when we support it) and
    # forbid detaching.
    neutron = clients.neutron(context)
    os_port = neutron.list_ports(id=network_interface['os_id'])['ports'][0]
    with utils.OnCrashCleaner() as cleaner:
        instance_id = network_interface['instance_id']
        attach_time = network_interface['attach_time']
        delete_on_termination = network_interface['delete_on_termination']
        _detach_network_interface_item(context, network_interface)
        cleaner.addCleanup(_attach_network_interface_item,
                           context, network_interface, instance_id,
                           attach_time, delete_on_termination)
        neutron.update_port(os_port['id'],
                            {'port': {'device_id': '',
                                      'device_owner': ''}})
    return True


def _format_network_interface(context, network_interface, os_port,
                              associated_addresses=[], security_groups={}):
    ec2_network_interface = {}
    ec2_network_interface['networkInterfaceId'] = network_interface['id']
    ec2_network_interface['subnetId'] = network_interface['subnet_id']
    ec2_network_interface['vpcId'] = network_interface['vpc_id']
    ec2_network_interface['description'] = network_interface['description']
    # TODO(Alex) Implement
    # ec2_network_interface['availabilityZone'] = ''
    ec2_network_interface['sourceDestCheck'] = (
        network_interface.get('source_dest_check', True))
    ec2_network_interface['requesterManaged'] = (
        os_port.get('device_owner', '').startswith('network:'))
    ec2_network_interface['ownerId'] = context.project_id
    security_group_set = []
    for sg_id in os_port['security_groups']:
        if security_groups.get(sg_id):
            security_group_set.append(security_groups[sg_id])
    ec2_network_interface['groupSet'] = security_group_set
    if 'instance_id' in network_interface:
        ec2_network_interface['status'] = 'in-use'
        ec2_network_interface['attachment'] = {
            'attachmentId': ec2utils.change_ec2_id_kind(
                    network_interface['id'], 'eni-attach'),
            'instanceId': network_interface['instance_id'],
            'status': 'attached',
            'deleteOnTermination': network_interface['delete_on_termination'],
            'attachTime': network_interface['attach_time'],
            'instanceOwnerId': context.project_id
        }
    else:
        ec2_network_interface['status'] = 'available'
    ec2_network_interface['ownerId'] = context.project_id
    ec2_network_interface['macAddress'] = os_port['mac_address']
    if os_port['fixed_ips']:
        ipsSet = []
        for ip in os_port['fixed_ips']:
            primary = (
                network_interface.get('private_ip_address', '') ==
                ip['ip_address'])
            item = {'privateIpAddress': ip['ip_address'],
                    'primary': primary}
            address = next((addr for addr in associated_addresses
                            if addr['private_ip_address'] == ip['ip_address']),
                           None)
            if address:
                item['association'] = {
                    'associationId': ec2utils.change_ec2_id_kind(address['id'],
                                                                 'eipassoc'),
                    'ipOwnerId': context.project_id,
                    'publicDnsName': None,
                    'publicIp': address['public_ip'],
                }
            if primary:
                ipsSet.insert(0, item)
            else:
                ipsSet.append(item)
        ec2_network_interface['privateIpAddressesSet'] = ipsSet
        primary_ip = ipsSet[0]
        ec2_network_interface['privateIpAddress'] = (
            primary_ip['privateIpAddress'])
        if 'association' in primary_ip:
            ec2_network_interface['association'] = primary_ip['association']
    return ec2_network_interface


def _attach_network_interface_item(context, network_interface, instance_id,
                                   attach_time=None,
                                   delete_on_termination=False):
    if not attach_time:
        attach_time = timeutils.isotime(None, True)
    network_interface.update({
        'instance_id': instance_id,
        'attach_time': attach_time,
        'delete_on_termination': delete_on_termination})
    db_api.update_item(context, network_interface)


def _detach_network_interface_item(context, network_interface):
    network_interface.pop('instance_id', None)
    network_interface.pop('attach_time', None)
    network_interface.pop('delete_on_termination', None)
    db_api.update_item(context, network_interface)
