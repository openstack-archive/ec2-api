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
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from ec2api.api import address as address_api
from ec2api.api import common
from ec2api.api import dhcp_options
from ec2api.api import ec2utils
from ec2api.api import security_group as security_group_api
from ec2api import clients
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""Network interface related API implementation
"""


Validator = common.Validator


def create_network_interface(context, subnet_id,
                             private_ip_address=None,
                             private_ip_addresses=None,
                             secondary_private_ip_address_count=None,
                             description=None,
                             security_group_id=None):
    subnet = ec2utils.get_db_item(context, subnet_id)
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
                parameter='PrivateIpAddresses',
                reason='IP address is out of the subnet range')
        if ip.get('primary', False):
            if primary_ip is not None:
                raise exception.InvalidParameterValue(
                    value=str(ip_address),
                    parameter='PrivateIpAddresses',
                    reason='More than one primary ip is supplied')
            else:
                primary_ip = str(ip_address)
                fixed_ips.insert(0, {'ip_address': primary_ip})
        else:
            fixed_ips.append({'ip_address': str(ip_address)})
    if not fixed_ips and not secondary_private_ip_address_count:
        secondary_private_ip_address_count = 1
    if secondary_private_ip_address_count is None:
        secondary_private_ip_address_count = 0
    if secondary_private_ip_address_count > 0:
        for _i in range(secondary_private_ip_address_count):
            fixed_ips.append({'subnet_id': os_subnet['id']})
    vpc = db_api.get_item_by_id(context, subnet['vpc_id'])
    vpc_id = vpc['id']
    dhcp_options_id = vpc.get('dhcp_options_id', None)
    if not security_group_id:
        default_groups = security_group_api.describe_security_groups(
            context,
            filter=[{'name': 'vpc-id', 'value': [vpc_id]},
                    {'name': 'group-name', 'value': ['default']}]
        )['securityGroupInfo']
        security_group_id = [default_group['groupId']
                             for default_group in default_groups]
    security_groups = db_api.get_items_by_ids(context, security_group_id)
    if any(security_group['vpc_id'] != vpc['id']
           for security_group in security_groups):
        msg = _('You have specified two resources that belong to '
                'different networks.')
        raise exception.InvalidGroupNotFound(msg)
    os_groups = [security_group['os_id'] for security_group in security_groups]
    with common.OnCrashCleaner() as cleaner:
        os_port_body = {'port': {'network_id': os_subnet['network_id'],
                                 'security_groups': os_groups}}
        os_port_body['port']['fixed_ips'] = fixed_ips
        try:
            os_port = neutron.create_port(os_port_body)['port']
        except (neutron_exception.IpAddressGenerationFailureClient,
                neutron_exception.OverQuotaClient):
            raise exception.InsufficientFreeAddressesInSubnet()
        except (neutron_exception.IpAddressInUseClient,
                neutron_exception.BadRequest) as ex:
            # NOTE(ft): AWS returns InvalidIPAddress.InUse for a primary IP
            # address, but InvalidParameterValue for secondary one.
            # AWS returns PrivateIpAddressLimitExceeded, but Neutron does
            # general InvalidInput (converted to BadRequest) in the same case.
            msg = _('Specified network interface parameters are invalid. '
                    'Reason: %(reason)s') % {'reason': ex.message}
            raise exception.InvalidParameterValue(msg)
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
                db_api.get_item_by_id(context, dhcp_options_id),
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
    network_interface = ec2utils.get_db_item(context, network_interface_id)
    if 'instance_id' in network_interface:
        msg = _("Network interface '%(eni_id)s' is currently in use.")
        msg = msg % {'eni_id': network_interface_id}
        raise exception.InvalidParameterValue(msg)

    for address in db_api.get_items(context, 'eipalloc'):
        if address.get('network_interface_id') == network_interface['id']:
            address_api._disassociate_address_item(context, address)

    neutron = clients.neutron(context)
    with common.OnCrashCleaner() as cleaner:
        db_api.delete_item(context, network_interface['id'])
        cleaner.addCleanup(db_api.restore_item, context, 'eni',
                           network_interface)
        try:
            neutron.delete_port(network_interface['os_id'])
        except neutron_exception.PortNotFoundClient:
            pass
    return True


class NetworkInterfaceDescriber(common.TaggableItemsDescriber):

    KIND = 'eni'
    FILTER_MAP = {'addresses.private-ip-address': ['privateIpAddressesSet',
                                                   'privateIpAddress'],
                  'addresses.primary': ['privateIpAddressesSet', 'primary'],
                  'addresses.association.public-ip': ['privateIpAddressesSet',
                                                      ('association',
                                                       'publicIp')],
                  'addresses.association.owner-id': ['privateIpAddressesSet',
                                                     ('association',
                                                      'ipOwnerId')],
                  'association.association-id': ('association',
                                                 'associationId'),
                  'association.allocation-id': ('association', 'allocationId'),
                  'association.ip-owner-id': ('association', 'ipOwnerId'),
                  'association.public-ip': ('association', 'publicIp'),
                  'attachment.attachment-id': ('attachment', 'attachmentId'),
                  'attachment.instance-id': ('attachment', 'instanceId'),
                  'attachment.instance-owner-id': ('attachment',
                                                   'instanceOwnerId'),
                  'attachment.device-index': ('attachment', 'deviceIndex'),
                  'attachment.status': ('attachment', 'status'),
                  'attachment.attach.time': ('attachment', 'attachTime'),
                  'attachment.delete-on-termination': ('attachment',
                                                       'deleteOnTermination'),
                  'description': 'description',
                  'group-id': ['groupSet', 'groupId'],
                  'group-name': ['groupSet', 'groupName'],
                  'mac-address': 'macAddress',
                  'network-interface-id': 'networkInterfaceId',
                  'owner-id': 'ownerId',
                  'private-ip-address': 'privateIpAddress',
                  'requester-managed': 'requesterManaged',
                  'source-dest-check': 'sourceDestCheck',
                  'status': 'status',
                  'vpc-id': 'vpcId',
                  'subnet-id': 'subnetId'}

    def format(self, network_interface, os_port):
        if not network_interface:
            return None
        return _format_network_interface(
                self.context, network_interface, os_port,
                self.ec2_addresses[network_interface['id']],
                self.security_groups)

    def get_os_items(self):
        addresses = address_api.describe_addresses(self.context)
        self.ec2_addresses = collections.defaultdict(list)
        for address in addresses['addressesSet']:
            if 'networkInterfaceId' in address:
                self.ec2_addresses[
                        address['networkInterfaceId']].append(address)
        self.security_groups = (
            security_group_api._format_security_groups_ids_names(self.context))
        neutron = clients.neutron(self.context)
        return neutron.list_ports(tenant_id=self.context.project_id)['ports']

    def get_name(self, os_item):
        return ''


def describe_network_interfaces(context, network_interface_id=None,
                                filter=None):
    formatted_network_interfaces = NetworkInterfaceDescriber().describe(
            context, ids=network_interface_id, filter=filter)
    return {'networkInterfaceSet': formatted_network_interfaces}


def assign_private_ip_addresses(context, network_interface_id,
                                private_ip_address=None,
                                secondary_private_ip_address_count=None,
                                allow_reassignment=False):
    # TODO(Alex): allow_reassignment is not supported at the moment
    network_interface = ec2utils.get_db_item(context, network_interface_id)
    subnet = db_api.get_item_by_id(context, network_interface['subnet_id'])
    neutron = clients.neutron(context)
    os_subnet = neutron.show_subnet(subnet['os_id'])['subnet']
    os_port = neutron.show_port(network_interface['os_id'])['port']
    subnet_ipnet = netaddr.IPNetwork(os_subnet['cidr'])
    fixed_ips = os_port['fixed_ips'] or []
    if private_ip_address is not None:
        for ip_address in private_ip_address:
            if netaddr.IPAddress(ip_address) not in subnet_ipnet:
                raise exception.InvalidParameterValue(
                    value=str(ip_address),
                    parameter='PrivateIpAddress',
                    reason='IP address is out of the subnet range')
            fixed_ips.append({'ip_address': str(ip_address)})
    elif secondary_private_ip_address_count > 0:
        for _i in range(secondary_private_ip_address_count):
            fixed_ips.append({'subnet_id': os_subnet['id']})
    try:
        neutron.update_port(os_port['id'],
                            {'port': {'fixed_ips': fixed_ips}})
    except neutron_exception.IpAddressGenerationFailureClient:
        raise exception.InsufficientFreeAddressesInSubnet()
    except neutron_exception.IpAddressInUseClient:
        msg = _('Some of %(addresses)s is assigned, but move is not '
                'allowed.') % {'addresses': private_ip_address}
        raise exception.InvalidParameterValue(msg)
    except neutron_exception.BadRequest as ex:
        # NOTE(ft):AWS returns PrivateIpAddressLimitExceeded, but Neutron does
        # general InvalidInput (converted to BadRequest) in the same case.
        msg = _('Specified network interface parameters are invalid. '
                'Reason: %(reason)s') % {'reason': ex.message}
        raise exception.InvalidParameterValue(msg)
    return True


def unassign_private_ip_addresses(context, network_interface_id,
                                  private_ip_address):
    network_interface = ec2utils.get_db_item(context, network_interface_id)
    if network_interface['private_ip_address'] in private_ip_address:
        raise exception.InvalidParameterValue(
                value=str(network_interface['private_ip_address']),
                parameter='PrivateIpAddresses',
                reason='Primary IP address cannot be unassigned')
    neutron = clients.neutron(context)
    os_port = neutron.show_port(network_interface['os_id'])['port']
    fixed_ips = os_port['fixed_ips'] or []
    new_fixed_ips = [ip for ip in fixed_ips
                     if ip['ip_address'] not in private_ip_address]
    if len(new_fixed_ips) + len(private_ip_address) != len(fixed_ips):
        msg = _('Some of the specified addresses are not assigned to '
                'interface %(id)s') % {'id': network_interface_id}
        raise exception.InvalidParameterValue(msg)
    os_port = neutron.update_port(os_port['id'],
                                  {'port': {'fixed_ips': new_fixed_ips}})
    return True


def describe_network_interface_attribute(context, network_interface_id,
                                         attribute=None):
    if attribute is None:
        raise exception.InvalidParameterCombination(
            _('No attributes specified.'))
    network_interface = ec2utils.get_db_item(context, network_interface_id)

    def _format_attr_description(result):
        result['description'] = {
            'value': network_interface.get('description', '')}

    def _format_attr_source_dest_check(result):
        result['sourceDestCheck'] = {
            'value': network_interface.get('source_dest_check', True)}

    def _format_attr_group_set(result):
        ec2_network_interface = describe_network_interfaces(context,
            network_interface_id=[network_interface_id]
        )['networkInterfaceSet'][0]
        result['groupSet'] = ec2_network_interface['groupSet']

    def _format_attr_attachment(result):
        ec2_network_interface = describe_network_interfaces(context,
            network_interface_id=[network_interface_id]
        )['networkInterfaceSet'][0]
        if 'attachment' in ec2_network_interface:
            result['attachment'] = ec2_network_interface['attachment']

    attribute_formatter = {
        'description': _format_attr_description,
        'sourceDestCheck': _format_attr_source_dest_check,
        'groupSet': _format_attr_group_set,
        'attachment': _format_attr_attachment,
    }

    fn = attribute_formatter.get(attribute)
    if fn is None:
        raise exception.InvalidParameterValue(value=attribute,
                                              parameter='attribute',
                                              reason='Unknown attribute.')

    result = {'networkInterfaceId': network_interface['id']}
    fn(result)
    return result


def modify_network_interface_attribute(context, network_interface_id,
                                       description=None,
                                       source_dest_check=None,
                                       security_group_id=None,
                                       attachment=None):
    params_count = (
        int(description is not None) +
        int(source_dest_check is not None) +
        int(security_group_id is not None) +
        int(attachment is not None))
    if params_count != 1:
        raise exception.InvalidParameterCombination(
            'Multiple attributes specified')
    network_interface = ec2utils.get_db_item(context, network_interface_id)
    if description is not None:
        network_interface['description'] = description
        db_api.update_item(context, network_interface)
    neutron = clients.neutron(context)
    if security_group_id is not None:
        os_groups = [sg['os_id']
                     for sg in ec2utils.get_db_items(context, 'sg',
                                                     security_group_id)]
        neutron.update_port(network_interface['os_id'],
                            {'port': {'security_groups': os_groups}})
    if source_dest_check is not None:
        allowed = [] if source_dest_check else [{'ip_address': '0.0.0.0/0'}]
        neutron.update_port(network_interface['os_id'],
                            {'port': {'allowed_address_pairs': allowed}})
        network_interface['source_dest_check'] = source_dest_check
        db_api.update_item(context, network_interface)
    if attachment:
        attachment_id = attachment.get('attachment_id')
        delete_on_termination = attachment.get('delete_on_termination')
        if attachment_id is None or delete_on_termination is None:
            raise exception.MissingParameter(
                _('The request must contain the parameter attachment '
                  'deleteOnTermination'))
        attachment_id_own = ec2utils.change_ec2_id_kind(
                network_interface['id'], 'eni-attach')
        if ('instance_id' not in network_interface
                or attachment_id_own != attachment_id):
            raise exception.InvalidAttachmentIDNotFound(id=attachment_id)
        network_interface['delete_on_termination'] = delete_on_termination
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
    network_interface = ec2utils.get_db_item(context, network_interface_id)
    if 'instance_id' in network_interface:
        raise exception.InvalidParameterValue(
            _("Network interface '%(id)s' is currently in use.") %
            {'id': network_interface_id})
    os_instance_id = ec2utils.get_db_item(context, instance_id)['os_id']
    # TODO(Alex) Check that the instance is not yet attached to another VPC
    # TODO(Alex) Check that the instance is "our", not created via nova
    # (which means that it doesn't belong to any VPC and can't be attached)
    if any(eni['device_index'] == device_index
           for eni in db_api.get_items(context, 'eni')
           if eni.get('instance_id') == instance_id):
        raise exception.InvalidParameterValue(
            _("Instance '%(id)s' already has an interface attached at "
              "device index '%(index)s'.") % {'id': instance_id,
                                              'index': device_index})
    neutron = clients.neutron(context)
    os_port = neutron.show_port(network_interface['os_id'])['port']
    nova = clients.nova(context)
    with common.OnCrashCleaner() as cleaner:
        # TODO(Alex) nova inserts compute:%availability_zone into device_owner
        #                              'device_owner': 'compute:None'}})
        _attach_network_interface_item(context, network_interface,
                                       instance_id, device_index)
        cleaner.addCleanup(_detach_network_interface_item, context,
                           network_interface)
        nova.servers.interface_attach(os_instance_id, os_port['id'],
                                      None, None)
    return {'attachmentId': ec2utils.change_ec2_id_kind(
                    network_interface['id'], 'eni-attach')}


def detach_network_interface(context, attachment_id, force=None):
    network_interface = db_api.get_item_by_id(
            context, ec2utils.change_ec2_id_kind(attachment_id, 'eni'))
    if not network_interface or 'instance_id' not in network_interface:
        raise exception.InvalidAttachmentIDNotFound(id=attachment_id)
    if network_interface['device_index'] == 0:
        raise exception.OperationNotPermitted(
            _('The network interface at device index 0 cannot be detached.'))
    neutron = clients.neutron(context)
    os_port = neutron.show_port(network_interface['os_id'])['port']
    with common.OnCrashCleaner() as cleaner:
        instance_id = network_interface['instance_id']
        device_index = network_interface['device_index']
        attach_time = network_interface['attach_time']
        delete_on_termination = network_interface['delete_on_termination']
        _detach_network_interface_item(context, network_interface)
        cleaner.addCleanup(_attach_network_interface_item,
                           context, network_interface, instance_id,
                           device_index, attach_time, delete_on_termination)
        neutron.update_port(os_port['id'],
                            {'port': {'device_id': '',
                                      'device_owner': ''}})
    return True


def _format_network_interface(context, network_interface, os_port,
                              associated_ec2_addresses=[], security_groups={}):
    ec2_network_interface = {}
    ec2_network_interface['networkInterfaceId'] = network_interface['id']
    ec2_network_interface['subnetId'] = network_interface['subnet_id']
    ec2_network_interface['vpcId'] = network_interface['vpc_id']
    ec2_network_interface['description'] = network_interface['description']
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
            'deviceIndex': network_interface['device_index'],
            'status': 'attached',
            'deleteOnTermination': network_interface['delete_on_termination'],
            'attachTime': network_interface['attach_time'],
            'instanceOwnerId': context.project_id
        }
    else:
        ec2_network_interface['status'] = 'available'
    ec2_network_interface['macAddress'] = os_port['mac_address']
    if os_port['fixed_ips']:
        ipsSet = []
        for ip in os_port['fixed_ips']:
            primary = (
                network_interface.get('private_ip_address', '') ==
                ip['ip_address'])
            item = {'privateIpAddress': ip['ip_address'],
                    'primary': primary}
            ec2_address = next(
                (addr for addr in associated_ec2_addresses
                 if addr['privateIpAddress'] == ip['ip_address']),
                None)
            if ec2_address:
                item['association'] = {
                    'associationId': ec2utils.change_ec2_id_kind(
                                    ec2_address['allocationId'], 'eipassoc'),
                    'allocationId': ec2_address['allocationId'],
                    'ipOwnerId': context.project_id,
                    'publicDnsName': None,
                    'publicIp': ec2_address['publicIp'],
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
    # NOTE(ft): AWS returns empty tag set for a network interface
    # if no tag exists
    ec2_network_interface['tagSet'] = []
    return ec2_network_interface


def _attach_network_interface_item(context, network_interface, instance_id,
                                   device_index, attach_time=None,
                                   delete_on_termination=False):
    if not attach_time:
        attach_time = timeutils.isotime(None, True)
    network_interface.update({
        'instance_id': instance_id,
        'device_index': device_index,
        'attach_time': attach_time,
        'delete_on_termination': delete_on_termination})
    db_api.update_item(context, network_interface)


def _detach_network_interface_item(context, network_interface):
    network_interface.pop('instance_id', None)
    network_interface.pop('device_index', None)
    network_interface.pop('attach_time', None)
    network_interface.pop('delete_on_termination', None)
    db_api.update_item(context, network_interface)
