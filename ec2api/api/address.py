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
try:
    from neutronclient.common import exceptions as neutron_exception
except ImportError:
    pass  # clients will log absense of neutronclient in this case
from novaclient import exceptions as nova_exception
from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _


CONF = cfg.CONF
CONF.import_opt('external_network', 'ec2api.api.internet_gateway')


def get_address_engine():
    if CONF.full_vpc_support:
        return AddressEngineNeutron()
    else:
        return AddressEngineNova()


# TODO(ft): generate unique association id

def allocate_address(context, domain=None):
    if domain and domain != 'vpc':
        msg = _("Invalid value '%(domain)s' for domain.") % {'domain': domain}
        raise exception.InvalidParameterValue(msg)

    address, os_floating_ip = address_engine.allocate_address(context, domain)

    return _format_address(context, address, os_floating_ip)


def associate_address(context, public_ip=None, instance_id=None,
                      allocation_id=None, network_interface_id=None,
                      private_ip_address=None, allow_reassociation=False):
    if not public_ip and not allocation_id:
        msg = _('Either public IP or allocation id must be specified')
        raise exception.MissingParameter(msg)
    if public_ip and allocation_id:
        msg = _('You may specify public IP or allocation id, '
                'but not both in the same call')
        raise exception.InvalidParameterCombination(msg)
    if not instance_id and not network_interface_id:
        msg = _('Either instance ID or network interface id must be specified')
        raise exception.MissingParameter(msg)
    associationId = address_engine.associate_address(
        context, public_ip, instance_id,
        allocation_id, network_interface_id,
        private_ip_address, allow_reassociation)
    if associationId:
        return {'return': True,
                'associationId': associationId}
    return {'return': True}


def disassociate_address(context, public_ip=None, association_id=None):
    if not public_ip and not association_id:
        msg = _('Either public IP or association id must be specified')
        raise exception.MissingParameter(msg)
    if public_ip and association_id:
        msg = _('You may specify public IP or association id, '
                'but not both in the same call')
        raise exception.InvalidParameterCombination(msg)
    address_engine.disassociate_address(context, public_ip, association_id)
    return True


def release_address(context, public_ip=None, allocation_id=None):
    if not public_ip and not allocation_id:
        msg = _('Either public IP or allocation id must be specified')
        raise exception.MissingParameter(msg)
    if public_ip and allocation_id:
        msg = _('You may specify public IP or allocation id, '
                'but not both in the same call')
        raise exception.InvalidParameterCombination(msg)

    address_engine.release_address(context, public_ip, allocation_id)
    return True


class AddressDescriber(common.TaggableItemsDescriber):

    KIND = 'eipalloc'
    FILTER_MAP = {'allocation-id': 'allocationId',
                  'association-id': 'associationId',
                  'domain': 'domain',
                  'instance-id': 'instanceId',
                  'network-interface-id': 'networkInterfaceId',
                  'network-interface-owner-id': 'networkInterfaceOwnerId',
                  'privateIpAddress': 'privateIpAddress',
                  'public-ip': 'publicIp'}

    def __init__(self, os_ports):
        self.os_ports = os_ports

    def format(self, item=None, os_item=None):
        return _format_address(self.context, item, os_item, self.os_ports)

    def get_os_items(self):
        return address_engine.get_os_floating_ips(self.context)

    def get_name(self, os_item):
        return os_item['floating_ip_address']


def describe_addresses(context, public_ip=None, allocation_id=None,
                       filter=None):
    if public_ip:
        for ip in public_ip:
            try:
                ip_address = netaddr.IPAddress(ip)
            except Exception as ex:
                raise exception.InvalidParameterValue(
                    value=str(public_ip),
                    parameter='public_ip',
                    reason='Invalid public IP specified')
    formatted_addresses = AddressDescriber(
        address_engine.get_os_ports(context)).describe(
            context, allocation_id, public_ip, filter)
    return {'addressesSet': formatted_addresses}


def _format_address(context, address, os_floating_ip, os_ports=[]):
    ec2_address = {'publicIp': os_floating_ip['floating_ip_address']}
    fixed_ip_address = os_floating_ip.get('fixed_ip_address')
    if fixed_ip_address:
        ec2_address['privateIpAddress'] = fixed_ip_address
        port_id = os_floating_ip.get('port_id')
        if port_id:
            port = next((port for port in os_ports
                if port['id'] == port_id), None)
            if port and port.get('device_id'):
                ec2_address['instanceId'] = (
                    ec2utils.id_to_ec2_inst_id(port['device_id']))
        elif os_floating_ip.get('instance_id'):
                ec2_address['instanceId'] = (
                    ec2utils.id_to_ec2_inst_id(os_floating_ip['instance_id']))
    if not address:
        ec2_address['domain'] = 'standard'
    else:
        ec2_address['domain'] = 'vpc'
        ec2_address['allocationId'] = address['id']
        if 'network_interface_id' in address:
            ec2_address.update({
                    'associationId': ec2utils.change_ec2_id_kind(
                            ec2_address['allocationId'], 'eipassoc'),
                    'networkInterfaceId': address['network_interface_id'],
                    'networkInterfaceOwnerId': context.project_id})
    return ec2_address


def _is_address_valid(context, neutron, address):
    try:
        neutron.show_floatingip(address['os_id'])
    except neutron_exception.NotFound:
        return False
    else:
        return True


def _associate_address_item(context, address, network_interface_id,
                            private_ip_address):
    address['network_interface_id'] = network_interface_id
    address['private_ip_address'] = private_ip_address
    db_api.update_item(context, address)


def _disassociate_address_item(context, address):
    address.pop('network_interface_id')
    address.pop('private_ip_address')
    db_api.update_item(context, address)


class AddressEngineNeutron(object):

    def allocate_address(self, context, domain=None):
        if not domain:
            return AddressEngineNova().allocate_address(context)
        neutron = clients.neutron(context)
        # TODO(ft): check no public network exists
        search_opts = {'router:external': True, 'name': CONF.external_network}
        os_networks = neutron.list_networks(**search_opts)['networks']
        os_public_network = os_networks[0]

        with utils.OnCrashCleaner() as cleaner:
            os_floating_ip = {'floating_network_id': os_public_network['id']}
            # TODO(ft): handle error to process floating ip overlimit
            os_floating_ip = neutron.create_floatingip(
                    {'floatingip': os_floating_ip})
            os_floating_ip = os_floating_ip['floatingip']
            cleaner.addCleanup(neutron.delete_floatingip, os_floating_ip['id'])

            address = {'os_id': os_floating_ip['id'],
                       'public_ip': os_floating_ip['floating_ip_address']}
            address = db_api.add_item(context, 'eipalloc', address)
        return address, os_floating_ip

    def release_address(self, context, public_ip, allocation_id):
        neutron = clients.neutron(context)
        if public_ip:
            # TODO(ft): implement search in DB layer
            address = next((addr for addr in
                                db_api.get_items(context, 'eipalloc')
                            if addr['public_ip'] == public_ip), None)
            if address and _is_address_valid(context, neutron, address):
                msg = _('You must specify an allocation id when releasing a '
                        'VPC elastic IP address')
                raise exception.InvalidParameterValue(msg)
            return AddressEngineNova().release_address(context,
                                                       public_ip, None)

        address = ec2utils.get_db_item(context, 'eipalloc', allocation_id)
        if not _is_address_valid(context, neutron, address):
            raise exception.InvalidAllocationIDNotFound(
                id=allocation_id)
        if 'network_interface_id' in address:
            raise exception.InvalidIPAddressInUse(
                ip_address=address['public_ip'])

        with utils.OnCrashCleaner() as cleaner:
            db_api.delete_item(context, address['id'])
            cleaner.addCleanup(db_api.restore_item, context,
                               'eipalloc', address)
            try:
                neutron.delete_floatingip(address['os_id'])
            except neutron_exception.NotFound:
                # TODO(ft): catch FloatingIPNotFound
                pass

    def associate_address(self, context, public_ip=None, instance_id=None,
                          allocation_id=None, network_interface_id=None,
                          private_ip_address=None, allow_reassociation=False):
        instance_network_interfaces = []
        if instance_id:
            # TODO(ft): check instance exists
            # TODO(ft): implement search in DB layer
            for eni in db_api.get_items(context, 'eni'):
                if instance_id and eni.get('instance_id') == instance_id:
                    instance_network_interfaces.append(eni)

        neutron = clients.neutron(context)
        if public_ip:
            if instance_network_interfaces:
                msg = _('You must specify an allocation id when mapping '
                        'an address to a VPC instance')
                raise exception.InvalidParameterCombination(msg)
            # TODO(ft): implement search in DB layer
            address = next((addr for addr in db_api.get_items(context,
                                                              'eipalloc')
                            if addr['public_ip'] == public_ip), None)
            if address and _is_address_valid(context, neutron, address):
                msg = _("The address '%(public_ip)s' does not belong to you.")
                raise exception.AuthFailure(msg % {'public_ip': public_ip})

            # NOTE(ft): in fact only the first two parameters are used to
            # associate an address in EC2 Classic mode. Other parameters are
            # sent to validate them for EC2 Classic mode and raise an error.
            return AddressEngineNova().associate_address(context,
                                                       public_ip=public_ip,
                                                       instance_id=instance_id)

        if instance_id:
            if not instance_network_interfaces:
                msg = _('You must specify an IP address when mapping '
                        'to a non-VPC instance')
                raise exception.InvalidParameterCombination(msg)
            if len(instance_network_interfaces) > 1:
                raise exception.InvalidInstanceId(instance_id=instance_id)
            network_interface = instance_network_interfaces[0]
        else:
            network_interface = ec2utils.get_db_item(context, 'eni',
                                                     network_interface_id)
        if not private_ip_address:
            private_ip_address = network_interface['private_ip_address']

        address = ec2utils.get_db_item(context, 'eipalloc', allocation_id)
        if not _is_address_valid(context, neutron, address):
            raise exception.InvalidAllocationIDNotFound(
                id=allocation_id)
        if address.get('network_interface_id') == network_interface['id']:
            # NOTE(ft): idempotent call
            pass
        elif address.get('network_interface_id') and not allow_reassociation:
            msg = _('resource %(eipalloc_id)s is already associated with '
                    'associate-id %(eipassoc_id)s')
            msg = msg % {'eipalloc_id': allocation_id,
                         'eipassoc_id': ec2utils.change_ec2_id_kind(
                            address['id'], 'eipassoc')}
            raise exception.ResourceAlreadyAssociated(msg)
        else:
            with utils.OnCrashCleaner() as cleaner:
                _associate_address_item(context, address,
                                        network_interface['id'],
                                        private_ip_address)
                cleaner.addCleanup(_disassociate_address_item, context,
                                   address)

                os_floating_ip = {'port_id': network_interface['os_id'],
                                  'fixed_ip_address': private_ip_address}
                neutron.update_floatingip(address['os_id'],
                                          {'floatingip': os_floating_ip})
        return ec2utils.change_ec2_id_kind(address['id'], 'eipassoc')

    def disassociate_address(self, context, public_ip=None,
                             association_id=None):
        neutron = clients.neutron(context)
        if public_ip:
            # TODO(ft): implement search in DB layer
            address = next((addr for addr in db_api.get_items(context,
                                                              'eipalloc')
                            if addr['public_ip'] == public_ip), None)
            if address and _is_address_valid(context, neutron, address):
                msg = _('You must specify an association id when unmapping '
                        'an address from a VPC instance')
                raise exception.InvalidParameterValue(msg)
            return AddressEngineNova().disassociate_address(context,
                                                          public_ip=public_ip)

        address = db_api.get_item_by_id(
            context, 'eipalloc', ec2utils.change_ec2_id_kind(association_id,
                                                             'eipalloc'))
        if address is None or not _is_address_valid(context, neutron, address):
            raise exception.InvalidAssociationIDNotFound(
                    id=association_id)
        if 'network_interface_id' in address:
            with utils.OnCrashCleaner() as cleaner:
                network_interface_id = address['network_interface_id']
                private_ip_address = address['private_ip_address']
                _disassociate_address_item(context, address)
                cleaner.addCleanup(_associate_address_item, context, address,
                                   network_interface_id, private_ip_address)

                neutron.update_floatingip(address['os_id'],
                                          {'floatingip': {'port_id': None}})

    def get_os_floating_ips(self, context):
        neutron = clients.neutron(context)
        return neutron.list_floatingips()['floatingips']

    def get_os_ports(self, context):
        neutron = clients.neutron(context)
        return neutron.list_ports()['ports']


class AddressEngineNova(object):

    def allocate_address(self, context, domain=None):
        nova = clients.nova(context)
        nova_floating_ip = nova.floating_ips.create()
        return None, self.convert_ips_to_neutron_format(context,
                                                        [nova_floating_ip])[0]

    def release_address(self, context, public_ip, allocation_id):
        nova = clients.nova(context)
        try:
            nova.floating_ips.delete(self.get_ip_os_id(context, public_ip))
        except nova_exception.NotFound:
            # TODO(ft): catch FloatingIPNotFound
            pass

    def associate_address(self, context, public_ip=None, instance_id=None,
                          allocation_id=None, network_interface_id=None,
                          private_ip_address=None, allow_reassociation=False):
        nova = clients.nova(context)
        os_instance_id = ec2utils.get_db_item(context, 'i',
                                              instance_id)['os_id']
        nova.servers.add_floating_ip(os_instance_id, public_ip)
        return None

    def disassociate_address(self, context, public_ip=None,
                             association_id=None):
        nova = clients.nova(context)
        os_instance_id = self.get_nova_ip_by_public_ip(context,
                                                       public_ip).instance_id
        if os_instance_id:
            try:
                nova.servers.remove_floating_ip(os_instance_id, public_ip)
            except nova_exception.Forbidden:
                raise exception.AuthFailure(
                    msg=_('The address %(public_ip)s does not belong to you') %
                    {'public_ip': public_ip})
        return None

    def get_os_floating_ips(self, context):
        nova = clients.nova(context)
        return self.convert_ips_to_neutron_format(context,
                                                  nova.floating_ips.list())

    def convert_ips_to_neutron_format(self, context, nova_ips):
        neutron_ips = []
        for nova_ip in nova_ips:
            neutron_ips.append({'id': nova_ip.id,
                                'floating_ip_address': nova_ip.ip,
                                'fixed_ip_address': nova_ip.fixed_ip,
                                'instance_id': nova_ip.instance_id})
        return neutron_ips

    def get_os_ports(self, context):
        return []

    def get_ip_os_id(self, context, public_ip,
                         nova_floating_ips=None):
        nova_ip = self.get_nova_ip_by_public_ip(context, public_ip,
                                                nova_floating_ips)
        return nova_ip.id

    def get_nova_ip_by_public_ip(self, context, public_ip,
                                 nova_floating_ips=None):
        if nova_floating_ips is None:
            nova = clients.nova(context)
            nova_floating_ips = nova.floating_ips.list()
        nova_ip = next((ip for ip in nova_floating_ips
                            if ip.ip == public_ip), None)
        if nova_ip is None:
            raise exception.InvalidAddressNotFound(ip=public_ip)
        return nova_ip


address_engine = get_address_engine()
