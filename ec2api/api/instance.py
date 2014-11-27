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

import base64
import collections
import copy
import itertools
import random
import re

from novaclient import exceptions as nova_exception
from oslo.config import cfg

from ec2api.api import address as address_api
from ec2api.api import clients
from ec2api.api import ec2utils
from ec2api.api import network_interface as network_interface_api
from ec2api.api import security_group as security_group_api
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api import novadb
from ec2api.openstack.common.gettextutils import _


ec2_opts = [
    cfg.BoolOpt('ec2_private_dns_show_ip',
                default=False,
                help='Return the IP address as private dns hostname in '
                     'describe instances'),
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)

"""Instance related API implementation
"""

# TODO(ft): implement DeviceIndex

INSTANCE_FILTER_MAP = {
        'block-device-mapping.device-name': ['blockDeviceMapping',
                                             'deviceName'],
        'client-token': 'clientToken',
        'dns-name': 'dnsName',
        'image-id': 'imageId',
        'instance-id': 'instanceId',
        'instance-type': 'instanceType',
        'ip-address': 'ipAddress',
        'kernel-id': 'kernelId',
        'key-name': 'keyName',
        'launch-index': 'amiLaunchIndex',
        'launch-time': 'launchTime',
        'private-dns-name': 'privateDnsName',
        'private-ip-address': 'privateIpAddress',
        'ramdisk-id': 'ramdiskId',
        'root-device-name': 'rootDeviceName',
        'root-device-type': 'rootDeviceType',
        'subnet-id': ['networkInterfaceSet', 'subnetId'],
        'vpc-id': ['networkInterfaceSet', 'vpcId'],
        'network-interface.description': ['networkInterfaceSet',
                                          'description'],
        'network-interface.subnet-id': ['networkInterfaceSet', 'subnetId'],
        'network-interface.vpc-id': ['networkInterfaceSet', 'vpcId'],
        'network-interface.network-interface.id': ['networkInterfaceSet',
                                                   'networkInterfaceId'],
        'network-interface.owner-id': ['networkInterfaceSet', 'ownerId'],
        'network-interface.requester-managed': ['networkInterfaceSet',
                                                'requesterManaged'],
        'network-interface.status': ['networkInterfaceSet', 'status'],
        'network-interface.mac-address': ['networkInterfaceSet', 'macAddress'],
        'network-interface.source-destination-check': ['networkInterfaceSet',
                                                       'sourceDestCheck'],
}
RESERVATION_FILTER_MAP = {
        'reservation-id': 'reservationId',
        'owner-id': 'ownerId',
}


def run_instances(context, image_id, min_count, max_count,
                  key_name=None, security_group_id=None,
                  security_group=None, user_data=None, instance_type=None,
                  placement=None, kernel_id=None, ramdisk_id=None,
                  block_device_mapping=None, subnet_id=None,
                  private_ip_address=None, client_token=None,
                  network_interface=None, **kwargs):
    # TODO(ft): fix passing complex network parameters create_network_interface
    # TODO(ft): check the compatibility of complex network parameters and
    # multiple running
    # NOTE(ft): check count params to be sure the results of check
    # network interface params function
    _check_min_max_count(min_count, max_count)

    if client_token:
        idempotent_run = _get_idempotent_run(context, client_token)
        if idempotent_run:
            return idempotent_run

    os_image, os_kernel_id, os_ramdisk_id = _parse_image_parameters(
            context, image_id, kernel_id, ramdisk_id)

    nova = clients.nova(context)
    os_flavor = next((f for f in nova.flavors.list()
                      if f.name == instance_type), None)
    if not os_flavor:
        raise exception.InvalidParameterValue(value=instance_type,
                                              parameter='InstanceType')

    bdm = _parse_block_device_mapping(block_device_mapping, os_image)

    # TODO(ft): support auto_assign_floating_ip

    (security_groups_names,
     vpc_network_parameters) = _merge_network_interface_parameters(
            security_group,
            subnet_id, private_ip_address, security_group_id,
            network_interface)

    _check_network_interface_parameters(
                    vpc_network_parameters, min_count, min_count)

    neutron = clients.neutron(context)
    (vpc_id,
     network_interfaces,
     create_network_interfaces_args,
     delete_on_termination_flags) = _parse_network_interface_parameters(
                    context, neutron, vpc_network_parameters)

    # NOTE(ft): workaround for Launchpad Bug #1384347 in Icehouse
    if not security_groups_names and vpc_network_parameters:
        security_groups_names = _get_vpc_default_security_group_id(
                context, vpc_id)

    instances_info = []
    ec2_reservation_id = _generate_reservation_id()

    # TODO(ft): Process min and max counts on running errors accordingly to
    # their meanings. Correct error messages are also critical
    with utils.OnCrashCleaner() as cleaner:
        # NOTE(ft): create Neutron's ports manually to have a chance to:
        # process individual network interface options like security_group
        # or private_ip_addresses (Nova's create_instances receives only
        # one fixed_ip for subnet)
        # set dhcp options to port
        # add network interfaces to our DB
        # TODO(ft): try to:
        # extend Nova's create_instances interface to accept additional
        # network options like for Neutron's create_port
        # improve Neutron's dhcp extension to have ability to store
        # dhcp options for subnet and use them when port is being created
        # TODO(ft): we should lock created network interfaces to prevent
        # their usage or deleting
        # TODO(ft): do correct error messages on create failures. For example,
        # overlimit, ip lack, ip overlapping, etc
        if max_count == 1:
            for eni in network_interfaces:
                cleaner.addFirstCleanup(neutron.update_port,
                                        eni['os_id'],
                                        {'port': {'device_id': '',
                                                  'device_owner': ''}})
            new_network_interfaces = _create_network_interfaces(
                    context, cleaner, create_network_interfaces_args)
            network_interfaces.extend(new_network_interfaces)
            instance_network_interfaces = [network_interfaces]
        else:
            instance_network_interfaces = []
            for dummy in range(max_count):
                network_interfaces = _create_network_interfaces(
                    context, cleaner, create_network_interfaces_args)
                instance_network_interfaces.append(network_interfaces)

        # NOTE(ft): run instances one by one using created ports
        for (launch_index,
             network_interfaces) in enumerate(instance_network_interfaces):
            nics = [{'port-id': eni['os_id']} for eni in network_interfaces]

            os_instance = nova.servers.create(
                'EC2 server', os_image.id, os_flavor,
                min_count=1, max_count=1,
                kernel_id=os_kernel_id, ramdisk_id=os_ramdisk_id,
                availability_zone=(placement or {}).get('availability_zone'),
                block_device_mapping=bdm,
                security_groups=security_groups_names,
                nics=nics,
                key_name=key_name, userdata=user_data)
            cleaner.addCleanup(nova.servers.delete, os_instance.id)

            instance = {'os_id': os_instance.id,
                        'vpc_id': vpc_id,
                        'reservation_id': ec2_reservation_id,
                        'launch_index': launch_index}
            if client_token:
                instance['client_token'] = client_token
            instance = db_api.add_item(context, 'i', instance)
            cleaner.addCleanup(db_api.delete_item, context, instance['id'])

            nova.servers.update(os_instance, name=instance['id'])

            delete_on_termination = iter(delete_on_termination_flags)
            for network_interface in network_interfaces:
                # TODO(ft): implement update items in DB layer to prevent
                # record by record modification
                # Alternatively a create_network_interface sub-function can
                # set attach_time  at once
                network_interface_api._attach_network_interface_item(
                        context, network_interface, instance['id'],
                        delete_on_termination=delete_on_termination.next())
                cleaner.addCleanup(
                        network_interface_api._detach_network_interface_item,
                        context, network_interface)

            novadb_instance = novadb.instance_get_by_uuid(context,
                                                          os_instance.id)
            instances_info.append((instance, os_instance, novadb_instance,))

    # NOTE(ft): we cann't use describe_network_interfaces at this stage
    # because network interfaces are not attached yet
    ec2_network_interfaces = _format_network_interfaces(
                                        context, instance_network_interfaces)
    return _format_reservation(context, ec2_reservation_id, instances_info,
                               ec2_network_interfaces)


def terminate_instances(context, instance_id):
    instance_ids = set(instance_id)
    instances = ec2utils.get_db_items(context, 'i', instance_ids)

    # TODO(ft): implement search db items in DB layer
    network_interfaces = collections.defaultdict(list)
    for eni in db_api.get_items(context, 'eni'):
        if eni.get('instance_id') in instance_ids:
            if eni['delete_on_termination']:
                network_interfaces[eni['instance_id']].append(eni)
            else:
                network_interface_api.detach_network_interface(
                        context,
                        ec2utils.change_ec2_id_kind(eni['id'], 'eni-attach'))

    _remove_instances(context, instances, network_interfaces)
    nova = clients.nova(context)
    state_changes = []
    for instance in instances:
        try:
            os_instance = nova.servers.get(instance['os_id'])
        except nova_exception.NotFound:
            os_instance = None
        else:
            os_instance.delete()
        state_change = _format_state_change(instance, os_instance)
        state_changes.append(state_change)

    return {'instancesSet': state_changes}


def describe_instances(context, instance_id=None, filter=None,
                       max_results=None, next_token=None):
    instances = ec2utils.get_db_items(context, 'i', instance_id)

    if instance_id:
        os_instances = _get_os_instances_by_instances(context, instances)
    else:
        os_instances = clients.nova(context).servers.list()

    instances_by_os_id = dict((i['os_id'], i) for i in instances)

    reservations = collections.defaultdict(list)
    for os_instance in os_instances:
        novadb_instance = novadb.instance_get_by_uuid(context, os_instance.id)
        instance = instances_by_os_id.pop(os_instance.id, None)
        if not instance:
            instance = db_api.add_item(
                    context, 'i',
                    {'os_id': os_instance.id,
                     'vpc_id': None,
                     'reservation_id': novadb_instance['reservation_id'],
                     'launch_index': novadb_instance['launch_index']})
        reservations[instance['reservation_id']].append(
                (instance, os_instance, novadb_instance,))

    _remove_instances(context, instances_by_os_id.itervalues())

    ec2_network_interfaces = _get_ec2_network_interfaces(context, instance_id)
    reservation_filters = []
    instance_filters = []
    for f in filter or []:
        if f.get('name') in RESERVATION_FILTER_MAP:
            reservation_filters.append(f)
        else:
            instance_filters.append(f)
    ec2_reservations = []
    for reservation_id, instances_info in reservations.iteritems():
        ec2_reservation = _format_reservation(
                context, reservation_id, instances_info,
                ec2_network_interfaces, instance_filters)
        if (ec2_reservation['instancesSet'] and
                not utils.filtered_out(ec2_reservation, reservation_filters,
                                       RESERVATION_FILTER_MAP)):
            ec2_reservations.append(ec2_reservation)
    return {'reservationSet': ec2_reservations}


def reboot_instances(context, instance_id):
    return _foreach_instance(context, instance_id,
                             lambda instance: instance.reboot())


def stop_instances(context, instance_id, force=False):
    return _foreach_instance(context, instance_id,
                             lambda instance: instance.stop())


def start_instances(context, instance_id):
    return _foreach_instance(context, instance_id,
                             lambda instance: instance.start())


def describe_instance_attribute(context, instance_id, attribute):
    instance = db_api.get_item_by_id(context, 'i', instance_id)
    nova = clients.nova(context)
    os_instance = nova.servers.get(instance['os_id'])
    novadb_instance = novadb.instance_get_by_uuid(context, os_instance.id)

    def _format_attr_block_device_mapping(result):
        root_device_name = _cloud_format_instance_root_device_name(
                                                               novadb_instance)
        # TODO(ft): next call add 'rootDeviceType' to result,
        # but AWS doesn't. This is legacy behavior of Nova EC2
        _cloud_format_instance_bdm(context, os_instance.id,
                                   root_device_name, result)

    def _format_attr_disable_api_termination(result):
        result['disableApiTermination'] = {
                                'value': novadb_instance['disable_terminate']}

    def _format_attr_group_set(result):
        result['groupSet'] = _format_group_set(context,
                                               os_instance.security_groups)

    def _format_attr_instance_initiated_shutdown_behavior(result):
        value = ('terminate' if novadb_instance['shutdown_terminate']
                 else 'stop')
        result['instanceInitiatedShutdownBehavior'] = {'value': value}

    def _format_attr_instance_type(result):
        result['instanceType'] = {'value': _cloud_format_instance_type(
                                                       context, os_instance)}

    def _format_attr_kernel(result):
        value = _cloud_format_kernel_id(context, novadb_instance)
        result['kernel'] = {'value': value}

    def _format_attr_ramdisk(result):
        value = _cloud_format_ramdisk_id(context, novadb_instance)
        result['ramdisk'] = {'value': value}

    def _format_attr_root_device_name(result):
        result['rootDeviceName'] = {
                'value': _cloud_format_instance_root_device_name(
                                                             novadb_instance)}

    def _format_attr_user_data(result):
        if novadb_instance['user_data']:
            value = base64.b64decode(novadb_instance['user_data'])
            result['userData'] = {'value': value}

    attribute_formatter = {
        'blockDeviceMapping': _format_attr_block_device_mapping,
        'disableApiTermination': _format_attr_disable_api_termination,
        'groupSet': _format_attr_group_set,
        'instanceInitiatedShutdownBehavior': (
                _format_attr_instance_initiated_shutdown_behavior),
        'instanceType': _format_attr_instance_type,
        'kernel': _format_attr_kernel,
        'ramdisk': _format_attr_ramdisk,
        'rootDeviceName': _format_attr_root_device_name,
        'userData': _format_attr_user_data,
        }

    fn = attribute_formatter.get(attribute)
    if fn is None:
        # TODO(ft): clarify an exact AWS error
        raise exception.InvalidAttribute(attr=attribute)

    result = {'instance_id': instance_id}
    fn(result)
    return result


def _get_idempotent_run(context, client_token):
    # TODO(ft): implement search in DB layer
    instances = dict((i['os_id'], i) for i in db_api.get_items(context, 'i')
                     if i.get('client_token') == client_token)
    if not instances:
        return
    os_instances = _get_os_instances_by_instances(context, instances)
    instances_info = []
    instance_ids = []
    for os_instance in os_instances:
        instance = instances.pop(os_instance['id'])
        novadb_instance = novadb.instance_get_by_uuid(context, os_instance.id)
        instances_info.append((instance, os_instance, novadb_instance,))
        instance_ids.append(instance['id'])
    if instances:
        _remove_instances(context, instances.itervalues())
    if not instances_info:
        return
    ec2_network_interfaces = _get_ec2_network_interfaces(context, instance_ids)
    return _format_reservation(context, instance['reservation_id'],
                               instances_info, ec2_network_interfaces)


def _format_reservation(context, reservation_id, instances_info,
                        ec2_network_interfaces, filters=None):
    ec2_instances = []
    for (instance, os_instance, novadb_instance) in instances_info:
        ec2_instance = _format_instance(
                context, instance, os_instance, novadb_instance,
                ec2_network_interfaces.get(instance['id']))
        if not utils.filtered_out(ec2_instance, filters, INSTANCE_FILTER_MAP):
            ec2_instances.append(ec2_instance)
    ec2_reservation = {'reservationId': reservation_id,
                       'ownerId': os_instance.tenant_id,
                       'instancesSet': ec2_instances}
    if not instance['vpc_id']:
        ec2_reservation['groupSet'] = _format_group_set(
                context, os_instance.security_groups)
    return ec2_reservation


def _format_instance(context, instance, os_instance, novadb_instance,
                     ec2_network_interfaces):
    ec2_instance = {}
    ec2_instance['instanceId'] = instance['id']
    image_uuid = os_instance.image['id'] if os_instance.image else ''
    ec2_instance['imageId'] = ec2utils.glance_id_to_ec2_id(context, image_uuid)
    kernel_id = _cloud_format_kernel_id(context, novadb_instance)
    if kernel_id:
        ec2_instance['kernelId'] = kernel_id
    ramdisk_id = _cloud_format_ramdisk_id(context, novadb_instance)
    if ramdisk_id:
        ec2_instance['ramdiskId'] = ramdisk_id
    ec2_instance['instanceState'] = _cloud_state_description(
            getattr(os_instance, 'OS-EXT-STS:vm_state'))

    fixed_ip, fixed_ip6, floating_ip = _get_ip_info_for_instance(os_instance)
    if fixed_ip6:
        ec2_instance['dnsNameV6'] = fixed_ip6
    if CONF.ec2_private_dns_show_ip:
        ec2_instance['privateDnsName'] = fixed_ip
    else:
        ec2_instance['privateDnsName'] = novadb_instance['hostname']
    ec2_instance['privateIpAddress'] = fixed_ip
    if floating_ip is not None:
        ec2_instance['ipAddress'] = floating_ip
    ec2_instance['dnsName'] = floating_ip
    ec2_instance['keyName'] = os_instance.key_name

    # NOTE(ft): add tags
#     i['tagSet'] = []
#
#     for k, v in utils.instance_meta(instance).iteritems():
#         i['tagSet'].append({'key': k, 'value': v})

    if 'client_token' in instance:
        ec2_instance['clientToken'] = instance['client_token']

    if context.is_admin:
        ec2_instance['keyName'] = '%s (%s, %s)' % (ec2_instance['keyName'],
            os_instance.tenant_id,
            getattr(os_instance, 'OS-EXT-SRV-ATTR:host'))
    ec2_instance['productCodesSet'] = None
    ec2_instance['instanceType'] = _cloud_format_instance_type(context,
                                                               os_instance)
    ec2_instance['launchTime'] = os_instance.created
    ec2_instance['amiLaunchIndex'] = instance['launch_index']
    ec2_instance['rootDeviceName'] = _cloud_format_instance_root_device_name(
                                                            novadb_instance)
    _cloud_format_instance_bdm(context, instance['os_id'],
                               ec2_instance['rootDeviceName'], ec2_instance)
    ec2_instance['placement'] = {
        'availabilityZone': getattr(os_instance,
                                    'OS-EXT-AZ:availability_zone')
    }
    if not ec2_network_interfaces:
        # TODO(ft): boto uses 2010-08-31 version of AWS protocol
        # which doesn't contain groupSet element in an instance
        # We should support different versions of output data
        # ec2_instance['groupSet'] = _format_group_set(
        #         context, os_instance.security_groups)
        return ec2_instance
    # NOTE(ft): get instance's subnet by instance's privateIpAddress
    instance_ip = ec2_instance['privateIpAddress']
    main_ec2_network_interface = None
    for ec2_network_interface in ec2_network_interfaces:
        ec2_network_interface['attachment'].pop('instanceId')
        ec2_network_interface['attachment'].pop('instanceOwnerId')
        if (not main_ec2_network_interface and
                any(address['privateIpAddress'] == instance_ip
                    for address in
                            ec2_network_interface['privateIpAddressesSet'])):
            main_ec2_network_interface = ec2_network_interface
    ec2_instance['networkInterfaceSet'] = ec2_network_interfaces
    if main_ec2_network_interface:
        ec2_instance['subnetId'] = main_ec2_network_interface['subnetId']
        # TODO(ft): boto uses 2010-08-31 version of AWS protocol
        # which doesn't contain groupSet element in an instance
        # We should support different versions of output data
        # ec2_instance['groupSet'] = main_ec2_network_interface['groupSet']
    ec2_instance['vpcId'] = ec2_network_interface['vpcId']
    return ec2_instance


def _format_state_change(instance, os_instance):
    prev_state = (_cloud_state_description(getattr(os_instance,
                                                   'OS-EXT-STS:vm_state'))
                  if os_instance else vm_states_DELETED)
    try:
        os_instance.get()
        curr_state = _cloud_state_description(getattr(os_instance,
                                                      'OS-EXT-STS:vm_state'))
    except nova_exception.NotFound:
        curr_state = _cloud_state_description(vm_states_DELETED)
    return {
        'instanceId': instance['id'],
        'previousState': prev_state,
        'currentState': curr_state,
    }


def _get_ec2_network_interfaces(context, instance_ids=None):
    ec2_network_interfaces = collections.defaultdict(list)
    if not instance_ids:
        network_interface_ids = None
    else:
        # TODO(ft): implement search db items in DB layer
        network_interface_ids = [
                eni['id'] for eni in db_api.get_items(context, 'eni')
                if eni.get('instance_id') in instance_ids]
    enis = network_interface_api.describe_network_interfaces(
            context,
            network_interface_id=network_interface_ids)['networkInterfaceSet']
    for eni in enis:
        if eni['status'] == 'in-use':
            ec2_network_interfaces[eni['attachment']['instanceId']].append(eni)
    return ec2_network_interfaces


def _format_network_interfaces(context, instances_network_interfaces):
    neutron = clients.neutron(context)

    os_ports = neutron.list_ports()['ports']
    os_ports = dict((p['id'], p) for p in os_ports)

    # TODO(ft): reuse following code from network_interface_api
    os_floating_ips = neutron.list_floatingips(fields=['id'])['floatingips']
    os_floating_ip_ids = set(ip['id'] for ip in os_floating_ips)
    addresses = collections.defaultdict(list)
    for address in db_api.get_items(context, 'eipalloc'):
        if ('network_interface_id' in address and
                address['os_id'] in os_floating_ip_ids):
            addresses[address['network_interface_id']].append(address)

    security_groups = security_group_api._format_security_groups_ids_names(
            context)

    ec2_network_interfaces = collections.defaultdict(list)
    for network_interfaces in instances_network_interfaces:
        for network_interface in network_interfaces:
            ec2_eni = network_interface_api._format_network_interface(
                    context, network_interface,
                    os_ports[network_interface['os_id']],
                    addresses[network_interface['id']], security_groups)
            ec2_network_interfaces[
                    network_interface['instance_id']].append(ec2_eni)
    return ec2_network_interfaces


def _remove_instances(context, instances, network_interfaces=None):
    if network_interfaces is None:
        # TODO(ft): implement search db items by os_id in DB layer
        network_interfaces = collections.defaultdict(list)
        for eni in db_api.get_items(context, 'eni'):
            if 'instance_id' in eni:
                network_interfaces[eni['instance_id']].append(eni)

    addresses = db_api.get_items(context, 'eipalloc')
    addresses = dict((a['network_interface_id'], a) for a in addresses
                     if 'network_interface_id' in a)
    for instance in instances:
        for eni in network_interfaces[instance['id']]:
            if eni['delete_on_termination']:
                address = addresses.get(eni['id'])
                if address:
                    address_api._disassociate_address_item(context, address)
                db_api.delete_item(context, eni['id'])
            else:
                network_interface_api._detach_network_interface_item(context,
                                                                     eni)
        db_api.delete_item(context, instance['id'])


def _check_min_max_count(min_count, max_count):
    # TODO(ft): figure out appropriate aws message and use them
    min_count = int(min_count)
    max_count = int(max_count)

    if min_count < 1:
        msg = _('Minimum instance count must be greater than zero')
        raise exception.InvalidParameterValue(msg)
    elif max_count < 1:
        msg = _('Maximum instance count must be greater than zero')
        raise exception.InvalidParameterValue(msg)
    elif min_count > max_count:
        msg = _('Maximum instance count must not be smaller than '
                'minimum instance count')
        raise exception.InvalidParameterValue(msg)


def _parse_image_parameters(context, image_id, kernel_id, ramdisk_id):

    def get_os_image_id(ec2_image_id):
        try:
            return ec2utils.ec2_id_to_glance_id(context, ec2_image_id)
        except exception.NovaDbImageNotFound:
            raise exception.NovaDbImageNotFound(image_id=ec2_image_id)

    glance = clients.glance(context)
    if kernel_id:
        os_kernel_id = get_os_image_id(kernel_id)
        glance.images.get(os_kernel_id)
    if ramdisk_id:
        os_ramdisk_id = get_os_image_id(ramdisk_id)
        glance.images.get(os_ramdisk_id)
    os_image_id = get_os_image_id(image_id)
    os_image = glance.images.get(os_image_id)

    if _cloud_get_image_state(os_image) != 'available':
        # TODO(ft): Change the message with the real AWS message
        msg = _('Image must be available')
        raise exception.ImageNotActive(message=msg)

    return os_image, kernel_id, ramdisk_id


def _parse_block_device_mapping(block_device_mapping, os_image):
    # NOTE(ft): The following code allows reconfiguration of devices
    # according to list of new parameters supplied in EC2 call.
    # This code merges these parameters with information taken from image.
    image_root_device_name = os_image.properties.get('root_device_name')
    image_bdm = dict(
        (_block_device_strip_dev(bd.get('device_name') or
                                image_root_device_name),
         bd)
        for bd in os_image.properties.get('block_device_mapping', [])
        if bd.get('device_name') or bd.get('boot_index') == 0)

    for args_bd in (block_device_mapping or []):
        _cloud_parse_block_device_mapping(args_bd)
        dev_name = _block_device_strip_dev(args_bd.get('device_name'))
        if (not dev_name or dev_name not in image_bdm or
                'snapshot_id' in args_bd or 'volume_id' in args_bd):
            continue
        image_bd = image_bdm[dev_name]
        for key in ('device_name', 'delete_on_termination', 'virtual_name',
                    'snapshot_id', 'volume_id', 'volume_size',
                    'no_device'):
            args_bd[key] = args_bd.get(key, image_bd.get(key))

    return block_device_mapping


def _merge_network_interface_parameters(security_group_names,
                                        subnet_id,
                                        private_ip_address,
                                        security_group_ids,
                                        network_interfaces):
    network_interfaces = network_interfaces or []

    if ((subnet_id or private_ip_address or security_group_ids or
            security_group_names) and
            (len(network_interfaces) > 1 or
            # NOTE(ft): the only case in AWS when simple subnet_id
            # and/or private_ip_address parameters are compatible with
            # network_interface parameter is default behavior change of
            # public IP association for passed subnet_id by specifying
            # the only element in network_interfaces:
            # {"device_index": 0,
            #  "associate_public_ip_address": <boolean>}
            # Both keys must be in the dict, and no other keys
            # are allowed
            # We should support such combination of parameters for
            # compatibility purposes, even if we ignore device_index
            # and associate_public_ip_address in all other code
            len(network_interfaces) == 1 and
                (len(network_interfaces[0]) != 2 or
                 'associate_public_ip_address' not in network_interfaces[0] or
                 'device_index' not in network_interfaces[0]))):
        msg = _(' Network interfaces and an instance-level subnet ID or '
                'private IP address or security groups may not be specified '
                'on the same request')
        raise exception.InvalidParameterCombination(msg)

    if subnet_id:
        if security_group_names:
            msg = _('The parameter groupName cannot be used with '
                    'the parameter subnet')
            raise exception.InvalidParameterCombination(msg)
        param = {'subnet_id': subnet_id}
        if private_ip_address:
            param['private_ip_address'] = private_ip_address
        if security_group_ids:
            param['security_group_id'] = security_group_ids
        return None, [param]
    elif private_ip_address:
        msg = _('Specifying an IP address is only valid for VPC instances '
                'and thus requires a subnet in which to launch')
        raise exception.InvalidParameterCombination(msg)
    elif security_group_ids:
        msg = _('VPC security groups may not be used for a non-VPC launch')
        raise exception.InvalidParameterCombination(msg)
    else:
        # NOTE(ft): only one of this variables is not empty
        return security_group_names, network_interfaces


def _check_network_interface_parameters(params,
                                        min_instance_count,
                                        max_instance_count):
    # NOTE(ft): we ignore device_index and associate_public_ip_address:
    # OpenStack doesn't support them
    for param in params:
        ni_exists = 'network_interface_id' in param
        subnet_exists = 'subnet_id' in param
        ip_exists = 'private_ip_address' in param
        if not ni_exists and not subnet_exists:
            msg = _('Each network interface requires either a subnet or '
                    'a network interface ID.')
            raise exception.InvalidParameterValue(msg)
        if ni_exists and (subnet_exists or ip_exists):
            param = (_('subnet') if subnet_exists else
                     _('private IP address'))
            msg = _('A network interface may not specify both a network '
                    'interface ID and a %(param)s') % {'param': param}
            raise exception.InvalidParameterCombination(msg)
        if ni_exists and param.get('delete_on_termination'):
            msg = _('A network interface may not specify a network '
                    'interface ID and delete on termination as true')
            raise exception.InvalidParameterCombination(msg)
        if max_instance_count > 1 and (ni_exists or ip_exists):
            msg = _('Multiple instances creation is not compatible with '
                    'private IP address or network interface ID parameters.')
            raise exception.InvalidParameterCombination(msg)


def _parse_network_interface_parameters(context, neutron, params):
    network_interfaces = []
    network_interface_id_set = set()
    create_network_interfaces_args = []
    subnets = []
    delete_on_termination_flags = []
    busy_network_interfaces = []
    for param in params:
        # TODO(ft): OpenStack doesn't support more than one port in a subnet
        # for an instance, but AWS does it.
        # We should check this before creating any object in OpenStack
        if 'network_interface_id' in param:
            ec2_eni_id = param['network_interface_id']
            if ec2_eni_id in network_interface_id_set:
                msg = _("Network interface ID '%(network_interface_id)s' "
                        "may not be specified on multiple interfaces.")
                msg = msg % {'network_interface_id': ec2_eni_id}
                raise exception.InvalidParameterValue(msg)
            if 'security_group_id' in param:
                msg = _('A network interface may not specify both a network '
                        'interface ID and security groups')
                raise exception.InvalidParameterCombination
            network_interface = ec2utils.get_db_item(context, 'eni',
                                                     ec2_eni_id)
            if 'instance_id' in network_interface:
                busy_network_interfaces.append(ec2_eni_id)
            network_interfaces.append(network_interface)
            network_interface_id_set.add(ec2_eni_id)
        else:
            subnet = ec2utils.get_db_item(context, 'subnet',
                                          param['subnet_id'])
            subnets.append(subnet)
            args = copy.deepcopy(param)
            args.pop('device_index', None)
            args.pop('associate_public_ip_address', None)
            delete_on_termination_flags.append(
                    args.pop('delete_on_termination', True))
            subnet_id = args.pop('subnet_id')
            create_network_interfaces_args.append((subnet_id, args,))

    if busy_network_interfaces:
        raise exception.InvalidNetworkInterfaceInUse(
                interface_ids=busy_network_interfaces)

    subnet_vpcs = set(s['vpc_id'] for s in subnets)
    network_interface_vpcs = set(eni['vpc_id']
                                 for eni in network_interfaces)
    vpc_ids = subnet_vpcs | network_interface_vpcs
    if len(vpc_ids) > 1:
        msg = _('Network interface attachments may not cross '
                'VPC boundaries.')
        raise exception.InvalidParameterValue(msg)

    # TODO(ft): a race condition can occure like using a network
    # interface for an instance in parallel run_instances, or even
    # deleting a network interface. We should lock such operations

    delete_on_termination_flags = ([False] * len(network_interfaces) +
                                   delete_on_termination_flags)
    return (next(iter(vpc_ids), None),
            network_interfaces,
            create_network_interfaces_args,
            delete_on_termination_flags)


def _create_network_interfaces(context, cleaner, params):
    network_interfaces = []
    for subnet_id, args in params:
        ec2_network_interface = network_interface_api.create_network_interface(
                context, subnet_id, **args)['networkInterface']
        ec2_network_interface_id = ec2_network_interface['networkInterfaceId']
        cleaner.addCleanup(network_interface_api.delete_network_interface,
                           context,
                           network_interface_id=ec2_network_interface_id)
        # TODO(ft): receive network_interface from a
        # create_network_interface sub-function
        network_interface = ec2utils.get_db_item(context, 'eni',
                                                 ec2_network_interface_id)
        network_interfaces.append(network_interface)

    return network_interfaces


def _get_vpc_default_security_group_id(context, vpc_id):
    default_groups = security_group_api.describe_security_groups(
        context,
        filter=[{'name': 'vpc-id', 'value': [vpc_id]},
                {'name': 'group-name', 'value': ['Default']}]
        )['securityGroupInfo']
    security_groups = [ec2utils.get_db_item(context, 'sg',
                                            default_group['groupId'])
                       for default_group in default_groups]
    return [sg['os_id'] for sg in security_groups]


def _format_group_set(context, os_security_groups):
    if not os_security_groups:
        return None
    # TODO(ft): add groupId
    return [{'groupName': sg['name']} for sg in os_security_groups]


def _get_ip_info_for_instance(os_instance):
    addresses = list(itertools.chain(*os_instance.addresses.itervalues()))
    fixed_ip = next((addr['addr'] for addr in addresses
                     if addr['version'] == 4 and
                            addr['OS-EXT-IPS:type'] == 'fixed'), None)
    fixed_ip6 = next((addr['addr'] for addr in addresses
                      if addr['version'] == 6 and
                            addr['OS-EXT-IPS:type'] == 'fixed'), None)
    floating_ip = next((addr['addr'] for addr in addresses
                        if addr['OS-EXT-IPS:type'] == 'floating'), None)
    return fixed_ip, fixed_ip6, floating_ip


def _foreach_instance(context, instance_ids, func):
    instances = ec2utils.get_db_items(context, 'i', instance_ids)
    os_instances = _get_os_instances_by_instances(context, instances,
                                                  exactly=True)
    for os_instance in os_instances:
        func(os_instance)
    return True


def _get_os_instances_by_instances(context, instances, exactly=False):
    nova = clients.nova(context)
    os_instances = []
    for instance in instances:
        try:
            os_instances.append(nova.servers.get(instance['os_id']))
        except nova_exception.NotFound:
            if exactly:
                raise exception.InvalidInstanceIDNotFound(i_id=instance['id'])

    return os_instances

# NOTE(ft): following functions are copied from various parts of Nova

_dev = re.compile('^/dev/')


def _block_device_strip_dev(device_name):
    """remove leading '/dev/'."""
    return _dev.sub('', device_name) if device_name else device_name


def _block_device_prepend_dev(device_name):
    """Make sure there is a leading '/dev/'."""
    return device_name and '/dev/' + _block_device_strip_dev(device_name)


def _cloud_parse_block_device_mapping(bdm):
    """Parse BlockDeviceMappingItemType into flat hash

    BlockDevicedMapping.<N>.DeviceName
    BlockDevicedMapping.<N>.Ebs.SnapshotId
    BlockDevicedMapping.<N>.Ebs.VolumeSize
    BlockDevicedMapping.<N>.Ebs.DeleteOnTermination
    BlockDevicedMapping.<N>.Ebs.NoDevice
    BlockDevicedMapping.<N>.VirtualName
    => remove .Ebs and allow volume id in SnapshotId
    """
    ebs = bdm.pop('ebs', None)
    if ebs:
        ec2_id = ebs.pop('snapshot_id', None)
        if ec2_id:
            if ec2_id.startswith('snap-'):
                bdm['snapshot_id'] = ec2utils.ec2_snap_id_to_uuid(ec2_id)
            elif ec2_id.startswith('vol-'):
                bdm['volume_id'] = ec2utils.ec2_vol_id_to_uuid(ec2_id)
            else:
                # NOTE(ft): AWS returns undocumented InvalidSnapshotID.NotFound
                raise exception.InvalidSnapshotIDMalformed(snapshot_id=ec2_id)
            ebs.setdefault('delete_on_termination', True)
        bdm.update(ebs)
    return bdm


def _utils_generate_uid(topic, size=8):
    characters = '01234567890abcdefghijklmnopqrstuvwxyz'
    choices = [random.choice(characters) for _x in xrange(size)]
    return '%s-%s' % (topic, ''.join(choices))


def _generate_reservation_id():
    return _utils_generate_uid('r')


def _cloud_get_image_state(image):
    state = image.status
    if state == 'active':
        state = 'available'
    return image.properties.get('image_state', state)


def _cloud_format_kernel_id(context, instance_ref):
    kernel_uuid = instance_ref['kernel_id']
    if kernel_uuid is None or kernel_uuid == '':
        return
    return ec2utils.glance_id_to_ec2_id(context, kernel_uuid, 'aki')


def _cloud_format_ramdisk_id(context, instance_ref):
    ramdisk_uuid = instance_ref['ramdisk_id']
    if ramdisk_uuid is None or ramdisk_uuid == '':
        return
    return ec2utils.glance_id_to_ec2_id(context, ramdisk_uuid, 'ari')


def _cloud_format_instance_type(context, os_instance):
    return clients.nova(context).flavors.get(os_instance.flavor['id']).name


def _cloud_format_instance_root_device_name(novadb_instance):
    return (novadb_instance.get('root_device_name') or
            block_device_DEFAULT_ROOT_DEV_NAME)


block_device_DEFAULT_ROOT_DEV_NAME = '/dev/sda1'


def _cloud_format_instance_bdm(context, instance_uuid, root_device_name,
                               result):
    """Format InstanceBlockDeviceMappingResponseItemType."""
    root_device_type = 'instance-store'
    root_device_short_name = _block_device_strip_dev(root_device_name)
    if root_device_name == root_device_short_name:
        root_device_name = _block_device_prepend_dev(root_device_name)
    cinder = clients.cinder(context)
    mapping = []
    for bdm in novadb.block_device_mapping_get_all_by_instance(context,
                                                               instance_uuid):
        volume_id = bdm['volume_id']
        if (volume_id is None or bdm['no_device']):
            continue

        if ((bdm['snapshot_id'] or bdm['volume_id']) and
                (bdm['device_name'] == root_device_name or
                 bdm['device_name'] == root_device_short_name)):
            root_device_type = 'ebs'

        vol = cinder.volumes.get(volume_id)
        # TODO(yamahata): volume attach time
        ebs = {'volumeId': ec2utils.id_to_ec2_vol_id(volume_id),
               'deleteOnTermination': bdm['delete_on_termination'],
               'attachTime': '',
               'status': _cloud_get_volume_attach_status(vol), }
        res = {'deviceName': bdm['device_name'],
               'ebs': ebs, }
        mapping.append(res)

    if mapping:
        result['blockDeviceMapping'] = mapping
    result['rootDeviceType'] = root_device_type


def _cloud_get_volume_attach_status(volume):
    if volume.status in ('attaching', 'detaching'):
        return volume.status
    elif volume.attachments:
        return 'attached'
    else:
        return 'detached'


# NOTE(ft): nova/compute/vm_states.py

"""Possible vm states for instances.

Compute instance vm states represent the state of an instance as it pertains to
a user or administrator.

vm_state describes a VM's current stable (not transition) state. That is, if
there is no ongoing compute API calls (running tasks), vm_state should reflect
what the customer expect the VM to be. When combined with task states
(task_states.py), a better picture can be formed regarding the instance's
health and progress.

See http://wiki.openstack.org/VMState
"""

vm_states_ACTIVE = 'active'  # VM is running
vm_states_BUILDING = 'building'  # VM only exists in DB
vm_states_PAUSED = 'paused'
vm_states_SUSPENDED = 'suspended'  # VM is suspended to disk.
vm_states_STOPPED = 'stopped'  # VM is powered off, the disk image is still
# there.
vm_states_RESCUED = 'rescued'  # A rescue image is running with the original VM
# image attached.
vm_states_RESIZED = 'resized'  # a VM with the new size is active. The user is
# expected to manually confirm or revert.

vm_states_SOFT_DELETED = 'soft-delete'  # VM is marked as deleted but the disk
# images are still available to restore.
vm_states_DELETED = 'deleted'  # VM is permanently deleted.

vm_states_ERROR = 'error'

vm_states_SHELVED = 'shelved'  # VM is powered off, resources still on
# hypervisor
vm_states_SHELVED_OFFLOADED = 'shelved_offloaded'  # VM and associated
# resources are not on hypervisor

vm_states_ALLOW_SOFT_REBOOT = [vm_states_ACTIVE]  # states we can soft reboot
# from
vm_states_ALLOW_HARD_REBOOT = (
    vm_states_ALLOW_SOFT_REBOOT +
    [vm_states_STOPPED, vm_states_PAUSED, vm_states_SUSPENDED,
     vm_states_ERROR])
# states we allow hard reboot from

# NOTE(ft): end of nova/compute/vm_states.py

# NOTE(ft): nova/api/ec2/inst_states.py

inst_state_PENDING_CODE = 0
inst_state_RUNNING_CODE = 16
inst_state_SHUTTING_DOWN_CODE = 32
inst_state_TERMINATED_CODE = 48
inst_state_STOPPING_CODE = 64
inst_state_STOPPED_CODE = 80

inst_state_PENDING = 'pending'
inst_state_RUNNING = 'running'
inst_state_SHUTTING_DOWN = 'shutting-down'
inst_state_TERMINATED = 'terminated'
inst_state_STOPPING = 'stopping'
inst_state_STOPPED = 'stopped'

# non-ec2 value
inst_state_MIGRATE = 'migrate'
inst_state_RESIZE = 'resize'
inst_state_PAUSE = 'pause'
inst_state_SUSPEND = 'suspend'
inst_state_RESCUE = 'rescue'

# EC2 API instance status code
_NAME_TO_CODE = {
    inst_state_PENDING: inst_state_PENDING_CODE,
    inst_state_RUNNING: inst_state_RUNNING_CODE,
    inst_state_SHUTTING_DOWN: inst_state_SHUTTING_DOWN_CODE,
    inst_state_TERMINATED: inst_state_TERMINATED_CODE,
    inst_state_STOPPING: inst_state_STOPPING_CODE,
    inst_state_STOPPED: inst_state_STOPPED_CODE,

    # approximation
    inst_state_MIGRATE: inst_state_RUNNING_CODE,
    inst_state_RESIZE: inst_state_RUNNING_CODE,
    inst_state_PAUSE: inst_state_STOPPED_CODE,
    inst_state_SUSPEND: inst_state_STOPPED_CODE,
    inst_state_RESCUE: inst_state_RUNNING_CODE,
}
_CODE_TO_NAMES = dict([(code,
                        [item[0] for item in _NAME_TO_CODE.iteritems()
                         if item[1] == code])
                       for code in set(_NAME_TO_CODE.itervalues())])


def inst_state_name_to_code(name):
    return _NAME_TO_CODE.get(name, inst_state_PENDING_CODE)


def inst_state_code_to_names(code):
    return _CODE_TO_NAMES.get(code, [])

# NOTE(ft): end of nova/api/ec2/inst_state.py

# EC2 API can return the following values as documented in the EC2 API
# http://docs.amazonwebservices.com/AWSEC2/latest/APIReference/
#    ApiReference-ItemType-InstanceStateType.html
# pending 0 | running 16 | shutting-down 32 | terminated 48 | stopping 64 |
# stopped 80
_STATE_DESCRIPTION_MAP = {
    None: inst_state_PENDING,
    vm_states_ACTIVE: inst_state_RUNNING,
    vm_states_BUILDING: inst_state_PENDING,
    vm_states_DELETED: inst_state_TERMINATED,
    vm_states_SOFT_DELETED: inst_state_TERMINATED,
    vm_states_STOPPED: inst_state_STOPPED,
    vm_states_PAUSED: inst_state_PAUSE,
    vm_states_SUSPENDED: inst_state_SUSPEND,
    vm_states_RESCUED: inst_state_RESCUE,
    vm_states_RESIZED: inst_state_RESIZE,
}
_EC2_STATE_TO_VM = dict((state,
                         [item[0]
                          for item in _STATE_DESCRIPTION_MAP.iteritems()
                          if item[1] == state])
                        for state in set(_STATE_DESCRIPTION_MAP.itervalues()))


def _cloud_state_description(vm_state):
    """Map the vm state to the server status string."""
    # Note(maoy): We do not provide EC2 compatibility
    # in shutdown_terminate flag behavior. So we ignore
    # it here.
    name = _STATE_DESCRIPTION_MAP.get(vm_state, vm_state)

    return {'code': inst_state_name_to_code(name),
            'name': name}
