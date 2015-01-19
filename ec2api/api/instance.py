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
import json
import random
import re

from glanceclient import exc as glance_exception
from novaclient import exceptions as nova_exception
from oslo.config import cfg

from ec2api.api import address as address_api
from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import network_interface as network_interface_api
from ec2api.api import security_group as security_group_api
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api import novadb
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import timeutils


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


Validator = common.Validator


def get_instance_engine():
    if CONF.full_vpc_support:
        return InstanceEngineNeutron()
    else:
        return InstanceEngineNova()


# TODO(ft): implement DeviceIndex


def run_instances(context, image_id, min_count, max_count,
                  key_name=None, security_group_id=None,
                  security_group=None, user_data=None, instance_type=None,
                  placement=None, kernel_id=None, ramdisk_id=None,
                  block_device_mapping=None, monitoring=None,
                  subnet_id=None, disable_api_termination=None,
                  instance_initiated_shutdown_behavior=None,
                  private_ip_address=None, client_token=None,
                  network_interface=None, iam_instance_profile=None,
                  ebs_optimized=None):

    _check_min_max_count(min_count, max_count)

    if client_token:
        idempotent_run = _get_idempotent_run(context, client_token)
        if idempotent_run:
            return idempotent_run

    return instance_engine.run_instances(
        context, image_id, min_count, max_count,
        key_name, security_group_id,
        security_group, user_data, instance_type,
        placement, kernel_id, ramdisk_id,
        block_device_mapping, monitoring,
        subnet_id, disable_api_termination,
        instance_initiated_shutdown_behavior,
        private_ip_address, client_token,
        network_interface, iam_instance_profile,
        ebs_optimized)


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

    _remove_instances(context, instances, network_interfaces)

    return {'instancesSet': state_changes}


class InstanceDescriber(common.TaggableItemsDescriber):

    KIND = 'i'
    FILTER_MAP = {
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
        'network-interface.mac-address': ['networkInterfaceSet',
                                          'macAddress'],
        'network-interface.source-destination-check': ['networkInterfaceSet',
                                                       'sourceDestCheck'],
    }

    def __init__(self):
        super(InstanceDescriber, self).__init__()
        self.reservations = {}
        self.reservation_instances = collections.defaultdict(list)
        self.reservation_os_groups = {}
        self.obsolete_instances = []

    def format(self, instance, os_instance):
        novadb_instance = self.novadb_instances[os_instance.id]
        formatted_instance = _format_instance(
                self.context, instance, os_instance, novadb_instance,
                self.ec2_network_interfaces.get(instance['id']),
                self.image_ids, self.volumes)

        reservation_id = instance['reservation_id']
        if reservation_id in self.reservations:
            reservation = self.reservations[reservation_id]
        else:
            reservation = {'id': reservation_id,
                           'owner_id': os_instance.tenant_id}
            self.reservations[reservation_id] = reservation
            if not instance['vpc_id']:
                self.reservation_os_groups[reservation_id] = (
                        os_instance.security_groups
                        if hasattr(os_instance, 'security_groups') else [])

        self.reservation_instances[
                reservation['id']].append(formatted_instance)

        return formatted_instance

    def get_db_items(self):
        instances = super(InstanceDescriber, self).get_db_items()
        self.ec2_network_interfaces = (
            instance_engine.get_ec2_network_interfaces(
                self.context, self.ids))
        self.volumes = dict((v['os_id'], v)
                            for v in db_api.get_items(self.context, 'vol'))
        self.image_ids = dict((i['os_id'], i['id'])
                              for i in itertools.chain(
                                  db_api.get_items(self.context, 'ami'),
                                  db_api.get_public_items(self.context,
                                                          'ami')))
        return instances

    def get_os_items(self):
        self.novadb_instances = {}
        return clients.nova(self.context).servers.list(
                # NOTE(ft): these filters are needed for metadata server
                # which calls describe_instances with an admin account
                # (but project_id is substituted to an instance's one).
                search_opts={'all_tenants': self.context.cross_tenants,
                             'project_id': self.context.project_id})

    def auto_update_db(self, instance, os_instance):
        novadb_instance = novadb.instance_get_by_uuid(self.context,
                                                      os_instance.id)
        self.novadb_instances[os_instance.id] = novadb_instance
        if not instance:
            instance = ec2utils.get_db_item_by_os_id(
                    self.context, 'i', os_instance.id,
                    novadb_instance=novadb_instance)
        return instance

    def get_name(self, os_item):
        return ''

    def delete_obsolete_item(self, instance):
        self.obsolete_instances.append(instance)


class ReservationDescriber(common.NonOpenstackItemsDescriber):

    KIND = 'r'
    FILTER_MAP = {
        'reservation-id': 'reservationId',
        'owner-id': 'ownerId',
    }

    def format(self, reservation):
        formatted_instances = [i for i in self.instances[reservation['id']]
                               if i['instanceId'] in self.suitable_instances]
        if not formatted_instances:
            return None
        return _format_reservation_body(self.context, reservation,
                                        formatted_instances,
                                        self.os_groups.get(reservation['id']))

    def get_db_items(self):
        return self.reservations

    def describe(self, context, ids=None, names=None, filter=None):
        reservation_filters = []
        instance_filters = []
        for f in filter or []:
            if f.get('name') in self.FILTER_MAP:
                reservation_filters.append(f)
            else:
                instance_filters.append(f)
        # NOTE(ft): set empty filter sets to None because Describer
        # requires None for no filter case
        if not instance_filters:
            instance_filters = None
        if not reservation_filters:
            reservation_filters = None

        instance_describer = InstanceDescriber()
        formatted_instances = instance_describer.describe(
                context, ids=ids, filter=instance_filters)

        _remove_instances(context, instance_describer.obsolete_instances)

        self.reservations = instance_describer.reservations.values()
        self.instances = instance_describer.reservation_instances
        self.os_groups = instance_describer.reservation_os_groups
        self.suitable_instances = set(i['instanceId']
                                      for i in formatted_instances)

        return super(ReservationDescriber, self).describe(
                context, filter=reservation_filters)


def describe_instances(context, instance_id=None, filter=None,
                       max_results=None, next_token=None):
    formatted_reservations = ReservationDescriber().describe(
            context, ids=instance_id, filter=filter)
    return {'reservationSet': formatted_reservations}


def reboot_instances(context, instance_id):
    return _foreach_instance(context, instance_id,
                             lambda instance: instance.reboot())


def stop_instances(context, instance_id, force=False):
    return _foreach_instance(context, instance_id,
                             lambda instance: instance.stop())


def start_instances(context, instance_id):
    return _foreach_instance(context, instance_id,
                             lambda instance: instance.start())


def get_password_data(context, instance_id):
    # NOTE(Alex): AWS supports one and only one instance_id here
    instance = ec2utils.get_db_item(context, 'i', instance_id)
    nova = clients.nova(context)
    os_instance = nova.servers.get(instance['os_id'])
    password = os_instance.get_password()
    # NOTE(vish): this should be timestamp from the metadata fields
    #             but it isn't important enough to implement properly
    now = timeutils.utcnow()
    return {"instanceId": instance_id,
            "timestamp": now,
            "passwordData": password}


def get_console_output(context, instance_id):
    # NOTE(Alex): AWS supports one and only one instance_id here
    instance = ec2utils.get_db_item(context, 'i', instance_id)
    nova = clients.nova(context)
    os_instance = nova.servers.get(instance['os_id'])
    console_output = os_instance.get_console_output()
    now = timeutils.utcnow()
    return {"instanceId": instance_id,
            "timestamp": now,
            "output": console_output}


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

    # NOTE(ft): delete obsolete instances
    if instances:
        _remove_instances(context, instances.itervalues())
    if not instances_info:
        return
    ec2_network_interfaces = (
        instance_engine.get_ec2_network_interfaces(context, instance_ids))
    return _format_reservation(context, instance['reservation_id'],
                               instances_info, ec2_network_interfaces)


def _format_reservation_body(context, reservation, formatted_instances,
                             os_groups):
    formatted_reservation = {'reservationId': reservation['id'],
                             'ownerId': reservation['owner_id'],
                             'instancesSet': formatted_instances}
    if os_groups is not None:
        formatted_reservation['groupSet'] = _format_group_set(
                context, os_groups)
    return formatted_reservation


def _format_reservation(context, reservation_id, instances_info,
                        ec2_network_interfaces, image_ids={}):
    formatted_instances = []
    for (instance, os_instance, novadb_instance) in instances_info:
        ec2_instance = _format_instance(
                context, instance, os_instance, novadb_instance,
                ec2_network_interfaces.get(instance['id']), image_ids)
        formatted_instances.append(ec2_instance)

    reservation = {'id': reservation_id,
                   'owner_id': os_instance.tenant_id}
    return _format_reservation_body(
            context, reservation, formatted_instances,
            None if instance['vpc_id'] else os_instance.security_groups)


def _format_instance(context, instance, os_instance, novadb_instance,
                     ec2_network_interfaces, image_ids, volumes=None):
    ec2_instance = {
        'amiLaunchIndex': instance['launch_index'],
        'imageId': (ec2utils.os_id_to_ec2_id(context, 'ami',
                                             os_instance.image['id'],
                                             ids_by_os_id=image_ids)
                    if os_instance.image else None),
        'instanceId': instance['id'],
        'instanceType': _cloud_format_instance_type(context, os_instance),
        'keyName': os_instance.key_name,
        'launchTime': os_instance.created,
        'placement': {
            'availabilityZone': getattr(os_instance,
                                        'OS-EXT-AZ:availability_zone')},
        'productCodesSet': None,
        'instanceState': _cloud_state_description(
                                getattr(os_instance, 'OS-EXT-STS:vm_state')),
        'rootDeviceName': _cloud_format_instance_root_device_name(
                                                            novadb_instance),
    }
    _cloud_format_instance_bdm(context, instance['os_id'],
                               ec2_instance['rootDeviceName'], ec2_instance,
                               volumes)
    kernel_id = _cloud_format_kernel_id(context, novadb_instance, image_ids)
    if kernel_id:
        ec2_instance['kernelId'] = kernel_id
    ramdisk_id = _cloud_format_ramdisk_id(context, novadb_instance, image_ids)
    if ramdisk_id:
        ec2_instance['ramdiskId'] = ramdisk_id

    if 'client_token' in instance:
        ec2_instance['clientToken'] = instance['client_token']

    if not ec2_network_interfaces:
        fixed_ip, fixed_ip6, floating_ip = (
            _get_ip_info_for_instance(os_instance))
        if fixed_ip6:
            ec2_instance['dnsNameV6'] = fixed_ip6
        dns_name = floating_ip
        # TODO(ft): boto uses 2010-08-31 version of AWS protocol
        # which doesn't contain groupSet element in an instance
        # We should support different versions of output data
        # ec2_instance['groupSet'] = _format_group_set(
        #         context, os_instance.security_groups)
    else:
        primary_ec2_network_interface = None
        for ec2_network_interface in ec2_network_interfaces:
            ec2_network_interface['attachment'].pop('instanceId')
            ec2_network_interface['attachment'].pop('instanceOwnerId')
            ec2_network_interface.pop('tagSet')
            if not primary_ec2_network_interface:
                primary_ec2_network_interface = ec2_network_interface
        ec2_instance['networkInterfaceSet'] = ec2_network_interfaces
        fixed_ip = primary_ec2_network_interface['privateIpAddress']
        if 'association' in primary_ec2_network_interface:
            association = primary_ec2_network_interface['association']
            floating_ip = association['publicIp']
            dns_name = association['publicDnsName']
        else:
            floating_ip = dns_name = None
        ec2_instance['vpcId'] = primary_ec2_network_interface['vpcId']
        ec2_instance['subnetId'] = primary_ec2_network_interface['subnetId']
        # TODO(ft): boto uses 2010-08-31 version of AWS protocol
        # which doesn't contain groupSet element in an instance
        # We should support different versions of output data
        # ec2_instance['groupSet'] = primary_ec2_network_interface['groupSet']
    ec2_instance.update({
        'privateIpAddress': fixed_ip,
        'privateDnsName': (fixed_ip if CONF.ec2_private_dns_show_ip else
                           novadb_instance['hostname']),
        'dnsName': dns_name,
    })
    if floating_ip is not None:
        ec2_instance['ipAddress'] = floating_ip

    if context.is_admin:
        ec2_instance['keyName'] = '%s (%s, %s)' % (ec2_instance['keyName'],
            os_instance.tenant_id,
            getattr(os_instance, 'OS-EXT-SRV-ATTR:host'))
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


def _remove_instances(context, instances, network_interfaces=None):
    if not instances:
        return
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
    glance = clients.glance(context)

    # TODO(ft): we can't get all images from DB per one request due different
    # kinds. It's need to refactor DB API and ec2utils functions to work with
    # kind smarter
    def get_os_image(kind, ec2_image_id):
        try:
            images = db_api.get_public_items(context, kind, (ec2_image_id,))
            if images:
                image = images[0]
            else:
                image = db_api.get_item_by_id(context, kind, ec2_image_id)
            os_image = glance.images.get(image['os_id'])
        except (IndexError, glance_exception.HTTPNotFound):
            raise exception.InvalidAMIIDNotFound(id=ec2_image_id)
        return os_image

    os_kernel_id = (get_os_image('aki', kernel_id)['os_id']
                    if kernel_id else None)
    os_ramdisk_id = (get_os_image('ari', ramdisk_id)['os_id']
                     if ramdisk_id else None)
    os_image = get_os_image('ami', image_id)

    if _cloud_get_image_state(os_image) != 'available':
        # TODO(ft): Change the message with the real AWS message
        msg = _('Image must be available')
        raise exception.ImageNotActive(message=msg)

    return os_image, os_kernel_id, os_ramdisk_id


def _parse_block_device_mapping(context, block_device_mapping, os_image):
    # NOTE(ft): The following code allows reconfiguration of devices
    # according to list of new parameters supplied in EC2 call.
    # This code merges these parameters with information taken from image.
    image_root_device_name = os_image.properties.get('root_device_name')
    image_bdm = dict(
        (_block_device_strip_dev(bd.get('device_name') or
                                image_root_device_name),
         bd)
        for bd in json.loads(
                os_image.properties.get('block_device_mapping', '[]'))
        if bd.get('device_name') or bd.get('boot_index') == 0)

    for args_bd in (block_device_mapping or []):
        _cloud_parse_block_device_mapping(context, args_bd)
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


def _format_group_set(context, os_security_groups):
    if not os_security_groups:
        return None
    # TODO(ft): Euca tools uses 2010-08-31 AWS protocol version which doesn't
    # contain groupId in groupSet of an instance structure
    # Euca crashes if groupId is present here
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
    found_obsolete_instance = False
    for instance in instances:
        try:
            os_instances.append(nova.servers.get(instance['os_id']))
        except nova_exception.NotFound:
            db_api.delete_item(context, instance['id'])
            found_obsolete_instance = True
    if found_obsolete_instance and exactly:
        raise exception.InvalidInstanceIDNotFound(id=instance['id'])

    return os_instances


def _is_ebs_instance(context, os_instance):
    novadb_instance = novadb.instance_get_by_uuid(context, os_instance.id)
    root_device_name = _cloud_format_instance_root_device_name(novadb_instance)
    root_device_short_name = _block_device_strip_dev(root_device_name)
    if root_device_name == root_device_short_name:
        root_device_name = _block_device_prepend_dev(root_device_name)
    for bdm in novadb.block_device_mapping_get_all_by_instance(context,
                                                               os_instance.id):
        volume_id = bdm['volume_id']
        if (volume_id is None or bdm['no_device']):
            continue

        if ((bdm['snapshot_id'] or bdm['volume_id']) and
                (bdm['device_name'] == root_device_name or
                 bdm['device_name'] == root_device_short_name)):
            return True
    return False


def _generate_reservation_id():
    return _utils_generate_uid('r')


class InstanceEngineNeutron(object):

    def run_instances(self, context, image_id, min_count, max_count,
                      key_name=None, security_group_id=None,
                      security_group=None, user_data=None, instance_type=None,
                      placement=None, kernel_id=None, ramdisk_id=None,
                      block_device_mapping=None, monitoring=None,
                      subnet_id=None, disable_api_termination=None,
                      instance_initiated_shutdown_behavior=None,
                      private_ip_address=None, client_token=None,
                      network_interface=None, iam_instance_profile=None,
                      ebs_optimized=None):
        # TODO(ft): fix passing complex network parameters to
        # create_network_interface
        # TODO(ft): check the compatibility of complex network parameters and
        # multiple running
        os_image, os_kernel_id, os_ramdisk_id = _parse_image_parameters(
                context, image_id, kernel_id, ramdisk_id)

        nova = clients.nova(context)
        os_flavor = next((f for f in nova.flavors.list()
                          if f.name == instance_type), None)
        if not os_flavor:
            raise exception.InvalidParameterValue(value=instance_type,
                                                  parameter='InstanceType')

        bdm = _parse_block_device_mapping(context, block_device_mapping,
                                          os_image)

        # TODO(ft): support auto_assign_floating_ip

        (security_groups_names,
         vpc_network_parameters) = self.merge_network_interface_parameters(
            security_group,
            subnet_id, private_ip_address, security_group_id,
            network_interface)

        self.check_network_interface_parameters(
            vpc_network_parameters, min_count, min_count)

        (vpc_id,
         network_interfaces,
         create_network_interfaces_args,
         delete_on_termination_flags) = (
            self.parse_network_interface_parameters(
                context, vpc_network_parameters))

        # NOTE(ft): workaround for Launchpad Bug #1384347 in Icehouse
        if not security_groups_names and vpc_network_parameters:
            security_groups_names = self.get_vpc_default_security_group_id(
                    context, vpc_id)

        neutron = clients.neutron(context)
        if not vpc_id:
            ec2_classic_nics = [
                {'net-id': self.get_ec2_classic_os_network(context,
                                                           neutron)['id']}]

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
            # TODO(ft): do correct error messages on create failures. For
            # example, overlimit, ip lack, ip overlapping, etc
            if max_count == 1:
                for eni in network_interfaces:
                    cleaner.addFirstCleanup(neutron.update_port,
                                            eni['os_id'],
                                            {'port': {'device_id': '',
                                                      'device_owner': ''}})
                new_network_interfaces = self.create_network_interfaces(
                        context, cleaner, create_network_interfaces_args)
                network_interfaces.extend(new_network_interfaces)
                instance_network_interfaces = [network_interfaces]
            else:
                instance_network_interfaces = []
                for dummy in range(max_count):
                    network_interfaces = self.create_network_interfaces(
                        context, cleaner, create_network_interfaces_args)
                    instance_network_interfaces.append(network_interfaces)

            # NOTE(ft): run instances one by one using created ports
            for (launch_index,
                 network_interfaces) in enumerate(instance_network_interfaces):
                nics = ([{'port-id': eni['os_id']} for eni in
                         network_interfaces]
                        if vpc_id else
                        ec2_classic_nics)

                os_instance = nova.servers.create(
                    'EC2 server', os_image.id, os_flavor,
                    min_count=1, max_count=1,
                    kernel_id=os_kernel_id, ramdisk_id=os_ramdisk_id,
                    availability_zone=(
                        (placement or {}).get('availability_zone')),
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
                instances_info.append((instance, os_instance, novadb_instance))

        # NOTE(ft): we cann't use describe_network_interfaces at this stage
        # because network interfaces are not attached yet
        ec2_network_interfaces = self.format_network_interfaces(
            context, instance_network_interfaces)
        return _format_reservation(context, ec2_reservation_id, instances_info,
                                   ec2_network_interfaces,
                                   image_ids={os_image.id: image_id})

    def get_ec2_network_interfaces(self, context, instance_ids=None):
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
                network_interface_id=network_interface_ids
                )['networkInterfaceSet']
        for eni in enis:
            if eni['status'] == 'in-use':
                ec2_network_interfaces[
                    eni['attachment']['instanceId']].append(eni)
        return ec2_network_interfaces

    def check_network_interface_parameters(self, params,
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
                        'private IP address or network interface ID '
                        'parameters.')
                raise exception.InvalidParameterCombination(msg)

    def parse_network_interface_parameters(self, context, params):
        network_interfaces = []
        network_interface_id_set = set()
        create_network_interfaces_args = []
        subnets = []
        delete_on_termination_flags = []
        busy_network_interfaces = []
        for param in params:
            # TODO(ft): OpenStack doesn't support more than one port in a
            # subnet for an instance, but AWS does it.
            # We should check this before creating any object in OpenStack
            if 'network_interface_id' in param:
                ec2_eni_id = param['network_interface_id']
                if ec2_eni_id in network_interface_id_set:
                    msg = _("Network interface ID '%(network_interface_id)s' "
                            "may not be specified on multiple interfaces.")
                    msg = msg % {'network_interface_id': ec2_eni_id}
                    raise exception.InvalidParameterValue(msg)
                if 'security_group_id' in param:
                    msg = _('A network interface may not specify both a '
                            'network interface ID and security groups')
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

    def create_network_interfaces(self, context, cleaner, params):
        network_interfaces = []
        for subnet_id, args in params:
            ec2_network_interface = (
                network_interface_api.create_network_interface(
                    context, subnet_id, **args)['networkInterface'])
            ec2_network_interface_id = (
                ec2_network_interface['networkInterfaceId'])
            cleaner.addCleanup(network_interface_api.delete_network_interface,
                               context,
                               network_interface_id=ec2_network_interface_id)
            # TODO(ft): receive network_interface from a
            # create_network_interface sub-function
            network_interface = ec2utils.get_db_item(context, 'eni',
                                                     ec2_network_interface_id)
            network_interfaces.append(network_interface)

        return network_interfaces

    def get_vpc_default_security_group_id(self, context, vpc_id):
        default_groups = security_group_api.describe_security_groups(
            context,
            filter=[{'name': 'vpc-id', 'value': [vpc_id]},
                    {'name': 'group-name', 'value': ['Default']}]
            )['securityGroupInfo']
        security_groups = [ec2utils.get_db_item(context, 'sg',
                                                default_group['groupId'])
                           for default_group in default_groups]
        return [sg['os_id'] for sg in security_groups]

    def get_ec2_classic_os_network(self, context, neutron):
        os_subnet_ids = [eni['os_id']
                         for eni in db_api.get_items(context, 'subnet')]
        if os_subnet_ids:
            os_subnets = neutron.list_subnets(id=os_subnet_ids,
                                              fields=['network_id'])['subnets']
            vpc_os_network_ids = set(sn['network_id'] for sn in os_subnets)
        else:
            vpc_os_network_ids = []
        os_networks = neutron.list_networks(**{'router:external': False,
                                               'fields': ['id']})['networks']
        ec2_classic_os_networks = [n for n in os_networks
                                   if n['id'] not in vpc_os_network_ids]
        if len(ec2_classic_os_networks) == 0:
            raise exception.Unsupported(
                    reason=_('There are no available networks '
                             'for EC2 Classic mode'))
        if len(ec2_classic_os_networks) > 1:
            raise exception.Unsupported(
                    reason=_('There is more than one available network '
                             'for EC2 Classic mode'))
        return ec2_classic_os_networks[0]

    def merge_network_interface_parameters(self,
                                           security_group_names,
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
                     'associate_public_ip_address' not in network_interfaces[0]
                     or 'device_index' not in network_interfaces[0]))):
            msg = _(' Network interfaces and an instance-level subnet ID or '
                    'private IP address or security groups may not be '
                    'specified on the same request')
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

    def format_network_interfaces(self, context, instances_network_interfaces):
        neutron = clients.neutron(context)

        os_ports = neutron.list_ports()['ports']
        os_ports = dict((p['id'], p) for p in os_ports)

        # TODO(ft): reuse following code from network_interface_api
        os_floating_ips = neutron.list_floatingips(
            fields=['id'])['floatingips']
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


class InstanceEngineNova(object):

    def run_instances(self, context, image_id, min_count, max_count,
                      key_name=None, security_group_id=None,
                      security_group=None, user_data=None, instance_type=None,
                      placement=None, kernel_id=None, ramdisk_id=None,
                      block_device_mapping=None, monitoring=None,
                      subnet_id=None, disable_api_termination=None,
                      instance_initiated_shutdown_behavior=None,
                      private_ip_address=None, client_token=None,
                      network_interface=None, iam_instance_profile=None,
                      ebs_optimized=None):
        os_image, os_kernel_id, os_ramdisk_id = _parse_image_parameters(
                context, image_id, kernel_id, ramdisk_id)

        nova = clients.nova(context)
        os_flavor = next((f for f in nova.flavors.list()
                          if f.name == instance_type), None)
        if not os_flavor:
            raise exception.InvalidParameterValue(value=instance_type,
                                                  parameter='InstanceType')

        bdm = _parse_block_device_mapping(context, block_device_mapping,
                                          os_image)

        # TODO(ft): support auto_assign_floating_ip

        instances_info = []
        ec2_reservation_id = _generate_reservation_id()

        # TODO(ft): Process min and max counts on running errors accordingly to
        # their meanings. Correct error messages are also critical
        with utils.OnCrashCleaner() as cleaner:
            for index in range(max_count):
                os_instance = nova.servers.create(
                    'EC2 server', os_image.id, os_flavor,
                    min_count=min_count, max_count=max_count,
                    kernel_id=os_kernel_id, ramdisk_id=os_ramdisk_id,
                    availability_zone=(
                        placement or {}).get('availability_zone'),
                    block_device_mapping=bdm,
                    security_groups=security_group,
                    key_name=key_name, userdata=user_data)
                cleaner.addCleanup(nova.servers.delete, os_instance)

                instance = {'os_id': os_instance.id,
                            'reservation_id': ec2_reservation_id,
                            'launch_index': index}
                if client_token:
                    instance['client_token'] = client_token
                instance = db_api.add_item(context, 'i', instance)
                cleaner.addCleanup(db_api.delete_item, context, instance['id'])

                nova.servers.update(os_instance, name=instance['id'])

                novadb_instance = novadb.instance_get_by_uuid(context,
                                                              os_instance.id)
                instances_info.append((instance, os_instance, novadb_instance))

        return _format_reservation(context, ec2_reservation_id, instances_info,
                                   {}, image_ids={os_image.id: image_id})

    def get_ec2_network_interfaces(self, context, instance_ids=None):
        return {}


instance_engine = get_instance_engine()


def _auto_create_instance_extension(context, instance, novadb_instance=None):
    if not novadb_instance:
        novadb_instance = novadb.instance_get_by_uuid(context,
                                                      instance['os_id'])
    instance['reservation_id'] = novadb_instance['reservation_id']
    instance['launch_index'] = novadb_instance['launch_index']


ec2utils.register_auto_create_db_item_extension(
        'i', _auto_create_instance_extension)


# NOTE(ft): following functions are copied from various parts of Nova

def _cloud_parse_block_device_mapping(context, bdm):
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
                snapshot = ec2utils.get_db_item(context, 'snap', ec2_id)
                bdm['snapshot_id'] = snapshot['id']
            elif ec2_id.startswith('vol-'):
                volume = ec2utils.get_db_item(context, 'vol', ec2_id)
                bdm['volume_id'] = volume['id']
            else:
                # NOTE(ft): AWS returns undocumented InvalidSnapshotID.NotFound
                raise exception.InvalidSnapshotIDMalformed(snapshot_id=ec2_id)
            ebs.setdefault('delete_on_termination', True)
        bdm.update(ebs)
    return bdm


def _cloud_get_image_state(image):
    state = image.status
    if state == 'active':
        state = 'available'
    return image.properties.get('image_state', state)


def _cloud_format_kernel_id(context, instance_ref, image_ids=None):
    kernel_uuid = instance_ref['kernel_id']
    if kernel_uuid is None or kernel_uuid == '':
        return
    return ec2utils.os_id_to_ec2_id(context, 'aki', kernel_uuid,
                                    ids_by_os_id=image_ids)


def _cloud_format_ramdisk_id(context, instance_ref, image_ids=None):
    ramdisk_uuid = instance_ref['ramdisk_id']
    if ramdisk_uuid is None or ramdisk_uuid == '':
        return
    return ec2utils.os_id_to_ec2_id(context, 'ari', ramdisk_uuid,
                                    ids_by_os_id=image_ids)


def _cloud_format_instance_type(context, os_instance):
    return clients.nova(context).flavors.get(os_instance.flavor['id']).name


def _cloud_format_instance_root_device_name(novadb_instance):
    return (novadb_instance.get('root_device_name') or
            _block_device_DEFAULT_ROOT_DEV_NAME)


def _cloud_state_description(vm_state):
    """Map the vm state to the server status string."""
    # Note(maoy): We do not provide EC2 compatibility
    # in shutdown_terminate flag behavior. So we ignore
    # it here.
    name = _STATE_DESCRIPTION_MAP.get(vm_state, vm_state)

    return {'code': inst_state_name_to_code(name),
            'name': name}


def _cloud_format_instance_bdm(context, instance_uuid, root_device_name,
                               result, volumes=None):
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
        volume = ec2utils.get_db_item_by_os_id(context, 'vol', volume_id,
                                               volumes)
        # TODO(yamahata): volume attach time
        ebs = {'volumeId': volume['id'],
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


_dev = re.compile('^/dev/')


def _block_device_strip_dev(device_name):
    """remove leading '/dev/'."""
    return _dev.sub('', device_name) if device_name else device_name


def _block_device_prepend_dev(device_name):
    """Make sure there is a leading '/dev/'."""
    return device_name and '/dev/' + _block_device_strip_dev(device_name)


_block_device_DEFAULT_ROOT_DEV_NAME = '/dev/sda1'


def _utils_generate_uid(topic, size=8):
    characters = '01234567890abcdefghijklmnopqrstuvwxyz'
    choices = [random.choice(characters) for _x in xrange(size)]
    return '%s-%s' % (topic, ''.join(choices))


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
