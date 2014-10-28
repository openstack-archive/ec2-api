#    Copyright 2014 Cloudscaling Group, Inc
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import collections
import copy
import random
import re

from ec2api.api import clients
from ec2api.api import ec2client
from ec2api.api import ec2utils
from ec2api.api import network_interface as network_interface_api
from ec2api.api import security_group as security_group_api
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import timeutils


"""Instance related API implementation
"""

# TODO(ft): implement DeviceIndex


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

    # TODO(ft): support client tokens

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
    (network_interfaces,
     create_network_interfaces_args,
     delete_on_termination_flags) = _parse_network_interface_parameters(
                    context, neutron, vpc_network_parameters)

    security_groups = security_group_api._format_security_groups_ids_names(
            context)

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

        ec2 = ec2client.ec2client(context)
        # NOTE(ft): run instances one by one using created ports
        network_interfaces_by_instances = {}
        ec2_instance_ids = []
        for network_interfaces in instance_network_interfaces:
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

            ec2_instance_id = ec2utils.id_to_ec2_inst_id(os_instance.id)
            cleaner.addCleanup(ec2.terminate_instances,
                               instance_id=ec2_instance_id)
            nova.servers.update(os_instance, name=ec2_instance_id)

            network_interfaces_by_instances[ec2_instance_id] = (
                network_interfaces)
            ec2_instance_ids.append(ec2_instance_id)

        # TODO(ft): receive port from a create_network_interface sub-function
        os_ports = neutron.list_ports()['ports']
        os_ports = dict((p['id'], p) for p in os_ports)
        ec2_instances = ec2.describe_instances(instance_id=ec2_instance_ids)
        ec2_instances = [i for r in ec2_instances['reservationSet']
                         for i in r['instancesSet']]
        attach_time = timeutils.isotime(None, True)
        # TODO(ft): Process min and max counts on running errors accordingly to
        # their meanings. Correct error messages are also critical
        for ec2_instance in ec2_instances:
            instance_ports_info = []
            delete_on_termination = iter(delete_on_termination_flags)
            for network_interface in network_interfaces_by_instances[
                    ec2_instance['instanceId']]:
                # TODO(ft): implement update items in DB layer to prevent
                # record by record modification
                # Alternatively a create_network_interface sub-function can
                # set attach_time  at once
                network_interface.update({
                        'instance_id': ec2_instance['instanceId'],
                        'attach_time': attach_time,
                        'delete_on_termination': delete_on_termination.next()})
                db_api.update_item(context, network_interface)
                cleaner.addCleanup(
                        network_interface_api._detach_network_interface_item,
                        context, network_interface)
                os_port = os_ports[network_interface['os_id']]
                instance_ports_info.append((network_interface, os_port, [],))

            _format_instance(context, ec2_instance,
                             instance_ports_info, security_groups)

    # TODO(ft): since we run instances separately each instance has its
    # own ec2_reservation id. Now we return ec2_reservation id of
    # the last started instance
    # If we aren't able to update OpenStack to fit ec2 requirements,
    # we should have our own ec2_reservation id to use it instead of Nova's.
    ec2_reservation_id = _generate_reservation_id()
    return _format_reservation(context, ec2_reservation_id, ec2_instances)


def terminate_instances(context, instance_id):
    # NOTE(ft): collect network interfaces to update and delete
    instance_ids = set(inst_id for inst_id in instance_id)
    os_instances_ids = [ec2utils.ec2_inst_id_to_uuid(context, inst_id)
                        for inst_id in instance_ids]
    neutron = clients.neutron(context)
    os_ports = neutron.list_ports(device_id=os_instances_ids)['ports']
    # TODO(ft): implement search db items by os_id in DB layer
    network_interfaces = db_api.get_items(context, 'eni')
    network_interfaces = dict((ni['os_id'], ni)
                              for ni in network_interfaces
                              if ni.get('instance_id') in instance_ids)
    neutron = clients.neutron(context)
    for os_port in os_ports:
        network_interface = network_interfaces.get(os_port['id'])
        if not network_interface:
            continue
        if not network_interface['delete_on_termination']:
            # NOTE(ft): detach port before terminating instance to prevent
            # nova deletes it
            neutron.update_port(os_port['id'],
                                {'port': {'device_id': '',
                                          'device_owner': ''}})

    ec2 = ec2client.ec2client(context)
    # TODO(ft): rollback detached ports on any error
    instances_set = ec2.terminate_instances(instance_id=instance_id)

    for network_interface in network_interfaces.itervalues():
        if network_interface['delete_on_termination']:
            db_api.delete_item(context, network_interface['id'])
        else:
            network_interface_api._detach_network_interface_item(
                    context, network_interface)

    return instances_set


def describe_instances(context, instance_id=None, filter=None, **kwargs):

    # TODO(ft): implement filters by network attributes
    ec2 = ec2client.ec2client(context)
    result = ec2.describe_instances(instance_id=instance_id,
                                    filter=filter, **kwargs)

    os_instance_ids = [
            ec2utils.ec2_inst_id_to_uuid(context, inst['instanceId'])
            for reservation in result['reservationSet']
            for inst in reservation['instancesSet']]
    neutron = clients.neutron(context)
    os_ports = neutron.list_ports(device_id=os_instance_ids)['ports']
    os_ports = dict((p['id'], p) for p in os_ports)
    # TODO(ft): implement search db items by os_id in DB layer
    network_interfaces = collections.defaultdict(list)
    for eni in db_api.get_items(context, 'eni'):
        if 'instance_id' in eni:
            network_interfaces[eni['instance_id']].append(eni)
    os_floating_ips = neutron.list_floatingips()['floatingips']
    os_floating_ip_ids = set(ip['id'] for ip in os_floating_ips)
    addresses = collections.defaultdict(list)
    for address in db_api.get_items(context, 'eipalloc'):
        if ('network_interface_id' in address and
                address['os_id'] in os_floating_ip_ids):
            addresses[address['network_interface_id']].append(address)
    security_groups = security_group_api._format_security_groups_ids_names(
            context)

    for ec2_reservation in result['reservationSet']:
        for ec2_instance in ec2_reservation['instancesSet']:
            inst_id = ec2_instance['instanceId']
            instance_network_interfaces = network_interfaces[inst_id]
            ports_info = [(eni, os_ports[eni['os_id']], addresses[eni['id']])
                          for eni in instance_network_interfaces
                          if eni['os_id'] in os_ports]
            _format_instance(context, ec2_instance, ports_info,
                             security_groups)

    return result


def _format_instance(context, ec2_instance, ports_info, security_groups):
    if not ports_info:
        return ec2_instance
    ec2_network_interfaces = []
    for network_interface, os_port, addresses in ports_info:
        ec2_network_interface = (
                network_interface_api._format_network_interface(
                        context, network_interface, os_port, addresses,
                        security_groups=security_groups))
        attachment = ec2_network_interface.get('attachment')
        if attachment:
            attachment.pop('instanceId', None)
            attachment.pop('instanceOwnerId', None)
        ec2_network_interfaces.append(ec2_network_interface)
    ec2_instance['networkInterfaceSet'] = ec2_network_interfaces
    # NOTE(ft): get instance's subnet by instance's privateIpAddress
    instance_ip = ec2_instance['privateIpAddress']
    network_interface = None
    for network_interface, os_port, addresses in ports_info:
        if instance_ip in (ip['ip_address']
                           for ip in os_port['fixed_ips']):
            ec2_instance['subnetId'] = network_interface['subnet_id']
            break
    if network_interface:
        ec2_instance['vpcId'] = network_interface['vpc_id']

    return ec2_instance


def _format_reservation(context, ec2_reservation_id, ec2_instances):
    return {'reservationId': ec2_reservation_id,
            'ownerId': context.project_id,
            'instancesSet': ec2_instances,
            # TODO(ft): Check AWS behavior: can it start zero instances with
            # successfull result?
            'groupSet': ec2_instances[0].get('groupSet')}


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
    if kernel_id:
        os_kernel_id = ec2utils.ec2_id_to_glance_id(context, kernel_id)
        glance.images.get(os_kernel_id)
    if ramdisk_id:
        os_ramdisk_id = ec2utils.ec2_id_to_glance_id(context, ramdisk_id)
        glance.images.get(os_ramdisk_id)
    os_image_id = ec2utils.ec2_id_to_glance_id(context, image_id)
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
    if len(subnet_vpcs | network_interface_vpcs) > 1:
        msg = _('Network interface attachments may not cross '
                'VPC boundaries.')
        raise exception.InvalidParameterValue(msg)

    # TODO(ft): a race condition can occure like using a network
    # interface for an instance in parallel run_instances, or even
    # deleting a network interface. We should lock such operations

    delete_on_termination_flags = ([False] * len(network_interfaces) +
                                   delete_on_termination_flags)
    return (network_interfaces, create_network_interfaces_args,
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


# NOTE(ft): following functions are copied from various parts of Nova

_dev = re.compile('^/dev/')


def _block_device_strip_dev(device_name):
    """remove leading '/dev/'."""
    return _dev.sub('', device_name) if device_name else device_name


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
