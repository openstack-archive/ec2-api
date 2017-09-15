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
import itertools

from novaclient import exceptions as nova_exception
from oslo_cache import core as cache_core
from oslo_config import cfg
from oslo_log import log as logging
import six

from ec2api.api import clients
from ec2api.api import ec2utils
from ec2api.api import instance as instance_api
from ec2api import exception


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

VERSIONS = [
    '1.0',
    '2007-01-19',
    '2007-03-01',
    '2007-08-29',
    '2007-10-10',
    '2007-12-15',
    '2008-02-01',
    '2008-09-01',
    '2009-04-04',
]

VERSION_DATA = {
    '1.0': ['ami-id',
            'ami-launch-index',
            'ami-manifest-path',
            'hostname',
            'instance-id',
            'local-ipv4',
            'public-keys',
            'reservation-id',
            'security-groups'],
    '2007-01-19': ['local-hostname',
                   'public-hostname',
                   'public-ipv4'],
    '2007-03-01': ['product-codes'],
    '2007-08-29': ['instance-type'],
    '2007-10-10': ['ancestor-ami-ids',
                   'ramdisk-id'],
    '2007-12-15': ['block-device-mapping'],
    '2008-02-01': ['kernel-id',
                   'placement'],
    '2008-09-01': ['instance-action'],
    '2009-04-04': [],
}


def get_version_list():
    return _format_metadata_item(VERSIONS + ["latest"])


def get_os_instance_and_project_id_by_provider_id(context, provider_id,
                                                  fixed_ip):
    neutron = clients.neutron(context)
    os_subnets = neutron.list_subnets(advanced_service_providers=[provider_id],
                                      fields=['network_id'])
    if not os_subnets:
        raise exception.EC2MetadataNotFound()
    os_networks = [subnet['network_id']
                   for subnet in os_subnets['subnets']]
    try:
        os_port = neutron.list_ports(
            fixed_ips='ip_address=' + fixed_ip,
            network_id=os_networks,
            fields=['device_id', 'tenant_id'])['ports'][0]
    except IndexError:
        raise exception.EC2MetadataNotFound()
    os_instance_id = os_port['device_id']
    project_id = os_port['tenant_id']
    return os_instance_id, project_id


def get_metadata_item(context, path_tokens, os_instance_id, remote_ip,
                      cache_region):
    version = path_tokens[0]
    if version == "latest":
        version = VERSIONS[-1]
    elif version not in VERSIONS:
        raise exception.EC2MetadataNotFound()

    cache_key = 'ec2api-metadata-%s' % os_instance_id
    cache = cache_region.get(
        cache_key, expiration_time=CONF.metadata.cache_expiration)
    if cache and cache != cache_core.NO_VALUE:
        _check_instance_owner(context, os_instance_id, cache['owner_id'])
        LOG.debug("Using cached metadata for instance %s", os_instance_id)
    else:
        ec2_instance, ec2_reservation = (
            _get_ec2_instance_and_reservation(context, os_instance_id))

        _check_instance_owner(context, os_instance_id,
                              ec2_reservation['ownerId'])

        metadata = _build_metadata(context, ec2_instance, ec2_reservation,
                                   os_instance_id, remote_ip)
        cache = {'metadata': metadata,
                 'owner_id': ec2_reservation['ownerId']}

        cache_region.set(cache_key, cache)

    metadata = cache['metadata']
    metadata = _cut_down_to_version(metadata, version)
    metadata_item = _find_path_in_tree(metadata, path_tokens[1:])
    return _format_metadata_item(metadata_item)


def _get_ec2_instance_and_reservation(context, os_instance_id):
    instance_id = ec2utils.os_id_to_ec2_id(context, 'i', os_instance_id)
    try:
        ec2_reservations = instance_api.describe_instances(
                context, [instance_id])
    except exception.InvalidInstanceIDNotFound:
        ec2_reservations = instance_api.describe_instances(
                context, filter=[{'name': 'instance-id',
                                  'value': [instance_id]}])
    if (len(ec2_reservations['reservationSet']) != 1 or
            len(ec2_reservations['reservationSet'][0]['instancesSet']) != 1):
        LOG.error('Failed to get metadata for instance id: %s',
                  os_instance_id)
        raise exception.EC2MetadataNotFound()

    ec2_reservation = ec2_reservations['reservationSet'][0]
    ec2_instance = ec2_reservation['instancesSet'][0]

    return ec2_instance, ec2_reservation


def _check_instance_owner(context, os_instance_id, owner_id):
    # NOTE(ft): check for case of Neutron metadata proxy.
    # It sends project_id as X-Tenant-ID HTTP header.
    # We make sure it's correct
    if context.project_id != owner_id:
        LOG.warning('Tenant_id %(tenant_id)s does not match tenant_id '
                    'of instance %(instance_id)s.',
                    {'tenant_id': context.project_id,
                     'instance_id': os_instance_id})
        raise exception.EC2MetadataNotFound()


def _build_metadata(context, ec2_instance, ec2_reservation,
                    os_instance_id, remote_ip):
    metadata = {
        'ami-id': ec2_instance['imageId'],
        'ami-launch-index': ec2_instance['amiLaunchIndex'],
        # NOTE (ft): the fake value as it is in Nova EC2 metadata
        'ami-manifest-path': 'FIXME',
        # NOTE (ft): empty value as it is in Nova EC2 metadata
        'ancestor-ami-ids': [],
        'block-device-mapping': _build_block_device_mappings(context,
                                                             ec2_instance,
                                                             os_instance_id),
        # NOTE(ft): Nova EC2 metadata returns instance's hostname with
        # dhcp_domain suffix if it's set in config.
        # But i don't see any reason to return a hostname differs from EC2
        # describe output one. If we need to consider dhcp_domain suffix
        # then we should do it in the describe operation
        'hostname': ec2_instance['privateDnsName'],
        # NOTE (ft): the fake value as it is in Nova EC2 metadata
        'instance-action': 'none',
        'instance-id': ec2_instance['instanceId'],
        'instance-type': ec2_instance['instanceType'],
        'local-hostname': ec2_instance['privateDnsName'],
        'local-ipv4': ec2_instance['privateIpAddress'] or remote_ip,
        'placement': {
            'availability-zone': ec2_instance['placement']['availabilityZone']
        },
        # NOTE (ft): empty value as it is in Nova EC2 metadata
        'product-codes': [],
        'public-hostname': ec2_instance['dnsName'],
        'public-ipv4': ec2_instance.get('ipAddress', ''),
        'reservation-id': ec2_reservation['reservationId'],
        'security-groups': [sg['groupName']
                            for sg in ec2_reservation.get('groupSet', [])],
    }
    if 'kernelId' in ec2_instance:
        metadata['kernel-id'] = ec2_instance['kernelId']
    if 'ramdiskId' in ec2_instance:
        metadata['ramdisk-id'] = ec2_instance['ramdiskId']
    # public keys are strangely rendered in ec2 metadata service
    #  meta-data/public-keys/ returns '0=keyname' (with no trailing /)
    # and only if there is a public key given.
    # '0=keyname' means there is a normally rendered dict at
    #  meta-data/public-keys/0
    #
    # meta-data/public-keys/ : '0=%s' % keyname
    # meta-data/public-keys/0/ : 'openssh-key'
    # meta-data/public-keys/0/openssh-key : '%s' % publickey
    if ec2_instance['keyName']:
        metadata['public-keys'] = {
            '0': {'_name': "0=" + ec2_instance['keyName']}}
        nova = clients.nova(context)
        os_instance = nova.servers.get(os_instance_id)
        try:
            keypair = nova.keypairs._get(
                '/%s/%s?user_id=%s' % (nova.keypairs.keypair_prefix,
                                       ec2_instance['keyName'],
                                       os_instance.user_id),
                'keypair')
        except nova_exception.NotFound:
            pass
        else:
            metadata['public-keys']['0']['openssh-key'] = keypair.public_key

    full_metadata = {'meta-data': metadata}

    userdata = instance_api.describe_instance_attribute(
                    context, ec2_instance['instanceId'], 'userData')
    if 'userData' in userdata:
        userdata = userdata['userData']['value']
        userdata = base64.b64decode(userdata)
        userdata = userdata.decode("utf-8")
        full_metadata['user-data'] = userdata

    return full_metadata


def _build_block_device_mappings(context, ec2_instance, os_instance_id):
    mappings = {'root': ec2_instance.get('rootDeviceName', ''),
                'ami': ec2utils.block_device_strip_dev(
                            ec2_instance.get('rootDeviceName', ''))}
    if 'blockDeviceMapping' in ec2_instance:
        # NOTE(yamahata): I'm not sure how ebs device should be numbered.
        #                 Right now sort by device name for deterministic
        #                 result.
        ebs_devices = [ebs['deviceName']
                       for ebs in ec2_instance['blockDeviceMapping']]
        ebs_devices.sort()
        ebs_devices = {'ebs%d' % num: ebs
                       for num, ebs in enumerate(ebs_devices)}
        mappings.update(ebs_devices)

    # TODO(ft): extend Nova API to get ephemerals and swap
    return mappings


def _cut_down_to_version(metadata, version):
    version_number = VERSIONS.index(version) + 1
    if version_number == len(VERSIONS):
        return metadata
    return {attr: metadata[attr]
            for attr in itertools.chain(
                *(VERSION_DATA[ver] for ver in VERSIONS[:version_number]))
            if attr in metadata}


def _format_metadata_item(data):
    if isinstance(data, dict):
        output = ''
        for key in sorted(data.keys()):
            if key == '_name':
                continue
            if isinstance(data[key], dict):
                if '_name' in data[key]:
                    output += str(data[key]['_name'])
                else:
                    output += key + '/'
            else:
                output += key

            output += '\n'
        return output[:-1]
    elif isinstance(data, list):
        return '\n'.join(data)
    else:
        return six.text_type(data)


def _find_path_in_tree(data, path_tokens):
    # given a dict/list tree, and a path in that tree, return data found there.
    for i in range(0, len(path_tokens)):
        if isinstance(data, dict) or isinstance(data, list):
            if path_tokens[i] in data:
                data = data[path_tokens[i]]
            else:
                raise exception.EC2MetadataNotFound()
        else:
            if i != len(path_tokens) - 1:
                raise exception.EC2MetadataNotFound()
            data = data[path_tokens[i]]
    return data
