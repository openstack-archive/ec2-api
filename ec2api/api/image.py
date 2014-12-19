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
import binascii
import itertools
import json
import os
import re
import shutil
import tarfile
import tempfile
import time

import boto.s3.connection
import eventlet
from glanceclient import exc as glance_exception
from lxml import etree
from oslo.config import cfg
from oslo_concurrency import processutils

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import instance as instance_api
from ec2api.api import utils
from ec2api import context as ec2_context
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import timeutils


s3_opts = [
    cfg.StrOpt('image_decryption_dir',
               default='/tmp',
               help='Parent directory for tempdir used for image decryption'),
    cfg.StrOpt('s3_host',
               default='$my_ip',
               help='Hostname or IP for OpenStack to use when accessing '
                    'the S3 api'),
    cfg.IntOpt('s3_port',
               default=3333,
               help='Port used when accessing the S3 api'),
    cfg.BoolOpt('s3_use_ssl',
               default=False,
               help='Whether to use SSL when talking to S3'),
    cfg.BoolOpt('s3_affix_tenant',
               default=False,
               help='Whether to affix the tenant id to the access key '
                    'when downloading from S3'),
    ]

CONF = cfg.CONF
CONF.register_opts(s3_opts)

rpcapi_opts = [
    cfg.StrOpt('cert_topic',
               default='cert',
               help='The topic cert nodes listen on'),
]

CONF.register_opts(rpcapi_opts)


# TODO(yamahata): race condition
# At the moment there is no way to prevent others from
# manipulating instances/volumes/snapshots.
# As other code doesn't take it into consideration, here we don't
# care of it for now. Ostrich algorithm
def create_image(context, instance_id, name=None, description=None,
                 no_reboot=False, block_device_mapping=None):
    instance = ec2utils.get_db_item(context, 'i', instance_id)
    nova = clients.nova(context)
    os_instance = nova.servers.get(instance['os_id'])

    if not instance_api._is_ebs_instance(context, os_instance):
        # TODO(ft): Change the error code and message with the real AWS ones
        msg = _('The instance is not an EBS-backed instance.')
        raise exception.InvalidParameterValue(value=instance_id,
                                              parameter='InstanceId',
                                              reason=msg)

    restart_instance = False
    if not no_reboot:
        vm_state = getattr(os_instance, 'OS-EXT-STS:vm_state')

        if vm_state not in (instance_api.vm_states_ACTIVE,
                            instance_api.vm_states_STOPPED):
            # TODO(ft): Change the error code and message with the real AWS
            # ones
            msg = _('Instance must be run or stopped')
            raise exception.IncorrectState(reason=msg)

        if vm_state == instance_api.vm_states_ACTIVE:
            restart_instance = True
            os_instance.stop()

        # wait instance for really stopped
        start_time = time.time()
        while vm_state != instance_api.vm_states_STOPPED:
            time.sleep(1)
            os_instance.get()
            vm_state = getattr(os_instance, 'OS-EXT-STS:vm_state')
            # NOTE(yamahata): timeout and error. 1 hour for now for safety.
            #                 Is it too short/long?
            #                 Or is there any better way?
            timeout = 1 * 60 * 60
            if time.time() > start_time + timeout:
                err = _("Couldn't stop instance within %d sec") % timeout
                raise exception.EC2Exception(message=err)

    # meaningful image name
    name_map = dict(instance=instance['os_id'], now=timeutils.isotime())
    name = name or _('image of %(instance)s at %(now)s') % name_map

    with utils.OnCrashCleaner() as cleaner:
        os_image = os_instance.create_image(name)
        cleaner.addCleanup(os_image.delete)
        image = db_api.add_item(context, 'ami', {'os_id': os_image.id,
                                                 'is_public': False})

    if restart_instance:
        os_instance.start()

    return {'imageId': image['id']}


def register_image(context, name=None, image_location=None,
                   description=None, architecture=None,
                   root_device_name=None, block_device_mapping=None,
                   virtualization_type=None, kernel_id=None,
                   ramdisk_id=None, sriov_net_support=None):
    if image_location is None and name:
        image_location = name
    if image_location is None:
        msg = _('imageLocation is required')
        raise exception.MissingParameter(msg)

    metadata = {'properties': {'image_location': image_location}}

    if name:
        metadata['name'] = name
    else:
        metadata['name'] = image_location

    if root_device_name:
        metadata['properties']['root_device_name'] = root_device_name

    mappings = [instance_api._cloud_parse_block_device_mapping(context, bdm)
                for bdm in block_device_mapping or []]
    if mappings:
        metadata['properties']['block_device_mapping'] = mappings

    with utils.OnCrashCleaner() as cleaner:
        os_image = _s3_create(context, metadata)
        cleaner.addCleanup(os_image.delete)
        image_type = ec2utils.image_type(os_image.container_format)
        image = db_api.add_item(context, image_type, {'os_id': os_image.id,
                                                      'is_public': False})
    return {'imageId': image['id']}


def deregister_image(context, image_id):
    # TODO(ft): AWS returns AuthFailure for public images,
    # but we return NotFound due searching for local images only
    kind = image_id.split('-')[0]
    image = ec2utils.get_db_item(context, kind, image_id)
    glance = clients.glance(context)
    try:
        glance.images.delete(image['os_id'])
    except glance_exception.HTTPNotFound:
        pass
    db_api.delete_item(context, image['id'])
    return True


def update_image(context, image_id, **kwargs):
    kind = image_id.split('-')[0]
    image = ec2utils.get_db_item(context, kind, image_id)
    glance = clients.glance(context)
    return glance.images.update(image['os_id'], **kwargs)


class ImageDescriber(common.UniversalDescriber):

    KIND = 'ami'
    FILTER_MAP = {'architecture': 'architecture',
                  'description': 'description',
                  'image-id': 'imageId',
                  'image-type': 'imageType',
                  'is-public': 'isPublic',
                  'kernel_id': 'kernelId',
                  'name': 'name',
                  'owner-id': 'ownerId',
                  'ramdisk-id': 'ramdiskId',
                  'state': 'state',
                  }

    def format(self, image, os_image):
        return _format_image(self.context, image, os_image, self.items_dict,
                             self.ids_dict, self.snapshot_ids)

    def get_db_items(self):
        local_images = [db_api.get_items_by_ids(self.context, kind, self.ids)
                        for kind in ('ami', 'ari', 'aki')]
        public_images = [db_api.get_public_items(self.context, kind, self.ids)
                         for kind in ('ami', 'ari', 'aki')]

        images = list(itertools.chain(*itertools.chain(local_images,
                                                       public_images)))
        if len(images) < len(self.ids):
            missed_ids = set(self.ids) - set(i['id']
                                             for i in images)
            raise exception.InvalidAMIIDNotFound(id=next(iter(missed_ids)))
        self.images = images
        self.snapshot_ids = dict((s['os_id'], s['id'])
                              for s in db_api.get_items(self.context, 'snap'))
        self.local_images_os_ids = set(i['os_id']
                                       for i in itertools.chain(*local_images))
        self.ids_dict = {}
        return images

    def get_os_items(self):
        return clients.glance(self.context).images.list()

    def auto_update_db(self, image, os_image):
        if not image:
            kind = ec2utils.image_type(os_image.container_format)
            ctx = (self.context if os_image.owner == self.context.project_id
                   else ec2_context.get_admin_context(
                            project_id=os_image.owner))
            image = ec2utils.auto_create_db_item(ctx, kind, os_image.id,
                                                 os_image=os_image)
            self.items_dict[os_image.id] = image
        elif (image['os_id'] in self.local_images_os_ids and
                image['is_public'] != os_image.is_public):
            image['is_public'] = os_image.is_public
            db_api.update_item(self.context, image)
        return image

    def get_name(self, os_item):
        return ''

    def delete_obsolete_item(self, image):
        if image['os_id'] in self.local_images_os_ids:
            db_api.delete_item(self.context, image['id'])


def describe_images(context, executable_by=None, image_id=None,
                    owner=None, filter=None):
    formatted_images = ImageDescriber().describe(
        context, ids=image_id, filter=filter)
    return {'imagesSet': formatted_images}


def describe_image_attribute(context, image_id, attribute):
    def _block_device_mapping_attribute(image, result):
        _cloud_format_mappings(image['properties'], result)

    def _launch_permission_attribute(image, result):
        result['launchPermission'] = []
        if image['is_public']:
            result['launchPermission'].append({'group': 'all'})

    def _root_device_name_attribute(image, result):
        _prop_root_dev_name = _block_device_properties_root_device_name
        result['rootDeviceName'] = _prop_root_dev_name(image['properties'])
        if result['rootDeviceName'] is None:
            result['rootDeviceName'] = _block_device_DEFAULT_ROOT_DEV_NAME

    def _kernel_attribute(image, result):
        kernel_id = image['properties'].get('kernel_id')
        if kernel_id:
            result['kernel'] = {
                'value': ec2utils.os_id_to_ec2_id(context, 'aki', kernel_id)
            }

    def _ramdisk_attribute(image, result):
        ramdisk_id = image['properties'].get('ramdisk_id')
        if ramdisk_id:
            result['ramdisk'] = {
                'value': ec2utils.os_id_to_ec2_id(context, 'ari', ramdisk_id)
            }

    supported_attributes = {
        'blockDeviceMapping': _block_device_mapping_attribute,
        'launchPermission': _launch_permission_attribute,
        'rootDeviceName': _root_device_name_attribute,
        'kernel': _kernel_attribute,
        'ramdisk': _ramdisk_attribute,
        }

    # TODO(ft): AWS returns AuthFailure for public images,
    # but we return NotFound due searching for local images only
    kind = image_id.split('-')[0]
    image = ec2utils.get_db_item(context, kind, image_id)
    fn = supported_attributes.get(attribute)
    if fn is None:
        raise exception.InvalidAttribute(attr=attribute)
    glance = clients.glance(context)
    os_image = glance.images.get(image['os_id'])

    result = {'imageId': image_id}
    fn(os_image, result)
    return result


def modify_image_attribute(context, image_id, attribute,
                           user_group, operation_type,
                           description=None, launch_permission=None,
                           product_code=None, user_id=None, value=None):
    if attribute != 'launchPermission':
        # TODO(ft): Change the error code and message with the real AWS ones
        raise exception.InvalidAttribute(attr=attribute)
    if not user_group:
        msg = _('user or group not specified')
        # TODO(ft): Change the error code and message with the real AWS ones
        raise exception.MissingParameter(msg)
    if len(user_group) != 1 and user_group[0] != 'all':
        msg = _('only group "all" is supported')
        raise exception.InvalidParameterValue(parameter='UserGroup',
                                              value=user_group,
                                              reason=msg)
    if operation_type not in ['add', 'remove']:
        msg = _('operation_type must be add or remove')
        raise exception.InvalidParameterValue(parameter='OperationType',
                                              value='operation_type',
                                              reason=msg)

    # TODO(ft): AWS returns AuthFailure for public images,
    # but we return NotFound due searching for local images only
    kind = image_id.split('-')[0]
    image = ec2utils.get_db_item(context, kind, image_id)
    glance = clients.glance(context)
    image = glance.images.get(image['os_id'])

    image.update(is_public=(operation_type == 'add'))
    return True


def _format_image(context, image, os_image, images_dict, ids_dict,
                  snapshot_ids=None):
    image_type = ec2utils.image_type(os_image.container_format)
    name = os_image.name
    display_mapping = {'aki': 'kernel',
                       'ari': 'ramdisk',
                       'ami': 'machine'}
    ec2_image = {'imageId': image['id'],
                 'imageOwnerId': os_image.owner,
                 'name': name,
                 'imageState': _cloud_get_image_state(os_image),
                 'description': '',
                 'imageType': display_mapping.get(image_type),
                 'isPublic': not not os_image.is_public,
                 'architecture': os_image.properties.get('architecture'),
                 }
    kernel_id = os_image.properties.get('kernel_id')
    if kernel_id:
        ec2_image['kernelId'] = ec2utils.os_id_to_ec2_id(
                context, 'aki', kernel_id,
                items_by_os_id=images_dict, ids_by_os_id=ids_dict)
    ramdisk_id = os_image.properties.get('ramdisk_id')
    if ramdisk_id:
        ec2_image['ramdiskId'] = ec2utils.os_id_to_ec2_id(
                context, 'ari', ramdisk_id,
                items_by_os_id=images_dict, ids_by_os_id=ids_dict)

    img_loc = os_image.properties.get('image_location')
    if img_loc:
        ec2_image['imageLocation'] = img_loc
    else:
        ec2_image['imageLocation'] = "%s (%s)" % (img_loc, name)

    if not name and img_loc:
        # This should only occur for images registered with ec2 api
        # prior to that api populating the glance name
        ec2_image['name'] = img_loc

    properties = os_image.properties
    root_device_name = _block_device_properties_root_device_name(properties)
    root_device_type = 'instance-store'

    for bdm in json.loads(properties.get('block_device_mapping', '[]')):
        if (bdm.get('boot_index') == 0 and
            ('snapshot_id' in bdm or 'volume_id' in bdm) and
                not bdm.get('no_device')):
            root_device_type = 'ebs'
    ec2_image['rootDeviceName'] = (root_device_name or
                                   _block_device_DEFAULT_ROOT_DEV_NAME)
    ec2_image['rootDeviceType'] = root_device_type

    _cloud_format_mappings(context, properties, ec2_image,
                           ec2_image['rootDeviceName'], snapshot_ids)

    return ec2_image


def _auto_create_image_extension(context, image, os_image):
    image['is_public'] = os_image.is_public


ec2utils.register_auto_create_db_item_extension(
        'ami', _auto_create_image_extension)
ec2utils.register_auto_create_db_item_extension(
        'ari', _auto_create_image_extension)
ec2utils.register_auto_create_db_item_extension(
        'aki', _auto_create_image_extension)


# NOTE(ft): following functions are copied from various parts of Nova

def _cloud_get_image_state(os_image):
    # NOTE(vish): fallback status if image_state isn't set
    state = os_image.status
    if state == 'active':
        state = 'available'
    return os_image.properties.get('image_state', state)


_block_device_DEFAULT_ROOT_DEV_NAME = '/dev/sda1'


def _block_device_properties_root_device_name(properties):
    """get root device name from image meta data.

    If it isn't specified, return None.
    """
    root_device_name = None

    # NOTE(yamahata): see image_service.s3.s3create()
    for bdm in properties.get('mappings', []):
        if bdm['virtual'] == 'root':
            root_device_name = bdm['device']

    # NOTE(yamahata): register_image's command line can override
    #                 <machine>.manifest.xml
    if 'root_device_name' in properties:
        root_device_name = properties['root_device_name']

    return root_device_name


def _cloud_properties_get_mappings(properties):
    return _block_device_mappings_prepend_dev(properties.get('mappings', []))


def _cloud_format_mappings(context, properties, result, root_device_name=None,
                           snapshot_ids=None):
    """Format multiple BlockDeviceMappingItemType."""
    mappings = [{'virtualName': m['virtual'], 'deviceName': m['device']}
                for m in _cloud_properties_get_mappings(properties)
                if _block_device_is_swap_or_ephemeral(m['virtual'])]

    block_device_mapping = [
        _cloud_format_block_device_mapping(context, bdm, root_device_name,
                                           snapshot_ids)
        for bdm in json.loads(properties.get('block_device_mapping', '[]'))]

    # NOTE(yamahata): overwrite mappings with block_device_mapping
    for bdm in block_device_mapping:
        for i in range(len(mappings)):
            if bdm['deviceName'] == mappings[i]['deviceName']:
                del mappings[i]
                break
        mappings.append(bdm)

    # NOTE(yamahata): trim ebs.no_device == true. Is this necessary?
    mappings = [bdm for bdm in mappings if not (bdm.get('noDevice', False))]

    if mappings:
        result['blockDeviceMapping'] = mappings


def _cloud_format_block_device_mapping(context, bdm, root_device_name=None,
                                       snapshot_ids=None):
    """Construct BlockDeviceMappingItemType

    {'device_name': '...', 'snapshot_id': , ...}
    => BlockDeviceMappingItemType
    """
    keys = (('deviceName', 'device_name'),
             ('virtualName', 'virtual_name'))
    item = {}
    for name, k in keys:
        if k in bdm:
            item[name] = bdm[k]
    if bdm.get('no_device'):
        item['noDevice'] = True
    if bdm.get('boot_index') == 0 and root_device_name:
        item['deviceName'] = root_device_name
    if ('snapshot_id' in bdm) or ('volume_id' in bdm):
        ebs_keys = (('snapshotId', 'snapshot_id'),
                    ('snapshotId', 'volume_id'),        # snapshotId is abused
                    ('volumeSize', 'volume_size'),
                    ('deleteOnTermination', 'delete_on_termination'))
        ebs = {}
        for name, k in ebs_keys:
            if bdm.get(k) is not None:
                if k == 'snapshot_id':
                    ebs[name] = ec2utils.os_id_to_ec2_id(
                            context, 'snap', bdm[k], ids_by_os_id=snapshot_ids)
                elif k == 'volume_id':
                    ebs[name] = ec2utils.os_id_to_ec2_id(context, 'vol',
                                                         bdm[k])
                else:
                    ebs[name] = bdm[k]
        assert 'snapshotId' in ebs
        item['ebs'] = ebs
    return item


def _block_device_mappings_prepend_dev(mappings):
    """Prepend '/dev/' to 'device' entry of swap/ephemeral virtual type."""
    for m in mappings:
        virtual = m['virtual']
        if (_block_device_is_swap_or_ephemeral(virtual) and
                (not m['device'].startswith('/'))):
            m['device'] = '/dev/' + m['device']
    return mappings


def _block_device_is_swap_or_ephemeral(device_name):
    return (device_name and
            (device_name == 'swap' or _block_device_is_ephemeral(device_name)))


_ephemeral = re.compile('^ephemeral(\d|[1-9]\d+)$')


def _block_device_is_ephemeral(device_name):
    return _ephemeral.match(device_name) is not None


def _s3_create(context, metadata):
    """Gets a manifest from s3 and makes an image."""
    image_path = tempfile.mkdtemp(dir=CONF.image_decryption_dir)

    image_location = metadata['properties']['image_location'].lstrip('/')
    bucket_name = image_location.split('/')[0]
    manifest_path = image_location[len(bucket_name) + 1:]
    bucket = _s3_conn(context).get_bucket(bucket_name)
    key = bucket.get_key(manifest_path)
    manifest = key.get_contents_as_string()

    manifest, image = _s3_parse_manifest(context, metadata, manifest)

    def _update_image_state(image_state):
        image.update(properties={'image_state': image_state})

    def delayed_create():
        """This handles the fetching and decrypting of the part files."""
        context.update_store()

        try:
            _update_image_state('downloading')

            try:
                parts = []
                elements = manifest.find('image').getiterator('filename')
                for fn_element in elements:
                    part = _s3_download_file(bucket, fn_element.text,
                                             image_path)
                    parts.append(part)

                # NOTE(vish): this may be suboptimal, should we use cat?
                enc_filename = os.path.join(image_path, 'image.encrypted')
                with open(enc_filename, 'w') as combined:
                    for filename in parts:
                        with open(filename) as part:
                            shutil.copyfileobj(part, combined)

            except Exception:
                _update_image_state('failed_download')
                return

            _update_image_state('decrypting')

            try:
                hex_key = manifest.find('image/ec2_encrypted_key').text
                encrypted_key = binascii.a2b_hex(hex_key)
                hex_iv = manifest.find('image/ec2_encrypted_iv').text
                encrypted_iv = binascii.a2b_hex(hex_iv)

                dec_filename = os.path.join(image_path, 'image.tar.gz')
                _s3_decrypt_image(context, enc_filename, encrypted_key,
                                  encrypted_iv, dec_filename)
            except Exception:
                _update_image_state('failed_decrypt')
                return

            _update_image_state('untarring')

            try:
                unz_filename = _s3_untarzip_image(image_path, dec_filename)
            except Exception:
                _update_image_state('failed_untar')
                return

            _update_image_state('uploading')
            try:
                with open(unz_filename) as image_file:
                    image.update(data=image_file)
            except Exception:
                _update_image_state('failed_upload')
                return

            _update_image_state('available')

            shutil.rmtree(image_path)
        except glance_exception.HTTPNotFound:
            return

    eventlet.spawn_n(delayed_create)

    return image


def _s3_parse_manifest(context, metadata, manifest):
    manifest = etree.fromstring(manifest)
    image_format = 'ami'

    try:
        kernel_id = manifest.find('machine_configuration/kernel_id').text
        if kernel_id == 'true':
            image_format = 'aki'
            kernel_id = None
    except Exception:
        kernel_id = None

    try:
        ramdisk_id = manifest.find('machine_configuration/ramdisk_id').text
        if ramdisk_id == 'true':
            image_format = 'ari'
            ramdisk_id = None
    except Exception:
        ramdisk_id = None

    try:
        arch = manifest.find('machine_configuration/architecture').text
    except Exception:
        arch = 'x86_64'

    # NOTE(yamahata):
    # EC2 ec2-budlne-image --block-device-mapping accepts
    # <virtual name>=<device name> where
    # virtual name = {ami, root, swap, ephemeral<N>}
    #                where N is no negative integer
    # device name = the device name seen by guest kernel.
    # They are converted into
    # block_device_mapping/mapping/{virtual, device}
    #
    # Do NOT confuse this with ec2-register's block device mapping
    # argument.
    mappings = []
    try:
        block_device_mapping = manifest.findall('machine_configuration/'
                                                'block_device_mapping/'
                                                'mapping')
        for bdm in block_device_mapping:
            mappings.append({'virtual': bdm.find('virtual').text,
                             'device': bdm.find('device').text})
    except Exception:
        mappings = []

    properties = metadata['properties']
    properties['architecture'] = arch

    def _translate_dependent_image_id(image_key, image_id):
        image_uuid = ec2utils.ec2_id_to_glance_id(context, image_id)
        properties[image_key] = image_uuid

    if kernel_id:
        _translate_dependent_image_id('kernel_id', kernel_id)

    if ramdisk_id:
        _translate_dependent_image_id('ramdisk_id', ramdisk_id)

    if mappings:
        properties['mappings'] = mappings

    metadata.update({'disk_format': image_format,
                     'container_format': image_format,
                     'is_public': False,
                     'properties': properties})
    metadata['properties']['image_state'] = 'pending'

    # TODO(bcwaldon): right now, this removes user-defined ids
    # We need to re-enable this.
    metadata.pop('id', None)

    glance = clients.glance(context)
    image = glance.images.create(**metadata)

    return manifest, image


def _s3_download_file(bucket, filename, local_dir):
    key = bucket.get_key(filename)
    local_filename = os.path.join(local_dir, os.path.basename(filename))
    key.get_contents_to_filename(local_filename)
    return local_filename


def _s3_decrypt_image(context, encrypted_filename, encrypted_key,
                      encrypted_iv, decrypted_filename):
    cert_client = clients.nova_cert(context)
    try:
        key = cert_client.decrypt_text(base64.b64encode(encrypted_key))
    except Exception as exc:
        msg = _('Failed to decrypt private key: %s') % exc
        raise exception.EC2Exception(msg)
    try:
        iv = cert_client.decrypt_text(base64.b64encode(encrypted_iv))
    except Exception as exc:
        msg = _('Failed to decrypt initialization vector: %s') % exc
        raise exception.EC2Exception(msg)

    try:
        processutils.execute('openssl', 'enc',
                             '-d', '-aes-128-cbc',
                             '-in', '%s' % (encrypted_filename,),
                             '-K', '%s' % (key,),
                             '-iv', '%s' % (iv,),
                             '-out', '%s' % (decrypted_filename,))
    except processutils.ProcessExecutionError as exc:
        raise exception.EC2Exception(_('Failed to decrypt image file '
                                       '%(image_file)s: %(err)s') %
                                     {'image_file': encrypted_filename,
                                      'err': exc.stdout})


def _s3_untarzip_image(path, filename):
    _s3_test_for_malicious_tarball(path, filename)
    tar_file = tarfile.open(filename, 'r|gz')
    tar_file.extractall(path)
    image_file = tar_file.getnames()[0]
    tar_file.close()
    return os.path.join(path, image_file)


def _s3_test_for_malicious_tarball(path, filename):
    """Raises exception if extracting tarball would escape extract path."""
    tar_file = tarfile.open(filename, 'r|gz')
    for n in tar_file.getnames():
        if not os.path.abspath(os.path.join(path, n)).startswith(path):
            tar_file.close()
            raise exception.Invalid(_('Unsafe filenames in image'))
    tar_file.close()


def _s3_conn(context):
    # NOTE(vish): access and secret keys for s3 server are not
    #             checked in nova-objectstore
    access = context.access_key
    if CONF.s3_affix_tenant:
        access = '%s:%s' % (access, context.project_id)
    secret = context.secret_key
    calling = boto.s3.connection.OrdinaryCallingFormat()
    return boto.s3.connection.S3Connection(aws_access_key_id=access,
                                           aws_secret_access_key=secret,
                                           is_secure=CONF.s3_use_ssl,
                                           calling_format=calling,
                                           port=CONF.s3_port,
                                           host=CONF.s3_host)
