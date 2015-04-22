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
from glanceclient.common import exceptions as glance_exception
from lxml import etree
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import instance as instance_api
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _, _LE, _LI


LOG = logging.getLogger(__name__)

s3_opts = [
    cfg.StrOpt('image_decryption_dir',
               default='/tmp',
               help='Parent directory for tempdir used for image decryption'),
    cfg.StrOpt('s3_host',
               default='$my_ip',
               help='Hostname or IP for OpenStack to use when accessing '
                    'the S3 api'),
    cfg.IntOpt('s3_port',
               default=3334,
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


"""Volume related API implementation
"""


Validator = common.Validator


CONTAINER_TO_KIND = {'aki': 'aki',
                     'ari': 'ari',
                     'ami': 'ami',
                     # NOTE(ft): this mappings are ported from legacy Nova EC2
                     # There is no idea about its actuality
                     'kernel': 'aki',
                     'ramdisk': 'ari'}
IMAGE_TYPES = {'aki': 'kernel',
               'ari': 'ramdisk',
               'ami': 'machine'}


# TODO(yamahata): race condition
# At the moment there is no way to prevent others from
# manipulating instances/volumes/snapshots.
# As other code doesn't take it into consideration, here we don't
# care of it for now. Ostrich algorithm
def create_image(context, instance_id, name=None, description=None,
                 no_reboot=False, block_device_mapping=None):
    instance = ec2utils.get_db_item(context, instance_id)

    if not instance_api._is_ebs_instance(context, instance['os_id']):
        msg = _('Instance does not have a volume attached at root (null).')
        raise exception.InvalidParameterValue(value=instance_id,
                                              parameter='InstanceId',
                                              reason=msg)

    nova = clients.nova(context)
    os_instance = nova.servers.get(instance['os_id'])
    restart_instance = False
    if not no_reboot and os_instance.status != 'SHUTOFF':
        if os_instance.status != 'ACTIVE':
            # TODO(ft): Change the error code and message with the real AWS
            # ones
            msg = _('Instance must be run or stopped')
            raise exception.IncorrectState(reason=msg)

        restart_instance = True
        os_instance.stop()

        # wait instance for really stopped
        start_time = time.time()
        while os_instance.status != 'SHUTOFF':
            time.sleep(1)
            os_instance.get()
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

    glance = clients.glance(context)
    with common.OnCrashCleaner() as cleaner:
        os_image_id = os_instance.create_image(name)
        cleaner.addCleanup(glance.images.delete, os_image_id)
        # TODO(andrey-mp): snapshot and volume also must be deleted in case
        # of error
        os_image = glance.images.get(os_image_id)
        image = db_api.add_item(context, _get_os_image_kind(os_image),
                                {'os_id': os_image_id,
                                 'is_public': False,
                                 'description': description})

    if restart_instance:
        os_instance.start()

    return {'imageId': image['id']}


def register_image(context, name=None, image_location=None,
                   description=None, architecture=None,
                   root_device_name=None, block_device_mapping=None,
                   virtualization_type=None, kernel_id=None,
                   ramdisk_id=None, sriov_net_support=None):
    if not image_location and not root_device_name:
        # NOTE(ft): for backward compatibility with a hypothetical code
        # which uses name as image_location
        image_location = name
    if not image_location and not root_device_name:
        msg = _("Either imageLocation or rootDeviceName must be set.")
        raise exception.InvalidParameterCombination(msg)
    if not image_location and not name:
        msg = _('The request must contain the parameter name')
        raise exception.MissingParameter(msg)

    # TODO(ft): check parameters
    properties = {}
    metadata = {'properties': properties}
    if name:
        # TODO(ft): check the name is unique (at least for EBS image case)
        metadata['name'] = name
    if image_location:
        properties['image_location'] = image_location
        if 'name' not in metadata:
            # NOTE(ft): it's needed for backward compatibility
            metadata['name'] = image_location
    if root_device_name:
        properties['root_device_name'] = root_device_name
    if block_device_mapping:
        mappings = [instance_api._cloud_parse_block_device_mapping(context,
                                                                   bdm)
                    for bdm in block_device_mapping]
        properties['block_device_mapping'] = json.dumps(mappings)
    if architecture is not None:
        properties['architecture'] = architecture
    if kernel_id:
        properties['kernel_id'] = ec2utils.get_os_image(context,
                                                        kernel_id).id
    if ramdisk_id:
        properties['ramdisk_id'] = ec2utils.get_os_image(context,
                                                         ramdisk_id).id

    with common.OnCrashCleaner() as cleaner:
        if 'image_location' in properties:
            os_image = _s3_create(context, metadata)
        else:
            metadata.update({'size': 0,
                             'is_public': False})
            # TODO(ft): set default values of image properties
            glance = clients.glance(context)
            os_image = glance.images.create(**metadata)
        cleaner.addCleanup(os_image.delete)
        kind = _get_os_image_kind(os_image)
        image = db_api.add_item(context, kind, {'os_id': os_image.id,
                                                'is_public': False,
                                                'description': description})
    return {'imageId': image['id']}


def deregister_image(context, image_id):
    os_image = ec2utils.get_os_image(context, image_id)
    _check_owner(context, os_image)

    glance = clients.glance(context)
    try:
        glance.images.delete(os_image.id)
    except glance_exception.HTTPNotFound:
        pass
    db_api.delete_item(context, image_id)
    return True


class ImageDescriber(common.TaggableItemsDescriber):

    KIND = 'ami'
    FILTER_MAP = {'architecture': 'architecture',
                  'block-device-mapping.device-name': ['blockDeviceMapping',
                                                       'deviceName'],
                  'block-device-mapping.snapshot-id': ['blockDeviceMapping',
                                                       ('ebs', 'snapshotId')],
                  'block-device-mapping.volume-size': ['blockDeviceMapping',
                                                       ('ebs', 'volumeSize')],
                  'description': 'description',
                  'image-id': 'imageId',
                  'image-type': 'imageType',
                  'is-public': 'isPublic',
                  'kernel_id': 'kernelId',
                  'name': 'name',
                  'owner-id': 'imageOwnerId',
                  'ramdisk-id': 'ramdiskId',
                  'root-device-name': 'rootDeviceName',
                  'root-device-type': 'rootDeviceType',
                  'state': 'imageState',
                  }

    def format(self, image, os_image):
        return _format_image(self.context, image, os_image, self.items_dict,
                             self.ids_dict, self.snapshot_ids)

    def get_db_items(self):
        # TODO(ft): we can't get all images from DB per one request due
        # different kinds. It's need to refactor DB API and ec2utils functions
        # to work with kind smarter
        if self.ids:
            local_images = db_api.get_items_by_ids(self.context, self.ids)
        else:
            local_images = list(itertools.chain(
                *(db_api.get_items(self.context, kind)
                  for kind in ('ami', 'ari', 'aki'))))
        public_images = [db_api.get_public_items(self.context, kind, self.ids)
                         for kind in ('ami', 'ari', 'aki')]

        images = list(itertools.chain(local_images, *public_images))
        if self.ids:
            # NOTE(ft): public images, owned by a current user, appear in both
            # local and public lists of images. Therefore it's not enough to
            # just compare length of requested and retrieved lists to make sure
            # that all requested images are retrieved.
            images_ids = set(i['id'] for i in images)
            if len(images_ids) < len(self.ids):
                missed_ids = self.ids - images_ids
                raise exception.InvalidAMIIDNotFound(id=next(iter(missed_ids)))
        self.snapshot_ids = dict(
            (s['os_id'], s['id'])
            for s in db_api.get_items(self.context, 'snap'))
        self.local_images_os_ids = set(i['os_id'] for i in local_images)
        self.ids_dict = {}
        return images

    def get_os_items(self):
        return clients.glance(self.context).images.list()

    def auto_update_db(self, image, os_image):
        if not image:
            kind = _get_os_image_kind(os_image)
            image = ec2utils.get_db_item_by_os_id(
                self.context, kind, os_image.id, self.items_dict,
                os_image=os_image, project_id=os_image.owner)
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

    def get_tags(self):
        return db_api.get_tags(self.context, ('ami', 'ari', 'aki'), self.ids)


def describe_images(context, executable_by=None, image_id=None,
                    owner=None, filter=None):
    formatted_images = ImageDescriber().describe(
        context, ids=image_id, filter=filter)
    return {'imagesSet': formatted_images}


def describe_image_attribute(context, image_id, attribute):
    def _block_device_mapping_attribute(os_image, image, result):
        _cloud_format_mappings(context, os_image.properties, result)

    def _description_attribute(os_image, image, result):
        result['description'] = {'value': image.get('description')}

    def _launch_permission_attribute(os_image, image, result):
        result['launchPermission'] = []
        if os_image.is_public:
            result['launchPermission'].append({'group': 'all'})

    def _kernel_attribute(os_image, image, result):
        kernel_id = os_image.properties.get('kernel_id')
        if kernel_id:
            result['kernel'] = {
                'value': ec2utils.os_id_to_ec2_id(context, 'aki', kernel_id)
            }

    def _ramdisk_attribute(os_image, image, result):
        ramdisk_id = os_image.properties.get('ramdisk_id')
        if ramdisk_id:
            result['ramdisk'] = {
                'value': ec2utils.os_id_to_ec2_id(context, 'ari', ramdisk_id)
            }

    # NOTE(ft): Openstack extension, AWS-incompability
    def _root_device_name_attribute(os_image, image, result):
        result['rootDeviceName'] = (
            _block_device_properties_root_device_name(os_image.properties))

    supported_attributes = {
        'blockDeviceMapping': _block_device_mapping_attribute,
        'description': _description_attribute,
        'launchPermission': _launch_permission_attribute,
        'kernel': _kernel_attribute,
        'ramdisk': _ramdisk_attribute,
        # NOTE(ft): Openstack extension, AWS-incompability
        'rootDeviceName': _root_device_name_attribute,
    }

    fn = supported_attributes.get(attribute)
    if fn is None:
        raise exception.InvalidRequest()

    os_image = ec2utils.get_os_image(context, image_id)
    _check_owner(context, os_image)
    _prepare_mappings(os_image)
    image = ec2utils.get_db_item(context, image_id)

    result = {'imageId': image_id}
    fn(os_image, image, result)
    return result


def modify_image_attribute(context, image_id, attribute=None,
                           user_group=None, operation_type=None,
                           description=None, launch_permission=None,
                           product_code=None, user_id=None, value=None):
    os_image = ec2utils.get_os_image(context, image_id)

    attributes = set()

    # NOTE(andrey-mp): launchPermission structure is converted here
    # to plain parameters: attribute, user_group, operation_type, user_id
    if launch_permission is not None:
        attributes.add('launchPermission')
        user_group = list()
        user_id = list()
        if len(launch_permission) == 0:
            msg = _('No operation specified for launchPermission attribute.')
            raise exception.InvalidParameterCombination(msg)
        if len(launch_permission) > 1:
            msg = _('Only one operation can be specified.')
            raise exception.InvalidParameterCombination(msg)
        operation_type, permissions = launch_permission.popitem()
        for index_key in permissions:
            permission = permissions[index_key]
            if 'group' in permission:
                user_group.append(permission['group'])
            if 'user_id' in permission:
                user_id.append(permission['user_id'])
    if attribute == 'launchPermission':
        attributes.add('launchPermission')

    if description is not None:
        attributes.add('description')
        value = description
    if attribute == 'description':
        attributes.add('description')

    # check attributes
    if len(attributes) == 0:
        if product_code is not None:
            attribute = 'productCodes'
        if attribute in ['kernel', 'ramdisk', 'productCodes',
                         'blockDeviceMapping']:
            raise exception.InvalidParameter(_('Parameter %s is invalid. '
                'The attribute is not supported.') % attribute)
        raise exception.InvalidParameterCombination('No attributes specified.')
    if len(attributes) > 1:
        raise exception.InvalidParameterCombination(
            _('Fields for multiple attribute types specified: %s')
            % str(attributes))

    if 'launchPermission' in attributes:
        if not user_group:
            msg = _('No operation specified for launchPermission attribute.')
            raise exception.InvalidParameterCombination(msg)
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

        _check_owner(context, os_image)
        os_image.update(is_public=(operation_type == 'add'))
        return True

    if 'description' in attributes:
        if not value:
            raise exception.MissingParameter(
                'The request must contain the parameter description')

        _check_owner(context, os_image)
        image = ec2utils.get_db_item(context, image_id)
        image['description'] = value
        db_api.update_item(context, image)
        return True


def reset_image_attribute(context, image_id, attribute):
    if attribute != 'launchPermission':
        raise exception.InvalidRequest()

    os_image = ec2utils.get_os_image(context, image_id)
    _check_owner(context, os_image)

    os_image.update(is_public=False)
    return True


def _check_owner(context, os_image):
    if os_image.owner != context.project_id:
        raise exception.AuthFailure(_('Not authorized for image:%s')
                                    % os_image.id)


def _format_image(context, image, os_image, images_dict, ids_dict,
                  snapshot_ids=None):
    ec2_image = {'imageId': image['id'],
                 'imageOwnerId': os_image.owner,
                 'imageType': IMAGE_TYPES[
                                   ec2utils.get_ec2_id_kind(image['id'])],
                 'isPublic': image['is_public'],
                 'architecture': os_image.properties.get('architecture'),
                 }
    if 'description' in image:
        ec2_image['description'] = image['description']
    state = os_image.status
    # NOTE(vish): fallback status if image_state isn't set
    if state == 'active':
        state = 'available'
    ec2_image['imageState'] = os_image.properties.get('image_state', state)

    kernel_id = os_image.properties.get('kernel_id')
    if kernel_id:
        ec2_image['kernelId'] = ec2utils.os_id_to_ec2_id(
                context, 'aki', kernel_id,
                items_by_os_id=images_dict, ids_by_os_id=ids_dict,
                project_id=os_image.owner)
    ramdisk_id = os_image.properties.get('ramdisk_id')
    if ramdisk_id:
        ec2_image['ramdiskId'] = ec2utils.os_id_to_ec2_id(
                context, 'ari', ramdisk_id,
                items_by_os_id=images_dict, ids_by_os_id=ids_dict,
                project_id=os_image.owner)

    name = os_image.name
    img_loc = os_image.properties.get('image_location')
    if img_loc:
        ec2_image['imageLocation'] = img_loc
    else:
        ec2_image['imageLocation'] = "%s (%s)" % (img_loc, name)
    if not name and img_loc:
        # This should only occur for images registered with ec2 api
        # prior to that api populating the glance name
        ec2_image['name'] = img_loc
    else:
        ec2_image['name'] = name

    _prepare_mappings(os_image)
    properties = os_image.properties
    root_device_name = _block_device_properties_root_device_name(properties)
    if root_device_name:
        ec2_image['rootDeviceName'] = root_device_name

        root_device_type = 'instance-store'
        short_root_device_name = instance_api._block_device_strip_dev(
                root_device_name)
        for bdm in properties.get('block_device_mapping', []):
            if (('snapshot_id' in bdm or 'volume_id' in bdm) and
                    not bdm.get('no_device') and
                    (bdm.get('boot_index') == 0 or
                     short_root_device_name ==
                        instance_api._block_device_strip_dev(
                            bdm.get('device_name')))):
                root_device_type = 'ebs'
                break
        ec2_image['rootDeviceType'] = root_device_type

    _cloud_format_mappings(context, properties, ec2_image,
                           root_device_name, snapshot_ids, os_image.owner)

    return ec2_image


def _prepare_mappings(os_image):
    def prepare_property(property_name):
        if property_name in os_image.properties:
            os_image.properties[property_name] = json.loads(
                    os_image.properties[property_name])
    prepare_property('mappings')
    prepare_property('block_device_mapping')


def _get_os_image_kind(os_image):
    return CONTAINER_TO_KIND.get(os_image.container_format, 'ami')


def _auto_create_image_extension(context, image, os_image):
    image['is_public'] = os_image.is_public


ec2utils.register_auto_create_db_item_extension(
        'ami', _auto_create_image_extension)
ec2utils.register_auto_create_db_item_extension(
        'ari', _auto_create_image_extension)
ec2utils.register_auto_create_db_item_extension(
        'aki', _auto_create_image_extension)


# NOTE(ft): following functions are copied from various parts of Nova

_ephemeral = re.compile('^ephemeral(\d|[1-9]\d+)$')


def _cloud_format_mappings(context, properties, result, root_device_name=None,
                           snapshot_ids=None, project_id=None):
    """Format multiple BlockDeviceMappingItemType."""
    mappings = [
        {'virtualName': m['virtual'],
         'deviceName': instance_api._block_device_prepend_dev(m['device'])}
        for m in properties.get('mappings', [])
        if (m['virtual'] and
            (m['virtual'] == 'swap' or _ephemeral.match(m['virtual'])))]

    for bdm in properties.get('block_device_mapping', []):
        formatted_bdm = _cloud_format_block_device_mapping(
                context, bdm, root_device_name, snapshot_ids, project_id)
        # NOTE(yamahata): overwrite mappings with block_device_mapping
        for i in range(len(mappings)):
            if (formatted_bdm.get('deviceName')
                    == mappings[i].get('deviceName')):
                del mappings[i]
                break
        mappings.append(formatted_bdm)

    # NOTE(yamahata): trim ebs.no_device == true. Is this necessary?
    mappings = [bdm for bdm in mappings if not (bdm.get('noDevice', False))]

    if mappings:
        result['blockDeviceMapping'] = mappings


def _cloud_format_block_device_mapping(context, bdm, root_device_name=None,
                                       snapshot_ids=None, project_id=None):
    """Construct BlockDeviceMappingItemType."""
    keys = (('deviceName', 'device_name'),
            ('virtualName', 'virtual_name'))
    item = {name: bdm[k] for name, k in keys if k in bdm}
    if bdm.get('no_device'):
        item['noDevice'] = True
    if bdm.get('boot_index') == 0 and root_device_name:
        item['deviceName'] = root_device_name
    if ('snapshot_id' in bdm) or ('volume_id' in bdm):
        ebs_keys = (('volumeSize', 'volume_size'),
                    ('deleteOnTermination', 'delete_on_termination'))
        ebs = {name: bdm[k] for name, k in ebs_keys if bdm.get(k) is not None}
        if bdm.get('snapshot_id'):
            ebs['snapshotId'] = ec2utils.os_id_to_ec2_id(
                context, 'snap', bdm['snapshot_id'], ids_by_os_id=snapshot_ids,
                project_id=project_id)
        # NOTE(ft): Openstack extension, AWS-incompability
        elif bdm.get('volume_id'):
            ebs['snapshotId'] = ec2utils.os_id_to_ec2_id(
                context, 'vol', bdm['volume_id'], project_id=project_id)
        assert 'snapshotId' in ebs
        item['ebs'] = ebs
    return item


def _block_device_properties_root_device_name(properties):
    """get root device name from image meta data.

    If it isn't specified, return None.
    """
    if 'root_device_name' in properties:
        return properties.get('root_device_name')
    elif 'mappings' in properties:
        return next((bdm['device'] for bdm in properties['mappings']
                     if bdm['virtual'] == 'root'), None)
    else:
        return None


def _s3_create(context, metadata):
    """Gets a manifest from s3 and makes an image."""
    image_location = metadata['properties']['image_location'].lstrip('/')
    bucket_name = image_location.split('/')[0]
    manifest_path = image_location[len(bucket_name) + 1:]
    bucket = _s3_conn(context).get_bucket(bucket_name)
    key = bucket.get_key(manifest_path)
    manifest = key.get_contents_as_string()

    (image_metadata, image_parts,
     encrypted_key, encrypted_iv) = _s3_parse_manifest(context, manifest)
    properties = metadata['properties']
    properties.update(image_metadata['properties'])
    properties['image_state'] = 'pending'
    metadata.update(image_metadata)
    metadata.update({'properties': properties,
                     'is_public': False})

    # TODO(bcwaldon): right now, this removes user-defined ids
    # We need to re-enable this.
    metadata.pop('id', None)

    glance = clients.glance(context)
    image = glance.images.create(**metadata)

    def _update_image_state(image_state):
        image.update(properties={'image_state': image_state})

    def delayed_create():
        """This handles the fetching and decrypting of the part files."""
        context.update_store()
        try:
            image_path = tempfile.mkdtemp(dir=CONF.image_decryption_dir)
            log_vars = {'image_location': image_location,
                        'image_path': image_path}

            _update_image_state('downloading')
            try:
                parts = []
                for part_name in image_parts:
                    part = _s3_download_file(bucket, part_name, image_path)
                    parts.append(part)

                # NOTE(vish): this may be suboptimal, should we use cat?
                enc_filename = os.path.join(image_path, 'image.encrypted')
                with open(enc_filename, 'w') as combined:
                    for filename in parts:
                        with open(filename) as part:
                            shutil.copyfileobj(part, combined)

            except Exception:
                LOG.exception(_LE('Failed to download %(image_location)s '
                                  'to %(image_path)s'), log_vars)
                _update_image_state('failed_download')
                return

            _update_image_state('decrypting')
            try:
                dec_filename = os.path.join(image_path, 'image.tar.gz')
                _s3_decrypt_image(context, enc_filename, encrypted_key,
                                  encrypted_iv, dec_filename)
            except Exception:
                LOG.exception(_LE('Failed to decrypt %(image_location)s '
                                  'to %(image_path)s'), log_vars)
                _update_image_state('failed_decrypt')
                return

            _update_image_state('untarring')
            try:
                unz_filename = _s3_untarzip_image(image_path, dec_filename)
            except Exception:
                LOG.exception(_LE('Failed to untar %(image_location)s '
                                  'to %(image_path)s'), log_vars)
                _update_image_state('failed_untar')
                return

            _update_image_state('uploading')
            try:
                with open(unz_filename) as image_file:
                    image.update(data=image_file)
            except Exception:
                LOG.exception(_LE('Failed to upload %(image_location)s '
                                  'to %(image_path)s'), log_vars)
                _update_image_state('failed_upload')
                return

            _update_image_state('available')

            shutil.rmtree(image_path)
        except glance_exception.HTTPNotFound:
            LOG.info(_LI('Image %swas deleted underneath us'), image.id)
        except Exception:
            LOG.exception(_LE('Failed to complete image %s creation'),
                          image.id)

    eventlet.spawn_n(delayed_create)

    return image


def _s3_parse_manifest(context, manifest):
    manifest = etree.fromstring(manifest)

    try:
        arch = manifest.find('machine_configuration/architecture').text
    except Exception:
        arch = 'x86_64'

    properties = {'architecture': arch}

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

    if mappings:
        properties['mappings'] = mappings

    def set_dependent_image_id(image_key):
        try:
            image_key_path = ('machine_configuration/%(image_key)s' %
                              {'image_key': image_key})
            image_id = manifest.find(image_key_path).text
        except Exception:
            return
        if image_id == 'true':
            return True
        os_image = ec2utils.get_os_image(context, image_id)
        properties[image_key] = os_image.id

    image_format = 'ami'
    if set_dependent_image_id('kernel_id'):
        image_format = 'aki'
    if set_dependent_image_id('ramdisk_id'):
        image_format = 'ari'

    metadata = {'disk_format': image_format,
                'container_format': image_format,
                'properties': properties}
    image_parts = [
           fn_element.text
           for fn_element in manifest.find('image').getiterator('filename')]
    encrypted_key = manifest.find('image/ec2_encrypted_key').text
    encrypted_iv = manifest.find('image/ec2_encrypted_iv').text

    return metadata, image_parts, encrypted_key, encrypted_iv


def _s3_download_file(bucket, filename, local_dir):
    key = bucket.get_key(filename)
    local_filename = os.path.join(local_dir, os.path.basename(filename))
    key.get_contents_to_filename(local_filename)
    return local_filename


def _s3_decrypt_image(context, encrypted_filename, encrypted_key,
                      encrypted_iv, decrypted_filename):
    encrypted_key = binascii.a2b_hex(encrypted_key)
    encrypted_iv = binascii.a2b_hex(encrypted_iv)
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
            # TODO(ft): figure out actual AWS exception
            raise exception.EC2InvalidException(_('Unsafe filenames in image'))
    tar_file.close()


def _s3_conn(context):
    # NOTE(vish): access and secret keys for s3 server are not
    #             checked in nova-objectstore
    ec2_creds = clients.keystone(context).ec2.list(context.user_id)
    access = ec2_creds[0].access
    if CONF.s3_affix_tenant:
        access = '%s:%s' % (access, context.project_id)
    secret = ec2_creds[0].secret
    calling = boto.s3.connection.OrdinaryCallingFormat()
    return boto.s3.connection.S3Connection(aws_access_key_id=access,
                                           aws_secret_access_key=secret,
                                           is_secure=CONF.s3_use_ssl,
                                           calling_format=calling,
                                           port=CONF.s3_port,
                                           host=CONF.s3_host)
