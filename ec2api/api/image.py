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

import itertools
import json
import re

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api import context as ec2_context
from ec2api.db import api as db_api
from ec2api import exception


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
                                             for i in images.itervalues())
            raise exception.InvalidAMIIDNotFound(
                    {'id': next(iter(missed_ids))})
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
