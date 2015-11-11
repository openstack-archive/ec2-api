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

from cinderclient import exceptions as cinder_exception
from novaclient import exceptions as nova_exception
from oslo_log import log as logging

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api import clients
from ec2api import context as ec2_context
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


LOG = logging.getLogger(__name__)


"""Volume related API implementation
"""


Validator = common.Validator


def create_volume(context, availability_zone=None, size=None,
                  snapshot_id=None, volume_type=None, iops=None,
                  encrypted=None, kms_key_id=None):
    if snapshot_id is not None:
        snapshot = ec2utils.get_db_item(context, snapshot_id)
        os_snapshot_id = snapshot['os_id']
    else:
        os_snapshot_id = None

    cinder = clients.cinder(context)
    with common.OnCrashCleaner() as cleaner:
        os_volume = cinder.volumes.create(
                size, snapshot_id=os_snapshot_id, volume_type=volume_type,
                availability_zone=availability_zone)
        cleaner.addCleanup(os_volume.delete)

        volume = db_api.add_item(context, 'vol', {'os_id': os_volume.id})
        cleaner.addCleanup(db_api.delete_item, context, volume['id'])
        os_volume.update(display_name=volume['id'])

    return _format_volume(context, volume, os_volume, snapshot_id=snapshot_id)


def attach_volume(context, volume_id, instance_id, device):
    volume = ec2utils.get_db_item(context, volume_id)
    instance = ec2utils.get_db_item(context, instance_id)

    nova = clients.nova(context)
    try:
        nova.volumes.create_server_volume(instance['os_id'], volume['os_id'],
                                          device)
    except (nova_exception.Conflict, nova_exception.BadRequest):
        # TODO(andrey-mp): raise correct errors for different cases
        LOG.exception(_('Attach has failed.'))
        raise exception.UnsupportedOperation()
    cinder = clients.cinder(context)
    os_volume = cinder.volumes.get(volume['os_id'])
    attachment = _format_attachment(context, volume, os_volume,
                                    instance_id=instance_id)
    # NOTE(andrey-mp): nova sets deleteOnTermination=False for attached volume
    attachment['deleteOnTermination'] = False
    return attachment


def detach_volume(context, volume_id, instance_id=None, device=None,
                  force=None):
    volume = ec2utils.get_db_item(context, volume_id)

    cinder = clients.cinder(context)
    os_volume = cinder.volumes.get(volume['os_id'])
    os_instance_id = next(iter(os_volume.attachments), {}).get('server_id')
    if not os_instance_id:
        # TODO(ft): Change the message with the real AWS message
        reason = _('Volume %(vol_id)s is not attached to anything')
        raise exception.IncorrectState(reason=reason % {'vol_id': volume_id})

    nova = clients.nova(context)
    nova.volumes.delete_server_volume(os_instance_id, os_volume.id)
    os_volume.get()
    instance_id = next((i['id'] for i in db_api.get_items(context, 'i')
                        if i['os_id'] == os_instance_id), None)
    return _format_attachment(context, volume, os_volume,
                              instance_id=instance_id)


def delete_volume(context, volume_id):
    volume = ec2utils.get_db_item(context, volume_id)
    cinder = clients.cinder(context)
    try:
        cinder.volumes.delete(volume['os_id'])
    except cinder_exception.BadRequest:
        # TODO(andrey-mp): raise correct errors for different cases
        raise exception.UnsupportedOperation()
    except cinder_exception.NotFound:
        pass
    # NOTE(andrey-mp) Don't delete item from DB until it disappears from Cloud
    # It will be deleted by describer in the future
    return True


class VolumeDescriber(common.TaggableItemsDescriber):

    KIND = 'vol'
    SORT_KEY = 'volumeId'
    FILTER_MAP = {
        'availability-zone': 'availabilityZone',
        'create-time': 'createTime',
        'encrypted': 'encrypted',
        'size': 'size',
        'snapshot-id': 'snapshotId',
        'status': 'status',
        'volume-id': 'volumeId',
        'volume-type': 'volumeType',
        'attachment.delete-on-termination':
            ['attachmentSet', 'deleteOnTermination'],
        'attachment.device': ['attachmentSet', 'device'],
        'attachment.instance-id': ['attachmentSet', 'instanceId'],
        'attachment.status': ['attachmentSet', 'status']}

    def format(self, volume, os_volume):
        return _format_volume(self.context, volume, os_volume,
                              self.instances, self.os_instances,
                              self.snapshots)

    def get_db_items(self):
        self.instances = {i['os_id']: i
                          for i in db_api.get_items(self.context, 'i')}
        self.snapshots = {s['os_id']: s
                          for s in db_api.get_items(self.context, 'snap')}
        return super(VolumeDescriber, self).get_db_items()

    def get_os_items(self):
        nova = clients.nova(ec2_context.get_os_admin_context())
        os_instances = nova.servers.list(
            search_opts={'all_tenants': True,
                         'project_id': self.context.project_id})
        self.os_instances = {i.id: i for i in os_instances}
        return clients.cinder(self.context).volumes.list()

    def get_name(self, os_item):
        return ''


def describe_volumes(context, volume_id=None, filter=None,
                     max_results=None, next_token=None):
    if volume_id and max_results:
        msg = _('The parameter volumeSet cannot be used with the parameter '
                'maxResults')
        raise exception.InvalidParameterCombination(msg)

    volume_describer = VolumeDescriber()
    formatted_volumes = volume_describer.describe(
        context, ids=volume_id, filter=filter,
        max_results=max_results, next_token=next_token)
    result = {'volumeSet': formatted_volumes}
    if volume_describer.next_token:
        result['nextToken'] = volume_describer.next_token
    return result


def _format_volume(context, volume, os_volume, instances={}, os_instances={},
                   snapshots={}, snapshot_id=None):
    valid_ec2_api_volume_status_map = {
        'attaching': 'in-use',
        'detaching': 'in-use'}

    ec2_volume = {
            'volumeId': volume['id'],
            'status': valid_ec2_api_volume_status_map.get(os_volume.status,
                                                          os_volume.status),
            'size': os_volume.size,
            'availabilityZone': os_volume.availability_zone,
            'createTime': os_volume.created_at,
            'volumeType': os_volume.volume_type,
            'encrypted': os_volume.encrypted,
    }
    if ec2_volume['status'] == 'in-use':
        ec2_volume['attachmentSet'] = (
                [_format_attachment(context, volume, os_volume, instances,
                                    os_instances)])
    else:
        ec2_volume['attachmentSet'] = {}
    if snapshot_id is None and os_volume.snapshot_id:
        snapshot = ec2utils.get_db_item_by_os_id(
                context, 'snap', os_volume.snapshot_id, snapshots)
        snapshot_id = snapshot['id']
    ec2_volume['snapshotId'] = snapshot_id

    return ec2_volume


def _format_attachment(context, volume, os_volume, instances={},
                       os_instances={}, instance_id=None):
    os_attachment = next(iter(os_volume.attachments), {})
    os_instance_id = os_attachment.get('server_id')
    if not instance_id and os_instance_id:
        instance = ec2utils.get_db_item_by_os_id(
                context, 'i', os_instance_id, instances)
        instance_id = instance['id']
    ec2_attachment = {
            'device': os_attachment.get('device'),
            'instanceId': instance_id,
            'status': (os_volume.status
                       if os_volume.status in ('attaching', 'detaching') else
                       'attached' if os_attachment else 'detached'),
            'volumeId': volume['id']}
    if os_instance_id in os_instances:
        os_instance = os_instances[os_instance_id]
        volumes_attached = getattr(os_instance,
                                   'os-extended-volumes:volumes_attached', [])
        volume_attached = next((va for va in volumes_attached
                                if va['id'] == volume['os_id']), None)
        if volume_attached and 'delete_on_termination' in volume_attached:
            ec2_attachment['deleteOnTermination'] = (
                volume_attached['delete_on_termination'])
    return ec2_attachment
