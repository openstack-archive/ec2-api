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

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api import clients
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


"""Snapshot related API implementation
"""


Validator = common.Validator


def create_snapshot(context, volume_id, description=None):
    volume = ec2utils.get_db_item(context, volume_id)
    cinder = clients.cinder(context)
    os_volume = cinder.volumes.get(volume['os_id'])
    # NOTE(ft): Easy fix to allow snapshot creation in statuses other than
    # AVAILABLE without cinder modifications. Potential race condition
    # though. Seems arguably non-fatal.
    if os_volume.status not in ['available', 'in-use',
                                'attaching', 'detaching']:
        msg = (_("'%s' is not in a state where snapshots are allowed.") %
               volume_id)
        raise exception.IncorrectState(reason=msg)
    with common.OnCrashCleaner() as cleaner:
        os_snapshot = cinder.volume_snapshots.create(os_volume.id, True)
        cleaner.addCleanup(os_snapshot.delete)
        snapshot = db_api.add_item(context, 'snap', {'os_id': os_snapshot.id})
        cleaner.addCleanup(db_api.delete_item, context, snapshot['id'])
        os_snapshot.update(display_name=snapshot['id'],
                           display_description=description)
        # NOTE(andrey-mp): to re-read description in version dependent format
        os_snapshot.get()

    return _format_snapshot(context, snapshot, os_snapshot,
                            volume_id=volume_id)


def delete_snapshot(context, snapshot_id):
    snapshot = ec2utils.get_db_item(context, snapshot_id)
    cinder = clients.cinder(context)
    try:
        cinder.volume_snapshots.delete(snapshot['os_id'])
    except cinder_exception.NotFound:
        pass
    # NOTE(andrey-mp) Don't delete item from DB until it disappears from Cloud
    # It will be deleted by describer in the future
    return True


class SnapshotDescriber(common.TaggableItemsDescriber):

    KIND = 'snap'
    SORT_KEY = 'snapshotId'
    FILTER_MAP = {'description': 'description',
                  'owner-id': 'ownerId',
                  'progress': 'progress',
                  'snapshot-id': 'snapshotId',
                  'start-time': 'startTime',
                  'status': 'status',
                  'volume-id': 'volumeId',
                  'volume-size': 'volumeSize'}

    def format(self, snapshot, os_snapshot):
        return _format_snapshot(self.context, snapshot, os_snapshot,
                                self.volumes)

    def get_db_items(self):
        self.volumes = {vol['os_id']: vol
                        for vol in db_api.get_items(self.context, 'vol')}
        return super(SnapshotDescriber, self).get_db_items()

    def get_os_items(self):
        return clients.cinder(self.context).volume_snapshots.list()

    def get_name(self, os_item):
        return ''


def describe_snapshots(context, snapshot_id=None, owner=None,
                       restorable_by=None, filter=None,
                       max_results=None, next_token=None):
    if snapshot_id and max_results:
        msg = _('The parameter snapshotSet cannot be used with the parameter '
                'maxResults')
        raise exception.InvalidParameterCombination(msg)

    snapshot_describer = SnapshotDescriber()
    formatted_snapshots = snapshot_describer.describe(
        context, ids=snapshot_id, filter=filter,
        max_results=max_results, next_token=next_token)
    result = {'snapshotSet': formatted_snapshots}
    if snapshot_describer.next_token:
        result['nextToken'] = snapshot_describer.next_token
    return result


def _format_snapshot(context, snapshot, os_snapshot, volumes={},
                     volume_id=None):
    # NOTE(mikal): this is just a set of strings in cinder. If they
    # implement an enum, then we should move this code to use it. The
    # valid ec2 statuses are "pending", "completed", and "error".
    status_map = {'new': 'pending',
                  'creating': 'pending',
                  'available': 'completed',
                  'active': 'completed',
                  'deleting': 'pending',
                  'deleted': None,
                  'error': 'error'}

    mapped_status = status_map.get(os_snapshot.status, os_snapshot.status)
    if not mapped_status:
        return None

    if not volume_id and os_snapshot.volume_id:
        volume = ec2utils.get_db_item_by_os_id(
                context, 'vol', os_snapshot.volume_id, volumes)
        volume_id = volume['id']

    # NOTE(andrey-mp): ownerId and progress are empty in just created snapshot
    ownerId = os_snapshot.project_id
    if not ownerId:
        ownerId = context.project_id
    progress = os_snapshot.progress
    if not progress:
        progress = '0%'
    description = (getattr(os_snapshot, 'description', None) or
        getattr(os_snapshot, 'display_description', None))
    return {'snapshotId': snapshot['id'],
            'volumeId': volume_id,
            'status': mapped_status,
            'startTime': os_snapshot.created_at,
            'progress': progress,
            'ownerId': ownerId,
            'volumeSize': os_snapshot.size,
            'description': description}
