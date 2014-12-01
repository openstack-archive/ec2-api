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

from ec2api.api import clients
from ec2api.api import ec2utils
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _


FILTER_MAP = {'description': 'description',
              'owner-id': 'ownerId',
              'progress': 'progress',
              'snapshot-id': 'snapshotId',
              'start-time': 'startTime',
              'status': 'status',
              'volume-id': 'volumeId',
              'volume-size': 'volumeSize'}


def create_snapshot(context, volume_id, description=None):
    volume = ec2utils.get_db_item(context, 'vol', volume_id)
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
    with utils.OnCrashCleaner() as cleaner:
        os_snapshot = cinder.volume_snapshots.create(
                os_volume.id, force=True,
                display_description=description)
        cleaner.addCleanup(os_snapshot.delete)
        snapshot = db_api.add_item(context, 'snap', {'os_id': os_snapshot.id})
        cleaner.addCleanup(db_api.delete_item(context, snapshot['id']))
        os_snapshot.update(display_name=snapshot['id'])

    return _format_snapshot(context, snapshot, os_snapshot,
                            volume_id=volume_id)


def delete_snapshot(context, snapshot_id):
    snapshot = ec2utils.get_db_item(context, 'snap', snapshot_id)
    cinder = clients.cinder(context)
    try:
        cinder.volume_snapshots.delete(snapshot['os_id'])
    except cinder_exception.NotFound:
        pass
    db_api.delete_item(context, snapshot['id'])
    return True


def describe_snapshots(context, snapshot_id=None, owner=None,
                       restorable_by=None, filter=None):
    snapshots = ec2utils.get_db_items(context, 'snap', snapshot_id)
    snapshots = dict((snap['os_id'], snap) for snap in snapshots)
    volumes = dict((vol['os_id'], vol)
                   for vol in db_api.get_items(context, 'vol'))

    formatted_snapshots = []
    cinder = clients.cinder(context)
    os_snapshots = cinder.volume_snapshots.list()
    for os_snapshot in os_snapshots:
        snapshot = snapshots.pop(os_snapshot.id, None)
        if not snapshot:
            if snapshot_id:
                # NOTE(ft): os_snapshot is not requested by
                # 'snapshot_id' filter
                continue
            else:
                snapshot = ec2utils.get_db_item_by_os_id(context, 'snap',
                                                         os_snapshot.id)
        formatted_snapshot = _format_snapshot(context, snapshot, os_snapshot,
                                              volumes)
        if (formatted_snapshot and
                not utils.filtered_out(formatted_snapshot, filter,
                                       FILTER_MAP)):
            formatted_snapshots.append(formatted_snapshot)

    # NOTE(ft): delete obsolete snapshots
    for snap in snapshots.itervalues():
        db_api.delete_item(context, snap['id'])
    # NOTE(ft): some requested snapshots are obsolete
    if snapshot_id and snapshots:
        raise exception.InvalidSnapshotNotFound(id=snap['id'])

    return {'snapshotSet': formatted_snapshots}


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

    return {'snapshotId': snapshot['id'],
            'volumeId': volume_id,
            'status': mapped_status,
            'startTime': os_snapshot.created_at,
            'progress': os_snapshot.progress,
            'ownerId': os_snapshot.project_id,
            'volumeSize': os_snapshot.size,
            'description': os_snapshot.display_description}
