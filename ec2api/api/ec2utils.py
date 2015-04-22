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

import re

from glanceclient.common import exceptions as glance_exception
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from ec2api.api import clients
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _, _LE

LOG = logging.getLogger(__name__)

ec2_opts = [
    cfg.StrOpt('external_network',
               default=None,
               help='Name of the external network, which is used to connect'
                    'VPCs to Internet and to allocate Elastic IPs.'),
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)

_c2u = re.compile('(((?<=[a-z])[A-Z])|([A-Z](?![A-Z]|$)))')


def camelcase_to_underscore(str):
    return _c2u.sub(r'_\1', str).lower().strip('_')


def _try_convert(value):
    """Return a non-string from a string or unicode, if possible.

    ============= =====================================================
    When value is returns
    ============= =====================================================
    zero-length   ''
    'None'        None
    'True'        True case insensitive
    'False'       False case insensitive
    '0', '-0'     0
    0xN, -0xN     int from hex (positive) (N is any number)
    0bN, -0bN     int from binary (positive) (N is any number)
    *             try conversion to int, float, complex, fallback value

    """
    def _negative_zero(value):
        epsilon = 1e-7
        return 0 if abs(value) < epsilon else value

    if len(value) == 0:
        return ''
    if value == 'None':
        return None
    lowered_value = value.lower()
    if lowered_value == 'true':
        return True
    if lowered_value == 'false':
        return False
    for prefix, base in [('0x', 16), ('0b', 2), ('0', 8), ('', 10)]:
        try:
            if lowered_value.startswith((prefix, "-" + prefix)):
                return int(lowered_value, base)
        except ValueError:
            pass
    try:
        return _negative_zero(float(value))
    except ValueError:
        return value


def dict_from_dotted_str(items):
    """parse multi dot-separated argument into dict.

    EBS boot uses multi dot-separated arguments like
    BlockDeviceMapping.1.DeviceName=snap-id
    Convert the above into
    {'block_device_mapping': {'1': {'device_name': snap-id}}}
    """
    args = {}
    for key, value in items:
        parts = key.split(".")
        key = str(camelcase_to_underscore(parts[0]))
        if isinstance(value, str) or isinstance(value, unicode):
            # NOTE(vish): Automatically convert strings back
            #             into their respective values
            value = _try_convert(value)

            if len(parts) > 1:
                d = args.get(key, {})
                args[key] = d
                for k in parts[1:-1]:
                    k = camelcase_to_underscore(k)
                    v = d.get(k, {})
                    d[k] = v
                    d = v
                d[camelcase_to_underscore(parts[-1])] = value
            else:
                args[key] = value

    return args


_ms_time_regex = re.compile('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,6}Z$')


def is_ec2_timestamp_expired(request, expires=None):
    """Checks the timestamp or expiry time included in an EC2 request

    and returns true if the request is expired
    """
    query_time = None
    timestamp = request.get('Timestamp')
    expiry_time = request.get('Expires')

    def parse_strtime(strtime):
        if _ms_time_regex.match(strtime):
            # NOTE(MotoKen): time format for aws-sdk-java contains millisecond
            time_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        else:
            time_format = "%Y-%m-%dT%H:%M:%SZ"
        return timeutils.parse_strtime(strtime, time_format)

    try:
        if timestamp and expiry_time:
            msg = _("Request must include either Timestamp or Expires,"
                    " but cannot contain both")
            LOG.error(msg)
            raise exception.InvalidRequest(msg)
        elif expiry_time:
            query_time = parse_strtime(expiry_time)
            return timeutils.is_older_than(query_time, -1)
        elif timestamp:
            query_time = parse_strtime(timestamp)

            # Check if the difference between the timestamp in the request
            # and the time on our servers is larger than 5 minutes, the
            # request is too old (or too new).
            if query_time and expires:
                return (timeutils.is_older_than(query_time, expires) or
                        timeutils.is_newer_than(query_time, expires))
        return False
    except ValueError:
        LOG.exception(_("Timestamp is invalid: "))
        return True


# NOTE(ft): extra functions to use in vpc specific code or instead of
# malformed existed functions


def get_ec2_id_kind(obj_id):
    return obj_id.split('-')[0]


def change_ec2_id_kind(obj_id, new_kind):
    return '%(kind)s-%(id)s' % {'kind': new_kind,
                                'id': obj_id.split('-')[-1]}

NOT_FOUND_EXCEPTION_MAP = {
    'vpc': exception.InvalidVpcIDNotFound,
    'igw': exception.InvalidInternetGatewayIDNotFound,
    'subnet': exception.InvalidSubnetIDNotFound,
    'eni': exception.InvalidNetworkInterfaceIDNotFound,
    'dopt': exception.InvalidDhcpOptionsIDNotFound,
    'eipalloc': exception.InvalidAllocationIDNotFound,
    'sg': exception.InvalidGroupNotFound,
    'rtb': exception.InvalidRouteTableIDNotFound,
    'i': exception.InvalidInstanceIDNotFound,
    'kp': exception.InvalidKeypairNotFound,
    'az': exception.InvalidAvailabilityZoneNotFound,
    'vol': exception.InvalidVolumeNotFound,
    'snap': exception.InvalidSnapshotNotFound,
    'ami': exception.InvalidAMIIDNotFound,
    'aki': exception.InvalidAMIIDNotFound,
    'ari': exception.InvalidAMIIDNotFound,
}


def get_db_item(context, ec2_id, expected_kind=None):
    """Get an DB item, raise AWS compliant exception if it's not found.

        Args:
            context (RequestContext): The request context.
            ec2_id (str): The ID of the requested item.
            expected_kind (str): The expected kind of the requested item.
                It should be specified for a kind of ec2_id to be validated,
                if you need it.

        Returns:
            The DB item.
    """
    item = db_api.get_item_by_id(context, ec2_id)
    if (item is None or
            expected_kind and get_ec2_id_kind(ec2_id) != expected_kind):
        kind = expected_kind or get_ec2_id_kind(ec2_id)
        params = {'id': ec2_id}
        raise NOT_FOUND_EXCEPTION_MAP[kind](**params)
    return item


def get_db_items(context, kind, ec2_ids):
    if not ec2_ids:
        return db_api.get_items(context, kind)

    if not isinstance(ec2_ids, set):
        ec2_ids = set(ec2_ids)
    items = db_api.get_items_by_ids(context, ec2_ids)
    if len(items) < len(ec2_ids):
        missed_ids = ec2_ids - set((item['id'] for item in items))
        params = {'id': next(iter(missed_ids))}
        raise NOT_FOUND_EXCEPTION_MAP[kind](**params)
    return items


_auto_create_db_item_extensions = {}


def register_auto_create_db_item_extension(kind, extension):
    _auto_create_db_item_extensions[kind] = extension


# TODO(Alex): The project_id passing mechanism can be potentially
# reconsidered in future.
def auto_create_db_item(context, kind, os_id, project_id=None,
                        **extension_kwargs):
    item = {'os_id': os_id}
    extension = _auto_create_db_item_extensions.get(kind)
    if extension:
        extension(context, item, **extension_kwargs)
    return db_api.add_item(context, kind, item, project_id=project_id)


# TODO(Alex): The project_id passing mechanism can be potentially
# reconsidered in future.
def get_db_item_by_os_id(context, kind, os_id, items_by_os_id=None,
                         project_id=None, **extension_kwargs):
    """Get DB item by OS id (create if it doesn't exist).

        Args:
            context (RequestContext): The request context.
            kind (str): The kind of item.
            os_id (str): OS id of an object.
            items_by_os_id (dict of items): The dict of known DB items,
                OS id is used as a key.
            extension_kwargs (dict): Additional parameters passed to
                a registered extension at creating item.

        Returns:
            A found or created item.

        Search item in passed dict. If it's not found - create a new item, and
        add it to the dict (if it's passed).
        If an extension is registered on corresponding item kind, call it
        passing extension_kwargs to it.
    """
    if os_id is None:
        return None
    if items_by_os_id is not None:
        item = items_by_os_id.get(os_id)
        if item:
            return item
    else:
        item = next((i for i in db_api.get_items(context, kind)
                     if i['os_id'] == os_id), None)
    if not item:
        item = auto_create_db_item(context, kind, os_id, project_id=project_id,
                                   **extension_kwargs)
    if items_by_os_id is not None:
        items_by_os_id[os_id] = item
    return item


# TODO(Alex): The project_id passing mechanism can be potentially
# reconsidered in future.
def os_id_to_ec2_id(context, kind, os_id, items_by_os_id=None,
                    ids_by_os_id=None, project_id=None):
    if os_id is None:
        return None
    if ids_by_os_id is not None:
        item_id = ids_by_os_id.get(os_id)
        if item_id:
            return item_id
    if items_by_os_id is not None:
        item = items_by_os_id.get(os_id)
        if item:
            return item['id']
    ids = db_api.get_items_ids(context, kind, (os_id,))
    if len(ids):
        item_id, _os_id = ids[0]
    else:
        item_id = db_api.add_item_id(context, kind, os_id,
                                     project_id=project_id)
    if ids_by_os_id is not None:
        ids_by_os_id[os_id] = item_id
    return item_id


def get_os_image(context, ec2_image_id):
    kind = get_ec2_id_kind(ec2_image_id)
    images = db_api.get_public_items(context, kind, (ec2_image_id,))
    image = (images[0] if len(images) else
             get_db_item(context, ec2_image_id))
    glance = clients.glance(context)
    try:
        return glance.images.get(image['os_id'])
    except glance_exception.HTTPNotFound:
        raise exception.InvalidAMIIDNotFound(id=ec2_image_id)


def get_os_public_network(context):
    neutron = clients.neutron(context)
    search_opts = {'router:external': True, 'name': CONF.external_network}
    os_networks = neutron.list_networks(**search_opts)['networks']
    if len(os_networks) != 1:
        if CONF.external_network:
            if len(os_networks) == 0:
                msg = _LE("No external network with name '%s' is found")
            else:
                msg = _LE("More than one external network with name '%s' "
                          "is found")
            LOG.error(msg, CONF.external_network)
        else:
            if len(os_networks) == 0:
                msg = _LE('No external network is found')
            else:
                msg = _LE('More than one external network is found')
            LOG.error(msg)
        raise exception.Unsupported(_('Feature is restricted by OS admin'))
    return os_networks[0]
