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

import datetime
import json
import re

from glanceclient.common import exceptions as glance_exception
from lxml import etree
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
import six

from ec2api import clients
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _

LOG = logging.getLogger(__name__)

ec2_opts = [
    cfg.StrOpt('external_network',
               default=None,
               help='Name of the external network, which is used to connect'
                    'VPCs to Internet and to allocate Elastic IPs.'),
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)

LEGACY_BDM_FIELDS = set(['device_name', 'delete_on_termination', 'snapshot_id',
                         'volume_id', 'volume_size', 'no_device'])

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
        if isinstance(value, six.string_types):
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


def _render_dict(el, data):
    try:
        for key, val in data.items():
            sub_el = etree.SubElement(el, key)
            _render_data(sub_el, val)
    except Exception:
        LOG.debug(data)
        raise


def _render_data(el, data):
    if isinstance(data, list):
        for item in data:
            sub_el = etree.SubElement(el, 'item')
            _render_data(sub_el, item)
    elif isinstance(data, dict):
        _render_dict(el, data)
    elif hasattr(data, '__dict__'):
        _render_dict(el, data.__dict__)
    elif isinstance(data, bool):
        el.text = str(data).lower()
    elif isinstance(data, datetime.datetime):
        el.text = _database_to_isoformat(data)
    elif isinstance(data, six.binary_type):
        el.text = data.decode("utf-8")
    elif data is not None:
        el.text = six.text_type(data)


def _database_to_isoformat(datetimeobj):
    """Return a xs:dateTime parsable string from datatime."""
    return datetimeobj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'


def dict_to_xml(data_dict, root_tag):
    root = etree.Element(root_tag)
    _render_dict(root, data_dict)
    return root


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
        LOG.exception("Timestamp is invalid: ")
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
    'vgw': exception.InvalidVpnGatewayIDNotFound,
    'cgw': exception.InvalidCustomerGatewayIDNotFound,
    'vpn': exception.InvalidVpnConnectionIDNotFound,
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


def auto_create_db_item(context, kind, os_id, **extension_kwargs):
    item = {'os_id': os_id}
    extension = _auto_create_db_item_extensions.get(kind)
    if extension:
        extension(context, item, **extension_kwargs)
    return db_api.add_item(context, kind, item)


def get_db_item_by_os_id(context, kind, os_id, items_by_os_id=None,
                         **extension_kwargs):
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
        item = auto_create_db_item(context, kind, os_id, **extension_kwargs)
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
    ids = db_api.get_items_ids(context, kind, item_os_ids=(os_id,))
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
    ids = db_api.get_items_ids(context, kind, item_ids=(ec2_image_id,))
    if not ids:
        raise exception.InvalidAMIIDNotFound(id=ec2_image_id)
    _id, os_id = ids[0]
    if not os_id:
        return None
    glance = clients.glance(context)
    try:
        return glance.images.get(os_id)
    except glance_exception.HTTPNotFound:
        raise exception.InvalidAMIIDNotFound(id=ec2_image_id)


def deserialize_os_image_properties(os_image):
    def prepare_property(property_name):
        if property_name in os_image_dict:
            os_image_dict[property_name] = json.loads(
                os_image_dict[property_name])

    os_image_dict = dict(os_image)
    prepare_property('mappings')
    prepare_property('block_device_mapping')
    return os_image_dict


def create_virtual_bdm(device_name, virtual_name):
    bdm = {'device_name': device_name,
           'source_type': 'blank',
           'destination_type': 'local',
           'device_type': 'disk',
           'delete_on_termination': True,
           'boot_index': -1,
           'virtual_name': virtual_name}
    if virtual_name == 'swap':
        bdm['guest_format'] = 'swap'
    return bdm


def get_os_image_mappings(os_image_properties):
    mappings = []
    names = set()
    # TODO(ft): validate device names for both virtual and block device
    # mappings

    def is_virtual(virtual_name):
        return virtual_name == 'swap' or (virtual_name and
                                          _ephemeral.match(virtual_name))

    # NOTE(ft): substitute mapping if the same device name is specified
    def add_mapping(mapping):
        device_name = block_device_strip_dev(mapping.get('device_name'))
        if device_name in names:
            for i, m in enumerate(mappings):
                if (device_name ==
                        block_device_strip_dev(m.get('device_name'))):
                    mappings[i] = mapping
                    break
        else:
            if device_name:
                names.add(device_name)
            mappings.append(mapping)

    # TODO(ft): From Juno virtual device mapping has precedence of block one
    # in boot logic. This function should do the same, despite Nova EC2
    # behavior.

    # NOTE(ft): Nova EC2 prepended device names for virtual device mappings.
    # But AWS doesn't do it.
    for vdm in os_image_properties.get('mappings', []):
        if is_virtual(vdm.get('virtual')):
            add_mapping(create_virtual_bdm(
                block_device_prepend_dev(vdm.get('device')), vdm['virtual']))

    legacy_mapping = not os_image_properties.get('bdm_v2', False)
    for bdm in os_image_properties.get('block_device_mapping', []):
        if legacy_mapping:
            virtual_name = bdm.get('virtual_name')
            if is_virtual(virtual_name):
                new_bdm = create_virtual_bdm(bdm.get('device_name'),
                                             virtual_name)
            else:
                new_bdm = {key: val for key, val in bdm.items()
                           if key in LEGACY_BDM_FIELDS}
                if bdm.get('snapshot_id'):
                    new_bdm.update({'source_type': 'snapshot',
                                    'destination_type': 'volume'})
                elif bdm.get('volume_id'):
                    new_bdm.update({'source_type': 'volume',
                                    'destination_type': 'volume'})
            bdm = new_bdm

        bdm.setdefault('delete_on_termination', False)
        add_mapping(bdm)

    return mappings


def get_os_public_network(context):
    neutron = clients.neutron(context)
    search_opts = {'router:external': True, 'name': CONF.external_network}
    os_networks = neutron.list_networks(**search_opts)['networks']
    if len(os_networks) != 1:
        if CONF.external_network:
            if len(os_networks) == 0:
                msg = "No external network with name '%s' is found"
            else:
                msg = "More than one external network with name '%s' is found"
            LOG.error(msg, CONF.external_network)
        else:
            if len(os_networks) == 0:
                msg = 'No external network is found'
            else:
                msg = 'More than one external network is found'
            LOG.error(msg)
        raise exception.Unsupported(_('Feature is restricted by OS admin'))
    return os_networks[0]


def get_attached_gateway(context, vpc_id, gateway_kind):
    # TODO(ft): move search by vpc_id to DB api
    return next((gw for gw in db_api.get_items(context, gateway_kind)
                 if gw['vpc_id'] == vpc_id), None)


_check_and_create_default_vpc = None


def check_and_create_default_vpc(context):
    return _check_and_create_default_vpc(context)


def set_check_and_create_default_vpc(check_and_create_default_vpc):
    global _check_and_create_default_vpc
    _check_and_create_default_vpc = check_and_create_default_vpc


def get_default_vpc(context):
    default_vpc = check_and_create_default_vpc(context)
    if not default_vpc:
        raise exception.VPCIdNotSpecified()
    return default_vpc


# NOTE(ft): following functions are copied from various parts of Nova

_ephemeral = re.compile('^ephemeral(\d|[1-9]\d+)$')

_dev = re.compile('^/dev/')


def block_device_strip_dev(device_name):
    """remove leading '/dev/'."""
    return _dev.sub('', device_name) if device_name else device_name


def block_device_prepend_dev(device_name):
    """Make sure there is a leading '/dev/'."""
    return device_name and '/dev/' + block_device_strip_dev(device_name)


def block_device_properties_root_device_name(properties):
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


_ISO8601_TIME_FORMAT_SUBSECOND = '%Y-%m-%dT%H:%M:%S.%f'
_ISO8601_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


def isotime(at=None, subsecond=False):
    """Stringify time in ISO 8601 format."""

    # Python provides a similar instance method for datetime.datetime objects
    # called isoformat(). The format of the strings generated by isoformat()
    # have a couple of problems:
    # 1) The strings generated by isotime are used in tokens and other public
    #    APIs that we can't change without a deprecation period. The strings
    #    generated by isoformat are not the same format, so we can't just
    #    change to it.
    # 2) The strings generated by isoformat do not include the microseconds if
    #    the value happens to be 0. This will likely show up as random failures
    #    as parsers may be written to always expect microseconds, and it will
    #    parse correctly most of the time.

    if not at:
        at = timeutils.utcnow()
    st = at.strftime(_ISO8601_TIME_FORMAT
                     if not subsecond
                     else _ISO8601_TIME_FORMAT_SUBSECOND)
    tz = at.tzinfo.tzname(None) if at.tzinfo else 'UTC'
    st += ('Z' if tz == 'UTC' else tz)
    return st
