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

import re

from ec2api import context
from ec2api.db import api as db_api
from ec2api import exception
from ec2api import novadb
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging
from ec2api.openstack.common import timeutils
from ec2api.openstack.common import uuidutils

LOG = logging.getLogger(__name__)


def resource_type_from_id(context, resource_id):
    """Get resource type by ID

    Returns a string representation of the Amazon resource type, if known.
    Returns None on failure.

    :param context: context under which the method is called
    :param resource_id: resource_id to evaluate
    """

    known_types = {
        'i': 'instance',
        'r': 'reservation',
        'vol': 'volume',
        'snap': 'snapshot',
        'ami': 'image',
        'aki': 'image',
        'ari': 'image'
    }

    type_marker = resource_id.split('-')[0]

    return known_types.get(type_marker)


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
        LOG.audit(_("Timestamp is invalid."))
        return True


# TODO(Alex) This function is copied as is from original cloud.py. It doesn't
# check for the prefix which allows any prefix used for any object.
def ec2_id_to_id(ec2_id):
    """Convert an ec2 ID (i-[base 16 number]) to an instance id (int)."""
    try:
        return int(ec2_id.split('-')[-1], 16)
    except ValueError:
        raise exception.InvalidEc2Id(ec2_id=ec2_id)


def id_to_ec2_id(instance_id, template='i-%08x'):
    """Convert an instance ID (int) to an ec2 ID (i-[base 16 number])."""
    return template % int(instance_id)


def id_to_ec2_inst_id(instance_id):
    """Get or create an ec2 instance ID (i-[base 16 number]) from uuid."""
    if instance_id is None:
        return None
    elif uuidutils.is_uuid_like(instance_id):
        ctxt = context.get_admin_context()
        int_id = get_int_id_from_instance_uuid(ctxt, instance_id)
        return id_to_ec2_id(int_id)
    else:
        return id_to_ec2_id(instance_id)


def ec2_inst_id_to_uuid(context, ec2_id):
    """"Convert an instance id to uuid."""
    int_id = ec2_id_to_id(ec2_id)
    return get_instance_uuid_from_int_id(context, int_id)


def get_instance_uuid_from_int_id(context, int_id):
    return novadb.get_instance_uuid_by_ec2_id(context, int_id)


def get_int_id_from_instance_uuid(context, instance_uuid):
    if instance_uuid is None:
        return
    try:
        return novadb.get_ec2_instance_id_by_uuid(context, instance_uuid)
    except exception.NotFound:
        return novadb.ec2_instance_create(context, instance_uuid)['id']


# NOTE(ft): extra functions to use in vpc specific code or instead of
# malformed existed functions


def get_ec2_id(obj_id, kind):
    # TODO(ft): move to standard conversion function
    if not isinstance(obj_id, int) and not isinstance(obj_id, long):
        raise TypeError('obj_id must be int')
    elif obj_id < 0 or obj_id > 0xffffffff:
        raise OverflowError('obj_id must be non negative integer')
    return '%(kind)s-%(id)08x' % {'kind': kind, 'id': obj_id}


_NOT_FOUND_EXCEPTION_MAP = {
    'vpc': exception.InvalidVpcIDNotFound,
    'igw': exception.InvalidInternetGatewayIDNotFound,
    'subnet': exception.InvalidSubnetIDNotFound,
    'eni': exception.InvalidNetworkInterfaceIDNotFound,
    'dopt': exception.InvalidDhcpOptionsIDNotFound,
    'eipalloc': exception.InvalidAllocationIDNotFound,
    'sg': exception.InvalidSecurityGroupIDNotFound,
    'rtb': exception.InvalidRouteTableIDNotFound,
}


def get_db_item(context, kind, ec2_id):
    db_id = ec2_id_to_id(ec2_id)
    item = db_api.get_item_by_id(context, kind, db_id)
    if item is None:
        params = {'%s_id' % kind: ec2_id}
        raise _NOT_FOUND_EXCEPTION_MAP[kind](**params)
    return item


def get_db_items(context, kind, ec2_ids):
    if ec2_ids is not None:
        db_ids = [ec2_id_to_id(id) for id in ec2_ids]
        items = db_api.get_items_by_ids(context, kind, db_ids)
        if items is None or items == []:
            params = {'%s_id' % kind: ec2_ids[0]}
            raise _NOT_FOUND_EXCEPTION_MAP[kind](**params)
    else:
        items = db_api.get_items(context, kind)
    return items


_cidr_re = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")


def validate_cidr(cidr, parameter_name):
    invalid_format_exception = exception.InvalidParameterValue(
        value=cidr,
        parameter=parameter_name,
        reason='This is not a valid CIDR block.')
    if not _cidr_re.match(cidr):
        raise invalid_format_exception
    address, size = cidr.split("/")
    octets = address.split(".")
    if any(int(octet) > 255 for octet in octets):
        raise invalid_format_exception
    size = int(size)
    if size > 32:
        raise invalid_format_exception


def validate_vpc_cidr(cidr, invalid_cidr_exception_class):
    validate_cidr(cidr, 'cidrBlock')
    size = int(cidr.split("/")[-1])
    if size > 28 or size < 16:
        raise invalid_cidr_exception_class(cidr_block=cidr)
