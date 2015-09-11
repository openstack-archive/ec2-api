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

import netaddr
from oslo_log import log as logging
import six

from ec2api import exception
from ec2api.i18n import _


LOG = logging.getLogger(__name__)


def validate_str(val, parameter_name, max_length=None):
    if (isinstance(val, six.string_types) and
            (max_length is None or max_length and len(val) <= max_length)):
        return True
    raise exception.ValidationError(
        reason=_("%s should not be greater "
                 "than 255 characters.") % parameter_name)


def validate_bool(val, parameter_name):
    if isinstance(val, bool):
        return True
    raise exception.ValidationError(
        reason=_("Expected a boolean value for parameter %s") % parameter_name)


def validate_int(val, parameter_name):
    if isinstance(val, int):
        return True
    raise exception.ValidationError(
        reason=(_("Expected an integer value for parameter %s") %
                parameter_name))


def validate_list(items, parameter_name):
    if not isinstance(items, list):
        raise exception.InvalidParameterValue(
            value=items,
            parameter=parameter_name,
            reason='Expected a list here')


def _is_valid_cidr(address):
    """Check if address is valid

    The provided address can be a IPv6 or a IPv4
    CIDR address.
    """
    try:
        # Validate the correct CIDR Address
        netaddr.IPNetwork(address)
    except netaddr.core.AddrFormatError:
        return False
    except UnboundLocalError:
        # NOTE(MotoKen): work around bug in netaddr 0.7.5 (see detail in
        # https://github.com/drkjam/netaddr/issues/2)
        return False

    # Prior validation partially verify /xx part
    # Verify it here
    ip_segment = address.split('/')

    if (len(ip_segment) <= 1 or
            ip_segment[1] == ''):
        return False

    return True


def validate_cidr_with_ipv6(cidr, parameter_name, **kwargs):
    invalid_format_exception = exception.InvalidParameterValue(
        value=cidr,
        parameter=parameter_name,
        reason='This is not a valid CIDR block.')
    if not _is_valid_cidr(cidr):
        raise invalid_format_exception
    return True


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
    return True


def _validate_cidr_block(cidr):
    validate_cidr(cidr, 'cidrBlock')
    size = int(cidr.split("/")[-1])
    return size >= 16 and size <= 28


def validate_vpc_cidr(cidr):
    if not _validate_cidr_block(cidr):
        raise exception.InvalidVpcRange(cidr_block=cidr)


def validate_subnet_cidr(cidr):
    if not _validate_cidr_block(cidr):
        raise exception.InvalidSubnetRange(cidr_block=cidr)


# NOTE(Alex) Unfortunately Amazon returns various kinds of error for invalid
# IDs (...ID.Malformed, ...Id.Malformed, ...ID.NotFound, InvalidParameterValue)
# So we decided here to commonize invalid IDs to InvalidParameterValue error.

def validate_ec2_id(val, parameter_name, prefices):
    try:
        prefix, value = val.rsplit('-', 1)
        int(value, 16)
        if not prefices or prefix in prefices:
            return True
    except Exception:
        pass

    if not prefices:
        reason = _('Invalid EC2 id was specified.')
    else:
        reason = _('Expected: %(prefix)s-...') % {'prefix': prefices[0]}
    raise exception.InvalidParameterValue(
        value=val, parameter=parameter_name, reason=reason)


def validate_ec2_association_id(id, parameter_name, action):
    if action == 'DisassociateAddress':
        return validate_ec2_id(['eipassoc'])(id, parameter_name)
    else:
        return validate_ec2_id(['rtbassoc'])(id, parameter_name)


def validate_ipv4(address, parameter_name):
    """Verify that address represents a valid IPv4 address."""
    try:
        if netaddr.valid_ipv4(address):
            return True
    except Exception:
        pass
    raise exception.InvalidParameterValue(
        value=address, parameter=parameter_name,
        reason=_('Not a valid IP address'))


def validate_enum(value, allowed_values, parameter_name, allow_empty=False):
    if value is None and allow_empty or value in allowed_values:
        return True
    raise exception.InvalidParameterValue(
        value=value, parameter=parameter_name,
        reason=_('Invalid parameter value specified'))


def validate_filter(filters):
    for filter in filters:
        if (not filter.get('name') or not filter.get('value') or
                not isinstance(filter['value'], list)):
            raise exception.InvalidFilter()
    return True


def validate_key_value_dict_list(dict_list, parameter_name):
    for dict in dict_list:
        if not dict.get('key') or dict.get('value') is None:
            raise exception.InvalidParameterValue(
                value=dict, parameter=parameter_name,
                reason=_('Expected list of key value dictionaries'))
    return True


def validate_security_group_str(value, parameter_name, vpc_id=None):
    # NOTE(Alex) Amazon accepts any ASCII for EC2 classic;
    # for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
    if vpc_id:
        allowed = '^[a-zA-Z0-9\._\-:/\(\)#,@\[\]\+=&;\{\}!\$\*\ ]+$'
    else:
        allowed = r'^[\x20-\x7E]+$'
    msg = ''
    try:
        val = value.strip()
    except AttributeError:
        msg = (_("Security group %s is not a string or unicode") %
               parameter_name)
    if not val:
        msg = _("Security group %s cannot be empty.") % parameter_name
    elif not re.match(allowed, val):
        msg = (_("Specified value for parameter Group%(property)s is "
                 "invalid. Content limited to '%(allowed)s'.") %
               {'allowed': 'allowed',
                'property': parameter_name})
    elif len(val) > 255:
        msg = _("Security group %s should not be greater "
                "than 255 characters.") % parameter_name
    if msg:
        raise exception.ValidationError(reason=msg)
    return True


def validate_vpn_connection_type(value):
    if value != 'ipsec.1':
        raise exception.InvalidParameterValue(
            value=type, parameter='type',
            reason=_('Invalid VPN connection type.'))
    return True
