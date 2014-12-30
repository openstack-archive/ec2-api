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
import re

import netaddr

from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging


LOG = logging.getLogger(__name__)


def _get_path_validator_regex():
    # rfc3986 path validator regex from
    # http://jmrware.com/articles/2009/uri_regexp/URI_regex.html
    pchar = "([A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})"
    path = "((/{pchar}*)*|"
    path += "/({pchar}+(/{pchar}*)*)?|"
    path += "{pchar}+(/{pchar}*)*|"
    path += "{pchar}+(/{pchar}*)*|)"
    path = path.format(pchar=pchar)
    return re.compile(path)


VALIDATE_PATH_RE = _get_path_validator_regex()


def validate_dummy(val, **kwargs):
    return True


def validate_str(val, parameter_name, max_length=None):
    if (isinstance(val, basestring) and
            (max_length is None or max_length and len(val) <= max_length)):
        return True
    raise exception.ValidationError(
        reason=_("%s should not be greater "
                 "than 255 characters.") % parameter_name)


def validate_int(max_value=None):

    def _do(val, **kwargs):
        if not isinstance(val, int):
            return False
        if max_value and val > max_value:
            return False
        return True

    return _do


def validate_url_path(val, parameter_name=None, **kwargs):
    """True if val is matched by the path component grammar in rfc3986."""

    if not validate_str()(val, parameter_name):
        return False

    return VALIDATE_PATH_RE.match(val).end() == len(val)


def validate_image_path(val, parameter_name=None, **kwargs):
    if not validate_str()(val, parameter_name):
        return False

    bucket_name = val.split('/')[0]
    manifest_path = val[len(bucket_name) + 1:]
    if not len(bucket_name) or not len(manifest_path):
        return False

    if val[0] == '/':
        return False

    # make sure the image path if rfc3986 compliant
    # prepend '/' to make input validate
    if not validate_url_path('/' + val):
        return False

    return True


def validate_list(items, parameter_name):
    if not isinstance(items, list):
        raise exception.InvalidParameterValue(
            value=items,
            parameter=parameter_name,
            reason='Expected a list here')


def validate_user_data(user_data, **kwargs):
    """Check if the user_data is encoded properly."""
    try:
        user_data = base64.b64decode(user_data)
    except TypeError:
        return False
    return True


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


def validate_cidr(cidr, parameter_name, **kwargs):
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
        if prefix in prefices:
            return True
    except Exception:
        pass
    raise exception.InvalidParameterValue(
        value=val, parameter=parameter_name,
        reason=_('Expected: %(prefix)s-...') % {'prefix': prefices[0]})


def validate_ec2_association_id(id, parameter_name, action):
    if action == 'DisassociateAddress':
        return validate_ec2_id(['eipassoc'])(id, parameter_name)
    else:
        return validate_ec2_id(['rtbassoc'])(id, parameter_name)


def validate_ipv4(address, parameter_name, **kwargs):
    """Verify that address represents a valid IPv4 address."""
    try:
        if netaddr.valid_ipv4(address):
            return True
    except Exception:
        pass
    raise exception.InvalidParameterValue(
        value=address, parameter=parameter_name,
        reason=_('Not a valid IP address'))


def validate(request, validator):
    """Validate values of args against validators in validator.

    :param args:      Dict of values to be validated.
    :param validator: A dict where the keys map to keys in args
                      and the values are validators.
                      Applies each validator to ``args[key]``
    :returns: True if validation succeeds. Otherwise False.

    A validator should be a callable which accepts 1 argument and which
    returns True if the argument passes validation. False otherwise.
    A validator should not raise an exception to indicate validity of the
    argument.

    Only validates keys which show up in both args and validator.

    """

    args = request.args
    for key in args:
        if key not in validator:
            continue

        f = validator[key]
        assert callable(f)

        if not f(args[key], parameter_name=key, action=request.action):
            LOG.debug(_("%(key)s with value %(value)s failed"
                        " validator %(name)s"),
                      {'key': key, 'value': args[key], 'name': f.__name__})
            return False
    return True
