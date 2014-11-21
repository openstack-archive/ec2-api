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

from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import utils
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""Keypair-object related API implementation
"""


FILTER_MAP = {'fingerprint': 'keyFingerprint',
              'key-name': 'keyName'}


def describe_key_pairs(context, key_name=None, filter=None):
    nova = clients.nova(context)
    key_pairs = nova.keypairs.list()
    if key_name is not None:
        key_pairs = [x for x in key_pairs if x.name in key_name]

    # If looking for non existent key pair
    if key_name is not None and not key_pairs:
        msg = _('Could not find key pair(s): %s') % ','.join(key_name)
        raise exception.KeypairNotFound(message=msg)

    formatted_key_pairs = []
    for key_pair in key_pairs:
        # Original EC2 in nova filters out vpn keys for admin user.
        # We're not filtering out the vpn keys for now.
        # In order to implement this we'd have to configure vpn_key_suffix
        # in our config which we consider an overkill.
        # suffix = CONF.vpn_key_suffix
        # if context.is_admin or not key_pair['name'].endswith(suffix):
        formatted_key_pair = _format_key_pair(key_pair)
        if not utils.filtered_out(formatted_key_pair, filter, FILTER_MAP):
            formatted_key_pairs.append(formatted_key_pair)

    return {'keySet': formatted_key_pairs}


def create_key_pair(context, key_name):
    nova = clients.nova(context)
    try:
        key_pair = nova.keypairs.create(key_name)
    except clients.novaclient.exceptions.Conflict as ex:
        raise exception.KeyPairExists(key_name=key_name)
    formatted_key_pair = _format_key_pair(key_pair)
    formatted_key_pair['keyMaterial'] = key_pair.private_key
    return formatted_key_pair


def import_key_pair(context, key_name, public_key_material):
    nova = clients.nova(context)
    public_key = base64.b64decode(public_key_material)
    try:
        key_pair = nova.keypairs.create(key_name, public_key)
    except clients.novaclient.exceptions.Conflict as ex:
        raise exception.KeyPairExists(key_name=key_name)

    return _format_key_pair(key_pair)


def delete_key_pair(context, key_name):
    nova = clients.nova(context)
    try:
        nova.keypairs.delete(key_name)
    except exception.NotFound:
        # aws returns true even if the key doesn't exist
        pass
    return True


def _format_key_pair(key_pair):
    return {'keyName': key_pair.name,
            'keyFingerprint': key_pair.fingerprint
            }
