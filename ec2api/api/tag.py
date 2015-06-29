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

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


"""Tag related API implementation
"""


Validator = common.Validator


RESOURCE_TYPES = {
    'dopt': 'dhcp-options',
    'ami': 'image',
    'aki': 'image',
    'ari': 'image',
    'cgw': 'customer-gateway',
    'i': 'instance',
    'igw': 'internet-gateway',
    'eni': 'network-interface',
    'rtb': 'route-table',
    'snap': 'snapshot',
    'subnet': 'subnet',
    'sg': 'security-group',
    'vgw': 'vpn-gateway',
    'vol': 'volume',
    'vpc': 'vpc',
    'vpn': 'vpn-connection',
}


def create_tags(context, resource_id, tag):
    reason = None
    for tag_pair in tag:
        if not tag_pair.get('key'):
            reason = _('Not empty key must be present')
        elif len(tag_pair['key']) > 127:
            reason = _('Tag key exceeds the maximum length of 127 characters')
        elif tag_pair['key'].startswith('aws:'):
            reason = _("Tag keys starting with 'aws:' are reserved for "
                       "internal use")
        elif 'value' not in tag_pair:
            reason = _('Value must be present')
        elif len(tag_pair['value']) > 255:
            reason = _('Tag value exceeds the maximum length of 255 '
                       'characters')
        if reason:
            raise exception.InvalidParameterValue(
                    parameter='Tag', value=str(tag_pair), reason=reason)

    for item_id in resource_id:
        kind = ec2utils.get_ec2_id_kind(item_id)
        if kind not in RESOURCE_TYPES:
            raise exception.InvalidID(id=item_id)
        # NOTE(ft): check items exist (excluding images because AWS allows to
        # create a tag with any image id)
        if kind not in ('ami', 'ari', 'aki'):
            ec2utils.get_db_item(context, item_id)

    tags = [dict(item_id=item_id,
                 key=tag_pair['key'],
                 value=tag_pair['value'])
            for item_id in resource_id
            for tag_pair in tag]

    db_api.add_tags(context, tags)
    return True


def delete_tags(context, resource_id, tag=None):
    db_api.delete_tags(context, resource_id, tag)
    return True


class TagDescriber(common.NonOpenstackItemsDescriber):

    SORT_KEY = 'key'
    FILTER_MAP = {'key': 'key',
                  'tag-key': 'key',
                  'resource-id': 'resourceId',
                  'resource-type': 'resourceType',
                  'value': 'value',
                  'tag-value': 'value'}

    def get_db_items(self):
        return db_api.get_tags(self.context)

    def format(self, item):
        return _format_tag(item)


def describe_tags(context, filter=None, max_results=None, next_token=None):
    tag_describer = TagDescriber()
    formatted_tags = tag_describer.describe(
        context, filter=filter, max_results=max_results, next_token=next_token)
    result = {'tagSet': formatted_tags}
    if tag_describer.next_token:
        result['nextToken'] = tag_describer.next_token
    return result


def _format_tag(tag):
    kind = ec2utils.get_ec2_id_kind(tag['item_id'])
    return {
        'resourceType': RESOURCE_TYPES.get(kind, kind),
        'resourceId': tag['item_id'],
        'key': tag['key'],
        'value': tag['value'],
    }
