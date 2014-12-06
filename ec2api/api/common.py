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


from ec2api.api import ec2utils
from ec2api.api import utils
from ec2api.db import api as db_api


vpc_kinds = ['vpc', 'igw', 'subnet', 'eni', 'dopt', 'eipalloc', 'sg', 'rtb']


def universal_describe(context, format_func, kind,
                       os_items=None, items=None,
                       describe_all=None, pre_filter_func=None,
                       filter=None, filter_map=None,
                       **kwargs):
    formatted_items = []
    if os_items is None:
        for item in items:
            kwargs['item'] = item
            formatted_item = format_func(**kwargs)
            if not utils.filtered_out(formatted_item, filter, filter_map):
                formatted_items.append(formatted_item)
        return formatted_items

    items_dict = dict((i['os_id'], i) for i in (items or []))
    for os_item in os_items:
        item = None
        if items is not None:
            os_item_id = (os_item['id'] if (type(os_item) is dict)
                          else os_item.id)
            item = items_dict.pop(os_item_id, None)
            if not item and kind not in vpc_kinds:
                if not describe_all:
                    # NOTE(Alex): the item is not requested by
                    # selective filter
                    continue
                else:
                    item = ec2utils.get_db_item_by_os_id(context, kind,
                                                         os_item_id)
        kwargs['context'] = context
        kwargs['os_item'] = os_item
        kwargs['item'] = item
        kwargs['os_items'] = os_items
        kwargs['items'] = items
        if pre_filter_func(**kwargs):
            continue
        formatted_item = format_func(**kwargs)
        if not utils.filtered_out(formatted_item, filter, filter_map):
            formatted_items.append(formatted_item)
    # NOTE(Alex): delete obsolete items
    for item in items_dict.values():
        db_api.delete_item(context, item['id'])
    # NOTE(Alex): some requested items are obsolete
    if not describe_all and (items_dict or not formatted_items):
        params = {'id': item['id'] if item else ''}
        raise ec2utils._NOT_FOUND_EXCEPTION_MAP[kind](**params)
    return formatted_items
