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


VPC_KINDS = ['vpc', 'igw', 'subnet', 'eni', 'dopt', 'eipalloc', 'sg', 'rtb']


class UniversalDescriber(object):
    """Abstract Describer class for various Describe implementations."""

    KIND = ''
    FILTER_MAP = {}

    def format(self, item=None, os_item=None):
        pass

    def get_db_items(self):
        return ec2utils.get_db_items(self.context, self.KIND, self.ids)

    def get_os_items(self):
        return []

    def auto_update_db(self, os_item_id):
        if self.KIND not in VPC_KINDS:
            item = ec2utils.get_db_item_by_os_id(self.context, self.KIND,
                                                 self.os_item_id)

    def get_id(self, os_item):
        return os_item['id'] if isinstance(os_item, dict) else os_item.id

    def get_name(self, os_item):
        return os_item['name']

    def describe(self, context, ids=None, names=None, filter=None):
        self.context = context
        selective_describe = ids is not None or names is not None
        self.ids = ids or []
        self.names = names or []
        self.items = self.get_db_items()
        self.os_items = self.get_os_items()
        formatted_items = []

        items_dict = dict((i['os_id'], i) for i in (self.items or []))
        for os_item in self.os_items:
            os_item_name = self.get_name(os_item)
            os_item_id = self.get_id(os_item)
            item = items_dict.get(os_item_id, None)
            # NOTE(Alex): Filter out items not requested in names or ids
            if selective_describe:
                if os_item_name in self.names:
                    self.names.remove(os_item_name)
                elif item and item['id'] in self.ids:
                    self.ids.remove(item['id'])
                else:
                    continue
            # NOTE(Alex): Autoupdate DB for autoupdatable items
            elif not item:
                item = self.auto_update_db(os_item_id)
            formatted_item = self.format(item, os_item)
            if not utils.filtered_out(formatted_item, filter, self.FILTER_MAP):
                formatted_items.append(formatted_item)
        # NOTE(Alex): delete obsolete items
        for id in self.ids:
            db_api.delete_item(context, id)
        # NOTE(Alex): some requested items are not found
        if self.ids or self.names:
            params = {'id': (self.ids or self.names)[0]}
            raise ec2utils._NOT_FOUND_EXCEPTION_MAP[self.KIND](**params)
        return formatted_items


class NonOpenstackItemsDescriber(UniversalDescriber):
    """Describer class for non-Openstack items Describe implementations."""

    def describe(self, context, ids=None, names=None, filter=None):
        self.context = context
        self.ids = ids
        self.items = self.get_db_items()
        formatted_items = []

        for item in self.items:
            formatted_item = self.format(item=item)
            if not utils.filtered_out(formatted_item, filter,
                                      self.FILTER_MAP):
                formatted_items.append(formatted_item)
        return formatted_items
