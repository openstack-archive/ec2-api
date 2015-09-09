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


import copy
import logging
import re

import fixtures
from lxml import etree
import mock
import six

from ec2api.api import ec2utils


def update_dict(dict1, dict2):
    """Get a copy of union of two dicts."""
    res = copy.deepcopy(dict1)
    res.update(dict2)
    return res


def purge_dict(dict1, trash_keys):
    """Get a copy of dict, removed keys."""
    res = copy.deepcopy(dict1)
    for key in trash_keys:
        res.pop(key, None)
    return res


def patch_dict(dict1, dict2, trash_iter):
    """Get a copy of union of two dicts, removed keys."""
    res = update_dict(dict1, dict2)
    res = purge_dict(res, trash_iter)
    return res


def get_db_api_add_item(item_id_dict):
    """Generate db_api.add_item mock function."""

    def db_api_add_item(context, kind, data):
        if isinstance(item_id_dict, dict):
            item_id = item_id_dict[kind]
        else:
            item_id = item_id_dict
        data = update_dict(data, {'id': item_id})
        data.setdefault('os_id')
        data.setdefault('vpc_id')
        return data
    return db_api_add_item


def get_db_api_get_items(*items):
    """Generate db_api.get_items mock function."""

    def db_api_get_items(context, kind):
        return [copy.deepcopy(item)
                for item in items
                if ec2utils.get_ec2_id_kind(item['id']) == kind]
    return db_api_get_items


def get_db_api_get_item_by_id(*items):
    """Generate db_api.get_item_by_id mock function."""

    def db_api_get_item_by_id(context, item_id):
        return next((copy.deepcopy(item)
                     for item in items
                     if item['id'] == item_id),
                    None)
    return db_api_get_item_by_id


def get_db_api_get_items_by_ids(*items):
    """Generate db_api.get_items_by_ids mock function."""

    def db_api_get_items_by_ids(context, item_ids):
        return [copy.deepcopy(item)
                for item in items
                if (item['id'] in item_ids)]
    return db_api_get_items_by_ids


def get_db_api_get_items_ids(*items):
    """Generate db_api.get_items_ids mock function."""

    def db_api_get_items_ids(context, kind, item_ids=None, item_os_ids=None):
        return [(item['id'], item['os_id'])
                for item in items
                if (ec2utils.get_ec2_id_kind(item['id']) == kind and
                    (not item_ids or item['id'] in item_ids) and
                    (not item_os_ids or item['os_id'] in item_os_ids))]
    return db_api_get_items_ids


def get_neutron_create(kind, os_id, addon={}):
    """Generate Neutron create an object mock function."""

    def neutron_create(body):
        body = copy.deepcopy(body)
        body[kind].update(addon)
        body[kind]['id'] = os_id
        return body
    return neutron_create


def get_by_1st_arg_getter(results_dict_by_id, notfound_exception=None):
    """Generate mock function for getter by 1st argurment."""

    def getter(obj_id):
        try:
            return copy.deepcopy(results_dict_by_id[obj_id])
        except KeyError:
            if notfound_exception:
                raise notfound_exception
            else:
                return None
    return getter


def get_by_2nd_arg_getter(results_dict_by_id):
    """Generate mock function for getter by 2nd argurment."""

    def getter(_context, obj_id):
        return copy.deepcopy(results_dict_by_id.get(obj_id))
    return getter


def _safe_copy_parameters(args, kwargs):
    # NOTE(ft): deepcopy fails to copy a complicated mock like
    # neutron client mock or OnCrashCleaner object
    def _safe_copy(obj):
        try:
            return copy.deepcopy(obj)
        except Exception:
            return obj

    args = [_safe_copy(arg)
            for arg in args]
    kwargs = {key: _safe_copy(val)
              for key, val in six.iteritems(kwargs)}
    return (args, kwargs)


class CopyingMock(mock.MagicMock):
    """Mock class for calls with mutable arguments.

    See https://docs.python.org/3/library/unittest.mock-examples.html#
        coping-with-mutable-arguments
    """

    def __call__(self, *args, **kwargs):
        args, kwargs = _safe_copy_parameters(args, kwargs)
        return super(CopyingMock, self).__call__(*args, **kwargs)


def deepcopy_call_args_saver(destination):
    def side_effect(*args, **kwargs):
        args, kwargs = _safe_copy_parameters(args, kwargs)
        destination.append(mock.call(*args, **kwargs))
    return side_effect


_xml_scheme = re.compile('\sxmlns=".*"')


def parse_xml(xml_string):
    xml_string = _xml_scheme.sub('', xml_string.decode("utf-8"))
    xml = etree.fromstring(xml_string)

    def convert_node(node):
        children = list(node)
        if len(children):
            if children[0].tag == 'item':
                val = list(convert_node(child)[1] for child in children)
            else:
                val = dict(convert_node(child) for child in children)
        elif node.tag.endswith('Set'):
            val = []
        else:
            # TODO(ft): do not use private function
            val = (ec2utils._try_convert(node.text)
                   if node.text
                   else node.text)
        return node.tag, val

    return dict([convert_node(xml)])


class KeepingHandler(logging.Handler):

    def __init__(self):
        super(KeepingHandler, self).__init__()
        self._storage = []

    def emit(self, record):
        self._storage.append(record)

    def emit_records_to(self, handlers, record_filter=None):
        for record in self._storage:
            if not record_filter or record_filter.filter(record):
                for handler in handlers:
                    if self != handler:
                        handler.emit(record)


class ScreeningFilter(logging.Filter):

    def __init__(self, name=None):
        self._name = name

    def filter(self, record):
        if self._name is not None and record.name == self._name:
            return False
        return True


class ScreeningLogger(fixtures.Fixture):

    def __init__(self, log_name=None):
        super(ScreeningLogger, self).__init__()
        self.handler = KeepingHandler()
        if log_name:
            self._filter = ScreeningFilter(name=log_name)
        else:
            self._filter = None

    def setUp(self):
        super(ScreeningLogger, self).setUp()
        self.useFixture(fixtures.LogHandler(self.handler))

    def __exit__(self, exc_type, exc_val, exc_tb):
        res = super(ScreeningLogger, self).__exit__(exc_type, exc_val, exc_tb)
        handlers = logging.getLogger().handlers
        if exc_type:
            self.handler.emit_records_to(handlers)
        elif self._filter:
            self.handler.emit_records_to(handlers, self._filter)
        return res


def screen_logs(log_name=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            with ScreeningLogger(log_name):
                return func(*args, **kwargs)
        return wrapper
    return decorator


screen_unexpected_exception_logs = screen_logs('ec2api.api')
screen_all_logs = screen_logs()
