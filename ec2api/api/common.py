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
import collections
import fnmatch
import inspect
import operator

from oslo_config import cfg
from oslo_log import log as logging
import six

from ec2api.api import ec2utils
from ec2api.api import validator
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _, _LI, _LW


ec2_opts = [
    cfg.BoolOpt('full_vpc_support',
                default=True,
                help='True if server supports Neutron for full VPC access'),
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)
LOG = logging.getLogger(__name__)


class OnCrashCleaner(object):

    def __init__(self):
        self._cleanups = []
        self._suppress_exception = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            return
        self._run_cleanups(self._cleanups)
        return self._suppress_exception

    def addCleanup(self, function, *args, **kwargs):
        self._cleanups.append((function, args, kwargs))

    def approveChanges(self):
        del self._cleanups[:]
        self._suppress_exception = True

    def _run_cleanups(self, cleanups):
        for function, args, kwargs in reversed(cleanups):
            try:
                function(*args, **kwargs)
            except Exception:
                if inspect.ismethod(function):
                    if six.PY2:
                        cmodule = function.im_class.__module__
                        cname = function.im_class.__name__
                    else:
                        cmodule = function.__self__.__class__.__module__
                        cname = function.__self__.__class__.__name__
                    name = '%s.%s.%s' % (cmodule, cname, function.__name__)
                elif inspect.isfunction(function):
                    name = '%s.%s' % (function.__module__, function.__name__)
                else:
                    name = '%s.%s' % (function.__class__.__module__,
                                      function.__class__.__name__)
                formatted_args = ''
                args_string = ', '.join([repr(arg) for arg in args])
                kwargs_string = ', '.join([
                    '%s=%r' % (key, value) for key, value in kwargs.items()
                ])
                if args_string:
                    formatted_args = args_string
                if kwargs_string:
                    if formatted_args:
                        formatted_args += ', '
                    formatted_args += kwargs_string
                LOG.warning(
                    _LW('Error cleaning up %(name)s(%(args)s)') %
                    {'name': name, 'args': formatted_args},
                    exc_info=True)
                pass


class Validator(object):

    def __init__(self, param_name="", action="", params=[]):
        self.param_name = param_name
        self.action = action
        self.params = params

    def multi(self, items, validation_func):
        validator.validate_list(items, self.param_name)
        for item in items:
            validation_func(item)

    def dummy(self, value):
        pass

    def bool(self, value):
        validator.validate_bool(value, self.param_name)

    def int(self, value):
        validator.validate_int(value, self.param_name)

    def str(self, value):
        validator.validate_str(value, self.param_name)

    def strs(self, values):
        self.multi(values, self.str)

    def str64(self, value):
        validator.validate_str(value, self.param_name, 64)

    def str255(self, value):
        validator.validate_str(value, self.param_name, 255)

    def str255s(self, values):
        self.multi(values, self.str255)

    def ip(self, ip):
        validator.validate_ipv4(ip, self.param_name)

    def ips(self, ips):
        self.multi(ips, self.ip)

    def cidr(self, cidr):
        validator.validate_cidr(cidr, self.param_name)

    def subnet_cidr(self, cidr):
        validator.validate_subnet_cidr(cidr)

    def vpc_cidr(self, cidr):
        validator.validate_vpc_cidr(cidr)

    def filter(self, filter):
        validator.validate_filter(filter)

    def key_value_dict_list(self, dict_list):
        validator.validate_key_value_dict_list(dict_list, self.param_name)

    def ec2_id(self, id, prefices=None):
        validator.validate_ec2_id(id, self.param_name, prefices)

    def ec2_ids(self, ids):
        self.multi(ids, self.ec2_id)

    def i_id(self, id):
        self.ec2_id(id, ['i'])

    def i_ids(self, ids):
        self.multi(ids, self.i_id)

    def ami_id(self, id):
        self.ec2_id(id, ['ami'])

    def aki_id(self, id):
        self.ec2_id(id, ['aki'])

    def ari_id(self, id):
        self.ec2_id(id, ['ari'])

    def amiariaki_id(self, id):
        self.ec2_id(id, ['ami', 'ari', 'aki'])

    def amiariaki_ids(self, ids):
        self.multi(ids, self.amiariaki_id)

    def sg_id(self, id):
        self.ec2_id(id, ['sg'])

    def sg_ids(self, ids):
        self.multi(ids, self.sg_id)

    def subnet_id(self, id):
        self.ec2_id(id, ['subnet'])

    def subnet_ids(self, ids):
        self.multi(ids, self.subnet_id)

    def igw_id(self, id):
        self.ec2_id(id, ['igw'])

    def igw_ids(self, ids):
        self.multi(ids, self.igw_id)

    def rtb_id(self, id):
        self.ec2_id(id, ['rtb'])

    def rtb_ids(self, ids):
        self.multi(ids, self.rtb_id)

    def eni_id(self, id):
        self.ec2_id(id, ['eni'])

    def eni_ids(self, ids):
        self.multi(ids, self.eni_id)

    def vpc_id(self, id):
        self.ec2_id(id, ['vpc'])

    def vpc_ids(self, ids):
        self.multi(ids, self.vpc_id)

    def eipalloc_id(self, id):
        self.ec2_id(id, ['eipalloc'])

    def eipalloc_ids(self, ids):
        self.multi(ids, self.eipalloc_id)

    def eipassoc_id(self, id):
        self.ec2_id(id, ['eipassoc'])

    def rtbassoc_id(self, id):
        self.ec2_id(id, ['rtbassoc'])

    def eni_attach_id(self, id):
        self.ec2_id(id, ['eni-attach'])

    def snap_id(self, id):
        self.ec2_id(id, ['snap'])

    def snap_ids(self, ids):
        self.multi(ids, self.snap_id)

    def vol_id(self, id):
        self.ec2_id(id, ['vol'])

    def vol_ids(self, ids):
        self.multi(ids, self.vol_id)

    def dopt_id(self, id):
        self.ec2_id(id, ['dopt'])

    def dopt_ids(self, ids):
        self.multi(ids, self.dopt_id)

    def vgw_id(self, id):
        self.ec2_id(id, ['vgw'])

    def vgw_ids(self, ids):
        self.multi(ids, self.vgw_id)

    def cgw_id(self, id):
        self.ec2_id(id, ['cgw'])

    def cgw_ids(self, ids):
        self.multi(ids, self.cgw_id)

    def vpn_id(self, id):
        self.ec2_id(id, ['vpn'])

    def vpn_ids(self, ids):
        self.multi(ids, self.vpn_id)

    def security_group_str(self, value):
        validator.validate_security_group_str(value, self.param_name,
                                              self.params.get('vpc_id'))

    def security_group_strs(self, values):
        self.multi(values, self.security_group_str)

    def vpn_connection_type(self, value):
        validator.validate_vpn_connection_type(value)


VPC_KINDS = ['vpc', 'igw', 'subnet', 'eni', 'dopt', 'eipalloc', 'rtb',
             'vgw', 'cgw', 'vpn']


class UniversalDescriber(object):
    """Abstract Describer class for various Describe implementations."""

    KIND = ''
    SORT_KEY = ''
    FILTER_MAP = {}

    def format(self, item=None, os_item=None):
        pass

    def post_format(self, formatted_item, item):
        pass

    def get_db_items(self):
        return ec2utils.get_db_items(self.context, self.KIND, self.ids)

    def get_os_items(self):
        return []

    def auto_update_db(self, item, os_item):
        if item is None and self.KIND not in VPC_KINDS:
            item = ec2utils.auto_create_db_item(self.context, self.KIND,
                                                self.get_id(os_item))
            LOG.info(
                _LI('Item %(item)s was updated to %(os_item)s.') %
                {'item': str(item), 'os_item': str(os_item)})
        return item

    def get_id(self, os_item):
        return os_item['id'] if isinstance(os_item, dict) else os_item.id

    def get_name(self, os_item):
        return os_item['name']

    def delete_obsolete_item(self, item):
        LOG.info(_LI('Deleting obsolete item %(item)s') % {'item': str(item)})
        db_api.delete_item(self.context, item['id'])

    def is_filtering_value_found(self, filter_value, value):
        if fnmatch.fnmatch(str(value), str(filter_value)):
            return True

    def filtered_out(self, item, filters):
        if filters is None:
            return False
        for filter in filters:
            filter_name = self.FILTER_MAP.get(filter['name'])
            if filter_name is None:
                raise exception.InvalidParameterValue(
                    value=filter['name'], parameter='filter',
                    reason='invalid filter')
            values = self.get_values_by_filter(filter_name, item)
            if not values:
                return True
            filter_values = filter['value']
            for filter_value in filter_values:
                if any(self.is_filtering_value_found(filter_value, value)
                       for value in values):
                    break
            else:
                return True
        return False

    def get_values_by_filter(self, filter_name, item):
        if isinstance(filter_name, list):
            values = []
            value_set = item.get(filter_name[0], [])
            for value in value_set:
                vals = self.get_values_by_filter(filter_name[1], value)
                if vals:
                    values += vals
        else:
            if isinstance(filter_name, tuple):
                value = item.get(filter_name[0], {}).get(filter_name[1])
            else:
                value = item.get(filter_name)
            values = [value] if value is not None else []
        return values

    def get_paged(self, formatted_items, max_results, next_token):
        self.next_token = None
        if not max_results and not next_token:
            return formatted_items

        if max_results and max_results > 1000:
            max_results = 1000
        formatted_items = sorted(formatted_items,
                                 key=operator.itemgetter(self.SORT_KEY))

        next_item = 0
        if next_token:
            next_item = int(base64.b64decode(next_token))
        if next_item:
            formatted_items = formatted_items[next_item:]
        if max_results and max_results < len(formatted_items):
            self.next_token = base64.b64encode(str(next_item + max_results))
            formatted_items = formatted_items[:max_results]

        return formatted_items

    def handle_unpaired_item(self, item):
        self.delete_obsolete_item(item)

    def describe(self, context, ids=None, names=None, filter=None,
                 max_results=None, next_token=None):
        if max_results and max_results < 5:
            msg = (_('Value ( %s ) for parameter maxResults is invalid. '
                     'Expecting a value greater than 5.') % max_results)
            raise exception.InvalidParameterValue(msg)

        self.context = context
        self.selective_describe = ids is not None or names is not None
        self.ids = set(ids or [])
        self.names = set(names or [])
        self.items = self.get_db_items()
        self.os_items = self.get_os_items()
        formatted_items = []

        self.items_dict = {i['os_id']: i for i in (self.items or [])}
        paired_items_ids = set()
        for os_item in self.os_items:
            os_item_name = self.get_name(os_item)
            os_item_id = self.get_id(os_item)
            item = self.items_dict.get(os_item_id, None)
            if item:
                paired_items_ids.add(item['id'])
            # NOTE(Alex): Filter out items not requested in names or ids
            if (self.selective_describe and
                    not (os_item_name in self.names or
                         (item and item['id'] in self.ids))):
                continue
            # NOTE(Alex): Autoupdate DB for autoupdatable items
            item = self.auto_update_db(item, os_item)
            # NOTE(andrey-mp): save item id again
            # (if item has created by auto update)
            if item:
                paired_items_ids.add(item['id'])
            formatted_item = self.format(item, os_item)
            self.post_format(formatted_item, item)
            if os_item_name in self.names:
                self.names.remove(os_item_name)
            if item and item['id'] in self.ids:
                self.ids.remove(item['id'])
            if (formatted_item and
                    not self.filtered_out(formatted_item, filter)):
                formatted_items.append(formatted_item)
        # NOTE(Alex): delete obsolete items
        for item in self.items:
            if item['id'] in paired_items_ids:
                continue
            formatted_item = self.handle_unpaired_item(item)
            if formatted_item:
                if not self.filtered_out(formatted_item, filter):
                    formatted_items.append(formatted_item)
                if item['id'] in self.ids:
                    self.ids.remove(item['id'])
        # NOTE(Alex): some requested items are not found
        if self.ids or self.names:
            params = {'id': next(iter(self.ids or self.names))}
            raise ec2utils.NOT_FOUND_EXCEPTION_MAP[self.KIND](**params)

        return self.get_paged(formatted_items, max_results, next_token)


class TaggableItemsDescriber(UniversalDescriber):

    tags = None

    def __init__(self):
        super(TaggableItemsDescriber, self).__init__()
        self.FILTER_MAP['tag-key'] = ['tagSet', 'key']
        self.FILTER_MAP['tag-value'] = ['tagSet', 'value']
        self.FILTER_MAP['tag'] = 'tagSet'

    def get_tags(self):
        return db_api.get_tags(self.context, (self.KIND,), self.ids)

    def post_format(self, formatted_item, item):
        if not item or not formatted_item:
            return

        if self.tags is None:
            tags = collections.defaultdict(list)
            for tag in self.get_tags():
                tags[tag['item_id']].append(tag)
            self.tags = tags

        formatted_tags = []
        for tag in self.tags[item['id']]:
            formatted_tags.append({'key': tag['key'],
                                   'value': tag['value']})
        if formatted_tags:
            # NOTE(ft): AWS returns tagSet element for all objects (there are
            # errors in AWS docs)
            formatted_item['tagSet'] = formatted_tags

    def describe(self, context, ids=None, names=None, filter=None,
                 max_results=None, next_token=None):
        if filter:
            for f in filter:
                if f['name'].startswith('tag:'):
                    tag_key = f['name'].split(':')[1]
                    tag_values = f['value']
                    f['name'] = 'tag'
                    f['value'] = [{'key': tag_key,
                                   'value': tag_values}]
        return super(TaggableItemsDescriber, self).describe(
            context, ids=ids, names=names, filter=filter,
            max_results=max_results, next_token=next_token)

    def is_filtering_value_found(self, filter_value, value):
        if isinstance(filter_value, dict):
            for tag_pair in value:
                if (not isinstance(tag_pair, dict) or
                        filter_value.get('key') != tag_pair.get('key')):
                    continue
                for filter_dict_value in filter_value.get('value'):
                    if super(TaggableItemsDescriber,
                             self).is_filtering_value_found(
                                filter_dict_value,
                                tag_pair.get('value')):
                        return True
            return False
        return super(TaggableItemsDescriber,
                     self).is_filtering_value_found(filter_value, value)


class NonOpenstackItemsDescriber(UniversalDescriber):
    """Describer class for non-Openstack items Describe implementations."""

    def describe(self, context, ids=None, names=None, filter=None,
                 max_results=None, next_token=None):
        if max_results and max_results < 5:
            msg = (_('Value ( %s ) for parameter maxResults is invalid. '
                     'Expecting a value greater than 5.') % max_results)
            raise exception.InvalidParameterValue(msg)

        self.context = context
        self.ids = ids
        self.items = self.get_db_items()
        formatted_items = []

        for item in self.items:
            formatted_item = self.format(item)
            self.post_format(formatted_item, item)
            if (formatted_item and
                    not self.filtered_out(formatted_item, filter)):
                formatted_items.append(formatted_item)

        return self.get_paged(formatted_items, max_results, next_token)
