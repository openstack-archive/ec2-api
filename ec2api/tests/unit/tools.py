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
import re

from lxml import etree
import mock

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


class CopyingMock(mock.MagicMock):
    """Mock class for calls with mutable arguments.

    See https://docs.python.org/3/library/unittest.mock-examples.html#
        coping-with-mutable-arguments
    """

    def __call__(self, *args, **kwargs):
        args = copy.deepcopy(args)
        kwargs = copy.deepcopy(kwargs)
        return super(CopyingMock, self).__call__(*args, **kwargs)


_xml_scheme = re.compile('\sxmlns=".*"')


def parse_xml(xml_string):
    xml_string = _xml_scheme.sub('', xml_string)
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
