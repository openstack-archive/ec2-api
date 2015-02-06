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


import testtools

from ec2api.tests import tools


class TestToolsTestCase(testtools.TestCase):

    def test_update_dict(self):
        d1 = {'a': 1, 'b': 2}
        d2 = {'b': 22, 'c': 33}
        res = tools.update_dict(d1, {})
        self.assertEqual({'a': 1, 'b': 2}, res)
        res = tools.update_dict(d1, d2)
        self.assertEqual({'a': 1, 'b': 22, 'c': 33}, res)
        self.assertEqual({'a': 1, 'b': 2}, d1)

    def test_purge_dict(self):
        d1 = {'a': 1, 'b': 2, 'c': 3}
        res = tools.purge_dict(d1, ())
        self.assertEqual({'a': 1, 'b': 2, 'c': 3}, res)
        res = tools.purge_dict(d1, ('b', 'c'))
        self.assertEqual({'a': 1}, res)
        self.assertEqual({'a': 1, 'b': 2, 'c': 3}, d1)

    def test_patch_dict(self):
        d1 = {'a': 1, 'b': 2, 'c': 3}
        d2 = {'c': 33, 'd': 44, 'e': 55}
        res = tools.patch_dict(d1, d2, ('b', 'e'))
        self.assertEqual({'a': 1, 'c': 33, 'd': 44}, res)
        self.assertEqual({'a': 1, 'b': 2, 'c': 3}, d1)
