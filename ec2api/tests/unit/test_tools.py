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

import fixtures
from oslo_log import log as logging
from oslotest import base as test_base
import testtools

from ec2api import exception
from ec2api.tests.unit import base
from ec2api.tests.unit import tools


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


class TestBaseTestCase(base.ApiTestCase):

    def test_validate_exception_format_is_enabled_for_tests(self):
        with tools.ScreeningLogger():
            self.assertRaises(KeyError, exception.InvalidVpcRange,
                              fake='value')
        with tools.ScreeningLogger():
            self.assertRaises(TypeError, exception.InvalidID, {'id': 'value'})


class LoggingTestCase(test_base.BaseTestCase):

    def test_hide_logs(self):
        with fixtures.FakeLogger() as logger:
            with tools.ScreeningLogger():
                LOG = logging.getLogger('ec2api.api')
                LOG.critical('critical message')
                LOG.error('error message')
                LOG.warning('warning message')
            self.assertEqual(0, len(logger.output))

    def test_screen_logs(self):
        with fixtures.FakeLogger() as logger:
            with tools.ScreeningLogger(log_name='ec2api.api'):
                LOG1 = logging.getLogger('ec2api.api')
                LOG1.error('error message')
                LOG2 = logging.getLogger('ec2api.api.vpc')
                LOG2.warning('warning message')
            self.assertIn('warning message', logger.output)
            self.assertNotIn('error message', logger.output)

    def test_show_logs_on_unhandled_exception(self):
        with fixtures.FakeLogger() as logger:
            try:
                with tools.ScreeningLogger():
                    LOG = logging.getLogger('ec2api.api')
                    LOG.error('error message')
                    raise Exception()
            except Exception:
                pass
            self.assertIn('error message', logger.output)
