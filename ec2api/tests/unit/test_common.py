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

from unittest import mock

from oslotest import base as test_base

from ec2api.api import common


class OnCrashCleanerTestCase(test_base.BaseTestCase):
    class FakeException(Exception):
        pass

    def test_clean(self):
        obj = mock.MagicMock()

        def run():
            with common.OnCrashCleaner() as cleaner:
                cleaner.addCleanup(obj.fake_clean_method,
                                   555, 'arg', {'k': 'v'})
                cleaner.addCleanup(obj.fake_clean_method,
                                   666, 'param', {'key': 'value'})
                raise self.FakeException()

        self.assertRaises(self.FakeException, run)
        self.assertEqual([mock.call(666, 'param', {'key': 'value'}),
                          mock.call(555, 'arg', {'k': 'v'})],
                         obj.fake_clean_method.mock_calls)

    @mock.patch.object(common, 'LOG')
    def test_approve_partially(self, log):
        class FakeCrasherClass(object):
            call_count = 0

            def fake_crashed_clean_method(self, *args, **kwargs):
                self.call_count += 1
                raise Exception()

            def __call__(self):
                raise Exception()

        obj = mock.MagicMock()
        cls = FakeCrasherClass()

        with common.OnCrashCleaner() as cleaner:
            cleaner.addCleanup(obj.fake_clean_method_25),
            cleaner.addCleanup(obj.fake_clean_method)
            cleaner.addCleanup(cls.fake_crashed_clean_method)
            cleaner.approveChanges()
            cleaner.addCleanup(cls)
            cleaner.addCleanup(fake_standalone_crashed_clean_method)
            cleaner.addCleanup(cls.fake_crashed_clean_method,
                               'args', 666, {'key': 'value'},
                               s='args', i=666, d={'key': 'value'})
            cleaner.addCleanup(obj.fake_clean_method, 'params')
            raise Exception()

        self.assertEqual(1, cls.call_count)
        self.assertEqual(3, log.warning.call_count)
        self.assertIn('ec2api.tests.unit.test_common.FakeCrasherClass.'
                      'fake_crashed_clean_method',
                      log.warning.mock_calls[0][1][0])
        for arg in ["'args'", "666", "{'key': 'value'}",
                    "s='args'", "i=666", "d={'key': 'value'}"]:
            self.assertIn(arg, log.warning.mock_calls[0][1][0])
        self.assertIn('ec2api.tests.unit.test_common.'
                      'fake_standalone_crashed_clean_method',
                      log.warning.mock_calls[1][1][0])
        self.assertIn('ec2api.tests.unit.test_common.FakeCrasherClass',
                      log.warning.mock_calls[2][1][0])
        obj.fake_clean_method.assert_called_once_with('params')
        self.assertFalse(obj.fake_clean_method_25.called)

    def test_normal_flow(self):
        obj = mock.MagicMock()

        with common.OnCrashCleaner() as cleaner:
            cleaner.addCleanup(obj.fake_clean_method),
            cleaner.addCleanup(obj.fake_clean_method_25),

        self.assertFalse(obj.fake_clean_method.called)
        self.assertFalse(obj.fake_clean_method_25.called)

    def test_filter(self):
        obj = common.UniversalDescriber()
        obj.FILTER_MAP = {'prop1': 'prop-1', 'prop2': 'prop-2'}

        res = obj.filtered_out(
            {'prop-1': 'val-0', 'prop-2': 'val-123'},
            [{'name': 'prop1', 'value': ['val-0']}])
        self.assertFalse(res)

        res = obj.filtered_out(
            {'prop-1': 'val-0', 'prop-2': 'val-123'},
            [{'name': 'prop1', 'value': ['val-0', '0-val']}])
        self.assertFalse(res)

        res = obj.filtered_out(
            {'prop-1': 'val-0', 'prop-2': 'val-123'},
            [{'name': 'prop1', 'value': ['0-val', 'val-0']}])
        self.assertFalse(res)

        res = obj.filtered_out(
            {'prop-1': 'val-0', 'prop-2': 'val-123'},
            [{'name': 'prop1', 'value': ['0-val']}])
        self.assertTrue(res)

        res = obj.filtered_out(
            {'prop-1': 'val-0', 'prop-2': 'val-123'},
            [{'name': 'prop1', 'value': ['val-0']},
             {'name': 'prop2', 'value': ['val-123']}])
        self.assertFalse(res)

        res = obj.filtered_out(
            {'prop-1': 'val-0', 'prop-2': 'val-123'},
            [{'name': 'prop1', 'value': ['val-0']},
             {'name': 'prop2', 'value': ['123-val']}])
        self.assertTrue(res)

        res = obj.filtered_out(
            {'prop-1': 'val-0', 'prop-2': 'val-123'},
            [{'name': 'prop1', 'value': ['0-val']},
             {'name': 'prop2', 'value': ['val-123']}])
        self.assertTrue(res)


def fake_standalone_crashed_clean_method():
    raise Exception()
