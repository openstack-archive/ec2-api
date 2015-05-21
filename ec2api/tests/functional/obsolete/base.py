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

import ConfigParser
import functools
import os

import testtools

import tempest.test


def skip(*args, **kwargs):
    """A decorator useful to skip tests with message."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*func_args, **func_kwargs):
            if "bug" in kwargs:
                msg = "Skipped until Bug %s is resolved." % kwargs["bug"]
            else:
                msg = kwargs["msg"]
            raise testtools.TestCase.skipException(msg)
        return wrapper
    return decorator


class TestCasePreparationError(Exception):
    def __init__(self, msg="Error in test case preparation"):
        self.msg = msg

    def __str__(self):
        return self.msg


class BaseTest(tempest.test.BaseTestCase):
    """Base class for Cloudscaling tests"""
    pass


class BaseBenchmarkTest(BaseTest):
    """Base class for Cloudscaling tests"""

    @classmethod
    def _load_benchmark_data(cls, class_name):
        cfg = cls.config.cloudscaling
        if not cfg.benchmark_data:
            return None

        config = ConfigParser.ConfigParser()
        f = open(os.path.expanduser(cfg.benchmark_data))
        config.readfp(f)
        f.close()
        items = config.items(class_name)
        result_items = {}
        for item in items:
            boundaries = item[1].split("-")
            if len(boundaries) == 2:
                result_items[item[0]] = (boundaries[0], boundaries[1])

        cls.benchmark_data = result_items

    def _get_benchmark_data(self):
        return self.benchmark_data

    def _get_benchmark_result(self, result_name=None):
        if not hasattr(self, 'benchmark_data'):
            return None

        key = self._testMethodName.lower()
        if result_name is not None:
            key += "." + result_name
        if key in self.benchmark_data:
            return self.benchmark_data[key]

        return None
