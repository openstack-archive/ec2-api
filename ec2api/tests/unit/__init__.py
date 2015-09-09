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

"""
:mod:`ec2api.tests.unit.unit` -- EC2api Unittests
=====================================================

.. automodule:: ec2api.tests.unit.unit
   :platform: Unix
"""

# See http://code.google.com/p/python-nose/issues/detail?id=373
# The code below enables nosetests to work with i18n _() blocks
from six.moves import builtins
setattr(builtins, '_', lambda x: x)

# NOTE(ft): this is required by test_s3.S3APITestCase to switch execution
# between test and server threads
import eventlet
eventlet.monkey_patch(socket=True)
