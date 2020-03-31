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


"""Utilities and helper functions."""

import hashlib
import hmac
from xml.sax import saxutils

from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def get_hash_str(base_str):
    """returns string that represents hash of base_str (in hex format)."""
    return hashlib.md5(base_str).hexdigest()


if hasattr(hmac, 'compare_digest'):
    constant_time_compare = hmac.compare_digest
else:
    def constant_time_compare(first, second):
        """Returns True if both string inputs are equal, otherwise False.

        This function should take a constant amount of time regardless of
        how many characters in the strings match.

        """
        if len(first) != len(second):
            return False
        result = 0
        for x, y in zip(first, second):
            result |= ord(x) ^ ord(y)
        return result == 0


def xhtml_escape(value):
    """Escapes a string so it is valid within XML or XHTML.

    """
    return saxutils.escape(value, {'"': '&quot;', "'": '&apos;'})
