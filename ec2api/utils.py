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

import contextlib
import hashlib
import hmac
import shutil
import socket
import tempfile
from xml.sax import saxutils

from oslo_config import cfg
from oslo_log import log as logging

from ec2api.i18n import _

utils_opts = [
    cfg.StrOpt('tempdir',
               help='Explicitly specify the temporary working directory'),
]
CONF = cfg.CONF
CONF.register_opts(utils_opts)

LOG = logging.getLogger(__name__)


def _get_my_ip():
    """Returns the actual ip of the local machine.

    This code figures out what source address would be used if some traffic
    were to be sent out to some well known address on the Internet. In this
    case, a Google DNS server is used, but the specific address does not
    matter much.  No traffic is actually sent.
    """
    try:
        csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        csock.connect(('8.8.8.8', 80))
        (addr, port) = csock.getsockname()
        csock.close()
        return addr
    except socket.error:
        # TODO(Alex) nova's code has a backup plan in this case.
        # We might want to move the code here as well
        return '127.0.0.1'


@contextlib.contextmanager
def tempdir(**kwargs):
    argdict = kwargs.copy()
    if 'dir' not in argdict:
        argdict['dir'] = CONF.tempdir
    tmpdir = tempfile.mkdtemp(**argdict)
    try:
        yield tmpdir
    finally:
        try:
            shutil.rmtree(tmpdir)
        except OSError as e:
            LOG.error(_('Could not remove tmpdir: %s'), str(e))


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


def utf8(value):
    """Try to turn a string into utf-8 if possible.

    Code is directly from the utf8 function in
    http://github.com/facebook/tornado/blob/master/tornado/escape.py

    """
    if isinstance(value, unicode):
        return value.encode('utf-8')
    assert isinstance(value, str)
    return value
