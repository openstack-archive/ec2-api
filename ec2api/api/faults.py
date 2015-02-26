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

from xml.sax import saxutils

from oslo_config import cfg
from oslo_log import log as logging
import webob.dec
import webob.exc

import ec2api.api
from ec2api import context

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


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


def ec2_error_response(request_id, code, message, status=500):
    """Helper to construct an EC2 compatible error response."""
    LOG.debug('EC2 error response: %(code)s: %(message)s',
              {'code': code, 'message': message})
    resp = webob.Response()
    resp.status = status
    resp.headers['Content-Type'] = 'text/xml'
    resp.body = str('<?xml version="1.0"?>\n'
                    '<Response><Errors><Error><Code>%s</Code>'
                    '<Message>%s</Message></Error></Errors>'
                    '<RequestID>%s</RequestID></Response>' %
                    (xhtml_escape(utf8(code)),
                     xhtml_escape(utf8(message)),
                     xhtml_escape(utf8(request_id))))
    return resp


class Fault(webob.exc.HTTPException):

    """Captures exception and return REST Response."""

    def __init__(self, exception):
        """Create a response for the given webob.exc.exception."""
        self.wrapped_exc = exception

    @webob.dec.wsgify
    def __call__(self, req):
        """Generate a WSGI response based on the exception passed to ctor."""
        code = ec2api.api.exception_to_ec2code(self.wrapped_exc)
        status = self.wrapped_exc.status_int
        message = self.wrapped_exc.explanation

        if status == 501:
            message = "The requested function is not supported"

        if 'AWSAccessKeyId' not in req.params:
            raise webob.exc.HTTPBadRequest()
        user_id, _sep, project_id = req.params['AWSAccessKeyId'].partition(':')
        project_id = project_id or user_id
        remote_address = getattr(req, 'remote_address', '127.0.0.1')
        if CONF.use_forwarded_for:
            remote_address = req.headers.get('X-Forwarded-For', remote_address)

        resp = ec2_error_response(context.generate_request_id(), code,
                                  message=message, status=status)
        return resp
