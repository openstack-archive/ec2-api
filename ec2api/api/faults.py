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

from oslo_config import cfg
from oslo_context import context as common_context
from oslo_log import log as logging
import webob.dec
import webob.exc

import ec2api.api
from ec2api import utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def ec2_error_response(request_id, code, message, status=500):
    """Helper to construct an EC2 compatible error response."""
    LOG.debug('EC2 error response: %(code)s: %(message)s',
              {'code': code, 'message': message})
    resp = webob.Response()
    resp.status = status
    resp.headers['Content-Type'] = 'text/xml'
    resp.body = (
        '<?xml version="1.0"?>\n'
        '<Response><Errors><Error><Code>%s</Code>'
        '<Message>%s</Message></Error></Errors>'
        '<RequestID>%s</RequestID></Response>' %
        (utils.xhtml_escape(code),
         utils.xhtml_escape(message),
         utils.xhtml_escape(request_id))).encode()
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

        resp = ec2_error_response(common_context.generate_request_id(), code,
                                  message=message, status=status)
        return resp
