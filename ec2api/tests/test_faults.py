#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock
from oslotest import base as test_base
import webob

from ec2api.api import faults
from ec2api import wsgi


class FakeResponse(object):
    reason = "Test Reason"

    def __init__(self, status_code=400):
        self.status_code = status_code

    def json(self):
        return {}


class TestFaults(test_base.BaseTestCase):
    """Tests covering ec2 Fault class."""

    def test_fault_exception(self):
        # Ensure the status_int is set correctly on faults.
        fault = faults.Fault(webob.exc.HTTPBadRequest(
                             explanation='test'))
        self.assertIsInstance(fault.wrapped_exc, webob.exc.HTTPBadRequest)

    def test_fault_exception_status_int(self):
        # Ensure the status_int is set correctly on faults.
        fault = faults.Fault(webob.exc.HTTPNotFound(explanation='test'))
        self.assertEqual(fault.wrapped_exc.status_int, 404)

    @mock.patch.object(faults, 'ec2_error_response',
                       return_value=FakeResponse())
    def test_fault_call(self, mock_request):
        # Ensure proper EC2 response on faults.
        message = 'test message'
        ex = webob.exc.HTTPNotFound(explanation=message)
        fault = faults.Fault(ex)
        req = wsgi.Request.blank('/test')
        req.GET['AWSAccessKeyId'] = "test_user_id:test_project_id"
        fault(req)
        mock_request.assert_called_with(mock.ANY, 'HTTPNotFound',
                                        message=message, status=ex.status_int)
