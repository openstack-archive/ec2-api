# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
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

from lxml import etree
import mock
from oslo_config import cfg
from oslo_context import context
from oslo_serialization import jsonutils
from oslotest import base as test_base
import requests
import webob.dec
import webob.exc

from ec2api import api as ec2
from ec2api import exception
from ec2api.tests.unit import tools
from ec2api import wsgi

CONF = cfg.CONF


@webob.dec.wsgify
def conditional_forbid(req):
    """Helper wsgi app returns 403 if param 'die' is 1."""
    if 'die' in req.params and req.params['die'] == '1':
        raise webob.exc.HTTPForbidden()
    return 'OK'


class ExecutorTestCase(test_base.BaseTestCase):
    def setUp(self):
        super(ExecutorTestCase, self).setUp()
        self.executor = ec2.Executor()

    def _execute(self, invoke):
        class Fake(object):
            pass
        fake_ec2_request = Fake()
        fake_ec2_request.invoke = invoke

        fake_wsgi_request = Fake()

        fake_wsgi_request.environ = {
            'ec2api.context': mock.Mock(
                request_id=context.generate_request_id()),
            'ec2.request': fake_ec2_request,
        }
        return self.executor(fake_wsgi_request)

    def _extract_message(self, result):
        tree = etree.fromstring(result.body)
        return tree.findall('./Errors')[0].find('Error/Message').text

    def _extract_code(self, result):
        tree = etree.fromstring(result.body)
        return tree.findall('./Errors')[0].find('Error/Code').text

    def test_instance_not_found(self):
        def not_found(context):
            raise exception.InvalidInstanceIDNotFound(id='i-01')
        result = self._execute(not_found)
        self.assertIn('i-01', self._extract_message(result))
        self.assertEqual('InvalidInstanceID.NotFound',
                         self._extract_code(result))

    def test_instance_not_found_none(self):
        def not_found(context):
            raise exception.InvalidInstanceIDNotFound(id=None)

        # NOTE(mikal): we want no exception to be raised here, which was what
        # was happening in bug/1080406
        result = self._execute(not_found)
        self.assertIn('None', self._extract_message(result))
        self.assertEqual('InvalidInstanceID.NotFound',
                         self._extract_code(result))

    def test_snapshot_not_found(self):
        def not_found(context):
            raise exception.InvalidSnapshotNotFound(id='snap-01')
        result = self._execute(not_found)
        self.assertIn('snap-01', self._extract_message(result))
        self.assertEqual('InvalidSnapshot.NotFound',
                         self._extract_code(result))

    def test_volume_not_found(self):
        def not_found(context):
            raise exception.InvalidVolumeNotFound(id='vol-01')
        result = self._execute(not_found)
        self.assertIn('vol-01', self._extract_message(result))
        self.assertEqual('InvalidVolume.NotFound', self._extract_code(result))


class FakeResponse(object):
    reason = "Test Reason"

    def __init__(self, status_code=400):
        self.status_code = status_code

    def json(self):
        return {}


class KeystoneAuthTestCase(test_base.BaseTestCase):
    def setUp(self):
        super(KeystoneAuthTestCase, self).setUp()
        self.kauth = ec2.EC2KeystoneAuth(conditional_forbid)

    def _validate_ec2_error(self, response, http_status, ec2_code):
        self.assertEqual(response.status_code, http_status,
                         'Expected HTTP status %s' % http_status)
        root_e = etree.XML(response.body)
        self.assertEqual(root_e.tag, 'Response',
                         "Top element must be Response.")
        errors_e = root_e.find('Errors')
        error_e = errors_e[0]
        code_e = error_e.find('Code')
        self.assertIsNotNone(code_e, "Code element must be present.")
        self.assertEqual(code_e.text, ec2_code)

    def test_no_signature(self):
        req = wsgi.Request.blank('/test')
        resp = self.kauth(req)
        self._validate_ec2_error(resp, 400, 'AuthFailure')

    def test_no_key_id(self):
        req = wsgi.Request.blank('/test')
        req.GET['Signature'] = 'test-signature'
        resp = self.kauth(req)
        self._validate_ec2_error(resp, 400, 'AuthFailure')

    @mock.patch.object(requests, 'request', return_value=FakeResponse())
    def test_communication_failure(self, mock_request):
        req = wsgi.Request.blank('/test')
        req.GET['Signature'] = 'test-signature'
        req.GET['AWSAccessKeyId'] = 'test-key-id'
        resp = self.kauth(req)
        self._validate_ec2_error(resp, 400, 'AuthFailure')
        mock_request.assert_called_with('POST',
                                        CONF.keystone_ec2_tokens_url,
                                        data=mock.ANY, headers=mock.ANY)

    @tools.screen_all_logs
    @mock.patch.object(requests, 'request', return_value=FakeResponse(200))
    def test_no_result_data(self, mock_request):
        req = wsgi.Request.blank('/test')
        req.GET['Signature'] = 'test-signature'
        req.GET['AWSAccessKeyId'] = 'test-key-id'
        resp = self.kauth(req)
        self._validate_ec2_error(resp, 400, 'AuthFailure')
        mock_request.assert_called_with('POST',
                                        CONF.keystone_ec2_tokens_url,
                                        data=mock.ANY, headers=mock.ANY)

        fake_request = mock.NonCallableMock(status_code=200, headers={})
        fake_request.json.return_value = {'token': {}}
        mock_request.return_value = fake_request
        resp = self.kauth(req)
        self._validate_ec2_error(resp, 400, 'AuthFailure')

        fake_request.json.return_value = {'access': {}}
        resp = self.kauth(req)
        self._validate_ec2_error(resp, 400, 'AuthFailure')

    @tools.screen_unexpected_exception_logs
    @mock.patch.object(requests, 'request', return_value=FakeResponse(200))
    def test_params_for_keystone_call(self, mock_request):
        req = wsgi.Request.blank('/test')
        req.GET['Signature'] = 'test-signature'
        req.GET['AWSAccessKeyId'] = 'test-key-id'
        self.kauth(req)
        mock_request.assert_called_with(
            'POST', CONF.keystone_ec2_tokens_url,
            data=mock.ANY, headers=mock.ANY)

        data = jsonutils.loads(mock_request.call_args[1]['data'])
        expected_data = {
            'ec2Credentials': {
                'access': 'test-key-id',
                'headers': {'Host': 'localhost:80'},
                'host': 'localhost:80',
                'verb': 'GET',
                'params': {'AWSAccessKeyId': 'test-key-id'},
                'signature': 'test-signature',
                'path': '/test',
                'body_hash': 'e3b0c44298fc1c149afbf4c8996fb924'
                             '27ae41e4649b934ca495991b7852b855'}}
        self.assertEqual(expected_data, data)
