#    Copyright 2014 Cloudscaling Group, Inc
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

import collections
import uuid

import mock
from oslotest import base as test_base

from ec2api import api
from ec2api.api import apirequest
from ec2api.api import cloud
from ec2api import exception
from ec2api.tests import fakes_request_response as fakes
from ec2api.tests import matchers
from ec2api import wsgi


class ApiInitTestCase(test_base.BaseTestCase):

    fake_context_class = collections.namedtuple('FakeRequestContext',
                                                ['request_id'])
    setattr(fake_context_class, 'to_dict', fake_context_class._asdict)

    def setUp(self):
        super(ApiInitTestCase, self).setUp()
        requester_patcher = mock.patch('ec2api.api.ec2client.EC2Requester')
        self.requester_class = requester_patcher.start()
        self.requester = self.requester_class.return_value
        self.addCleanup(requester_patcher.stop)

        controller_patcher = mock.patch('ec2api.api.cloud.CloudController')
        self.controller_class = controller_patcher.start()
        self.controller = self.controller_class.return_value
        self.addCleanup(controller_patcher.stop)

        self.fake_context = self.fake_context_class(str(uuid.uuid4()))

        ec2_request = apirequest.APIRequest('FakeAction', 'fake_v1',
                                            {'Param': 'fake_param'})
        self.environ = {'REQUEST_METHOD': 'FAKE',
                        'ec2.request': ec2_request,
                        'ec2api.context': self.fake_context}
        self.request = wsgi.Request(self.environ)
        self.application = api.Executor()

    def test_execute(self):
        self.controller.fake_action.return_value = {'fakeTag': 'fake_data'}

        res = self.request.send(self.application)

        self.assertEqual(200, res.status_code)
        self.assertEqual('text/xml', res.content_type)
        expected_xml = fakes.XML_RESULT_TEMPLATE % {
            'action': 'FakeAction',
            'api_version': 'fake_v1',
            'request_id': self.fake_context.request_id,
            'data': '<fakeTag>fake_data</fakeTag>'}
        self.assertThat(res.body, matchers.XMLMatches(expected_xml))
        self.controller.fake_action.assert_called_once_with(self.fake_context,
                                                            param='fake_param')

    def test_execute_error(self):
        def do_check(ex, status, code, message):
            self.controller.reset_mock()
            self.controller.fake_action.side_effect = ex

            res = self.request.send(self.application)

            self.assertEqual(status, res.status_code)
            self.assertEqual('text/xml', res.content_type)
            expected_xml = fakes.XML_ERROR_TEMPLATE % {
                'code': code,
                'message': message,
                'request_id': self.fake_context.request_id}
            self.assertThat(res.body, matchers.XMLMatches(expected_xml))
            self.controller.fake_action.assert_called_once_with(
                self.fake_context, param='fake_param')

        do_check(exception.EC2Exception('fake_msg'), 500,
                 'EC2Exception', 'Unknown error occurred.')
        do_check(KeyError('fake_msg'), 500,
                 'KeyError', 'Unknown error occurred.')
        do_check(exception.InvalidVpcIDNotFound('fake_msg'), 400,
                 'InvalidVpcID.NotFound', 'fake_msg')

    def test_execute_proxy(self):
        self.controller_class.return_value = mock.create_autospec(
            cloud.CloudController, instance=True)
        # NOTE(ft): recreate APIRequest to use mock with autospec
        ec2_request = apirequest.APIRequest('FakeAction', 'fake_v1',
                                            {'Param': 'fake_param'})
        self.environ['ec2.request'] = ec2_request
        self.environ['QUERY_STRING'] = 'Version=fake_v1&Action=FakeAction'
        self.requester.request.return_value = ({'status': 200,
                                                'content-type': 'fake_type'},
                                               'fake_data')

        res = self.request.send(self.application)

        self.requester_class.assert_called_once_with('fake_v1', 'FAKE')
        self.requester.request.assert_called_once_with(self.fake_context,
                                                       'FakeAction',
                                                       {'Param': 'fake_param'})
        self.assertEqual(200, res.status_code)
        self.assertEqual('fake_type', res.content_type)
        self.assertEqual('fake_data', res.body)

    def test_execute_proxy_error(self):
        self.controller.fake_action.side_effect = exception.EC2ServerError(
            {'status': 400, 'content-type': 'fake_type'},
            'fake_content')

        res = self.request.send(self.application)

        self.assertEqual(400, res.status_code)
        self.assertEqual('fake_type', res.content_type)
        self.assertEqual('fake_content', res.body)
