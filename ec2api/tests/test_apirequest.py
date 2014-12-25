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

import collections
import uuid

from lxml import etree
import mock
from oslotest import base as test_base

from ec2api.api import apirequest
from ec2api.tests import fakes_request_response as fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class EC2RequesterTestCase(test_base.BaseTestCase):

    fake_context_class = collections.namedtuple('FakeContext',
                                                ['request_id'])
    fake_request_class = collections.namedtuple('FakeRequest',
                                                ['params', 'environ'])

    def setUp(self):
        super(EC2RequesterTestCase, self).setUp()

        controller_patcher = mock.patch('ec2api.api.cloud.VpcCloudController')
        self.controller = controller_patcher.start().return_value
        self.addCleanup(controller_patcher.stop)

        self.fake_context = self.fake_context_class(str(uuid.uuid4()))

    def test_invoke_returns_data(self):
        self.controller.fake_action.return_value = fakes.DICT_FAKE_RESULT_DATA

        api_request = apirequest.APIRequest('FakeAction', 'fake_v1',
                                            {'Param': 'fake'})
        result = api_request.invoke(self.fake_context)

        self._compare_aws_xml('FakeActionResponse',
                              'http://ec2.amazonaws.com/doc/fake_v1/',
                              self.fake_context.request_id,
                              fakes.DICT_FAKE_RESULT_DATA,
                              result)
        self.controller.fake_action.assert_called_once_with(
                self.fake_context, param='fake')

    def test_invoke_returns_true(self):
        self.controller.fake_action.return_value = True

        api_request = apirequest.APIRequest('FakeAction', 'fake_v1',
                                            {'Param': 'fake'})
        result = api_request.invoke(self.fake_context)

        self._compare_aws_xml('FakeActionResponse',
                              'http://ec2.amazonaws.com/doc/fake_v1/',
                              self.fake_context.request_id,
                              {'return': True},
                              result)
        self.controller.fake_action.assert_called_once_with(
                self.fake_context, param='fake')

    def test_invoke_prepare_params(self):
        api_request = apirequest.APIRequest('FakeAction', 'fake_v1',
                                            fakes.DOTTED_FAKE_PARAMS)
        api_request.invoke(self.fake_context)

        self.controller.fake_action.assert_called_once_with(
                self.fake_context, **fakes.DICT_FAKE_PARAMS)

    def _compare_aws_xml(self, root_tag, xmlns, request_id, dict_data,
                         observed):
        # NOTE(ft): we cann't use matchers.XMLMatches since it makes comparison
        # based on the order of tags
        xml = etree.fromstring(observed)
        self.assertEqual(xmlns, xml.nsmap.get(None))
        observed_data = tools.parse_xml(observed)
        expected = {root_tag: tools.update_dict(dict_data,
                                                {'requestId': request_id})}
        self.assertThat(observed_data, matchers.DictMatches(expected))
