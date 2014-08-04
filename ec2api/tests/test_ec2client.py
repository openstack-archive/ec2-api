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
import time

import mock
from oslotest import base as test_base

from ec2api.api import ec2client
from ec2api import exception
from ec2api.tests import fakes_request_response as fakes
from ec2api.tests import matchers


class EC2RequesterTestCase(test_base.BaseTestCase):

    fake_context_class = collections.namedtuple('FakeContext', ['access_key',
                                                                'secret_key'])

    def setUp(self):
        super(EC2RequesterTestCase, self).setUp()
        httplib2_patcher = mock.patch('ec2api.api.ec2client.httplib2')
        self.httplib2 = httplib2_patcher.start()
        self.addCleanup(httplib2_patcher.stop)
        gmtime_patcher = mock.patch('ec2api.api.ec2client.time.gmtime')
        self.gmtime = gmtime_patcher.start()
        self.addCleanup(gmtime_patcher.stop)

    def test_post_request(self):
        http_obj = self.httplib2.Http.return_value
        http_obj.request.return_value = ('fake_response', 'fake_context',)
        self.gmtime.return_value = time.struct_time((2014, 6, 13,
                                                     7, 43, 54, 4, 164, 0,))

        requester = ec2client.EC2Requester('fake_v1', 'POST')
        requester._ec2_url = 'http://fake.host.com:1234/fake_Service'
        context = self.fake_context_class('caeafa52dda845d78a54786aa2ad355b',
                                          'f889ec080e094a92badb6f6ba0253393')
        result = requester.request(context, 'FakeAction',
                                   {'Arg1': 'Val1', 'Arg2': 'Val2'})
        http_obj.request.assert_called_once_with(
            'http://fake.host.com:1234/fake_Service',
            'POST',
            body='AWSAccessKeyId=caeafa52dda845d78a54786aa2ad355b&'
            'Action=FakeAction&Arg1=Val1&Arg2=Val2&Signature='
            'uBRxsBHetogWlgv%2FHJnJLK0vBMEChm1LFX%2BH9U1kjHo%3D&'
            'SignatureMethod=HmacSHA256&SignatureVersion=2&'
            'Timestamp=2014-06-13T07%3A43%3A54Z&Version=fake_v1',
            headers={'content-type': 'application/x-www-form-urlencoded',
                     'connection': 'close'})
        self.assertEqual(('fake_response', 'fake_context',), result)

    def test_get_request(self):
        http_obj = self.httplib2.Http.return_value
        http_obj.request.return_value = ('fake_response', 'fake_context',)
        self.gmtime.return_value = time.struct_time((2014, 6, 14,
                                                     10, 6, 16, 5, 165, 0,))
        requester = ec2client.EC2Requester('fake_v1', 'GET')
        requester._ec2_url = 'http://fake.host.com'
        context = self.fake_context_class('c1ba55bbcaeb4b41bc9a6d5344392825',
                                          '24aaf70906fe4d799f6360d7cd6320ba')
        result = requester.request(context, 'FakeAction',
                                   {'Arg1': 'Val1', 'Arg2': 'Val2'})
        http_obj.request.assert_called_once_with(
            'http://fake.host.com?'
            'AWSAccessKeyId=c1ba55bbcaeb4b41bc9a6d5344392825&'
            'Action=FakeAction&Arg1=Val1&Arg2=Val2&Signature='
            'puCc5v7kjOLibLTaT5bDp%2FPcgtbWMGt3kvh54z%2BpedE%3D&'
            'SignatureMethod=HmacSHA256&SignatureVersion=2&'
            'Timestamp=2014-06-14T10%3A06%3A16Z&Version=fake_v1',
            'GET',
            body=None,
            headers={'content-type': 'application/x-www-form-urlencoded',
                     'connection': 'close'})
        self.assertEqual(('fake_response', 'fake_context',), result)


class EC2ClientTestCase(test_base.BaseTestCase):

    fake_response_class = collections.namedtuple('response', ['status'])

    def test_ec2_xml_to_json_on_fake_result(self):
        json = ec2client.EC2Client._parse_xml(fakes.XML_FAKE_RESULT)
        self.assertIsInstance(json, dict)
        self.assertThat(fakes.DICT_FAKE_RESULT, matchers.DictMatches(json))

    def test_ec2_xml_to_json_on_single_result(self):
        json = ec2client.EC2Client._parse_xml(fakes.XML_SINGLE_RESULT)
        self.assertIsInstance(json, dict)
        self.assertThat(fakes.DICT_SINGLE_RESULT, matchers.DictMatches(json))

    def test_ec2_xml_to_json_on_result_set(self):
        json = ec2client.EC2Client._parse_xml(fakes.XML_RESULT_SET)
        self.assertIsInstance(json, dict)
        self.assertThat(fakes.DICT_RESULT_SET, matchers.DictMatches(json))

    def test_ec2_xml_to_json_on_empty_result_set(self):
        json = ec2client.EC2Client._parse_xml(fakes.XML_EMPTY_RESULT_SET)
        self.assertIsInstance(json, dict)
        self.assertThat(fakes.DICT_EMPTY_RESULT_SET,
                        matchers.DictMatches(json))

    def test_ec2_xml_to_json_on_error(self):
        json = ec2client.EC2Client._parse_xml(fakes.XML_ERROR)
        self.assertIsInstance(json, dict)
        self.assertThat(fakes.DICT_ERROR, matchers.DictMatches(json))

    def test_process_response_on_data_result(self):
        response = self.fake_response_class(200)
        json = ec2client.EC2Client._process_response(response,
                                                     fakes.XML_FAKE_RESULT)
        self.assertThat(json,
                        matchers.DictMatches(fakes.DICT_FAKE_RESULT_DATA))

    def test_process_response_on_ok_result(self):
        response = self.fake_response_class(200)
        result = ec2client.EC2Client._process_response(
            response, fakes.XML_SILENT_OPERATIN_RESULT)
        self.assertEqual(True, result)

    def test_process_response_on_error(self):
        response = self.fake_response_class(400)
        try:
            ec2client.EC2Client._process_response(response, fakes.XML_ERROR)
        except exception.EC2ServerError as ex:
            self.assertEqual(response, ex.response)
            self.assertEqual(fakes.XML_ERROR, ex.content)
        except Exception as ex:
            self.fail('%s was raised instead of '
                      'ec2api.exception.EC2ServerError' % str(ex))
        else:
            self.fail('No ec2api.exception.EC2ServerError was raised')

    def test_build_params(self):
        ec2_params = ec2client.EC2Client._build_params(
            **fakes.DICT_FAKE_PARAMS)
        self.assertThat(ec2_params,
                        matchers.DictMatches(fakes.DOTTED_FAKE_PARAMS))

    @mock.patch('ec2api.api.ec2client.EC2Requester')
    def test_call_action(self, requester_class):
        requester = requester_class.return_value
        fake_response = self.fake_response_class(200)
        requester.request.return_value = (fake_response,
                                          fakes.XML_FAKE_RESULT,)

        fake_context_class = collections.namedtuple('FakeContext',
                                                    ['api_version'])
        fake_context = fake_context_class('fake_v1')

        ec2 = ec2client.ec2client(fake_context)
        json = ec2.fake_action(fake_int=1234, fake_str='fake')

        self.assertThat(json,
                        matchers.DictMatches(fakes.DICT_FAKE_RESULT_DATA))
        requester_class.assert_called_once_with('fake_v1', 'POST')
        requester.request.assert_called_once_with(
            fake_context, 'FakeAction',
            {'FakeInt': '1234', 'FakeStr': 'fake'})
