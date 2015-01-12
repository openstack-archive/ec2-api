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

import mock
from oslo.config import cfg
from oslotest import base as test_base
import testtools
import webob

from ec2api import metadata
from ec2api.tests import matchers


class ProxyTestCase(test_base.BaseTestCase):

    def setUp(self):
        super(ProxyTestCase, self).setUp()
        self.handler = metadata.MetadataRequestHandler()
        conf = cfg.CONF
        self.addCleanup(conf.reset)
        conf.set_override('nova_metadata_ip', '9.9.9.9', group='metadata')
        conf.set_override('nova_metadata_port', 8775, group='metadata')
        conf.set_override('nova_metadata_protocol', 'http', group='metadata')
        conf.set_override('nova_metadata_insecure', True, group='metadata')
        conf.set_override('auth_ca_cert', None, group='metadata')
        conf.set_override('nova_client_cert', 'nova_cert', group='metadata')
        conf.set_override('nova_client_priv_key', 'nova_priv_key',
                          group='metadata')
        conf.set_override('admin_user', 'admin', group='metadata')
        conf.set_override('admin_password', 'password', group='metadata')
        conf.set_override('admin_tenant_name', 'service', group='metadata')
        conf.set_override('metadata_proxy_shared_secret', 'secret',
                          group='metadata')

    @mock.patch.object(metadata.MetadataRequestHandler, '_proxy_request')
    def test_call(self, proxy):
        req = mock.Mock()
        proxy.return_value = 'value'

        retval = self.handler(req)
        self.assertEqual(retval, 'value')

    @mock.patch.object(metadata, 'LOG')
    @mock.patch.object(metadata.MetadataRequestHandler, '_proxy_request')
    def test_call_internal_server_error(self, proxy, log):
        req = mock.Mock()
        proxy.side_effect = Exception
        retval = self.handler(req)
        self.assertIsInstance(retval, webob.exc.HTTPInternalServerError)
        self.assertEqual(len(log.mock_calls), 2)

    @mock.patch.object(metadata.MetadataRequestHandler,
                       '_build_proxy_request_headers')
    def _proxy_request_test_helper(self, build_headers,
                                   response_code=200, method='GET'):
        hdrs = {'X-Forwarded-For': '8.8.8.8'}
        body = 'body'

        req = mock.Mock(path_info='/the_path', query_string='', headers=hdrs,
                        method=method, body=body)
        resp = mock.MagicMock(status=response_code)
        req.response = resp
        build_headers.return_value = hdrs
        with mock.patch('httplib2.Http') as mock_http:
            resp.__getitem__.return_value = "text/plain"
            mock_http.return_value.request.return_value = (resp, 'content')

            retval = self.handler._proxy_request(req)
            mock_http.assert_called_once_with(
                ca_certs=None, disable_ssl_certificate_validation=True)
            mock_http.assert_has_calls([
                mock.call().add_certificate(
                    cfg.CONF.metadata.nova_client_priv_key,
                    cfg.CONF.metadata.nova_client_cert,
                    "%s:%s" % (cfg.CONF.metadata.nova_metadata_ip,
                               cfg.CONF.metadata.nova_metadata_port)
                ),
                mock.call().request(
                    'http://9.9.9.9:8775/the_path',
                    method=method,
                    headers={
                        'X-Forwarded-For': '8.8.8.8',
                    },
                    body=body
                )]
            )
            build_headers.assert_called_once_with(req)

            return retval

    def test_proxy_request_post(self):
        response = self._proxy_request_test_helper(method='POST')
        self.assertEqual(response.content_type, "text/plain")
        self.assertEqual(response.body, 'content')

    def test_proxy_request_200(self):
        response = self._proxy_request_test_helper(response_code=200)
        self.assertEqual(response.content_type, "text/plain")
        self.assertEqual(response.body, 'content')

    def test_proxy_request_400(self):
        self.assertIsInstance(
            self._proxy_request_test_helper(response_code=400),
            webob.exc.HTTPBadRequest)

    def test_proxy_request_403(self):
        self.assertIsInstance(
            self._proxy_request_test_helper(response_code=403),
            webob.exc.HTTPForbidden)

    def test_proxy_request_404(self):
        self.assertIsInstance(
            self._proxy_request_test_helper(response_code=404),
            webob.exc.HTTPNotFound)

    def test_proxy_request_409(self):
        self.assertIsInstance(
            self._proxy_request_test_helper(response_code=409),
            webob.exc.HTTPConflict)

    def test_proxy_request_500(self):
        self.assertIsInstance(
            self._proxy_request_test_helper(response_code=500),
            webob.exc.HTTPInternalServerError)

    def test_proxy_request_other_code(self):
        with testtools.ExpectedException(Exception):
            self._proxy_request_test_helper(response_code=302)

    @mock.patch.object(metadata.MetadataRequestHandler,
                       '_build_proxy_request_headers')
    def test_proxy_request_no_headers(self, build_headers):
        build_headers.return_value = None
        self.assertIsInstance(
            self.handler._proxy_request('fake_request'),
            webob.exc.HTTPNotFound)
        build_headers.assert_called_once_with('fake_request')

    @mock.patch.object(metadata.MetadataRequestHandler, '_sign_instance_id')
    @mock.patch.object(metadata.MetadataRequestHandler, '_get_context')
    @mock.patch.object(metadata.MetadataRequestHandler, '_get_instance_ip')
    def test_build_proxy_request_headers(self, get_instance_ip, get_context,
                                         sign_instance_id):
        req = mock.Mock(headers={})

        req.headers = {'X-Instance-ID': 'fake_instance_id',
                       'fake_key': 'fake_value'}

        self.assertThat(self.handler._build_proxy_request_headers(req),
                        matchers.DictMatches(req.headers))

        req.headers = {'fake_key': 'fake_value'}
        get_instance_ip.return_value = 'fake_instance_ip'
        get_context.return_value = 'fake_context'
        sign_instance_id.return_value = 'signed'

        with mock.patch('ec2api.metadata.api.'
                        'get_instance_and_project_id') as get_ids:

            get_ids.return_value = None, None
            self.assertIsNone(self.handler._build_proxy_request_headers(req))

            get_ids.return_value = ('fake_instance_id', 'fake_project_id')
            self.assertThat(self.handler._build_proxy_request_headers(req),
                            matchers.DictMatches(
                                {'X-Forwarded-For': 'fake_instance_ip',
                                 'X-Instance-ID': 'fake_instance_id',
                                 'X-Tenant-ID': 'fake_project_id',
                                 'X-Instance-ID-Signature': 'signed'}))
            get_instance_ip.assert_called_with(req)
            get_context.assert_called_with()
            sign_instance_id.assert_called_with('fake_instance_id')
            get_ids.assert_called_with('fake_context', 'fake_instance_ip')

    def test_sign_instance_id(self):
        self.assertEqual(
            self.handler._sign_instance_id('foo'),
            '773ba44693c7553d6ee20f61ea5d2757a9a4f4a44d2841ae4e95b52e4cd62db4'
        )

    def test_get_instance_ip(self):
        req = mock.Mock(remote_addr='fake_addr', headers={})

        self.assertEqual('fake_addr', self.handler._get_instance_ip(req))

        cfg.CONF.set_override('use_forwarded_for', True)
        self.assertEqual('fake_addr', self.handler._get_instance_ip(req))

        req.headers['X-Forwarded-For'] = 'fake_forwarded_for'
        self.assertEqual('fake_forwarded_for',
                         self.handler._get_instance_ip(req))

        cfg.CONF.set_override('use_forwarded_for', False)
        self.assertEqual('fake_addr', self.handler._get_instance_ip(req))

    @mock.patch('keystoneclient.v2_0.client.Client')
    def test_get_context(self, keystone):
        service_catalog = mock.MagicMock()
        service_catalog.get_data.return_value = 'fake_service_catalog'
        keystone.return_value = mock.Mock(auth_user_id='fake_user_id',
                                          auth_tenant_id='fake_project_id',
                                          auth_token='fake_token',
                                          service_catalog=service_catalog)
        context = self.handler._get_context()
        self.assertEqual('fake_user_id', context.user_id)
        self.assertEqual('fake_project_id', context.project_id)
        self.assertEqual('fake_token', context.auth_token)
        self.assertEqual('fake_service_catalog', context.service_catalog)
        conf = cfg.CONF
        keystone.assert_called_with(
                username=conf.metadata.admin_user,
                password=conf.metadata.admin_password,
                tenant_name=conf.metadata.admin_tenant_name,
                auth_url=conf.keystone_url)
