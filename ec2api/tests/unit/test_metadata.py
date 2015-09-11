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

import base64

import mock
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslotest import base as test_base
import six
import testtools
import webob

from ec2api import exception
from ec2api import metadata
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers


class ProxyTestCase(test_base.BaseTestCase):

    def setUp(self):
        super(ProxyTestCase, self).setUp()
        self.handler = metadata.MetadataRequestHandler()
        conf = self.useFixture(config_fixture.Config())
        conf.config(group='metadata',
                    nova_metadata_ip='9.9.9.9',
                    nova_metadata_port=8775,
                    nova_metadata_protocol='http',
                    nova_metadata_insecure=True,
                    auth_ca_cert=None,
                    nova_client_cert='nova_cert',
                    nova_client_priv_key='nova_priv_key',
                    metadata_proxy_shared_secret='secret')

    @mock.patch('ec2api.metadata.api.get_version_list')
    def test_callable(self, get_version_list):
        get_version_list.return_value = 'foo'
        request = webob.Request.blank('/')
        response = request.get_response(self.handler)
        self.assertEqual(200, response.status_int)
        self.assertEqual('foo', response.body.decode("utf-8"))

    @mock.patch('ec2api.metadata.api.get_version_list')
    def test_root(self, get_version_list):
        get_version_list.return_value = 'fake_version'
        request = webob.Request.blank('/')
        response = request.get_response(self.handler)
        self.assertEqual('fake_version', response.body.decode("utf-8"))
        response_ctype = response.headers['Content-Type']
        self.assertTrue(response_ctype.startswith("text/plain"))
        get_version_list.assert_called_with()

        request = webob.Request.blank('/foo/../')
        response = request.get_response(self.handler)
        self.assertEqual('fake_version', response.body.decode("utf-8"))

    @mock.patch.object(metadata.MetadataRequestHandler, '_get_metadata')
    @mock.patch.object(metadata.MetadataRequestHandler, '_get_requester')
    def test_version_root(self, get_requester, get_metadata):
        get_requester.return_value = mock.sentinel.requester
        get_metadata.return_value = 'fake'
        request = webob.Request.blank('/latest')
        response = request.get_response(self.handler)
        self.assertEqual('fake', response.body.decode("utf-8"))
        response_ctype = response.headers['Content-Type']
        self.assertTrue(response_ctype.startswith("text/plain"))
        get_requester.assert_called_with(mock.ANY)
        get_metadata.assert_called_with(['latest'], mock.sentinel.requester)

        get_metadata.side_effect = exception.EC2MetadataNotFound()
        request = webob.Request.blank('/latest')
        response = request.get_response(self.handler)
        self.assertEqual(404, response.status_int)

        with mock.patch.object(metadata, 'LOG') as log:
            get_metadata.side_effect = Exception()
            request = webob.Request.blank('/latest')
            response = request.get_response(self.handler)
            self.assertEqual(500, response.status_int)
            self.assertEqual(len(log.mock_calls), 2)

    def test_get_requester(self):
        expected = {'os_instance_id': mock.sentinel.os_instance_id,
                    'project_id': mock.sentinel.project_id,
                    'private_ip': mock.sentinel.private_ip}
        req = mock.Mock(headers={})

        @mock.patch('ec2api.metadata.api.get_os_instance_and_project_id')
        @mock.patch('ec2api.context.get_os_admin_context')
        @mock.patch.object(metadata.MetadataRequestHandler,
                           '_unpack_nova_network_request')
        def do_test1(unpack_request, get_context, get_ids):
            get_context.return_value = base.create_context(is_os_admin=True)
            unpack_request.return_value = mock.sentinel.private_ip
            get_ids.return_value = (mock.sentinel.os_instance_id,
                                    mock.sentinel.project_id)

            retval = self.handler._get_requester(req)
            self.assertEqual(expected, retval)
            get_context.assert_called_with()
            unpack_request.assert_called_with(req)
            get_ids.assert_called_with(get_context.return_value,
                                       mock.sentinel.private_ip)

        do_test1()

        req.headers['X-Instance-ID'] = mock.sentinel.os_instance_id

        @mock.patch.object(metadata.MetadataRequestHandler,
                           '_unpack_neutron_request')
        def do_test2(unpack_request):
            unpack_request.return_value = (mock.sentinel.os_instance_id,
                                           mock.sentinel.project_id,
                                           mock.sentinel.private_ip)

            retval = self.handler._get_requester(req)
            self.assertEqual(expected, retval)
            unpack_request.assert_called_with(req)

        do_test2()

        req.headers['X-Metadata-Provider'] = mock.sentinel.provider_id

        @mock.patch('ec2api.metadata.api.'
                    'get_os_instance_and_project_id_by_provider_id')
        @mock.patch('ec2api.context.get_os_admin_context')
        @mock.patch.object(metadata.MetadataRequestHandler,
                           '_unpack_nsx_request')
        def do_test3(unpack_request, get_context, get_ids):
            unpack_request.return_value = (mock.sentinel.provider_id,
                                           mock.sentinel.private_ip)
            get_context.return_value = base.create_context(is_os_admin=True)
            get_ids.return_value = (mock.sentinel.os_instance_id,
                                    mock.sentinel.project_id)

            retval = self.handler._get_requester(req)
            self.assertEqual(expected, retval)
            unpack_request.assert_called_with(req)
            get_context.assert_called_with()
            get_ids.assert_called_with(get_context.return_value,
                                       mock.sentinel.provider_id,
                                       mock.sentinel.private_ip)

        do_test3()

    @mock.patch('ec2api.metadata.api.get_metadata_item')
    @mock.patch('ec2api.context.get_os_admin_context')
    def test_get_metadata(self, get_context, get_metadata_item):
        get_context.return_value = base.create_context(is_os_admin=True)
        requester = {'os_instance_id': mock.sentinel.os_instance_id,
                     'project_id': mock.sentinel.project_id,
                     'private_ip': mock.sentinel.private_ip}
        get_metadata_item.return_value = 'fake_item'

        retval = self.handler._get_metadata(['fake_ver', 'fake_attr'],
                                            requester)
        self.assertEqual('fake_item', retval)
        get_context.assert_called_with()
        get_metadata_item.assert_called_with(
            get_context.return_value, ['fake_ver', 'fake_attr'],
            mock.sentinel.os_instance_id, mock.sentinel.private_ip)
        self.assertEqual(mock.sentinel.project_id,
                         get_context.return_value.project_id)

    @mock.patch.object(metadata.MetadataRequestHandler, '_proxy_request')
    def test_proxy_call(self, proxy):
        req = mock.Mock(path_info='/openstack')
        proxy.return_value = 'value'

        with mock.patch.object(metadata.MetadataRequestHandler,
                               '_get_requester'):
            retval = self.handler(req)
        self.assertEqual(retval, 'value')

    @mock.patch.object(metadata, 'LOG')
    @mock.patch.object(metadata.MetadataRequestHandler, '_proxy_request')
    def test_proxy_call_internal_server_error(self, proxy, log):
        req = mock.Mock(path_info='/openstack')
        proxy.side_effect = Exception()
        retval = self.handler(req)
        self.assertIsInstance(retval, webob.exc.HTTPInternalServerError)
        self.assertEqual(len(log.mock_calls), 2)

        proxy.side_effect = exception.EC2MetadataException()
        retval = self.handler(req)
        self.assertIsInstance(retval, webob.exc.HTTPInternalServerError)

    @mock.patch.object(metadata.MetadataRequestHandler, '_proxy_request')
    def test_proxy_call_no_instance(self, proxy):
        req = mock.Mock(path_info='/openstack')
        proxy.side_effect = exception.EC2MetadataNotFound()
        with mock.patch.object(metadata.MetadataRequestHandler,
                               '_get_requester'):
            retval = self.handler(req)
        self.assertIsInstance(retval, webob.exc.HTTPNotFound)

    @mock.patch.object(metadata.MetadataRequestHandler,
                       '_build_proxy_request_headers')
    def _proxy_request_test_helper(self, build_headers,
                                   response_code=200, method='GET'):
        hdrs = {'X-Forwarded-For': '8.8.8.8'}
        body = 'body'

        req = mock.Mock(path_info='/openstack', query_string='', headers=hdrs,
                        method=method, body=body)
        resp = mock.MagicMock(status=response_code)
        req.response = resp
        build_headers.return_value = hdrs
        with mock.patch('httplib2.Http') as mock_http:
            resp.__getitem__.return_value = "text/plain"
            mock_http.return_value.request.return_value = (resp, 'content')

            retval = self.handler._proxy_request(req, mock.sentinel.requester)
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
                    'http://9.9.9.9:8775/openstack',
                    method=method,
                    headers={
                        'X-Forwarded-For': '8.8.8.8',
                    },
                    body=body
                )]
            )
            build_headers.assert_called_once_with(mock.sentinel.requester)

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

    @mock.patch.object(metadata.MetadataRequestHandler, '_sign_instance_id')
    def test_build_proxy_request_headers(self, sign_instance_id):
        sign_instance_id.return_value = mock.sentinel.signed
        requester = {'os_instance_id': mock.sentinel.os_instance_id,
                     'project_id': mock.sentinel.project_id,
                     'private_ip': mock.sentinel.private_ip}
        result = self.handler._build_proxy_request_headers(requester)
        expected = {'X-Forwarded-For': mock.sentinel.private_ip,
                    'X-Instance-ID': mock.sentinel.os_instance_id,
                    'X-Tenant-ID': mock.sentinel.project_id,
                    'X-Instance-ID-Signature': mock.sentinel.signed}
        self.assertThat(result, matchers.DictMatches(expected))

    def test_sign_instance_id(self):
        self.assertEqual(
            '773ba44693c7553d6ee20f61ea5d2757a9a4f4a44d2841ae4e95b52e4cd62db4',
            self.handler._sign_instance_id('foo')
        )

    def test_unpack_nova_network_request(self):
        req = mock.Mock(remote_addr='fake_addr', headers={})

        self.assertEqual('fake_addr',
                         self.handler._unpack_nova_network_request(req))

        cfg.CONF.set_override('use_forwarded_for', True)
        self.assertEqual('fake_addr',
                         self.handler._unpack_nova_network_request(req))

        req.headers['X-Forwarded-For'] = 'fake_forwarded_for'
        self.assertEqual('fake_forwarded_for',
                         self.handler._unpack_nova_network_request(req))

        cfg.CONF.set_override('use_forwarded_for', False)
        self.assertEqual('fake_addr',
                         self.handler._unpack_nova_network_request(req))

    def test_unpack_neutron_request(self):
        sign = (
            '97e7709481495f1a3a589e5ee03f8b5d51a3e0196768e300c441b58fe0382f4d')
        req = mock.Mock(headers={'X-Instance-ID': 'fake_instance_id',
                                 'X-Tenant-ID': 'fake_project_id',
                                 'X-Forwarded-For': 'fake_instance_ip',
                                 'X-Instance-ID-Signature': sign})
        retval = self.handler._unpack_neutron_request(req)
        self.assertEqual(
            ('fake_instance_id', 'fake_project_id', 'fake_instance_ip'),
            retval)

        req.headers['X-Instance-ID-Signature'] = 'fake'
        self.assertRaises(webob.exc.HTTPForbidden,
                          self.handler._unpack_neutron_request, req)

        req.headers.pop('X-Instance-ID-Signature')
        self.assertRaises(webob.exc.HTTPForbidden,
                          self.handler._unpack_neutron_request, req)

        req.headers.pop('X-Tenant-ID')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.handler._unpack_neutron_request, req)

        req.headers.pop('X-Forwarded-For')
        self.assertRaises(exception.EC2MetadataInvalidAddress,
                          self.handler._unpack_neutron_request, req)

    def test_unpack_nsx_request(self):
        sign = (
            '344aa301e652d6c214c4f4a475a43c9f69d9f2d26d87e939c6bac3f21a9d2476')
        req = mock.Mock(headers={'X-Metadata-Provider': 'fake_provider_id',
                                 'X-Forwarded-For': 'fake_instance_ip',
                                 'X-Metadata-Provider-Signature': sign})
        retval = self.handler._unpack_nsx_request(req)
        self.assertEqual(('fake_provider_id', 'fake_instance_ip'), retval)

        req.headers['X-Forwarded-For'] = 'fake_instance_ip,fake_router_ip'
        retval = self.handler._unpack_nsx_request(req)
        self.assertEqual(('fake_provider_id', 'fake_instance_ip'), retval)

        req.headers['X-Metadata-Provider-Signature'] = 'fake'
        self.assertRaises(webob.exc.HTTPForbidden,
                          self.handler._unpack_nsx_request, req)

        req.headers.pop('X-Metadata-Provider-Signature')
        self.assertRaises(webob.exc.HTTPForbidden,
                          self.handler._unpack_nsx_request, req)

        with config_fixture.Config() as conf:
            conf.config(group='metadata',
                        metadata_proxy_shared_secret=None)
            retval = self.handler._unpack_nsx_request(req)
            self.assertEqual(('fake_provider_id', 'fake_instance_ip'), retval)

        req.headers.pop('X-Metadata-Provider')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.handler._unpack_nsx_request, req)

        req.headers.pop('X-Forwarded-For')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.handler._unpack_nsx_request, req)

    @mock.patch('ec2api.utils.constant_time_compare')
    def test_usage_of_constant_time_compare(self, constant_time_compare):
        sign = (
            '97e7709481495f1a3a589e5ee03f8b5d51a3e0196768e300c441b58fe0382f4d')
        req = mock.Mock(headers={'X-Instance-ID': 'fake_instance_id',
                                 'X-Tenant-ID': 'fake_project_id',
                                 'X-Forwarded-For': 'fake_instance_ip',
                                 'X-Instance-ID-Signature': sign})
        self.handler._unpack_neutron_request(req)
        self.assertEqual(1, constant_time_compare.call_count)

    @mock.patch('novaclient.client.Client')
    @mock.patch('ec2api.db.api.IMPL')
    @mock.patch('ec2api.metadata.api.instance_api')
    def test_get_metadata_items(self, instance_api, db_api, nova):
        FAKE_USER_DATA = u'fake_user_data-' + six.unichr(1071)
        nova.return_value.fixed_ips.get.return_value = (
                mock.Mock(hostname='fake_name'))
        nova.return_value.servers.list.return_value = [
            fakes.OSInstance(fakes.OS_INSTANCE_1)]
        keypair = mock.Mock(public_key=fakes.PUBLIC_KEY_KEY_PAIR)
        keypair.configure_mock(name=fakes.NAME_KEY_PAIR)
        nova.return_value.keypairs.get.return_value = keypair
        db_api.get_items_ids.return_value = [
                (fakes.ID_EC2_INSTANCE_1, fakes.ID_OS_INSTANCE_1)]
        instance_api.describe_instances.return_value = {
               'reservationSet': [fakes.EC2_RESERVATION_1]}
        userDataValue = base64.b64encode(FAKE_USER_DATA.encode('utf-8'))
        instance_api.describe_instance_attribute.return_value = {
                'instanceId': fakes.ID_EC2_INSTANCE_1,
                'userData': {'value': userDataValue}}

        def _test_metadata_path(relpath):
            # recursively confirm a http 200 from all meta-data elements
            # available at relpath.
            request = webob.Request.blank(
                    relpath, remote_addr=fakes.IP_NETWORK_INTERFACE_2)
            response = request.get_response(self.handler)
            self.assertEqual(200, response.status_int)
            for item in response.body.decode("utf-8").split('\n'):
                if 'public-keys' in relpath:
                    # meta-data/public-keys/0=keyname refers to
                    # meta-data/public-keys/0
                    item = item.split('=')[0]
                if item.endswith('/'):
                    path = relpath + '/' + item
                    _test_metadata_path(path)
                    continue

                path = relpath + '/' + item
                request = webob.Request.blank(
                        path, remote_addr=fakes.IP_NETWORK_INTERFACE_2)
                response = request.get_response(self.handler)
                self.assertEqual(200, response.status_int, message=path)

        _test_metadata_path('/latest')
