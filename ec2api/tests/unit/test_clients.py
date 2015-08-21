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

import fixtures
import mock
from novaclient import exceptions as nova_exception

from ec2api.api import clients
from ec2api.tests.unit import base


class ClientsTestCase(base.BaseTestCase):

    def setUp(self):
        reload(clients)
        super(ClientsTestCase, self).setUp()
        self.configure(keystone_url='keystone_url')

    @mock.patch.object(clients, '_get_nova_api_version', return_value='2.3')
    @mock.patch('novaclient.client.Client')
    def test_nova(self, nova, get_api_version):
        context = mock.NonCallableMock(
            auth_token='fake_token',
            service_catalog=[{'type': 'compute',
                              'endpoints': [{'publicURL': 'nova_url'}]}])

        # test normal flow with get_api_version call
        res = clients.nova(context)
        self.assertEqual(nova.return_value, res)
        nova.assert_called_with(
            '2.3', bypass_url='nova_url', http_log_debug=False,
            auth_url='keystone_url', auth_token='fake_token')
        get_api_version.assert_called_once_with(context)

        # test logging with debug option and no get_api_version call
        get_api_version.reset_mock()
        self.configure(debug=True)
        clients.nova(context)
        nova.assert_called_with(
            '2.3', bypass_url='nova_url', http_log_debug=True,
            auth_url='keystone_url', auth_token='fake_token')
        self.assertFalse(get_api_version.called)
        self.configure(debug=False)

        # test CONF.nova_service_type is used
        context.service_catalog.append({
            'type': 'compute_legacy',
            'endpoints': [{'publicURL': 'nova_legacy_url'}]})
        self.configure(nova_service_type='compute_legacy')
        clients.nova(context)
        nova.assert_called_with(
            '2.3', bypass_url='nova_legacy_url', http_log_debug=False,
            auth_url='keystone_url', auth_token='fake_token')

    @mock.patch.object(clients, '_url_for')
    @mock.patch('novaclient.client.Client')
    def test_get_api_version(self, nova, url_for):
        context = mock.NonCallableMock(auth_token='fake_token')
        v2 = mock.NonCallableMock()
        v2.configure_mock(id='v2',
                          version='',
                          links=[{'href': 'http://host:port/path/v2/'}])
        v2_1 = mock.NonCallableMock()
        v2_1.configure_mock(id='v2.1',
                            version='2.11',
                            links=[{'href': 'http://host:port/path/v2.1/'}])

        # test normal flow
        url_for.return_value = 'http://host:port/path/v2.1/projectid'
        nova.return_value.versions.get_current.return_value = v2_1
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual(clients.REQUIRED_NOVA_API_MICROVERSION, res)
        url_for.assert_called_with(context, service_type='compute')
        nova.assert_called_with('2.1', http_log_debug=False,
                                bypass_url=url_for.return_value)
        nova.return_value.versions.get_current.assert_called_with()
        self.assertTrue(logs.output.startswith('[INFO]'))

        # test normal flow with debug log and custom service_type
        self.configure(debug=True)
        self.configure(nova_service_type='compute')
        clients._get_nova_api_version(context)
        url_for.assert_called_with(context, service_type='compute')
        nova.assert_called_with('2.1', http_log_debug=True,
                                bypass_url=url_for.return_value)
        self.configure(debug=False)
        self.configure(nova_service_type='compute')

        # test Nova doesn't supprt required microversion
        v2_1.version = '2.2'
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual('2.2', res)
        self.assertTrue(logs.output.startswith('[WARNING]'))

        # test service type is not v2.1
        nova.return_value.versions.get_current.return_value = v2
        url_for.return_value = 'http://host:port/path/v2/projectid'
        self.configure(nova_service_type='compute_legacy')
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual('2', res)
        self.assertTrue(logs.output.startswith('[WARNING]'))
        self.configure(nova_service_type='compute')

        # test service url is not found in version list
        nova.return_value.versions.get_current.return_value = None
        url_for.return_value = 'fake_url'
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual(clients.REQUIRED_NOVA_API_MICROVERSION, res)
        self.assertTrue(logs.output.startswith('[WARNING]'))

        # test switching to v2 client
        nova.side_effect = nova_exception.UnsupportedVersion()
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual('2', res)
        self.assertTrue(logs.output.startswith('[WARNING]'))

    @mock.patch('neutronclient.v2_0.client.Client')
    def test_neutron(self, neutron):
        context = mock.NonCallableMock(
            auth_token='fake_token',
            service_catalog=[{'type': 'network',
                              'endpoints': [{'publicURL': 'neutron_url'}]}])
        res = clients.neutron(context)
        self.assertEqual(neutron.return_value, res)
        neutron.assert_called_with(
            auth_url='keystone_url', service_type='network',
            token='fake_token', endpoint_url='neutron_url')

    @mock.patch('glanceclient.client.Client')
    def test_glance(self, glance):
        context = mock.NonCallableMock(
            auth_token='fake_token',
            service_catalog=[{'type': 'image',
                              'endpoints': [{'publicURL': 'glance_url'}]}])
        res = clients.glance(context)
        self.assertEqual(glance.return_value, res)
        glance.assert_called_with(
            '1', auth_url='keystone_url', service_type='image',
            token='fake_token', endpoint='glance_url')

    @mock.patch('cinderclient.client.Client')
    def test_cinder(self, cinder):
        # test normal flow
        context = mock.NonCallableMock(
            auth_token='fake_token',
            service_catalog=[{'type': 'volume',
                              'endpoints': [{'publicURL': 'cinder_url'}]}])
        res = clients.cinder(context)
        self.assertEqual(cinder.return_value, res)
        cinder.assert_called_with(
            '1', auth_url='keystone_url', service_type='volume',
            username=None, api_key=None, http_log_debug=False)
        self.assertEqual('fake_token', res.client.auth_token)
        self.assertEqual('cinder_url', res.client.management_url)

        # test logging with debug option
        self.configure(debug=True)
        clients.cinder(context)
        cinder.assert_called_with(
            '1', auth_url='keystone_url', service_type='volume',
            username=None, api_key=None, http_log_debug=True)

    @mock.patch('ec2api.context.get_keystone_client_class',
                return_value=mock.Mock(return_value=mock.Mock()))
    def test_keystone(self, keystone_client_class):
        context = mock.NonCallableMock(
            auth_token='fake_token',
            project_id='fake_project')
        res = clients.keystone(context)
        self.assertEqual(keystone_client_class.return_value.return_value, res)
        keystone_client_class.return_value.assert_called_with(
            auth_url='keystone_url', token='fake_token',
            tenant_id='fake_project', project_id='fake_project')
