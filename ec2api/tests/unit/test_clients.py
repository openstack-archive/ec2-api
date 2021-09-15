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

import importlib
from unittest import mock

import fixtures

from ec2api.api import clients
from ec2api.tests.unit import base


class ClientsTestCase(base.BaseTestCase):

    def setUp(self):
        importlib.reload(clients)
        super(ClientsTestCase, self).setUp()

    @mock.patch.object(clients, '_get_nova_api_version', return_value='2.3')
    @mock.patch('novaclient.client.Client')
    def test_nova(self, nova, get_api_version):
        context = mock.NonCallableMock(session=mock.sentinel.session)

        # test normal flow with get_api_version call
        res = clients.nova(context)
        self.assertEqual(nova.return_value, res)
        nova.assert_called_with('2.3', service_type='compute',
                                session=mock.sentinel.session)
        get_api_version.assert_called_once_with(context)

        # test CONF.nova_service_type is used
        self.configure(nova_service_type='compute_legacy')
        clients.nova(context)
        nova.assert_called_with('2.3', service_type='compute_legacy',
                                session=mock.sentinel.session)

    @mock.patch('novaclient.client.Client')
    def test_get_api_version(self, nova):
        context = mock.NonCallableMock(session=mock.sentinel.session)
        v2 = mock.NonCallableMock()
        v2.configure_mock(id='v2',
                          version='',
                          links=[{'href': 'http://host:port/path/v2/'}])
        v2_1 = mock.NonCallableMock()
        v2_1.configure_mock(id='v2.1',
                            version='2.40',
                            links=[{'href': 'http://host:port/path/v2.1/'}])

        # test normal flow
        nova.return_value.versions.get_current.return_value = v2_1
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual(clients.REQUIRED_NOVA_API_MICROVERSION, res)
        nova.assert_called_with('2.1', service_type='compute',
                                session=mock.sentinel.session)
        nova.return_value.versions.get_current.assert_called_with()
        self.assertTrue(logs.output.startswith('[INFO]'))

        # test Nova doesn't supprt required microversion
        v2_1.version = '2.2'
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual('2.2', res)
        self.assertTrue(logs.output.startswith('[WARNING]'))

        # test service type is not v2.1
        nova.return_value.versions.get_current.return_value = v2
        self.configure(nova_service_type='compute_legacy')
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual('2', res)
        self.assertTrue(logs.output.startswith('[WARNING]'))
        self.configure(nova_service_type='compute')

        # test service url is not found in version list
        nova.return_value.versions.get_current.return_value = None
        with fixtures.LoggerFixture(
                format='[%(levelname)s] %(message)s') as logs:
            res = clients._get_nova_api_version(context)
        self.assertEqual(clients.REQUIRED_NOVA_API_MICROVERSION, res)
        self.assertTrue(logs.output.startswith('[WARNING]'))

    @mock.patch('neutronclient.v2_0.client.Client')
    def test_neutron(self, neutron):
        context = mock.NonCallableMock(session=mock.sentinel.session)
        res = clients.neutron(context)
        self.assertEqual(neutron.return_value, res)
        neutron.assert_called_with(service_type='network',
                                   session=mock.sentinel.session)

    @mock.patch('glanceclient.client.Client')
    def test_glance(self, glance):
        context = mock.NonCallableMock(session=mock.sentinel.session)
        res = clients.glance(context)
        self.assertEqual(glance.return_value, res)
        glance.assert_called_with(version='2', service_type='image',
                                  session=mock.sentinel.session)

    @mock.patch('cinderclient.client.Client')
    def test_cinder(self, cinder):
        # test normal flow
        context = mock.NonCallableMock(session=mock.sentinel.session)
        res = clients.cinder(context)
        self.assertEqual(cinder.return_value, res)
        cinder.assert_called_with('3', service_type='volumev3',
                                  session=mock.sentinel.session)

    @mock.patch('keystoneclient.client.Client')
    def test_keystone(self, keystone):
        context = mock.NonCallableMock(session=mock.sentinel.session)
        res = clients.keystone(context)
        self.assertEqual(keystone.return_value, res)
        keystone.assert_called_with(auth_url='v3',
                                    session=mock.sentinel.session)
