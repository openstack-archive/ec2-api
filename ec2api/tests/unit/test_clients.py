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
from oslo_config import fixture as config_fixture
from oslotest import base as test_base

from ec2api.api import clients


class ClientsTestCase(test_base.BaseTestCase):

    def setUp(self):
        super(ClientsTestCase, self).setUp()

        conf = self.useFixture(config_fixture.Config())
        conf.config(keystone_url='keystone_url')

    @mock.patch('novaclient.client.Client')
    def test_nova(self, nova):
        reload(clients)

        # test normal flow
        context = mock.Mock(
            auth_token='fake_token',
            service_catalog=[{'type': 'computev21',
                              'endpoints': [{'publicURL': 'novav21_url'}]}])
        with fixtures.LoggerFixture() as logs:
            res = clients.nova(context)
        self.assertEqual(nova.return_value, res)
        nova.assert_called_with(
            '2.3', bypass_url='novav21_url', cacert=None, insecure=False,
            auth_url='keystone_url', auth_token='fake_token',
            username=None, api_key=None, project_id=None)
        self.assertEqual(0, len(logs.output))

        # test switching to v2 client
        nova.side_effect = [nova_exception.UnsupportedVersion(), 'v2_client']
        with fixtures.LoggerFixture() as logs:
            res = clients.nova(context)
        self.assertEqual('v2_client', res)
        nova.assert_called_with(
            '2', bypass_url='novav21_url', cacert=None, insecure=False,
            auth_url='keystone_url', auth_token='fake_token',
            username=None, api_key=None, project_id=None)
        self.assertNotEqual(0, len(logs.output))

        # test raising of an exception if v2 client is not supported as well
        nova.side_effect = nova_exception.UnsupportedVersion()
        self.assertRaises(nova_exception.UnsupportedVersion,
                          clients.nova, context)

        nova.side_effect = None
        reload(clients)

        # test switching to 'compute' service type
        context.service_catalog = [{'type': 'compute',
                                    'endpoints': [{'publicURL': 'nova_url'}]}]
        with fixtures.LoggerFixture() as logs:
            res = clients.nova(context)
        nova.assert_called_with(
            '2.3', bypass_url='nova_url', cacert=None, insecure=False,
            auth_url='keystone_url', auth_token='fake_token',
            username=None, api_key=None, project_id=None)
        self.assertNotEqual(0, len(logs.output))

        # test behavior if 'compute' service type is not found as well
        context.service_catalog = [{'type': 'fake'}]
        clients.nova(context)
        nova.assert_called_with(
            '2.3', bypass_url=None, cacert=None, insecure=False,
            auth_url='keystone_url', auth_token='fake_token',
            username=None, api_key=None, project_id=None)

    @mock.patch('neutronclient.v2_0.client.Client')
    def test_neutron(self, neutron):
        context = mock.Mock(
            auth_token='fake_token',
            service_catalog=[{'type': 'network',
                              'endpoints': [{'publicURL': 'neutron_url'}]}])
        res = clients.neutron(context)
        self.assertEqual(neutron.return_value, res)
        neutron.assert_called_with(
            auth_url='keystone_url', cacert=None, service_type='network',
            insecure=False, token='fake_token', endpoint_url='neutron_url')

    @mock.patch('glanceclient.client.Client')
    def test_glance(self, glance):
        context = mock.Mock(
            auth_token='fake_token',
            service_catalog=[{'type': 'image',
                              'endpoints': [{'publicURL': 'glance_url'}]}])
        res = clients.glance(context)
        self.assertEqual(glance.return_value, res)
        glance.assert_called_with(
            '1', auth_url='keystone_url', service_type='image',
            token='fake_token', cacert=None, endpoint='glance_url',
            insecure=False)

    @mock.patch('cinderclient.client.Client')
    def test_cinder(self, cinder):
        context = mock.Mock(
            auth_token='fake_token',
            service_catalog=[{'type': 'volume',
                              'endpoints': [{'publicURL': 'cinder_url'}]}])
        res = clients.cinder(context)
        self.assertEqual(cinder.return_value, res)
        cinder.assert_called_with(
            '1', auth_url='keystone_url', cacert=None, insecure=False,
            service_type='volume', username=None, api_key=None)
        self.assertEqual('fake_token', res.client.auth_token)
        self.assertEqual('cinder_url', res.client.management_url)

    @mock.patch('ec2api.context.get_keystone_client_class',
                return_value=mock.Mock(return_value=mock.Mock()))
    def test_keystone(self, keystone_client_class):
        context = mock.Mock(
            auth_token='fake_token',
            project_id='fake_project')
        res = clients.keystone(context)
        self.assertEqual(keystone_client_class.return_value.return_value, res)
        keystone_client_class.return_value.assert_called_with(
            auth_url='keystone_url', cacert=None, insecure=False,
            token='fake_token', tenant_id='fake_project',
            project_id='fake_project')
