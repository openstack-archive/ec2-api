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

from keystoneclient.v2_0 import client as keystone_client_v2
from keystoneclient.v3 import client as keystone_client_v3
import mock
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslotest import base as test_base

from ec2api import context as ec2_context
from ec2api import exception

cfg.CONF.import_opt('keystone_url', 'ec2api.api')


class ContextTestCase(test_base.BaseTestCase):

    def setUp(self):
        super(ContextTestCase, self).setUp()
        conf = config_fixture.Config()
        conf.config(admin_user='admin',
                    admin_password='password',
                    admin_tenant_name='service')

    @mock.patch('keystoneclient.v2_0.client.Client')
    def test_get_os_admin_context(self, keystone):
        service_catalog = mock.Mock()
        service_catalog.get_data.return_value = 'fake_service_catalog'
        ec2_context._keystone_client_class = mock.Mock(
            return_value=mock.Mock(
                auth_user_id='fake_user_id',
                auth_tenant_id='fake_project_id',
                auth_token='fake_token',
                service_catalog=service_catalog))
        context = ec2_context.get_os_admin_context()
        self.assertEqual('fake_user_id', context.user_id)
        self.assertEqual('fake_project_id', context.project_id)
        self.assertEqual('fake_token', context.auth_token)
        self.assertEqual('fake_service_catalog', context.service_catalog)
        self.assertTrue(context.is_os_admin)
        conf = cfg.CONF
        ec2_context._keystone_client_class.assert_called_once_with(
            username=conf.admin_user,
            password=conf.admin_password,
            tenant_name=conf.admin_tenant_name,
            project_name=conf.admin_tenant_name,
            auth_url=conf.keystone_url,
            cacert=conf.ssl_ca_file,
            insecure=conf.ssl_insecure)
        service_catalog.get_data.assert_called_once_with()

        keystone.reset_mock()
        self.assertEqual(context, ec2_context.get_os_admin_context())
        self.assertFalse(keystone.called)

    @mock.patch('keystoneclient.client.Client')
    def test_get_keystone_client_class(self, client):
        client.return_value = mock.MagicMock(spec=keystone_client_v2.Client)
        ec2_context._keystone_client_class = None
        client_class = ec2_context.get_keystone_client_class()
        client.assert_called_once_with(auth_url='http://localhost:5000/v2.0',
                                       cacert=None, insecure=False)
        self.assertEqual(keystone_client_v2.Client, client_class)
        client.reset_mock()

        client.return_value = mock.MagicMock(spec=keystone_client_v3.Client)
        ec2_context._keystone_client_class = None
        client_class = ec2_context.get_keystone_client_class()
        client.assert_called_once_with(auth_url='http://localhost:5000/v2.0',
                                       cacert=None, insecure=False)
        self.assertEqual(keystone_client_v3.Client, client_class)
        client.reset_mock()

        client.return_value = mock.MagicMock()
        ec2_context._keystone_client_class = None
        self.assertRaises(exception.EC2KeystoneDiscoverFailure,
                          ec2_context.get_keystone_client_class)
