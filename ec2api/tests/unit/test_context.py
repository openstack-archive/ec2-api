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

import imp

import mock
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_context import context
from oslotest import base as test_base

from ec2api import clients
from ec2api import context as ec2_context


GROUP_AUTHTOKEN = 'keystone_authtoken'


class ContextTestCase(test_base.BaseTestCase):

    @mock.patch('keystoneauth1.loading.load_auth_from_conf_options')
    @mock.patch('keystoneauth1.loading.load_session_from_conf_options')
    def test_get_os_admin_context(self, session, auth):
        conf = config_fixture.Config()
        clients._admin_session = None
        conf.config(auth_type='fake', group=GROUP_AUTHTOKEN)

        imp.reload(ec2_context)
        # NOTE(ft): initialize a regular context to populate oslo_context's
        # local storage to prevent admin context to populate it.
        # Used to implicitly validate overwrite=False argument of the call
        # RequestContext constructor from inside get_os_admin_context
        if not context.get_current():
            ec2_context.RequestContext(None, None)

        ctx = ec2_context.get_os_admin_context()
        conf = cfg.CONF
        auth.assert_called_once_with(conf, GROUP_AUTHTOKEN)
        auth_plugin = auth.return_value
        session.assert_called_once_with(conf, GROUP_AUTHTOKEN,
                                        auth=auth_plugin)
        self.assertIsNone(ctx.user_id)
        self.assertIsNone(ctx.project_id)
        self.assertIsNone(ctx.auth_token)
        self.assertEqual([], ctx.service_catalog)
        self.assertTrue(ctx.is_os_admin)
        self.assertIsNotNone(ctx.session)
        self.assertIsNotNone(ctx.session.auth)
        self.assertNotEqual(context.get_current(), ctx)

        session.reset_mock()
        ec2_context.get_os_admin_context()
        self.assertFalse(session.called)
