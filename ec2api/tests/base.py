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
from oslotest import base as test_base

import ec2api.api.apirequest
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools
import ec2api.wsgi


def skip_not_implemented(test_item):
    def decorator(test_item):
        test_item.skip('The feature is not yet implemented')
    return decorator


class ApiTestCase(test_base.BaseTestCase):

    def setUp(self):
        super(ApiTestCase, self).setUp()

        neutron_patcher = mock.patch('neutronclient.v2_0.client.Client')
        self.neutron = neutron_patcher.start().return_value
        self.addCleanup(neutron_patcher.stop)

        nova_patcher = mock.patch('novaclient.v1_1.client.Client')
        nova_mock = nova_patcher.start()
        self.nova_availability_zones = (
            nova_mock.return_value.availability_zones)
        self.nova_servers = nova_mock.return_value.servers
        self.nova_flavors = nova_mock.return_value.flavors
        self.nova_floating_ips = nova_mock.return_value.floating_ips
        self.nova_key_pairs = nova_mock.return_value.keypairs
        self.nova_security_groups = nova_mock.return_value.security_groups
        self.nova_security_group_rules = (
            nova_mock.return_value.security_group_rules)
        self.addCleanup(nova_patcher.stop)

        glance_patcher = mock.patch('glanceclient.client.Client')
        self.glance = glance_patcher.start().return_value
        self.addCleanup(glance_patcher.stop)

        cinder_patcher = mock.patch('cinderclient.v1.client.Client')
        self.cinder = cinder_patcher.start().return_value
        self.addCleanup(cinder_patcher.stop)

        db_api_patcher = mock.patch('ec2api.db.api.IMPL')
        self.db_api = db_api_patcher.start()
        self.addCleanup(db_api_patcher.stop)

        isotime_patcher = mock.patch('ec2api.openstack.common.timeutils.'
                                     'isotime')
        self.isotime = isotime_patcher.start()
        self.addCleanup(isotime_patcher.stop)

    def execute(self, action, args):
        ec2_request = ec2api.api.apirequest.APIRequest(action, 'fake_v1', args)
        ec2_context = self._create_context()
        environ = {'REQUEST_METHOD': 'FAKE',
                   'ec2.request': ec2_request,
                   'ec2api.context': ec2_context}
        request = ec2api.wsgi.Request(environ)
        response = request.send(ec2api.api.Executor())
        return self._check_and_transform_response(response, action)

    def _create_context(self):
        return ec2api.context.RequestContext(
            fakes.ID_OS_USER, fakes.ID_OS_PROJECT,
            'fake_access_key', 'fake_secret_key',
            service_catalog=[{'type': 'network',
                              'endpoints': [{'publicUrl': 'fake_url'}]}])

    def _check_and_transform_response(self, response, action):
        body = tools.parse_xml(response.body)
        if response.status_code == 200:
            action_tag = '%sResponse' % action
            self.assertIn(action_tag, body)
            body = body.pop(action_tag)
            self.assertIn('requestId', body)
            body.pop('requestId')
        else:
            self.assertIn('Response', body)
            body = body.pop('Response')
            self.assertIn('RequestID', body)
            body.pop('RequestID')
            self.assertEqual(1, len(body))
            self.assertIn('Errors', body)
            body = body.pop('Errors')
            self.assertEqual(1, len(body))
            self.assertIn('Error', body)
            self.assertEqual(2, len(body['Error']))
        body['http_status_code'] = response.status_code
        return body

    def assert_any_call(self, func, *args, **kwargs):
        calls = func.mock_calls
        for call in calls:
            call_args = call[1]
            if matchers.ListMatches(call_args, args, orderless_lists=True):
                return
        self.assertEqual(False, True)
