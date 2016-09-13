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

import copy
import itertools

from cinderclient import client as cinderclient
from glanceclient import client as glanceclient
import mock
from novaclient import client as novaclient
from oslo_config import fixture as config_fixture
from oslotest import base as test_base

import ec2api.api.apirequest
from ec2api.api import clients
from ec2api.api import ec2utils
from ec2api import config
from ec2api.db import migration
from ec2api.db.sqlalchemy import api as db_backend
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools
import ec2api.wsgi


DB_SCHEMA = None


config.parse_args([], default_config_files=[])
# TODO(ft): temporary solution to prevent discovery of Nova API version
# in clients.nova. This should be removed when all tests either use
# MockOSMixin (which should be improved in its turn) to mock novaclient,
# or mock clients.nova directly.
clients._nova_api_version = '2.3'


def skip_not_implemented(test_item):
    def decorator(test_item):
        test_item.skip('The feature is not yet implemented')
    return decorator


def create_context(is_os_admin=False):
    session = (mock.sentinel.admin_session
               if is_os_admin else
               mock.sentinel.session)
    session.get_endpoint = mock.Mock(name="get_endpoint")
    session.get_endpoint.return_value = 'v2'
    return ec2api.context.RequestContext(fakes.ID_OS_USER, fakes.ID_OS_PROJECT,
                                         is_os_admin=is_os_admin,
                                         session=session)


class MockOSMixin(object):

    def mock(self, object_name):
        patcher = mock.patch(object_name)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def mock_all_os(self):
        self.neutron = self.mock_neutron()
        self.nova, self.nova_admin = self.mock_nova()
        self.glance = self.mock_glance()
        self.cinder = self.mock_cinder()

        self.get_os_admin_context = self.mock(
            'ec2api.context.get_os_admin_context')
        self.get_os_admin_context.return_value = (
            create_context(is_os_admin=True))

    def mock_neutron(self):
        neutron_patcher = mock.patch('neutronclient.v2_0.client.Client',
                                     autospec=True)
        neutron = neutron_patcher.start().return_value
        self.addCleanup(neutron_patcher.stop)
        return neutron

    def mock_nova(self):
        # NOTE(ft): create an extra mock for Nova calls with an admin account.
        # Also make sure that the admin account is used only for this calls.
        # The special mock is needed to validate tested function to retrieve
        # appropriate data, as long as only calls with admin account return
        # some specific data.
        novaclient_spec = novaclient.Client('2')
        nova = mock.create_autospec(novaclient_spec)
        nova_admin = mock.create_autospec(novaclient_spec)
        nova_patcher = mock.patch('novaclient.client.Client')
        novaclient_getter = nova_patcher.start()
        self.addCleanup(nova_patcher.stop)
        novaclient_getter.side_effect = (
            lambda *args, **kwargs: (
                nova_admin
                if (kwargs.get('session') == mock.sentinel.admin_session) else
                nova
                if (kwargs.get('session') == mock.sentinel.session) else
                None))
        return nova, nova_admin

    def mock_glance(self):
        glance_patcher = mock.patch('glanceclient.client.Client')
        glance = mock.create_autospec(glanceclient.Client(endpoint='v1'))
        glance_patcher.start().return_value = glance
        self.addCleanup(glance_patcher.stop)
        return glance

    def mock_cinder(self):
        cinder_patcher = mock.patch('cinderclient.client.Client')
        cinder = mock.create_autospec(cinderclient.Client('2'))
        cinder_patcher.start().return_value = cinder
        self.addCleanup(cinder_patcher.stop)
        return cinder


class MockDBMixin(object):

    def mock_db(self):
        db_api_patcher = mock.patch('ec2api.db.api.IMPL', autospec=db_backend)
        db_api = db_api_patcher.start()
        self.addCleanup(db_api_patcher.stop)

        def set_mock_items(*items):
            db_api.__db_items = copy.copy(items)
            db_api.get_items.side_effect = (
                tools.get_db_api_get_items(*db_api.__db_items))
            db_api.get_item_by_id.side_effect = (
                tools.get_db_api_get_item_by_id(*db_api.__db_items))
            db_api.get_items_by_ids.side_effect = (
                tools.get_db_api_get_items_by_ids(*db_api.__db_items))
            db_api.get_items_ids.side_effect = (
                tools.get_db_api_get_items_ids(*db_api.__db_items))

        def add_mock_items(*items):
            merged_items = items + tuple(item for item in db_api.__db_items
                                         if all(i['id'] != item['id']
                                                for i in items))
            db_api.set_mock_items(*merged_items)

        setattr(db_api, 'set_mock_items', set_mock_items)
        setattr(db_api, 'add_mock_items', add_mock_items)
        return db_api


class BaseTestCase(MockOSMixin, MockDBMixin, test_base.BaseTestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self._conf = self.useFixture(config_fixture.Config())
        self.configure(fatal_exception_format_errors=True)

    def configure(self, **kwargs):
        self._conf.config(**kwargs)


class ApiTestCase(BaseTestCase):

    ANY_EXECUTE_ERROR = object()

    def setUp(self):
        super(ApiTestCase, self).setUp()
        self.mock_all_os()
        self.db_api = self.mock_db()
        self.isotime = self.mock('oslo_utils.timeutils.isotime')

    def execute(self, action, args):
        status_code, response = self._execute(action, args)
        self.assertEqual(200, status_code,
                         self._format_error_message(status_code, response))
        return response

    def assert_execution_error(self, error_code, action, args):
        status_code, response = self._execute(action, args)
        if error_code == self.ANY_EXECUTE_ERROR:
            self.assertLessEqual(400, status_code)
        else:
            self.assertEqual(400, status_code)
            self.assertEqual(error_code, response['Error']['Code'],
                             self._format_error_message(status_code, response))

    def assert_any_call(self, func, *args, **kwargs):
        calls = func.mock_calls
        for call in calls:
            call_args = call[1]
            if matchers.ListMatches(call_args, args, orderless_lists=True):
                return
        self.assertEqual(False, True)

    def set_mock_db_items(self, *items):
        self.db_api.set_mock_items(*items)

    def add_mock_db_items(self, *items):
        self.db_api.add_mock_items(*items)

    def check_filtering(self, operation, resultset_key, filters):
        for name, value in filters:
            resp = self.execute(operation,
                                {'Filter.1.Name': name,
                                 'Filter.1.Value.1': str(value)})
            self.assertTrue(resp[resultset_key] is not None and
                            len(resp[resultset_key]) > 0,
                            'Filter by %s does not work' % name)

            resp = self.execute(operation,
                                {'Filter.1.Name': name,
                                 'Filter.1.Value.1': 'dummy filter value'})
            self.assertTrue(resp[resultset_key] is None or
                            len(resp[resultset_key]) == 0)

    def check_tag_support(self, operation, resultset_key, sample_item_id,
                          id_key, item_kinds=[]):
        self.db_api.get_tags = tools.CopyingMock(
            return_value=[{'item_id': sample_item_id,
                           'key': 'fake_key',
                           'value': 'fake_value'}])
        ec2_tags = [{'key': 'fake_key',
                     'value': 'fake_value'}]

        resp = self.execute(operation, {})
        tag_found = False
        if type(resultset_key) is list:
            resp_items = itertools.chain(*(r[resultset_key[1]]
                                           for r in resp[resultset_key[0]]))
        else:
            resp_items = resp[resultset_key]
            resultset_key = [resultset_key]
        for resp_item in resp_items:
            if resp_item.get(id_key) == sample_item_id:
                self.assertIn('tagSet', resp_item)
                self.assertThat(resp_item['tagSet'],
                                matchers.ListMatches(ec2_tags))
                tag_found = True
            else:
                self.assertTrue('tagSet' not in resp_item or
                                resp_item['tagSet'] == [])
        self.assertTrue(tag_found)
        if not item_kinds:
            item_kinds = (ec2utils.get_ec2_id_kind(sample_item_id),)
        self.assertTrue(self.db_api.get_tags.call_count == 1 and
                        (self.db_api.get_tags.mock_calls[0] in
                         (mock.call(mock.ANY, item_kinds, set()),
                          mock.call(mock.ANY, item_kinds, None))))
        self.db_api.reset_mock()

        id_param = '%s%s.1' % (id_key[0].capitalize(), id_key[1:])
        resp = self.execute(operation, {id_param: sample_item_id})
        self.assertTrue(
            self.db_api.get_tags.call_count == 1 and
            (self.db_api.get_tags.mock_calls[0] in
             (mock.call(mock.ANY, item_kinds, set([sample_item_id])),
              mock.call(mock.ANY, item_kinds, [sample_item_id]))))

        self.check_filtering(
             operation, resultset_key[0],
             [('tag-key', 'fake_key'),
              ('tag-value', 'fake_value'),
              ('tag:fake_key', 'fake_value')])

    def _execute(self, action, args):
        ec2_request = ec2api.api.apirequest.APIRequest(action, 'fake_v1', args)
        ec2_context = create_context()
        environ = {'REQUEST_METHOD': 'FAKE',
                   'ec2.request': ec2_request,
                   'ec2api.context': ec2_context}
        request = ec2api.wsgi.Request(environ)
        response = request.send(ec2api.api.Executor())
        return (response.status_code,
                self._check_and_transform_response(response, action))

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
        return body

    def _format_error_message(self, status_code, response):
        if status_code >= 400:
            return '%s: %s' % (response['Error']['Code'],
                               response['Error']['Message'])
        else:
            return ''


class DbTestCase(BaseTestCase):

    def setUp(self):
        super(DbTestCase, self).setUp()
        self.configure(connection='sqlite://', group='database')
        self.configure(sqlite_synchronous=False, group='database')
        self._init_db_schema()
        engine = db_backend.get_engine()
        conn = engine.connect()
        conn.connection.executescript(DB_SCHEMA)
        self.addCleanup(engine.dispose)

    def _init_db_schema(self):
        global DB_SCHEMA
        if not DB_SCHEMA:

            engine = db_backend.get_engine()
            conn = engine.connect()
            migration.db_sync()
            DB_SCHEMA = "".join(line for line in conn.connection.iterdump())
            engine.dispose()
