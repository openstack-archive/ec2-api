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

from oslo.config import cfg
from oslotest import base as test_base
from sqlalchemy.orm import exc as orm_exception

from ec2api.api import validator
from ec2api import context as ec2_context
from ec2api.db import api as db_api
from ec2api.db import migration
from ec2api.db.sqlalchemy import api as session
from ec2api.tests import fakes
from ec2api.tests import matchers


class DbApiTestCase(test_base.BaseTestCase):

    DB_SCHEMA = None

    @classmethod
    def setUpClass(cls):
        super(DbApiTestCase, cls).setUpClass()
        conf = cfg.CONF
        try:
            conf.set_override('connection', 'sqlite://', group='database')
            conf.set_override('sqlite_synchronous', False, group='database')

            engine = session.get_engine()
            conn = engine.connect()
            migration.db_sync()
            cls.DB_SCHEMA = "".join(line
                                    for line in conn.connection.iterdump())
            engine.dispose()
        finally:
            conf.reset()

    def setUp(self):
        super(DbApiTestCase, self).setUp()
        engine = session.get_engine()
        engine.dispose()
        conn = engine.connect()
        conn.connection.executescript(self.DB_SCHEMA)
        self.context = ec2_context.RequestContext(fakes.ID_OS_USER,
                                                  fakes.ID_OS_PROJECT,
                                                  None, None)
        self.other_context = ec2_context.RequestContext(
            fakes.random_os_id(), fakes.random_os_id(), None, None)

    def test_add_item(self):
        new_item = {'os_id': fakes.random_os_id(),
                    'vpc_id': fakes.random_ec2_id('fake_vpc'),
                    'str_attr': 'fake_str',
                    'int_attr': 1234,
                    'bool_attr': True,
                    'dict_attr': {'key1': 'val1',
                                  'key2': 'val2'},
                    'list_attr': ['fake_str', 1234, True, {'key': 'val'}, []]}
        item = db_api.add_item(self.context, 'fake', new_item)
        self.assertIn('id', item)
        self.assertIsNotNone(item['id'])
        item_id = item.pop('id')
        self.assertTrue(validator.validate_ec2_id(('fake',))(item_id, ''))
        self.assertThat(item, matchers.DictMatches(new_item,
                                                   orderless_lists=True))

        item = db_api.get_item_by_id(self.context, 'fake', item_id)
        new_item['id'] = item_id
        self.assertThat(item, matchers.DictMatches(new_item,
                                                   orderless_lists=True))

    def test_add_item_defaults(self):
        def do_check(new_item):
            item = db_api.add_item(self.context, 'fake', new_item)
            item_id = item.pop('id')
            if 'id' in new_item:
                new_item_id = new_item.pop('id')
                self.assertNotEqual(new_item_id, item_id)
            new_item.setdefault('os_id', None)
            new_item.setdefault('vpc_id', None)
            self.assertThat(item, matchers.DictMatches(new_item,
                                                       orderless_lists=True))

        do_check({})
        do_check({'os_id': fakes.random_os_id()})
        do_check({'vpc_id': fakes.random_ec2_id('fake_vpc')})
        do_check({'id': fakes.random_ec2_id('fake')})

    def test_add_item_with_same_os_id(self):
        # NOTE(ft): check normal update item on add
        os_id = fakes.random_os_id()
        item1 = db_api.add_item(self.context, 'fake',
                                {'os_id': os_id,
                                 'key': 'val1',
                                 'key1': 'val'})
        item_id = item1['id']
        item2 = db_api.add_item(self.context, 'fake',
                                {'os_id': os_id,
                                 'key': 'val2',
                                 'key2': 'val'})
        expected_item = {'id': item_id,
                         'os_id': os_id,
                         'vpc_id': None,
                         'key': 'val2',
                         'key1': 'val',
                         'key2': 'val'}
        self.assertThat(item2, matchers.DictMatches(expected_item))

    def test_add_item_isolation(self):
        os_id = fakes.random_os_id()
        db_api.add_item(self.context, 'fake', {'os_id': os_id})
        self.assertRaises(
                orm_exception.NoResultFound,
                db_api.add_item, self.context, 'fake1', {'os_id': os_id})
        self.assertRaises(
                orm_exception.NoResultFound,
                db_api.add_item, self.other_context, 'fake', {'os_id': os_id})

    def test_add_item_id(self):
        os_id = fakes.random_os_id()
        item_id = db_api.add_item_id(self.context, 'fake', os_id)
        self.assertTrue(validator.validate_ec2_id(('fake',))(item_id, ''))
        item = db_api.get_item_by_id(self.context, 'fake', item_id)
        self.assertIsNone(item)
        item = db_api.add_item(self.context, 'fake', {'os_id': os_id})
        self.assertThat(item, matchers.DictMatches({'id': item_id,
                                                    'os_id': os_id,
                                                    'vpc_id': None}))
        # NOTE(ft): add os_id when item exists
        item_id = db_api.add_item_id(self.context, 'fake', os_id)
        self.assertEqual(item_id, item['id'])

        # NOTE(ft): add os_id when id exists
        os_id = fakes.random_os_id()
        item_id1 = db_api.add_item_id(self.context, 'fake', os_id)
        item_id2 = db_api.add_item_id(self.context, 'fake', os_id)
        self.assertEqual(item_id1, item_id2)

    def test_update_item(self):
        item = db_api.add_item(self.context, 'fake', {'key': 'val1',
                                                      'key1': 'val'})
        item['key'] = 'val2'
        item.pop('key1')
        item['key2'] = 'val'
        item_id = item['id']
        db_api.update_item(self.context, item)
        item = db_api.get_item_by_id(self.context, 'fake', item_id)
        self.assertThat(item, matchers.DictMatches({'id': item_id,
                                                    'os_id': None,
                                                    'vpc_id': None,
                                                    'key': 'val2',
                                                    'key2': 'val'}))

    def test_update_item_invalid(self):
        self.assertRaises(orm_exception.NoResultFound,
                          db_api.update_item,
                          self.context,
                          {'id': fakes.random_ec2_id('fake'),
                           'key': 'val'})

    def test_delete_item(self):
        item = db_api.add_item(self.context, 'fake', {})
        db_api.delete_item(self.context, item['id'])
        item = db_api.get_item_by_id(self.context, 'fake', item['id'])
        self.assertIsNone(item)

        # NOTE(ft): delete not existing item should pass quitely
        db_api.delete_item(self.context, fakes.random_ec2_id('fake'))

        item = db_api.add_item(self.context, 'fake', {})
        db_api.delete_item(self.other_context, item['id'])
        item = db_api.get_item_by_id(self.context, 'fake', item['id'])
        self.assertIsNotNone(item)

    def _setup_items(self):
        db_api.add_item(self.context, 'fake', {})
        db_api.add_item(self.context, 'fake', {'is_public': True})
        db_api.add_item(self.context, 'fake1', {})
        db_api.add_item(self.other_context, 'fake', {})
        db_api.add_item(self.other_context, 'fake', {'is_public': False})
        db_api.add_item(self.other_context, 'fake', {'is_public': True})
        db_api.add_item_id(self.other_context, 'fake', fakes.random_os_id())
        db_api.add_item(self.other_context, 'fake1', {'is_public': True})

    def test_get_items(self):
        self._setup_items()

        items = db_api.get_items(self.context, 'fake')
        self.assertEqual(2, len(items))
        items = db_api.get_items(self.context, 'fake0')
        self.assertEqual(0, len(items))

    def test_get_item_by_id(self):
        self._setup_items()
        item_id = db_api.get_items(self.context, 'fake')[0]['id']
        other_item_id = db_api.get_items(self.other_context, 'fake')[0]['id']

        item = db_api.get_item_by_id(self.context, 'fake', item_id)
        self.assertThat(item, matchers.DictMatches({'id': item_id,
                                                    'os_id': None,
                                                    'vpc_id': None}))
        item = db_api.get_item_by_id(self.context, 'fake1', item_id)
        self.assertIsNone(item)
        item = db_api.get_item_by_id(self.context, 'fake0', item_id)
        self.assertIsNone(item)
        item = db_api.get_item_by_id(self.context, 'fake', other_item_id)
        self.assertIsNone(item)
        item = db_api.get_item_by_id(self.context, 'fake',
                                     fakes.random_ec2_id('fake'))

    def test_get_items_by_ids(self):
        self._setup_items()
        item_id = db_api.get_items(self.context, 'fake')[0]['id']
        other_item_id = db_api.get_items(self.other_context, 'fake')[0]['id']

        items = db_api.get_items_by_ids(self.context, 'fake', [])
        self.assertEqual(2, len(items))
        items = db_api.get_items_by_ids(self.context, 'fake', set([]))
        self.assertEqual(2, len(items))
        items = db_api.get_items_by_ids(self.context, 'fake',
                                        [i['id'] for i in items])
        self.assertEqual(2, len(items))
        items = db_api.get_items_by_ids(self.context, 'fake', (item_id,))
        self.assertEqual(1, len(items))
        self.assertEqual(item_id, items[0]['id'])
        items = db_api.get_items_by_ids(self.context, 'fake0', [])
        self.assertEqual(0, len(items))
        items = db_api.get_items_by_ids(self.context, 'fake', (other_item_id,))
        self.assertEqual(0, len(items))
        items = db_api.get_items_by_ids(self.context, 'fake',
                                        (fakes.random_ec2_id('fake')),)
        self.assertEqual(0, len(items))
        items = db_api.get_items_by_ids(self.context, 'fake1', (item_id,))
        self.assertEqual(0, len(items))

    def test_get_public_items(self):
        self._setup_items()
        items = db_api.get_public_items(self.context, 'fake')
        self.assertEqual(2, len(items))
        public_item_ids = [i['id'] for i in items]

        items = db_api.get_public_items(self.context, 'fake', public_item_ids)
        self.assertEqual(2, len(items))
        items = db_api.get_public_items(self.context, 'fake',
                                        [public_item_ids[0]])
        self.assertEqual(1, len(items))
        items = db_api.get_public_items(self.context, 'fake',
                                        (public_item_ids[1],))
        self.assertEqual(1, len(items))
        items = db_api.get_public_items(self.context, 'fake1',
                                        [public_item_ids[0]])
        self.assertEqual(0, len(items))
        items = db_api.get_public_items(self.context, 'fake',
                                        fakes.random_ec2_id('fake'))
        self.assertEqual(0, len(items))
        items = db_api.get_public_items(self.context, 'fake0', [])
        self.assertEqual(0, len(items))
