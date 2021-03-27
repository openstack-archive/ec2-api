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

from sqlalchemy.orm import exc as orm_exception
from unittest import mock

from ec2api.api import validator
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers


class DbApiTestCase(base.DbTestCase):

    def setUp(self):
        super(DbApiTestCase, self).setUp()
        self.context = mock.NonCallableMock(
            project_id=fakes.random_os_id())
        self.other_context = mock.NonCallableMock(
            project_id=fakes.random_os_id())

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
        self.assertTrue(validator.validate_ec2_id(item_id, '', ['fake']))
        self.assertThat(item, matchers.DictMatches(new_item,
                                                   orderless_lists=True))

        item = db_api.get_item_by_id(self.context, item_id)
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
        self.assertTrue(validator.validate_ec2_id(item_id, '', ['fake']))
        item = db_api.get_item_by_id(self.context, item_id)
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

    def test_restore_item(self):
        os_id = fakes.random_os_id()
        item = {'os_id': os_id, 'key': 'val1'}
        new_item = db_api.add_item(self.context, 'fake', item)
        item['id'] = new_item['id']
        self.assertRaises(
            exception.EC2DBDuplicateEntry,
            db_api.restore_item, self.context, 'fake', item)

    def test_update_item(self):
        item = db_api.add_item(self.context, 'fake', {'key': 'val1',
                                                      'key1': 'val'})
        item['key'] = 'val2'
        item.pop('key1')
        item['key2'] = 'val'
        item_id = item['id']
        db_api.update_item(self.context, item)
        item = db_api.get_item_by_id(self.context, item_id)
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

    def test_update_item_os_id(self):
        item = db_api.add_item(self.context, 'fake', {})
        item['os_id'] = 'fake_os_id'
        db_api.update_item(self.context, item)
        item = db_api.get_item_by_id(self.context, item['id'])
        self.assertThat({'os_id': 'fake_os_id'},
                        matchers.IsSubDictOf(item))
        item['os_id'] = 'other_fake_os_id'
        self.assertRaises(exception.EC2DBInvalidOsIdUpdate,
                          db_api.update_item,
                          self.context, item)
        item['os_id'] = None
        self.assertRaises(exception.EC2DBInvalidOsIdUpdate,
                          db_api.update_item,
                          self.context, item)

    def test_delete_item(self):
        item = db_api.add_item(self.context, 'fake', {})
        db_api.delete_item(self.context, item['id'])
        item = db_api.get_item_by_id(self.context, item['id'])
        self.assertIsNone(item)

        # NOTE(ft): delete not existing item should pass quitely
        db_api.delete_item(self.context, fakes.random_ec2_id('fake'))

        item = db_api.add_item(self.context, 'fake', {})
        db_api.delete_item(self.other_context, item['id'])
        item = db_api.get_item_by_id(self.context, item['id'])
        self.assertIsNotNone(item)

    def _setup_items(self):
        db_api.add_item(self.context, 'fake', {})
        db_api.add_item(self.context, 'fake', {'is_public': True})
        db_api.add_item(self.context, 'fake1', {'os_id': fakes.random_os_id()})
        db_api.add_item(self.other_context, 'fake', {})
        db_api.add_item(self.other_context, 'fake', {'is_public': False})
        db_api.add_item(self.other_context, 'fake', {'is_public': True})
        db_api.add_item(self.other_context, 'fake1',
                        {'is_public': False,
                         'os_id': fakes.random_os_id()})

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

        item = db_api.get_item_by_id(self.context, item_id)
        self.assertThat(item, matchers.DictMatches({'id': item_id,
                                                    'os_id': None,
                                                    'vpc_id': None}))
        item = db_api.get_item_by_id(self.context, other_item_id)
        self.assertIsNone(item)
        item = db_api.get_item_by_id(self.context, fakes.random_ec2_id('fake'))
        self.assertIsNone(item)

    def test_get_items_by_ids(self):
        self._setup_items()
        fake_kind_items = db_api.get_items(self.context, 'fake')
        fake1_kind_items = db_api.get_items(self.context, 'fake1')
        item_id = fake_kind_items[0]['id']
        other_item_id = db_api.get_items(self.other_context, 'fake')[0]['id']

        items = db_api.get_items_by_ids(self.context, [])
        self.assertEqual(0, len(items))
        items = db_api.get_items_by_ids(self.context, set([]))
        self.assertEqual(0, len(items))
        items = db_api.get_items_by_ids(self.context,
                                        [i['id'] for i in fake_kind_items])
        self.assertEqual(2, len(items))
        items = db_api.get_items_by_ids(
            self.context, (fake_kind_items[0]['id'],
                           fake1_kind_items[0]['id']))
        self.assertEqual(2, len(items))
        items = db_api.get_items_by_ids(self.context, (item_id,))
        self.assertEqual(1, len(items))
        self.assertEqual(item_id, items[0]['id'])
        items = db_api.get_items_by_ids(self.context, (other_item_id,))
        self.assertEqual(0, len(items))
        items = db_api.get_items_by_ids(self.context,
                                        (item_id, other_item_id))
        self.assertEqual(1, len(items))
        items = db_api.get_items_by_ids(self.context,
                                        (fakes.random_ec2_id('fake'),))
        self.assertEqual(0, len(items))
        items = db_api.get_items_by_ids(self.context,
                                        (item_id, fakes.random_ec2_id('fake')))
        self.assertEqual(1, len(items))

    def test_get_items_ids(self):
        self._setup_items()
        item = db_api.get_items(self.context, 'fake1')[0]
        other_item = db_api.get_items(self.other_context, 'fake1')[0]
        items_ids = db_api.get_items_ids(self.context, 'fake1',
                                         item_os_ids=[item['os_id'],
                                                      other_item['os_id']])
        self.assertThat(items_ids,
                        matchers.ListMatches(
                            [(item['id'], item['os_id']),
                             (other_item['id'], other_item['os_id'])],
                            orderless_lists=True))
        items_ids = db_api.get_items_ids(self.context, 'fake',
                                         item_os_ids=[item['os_id']])
        self.assertEqual(0, len(items_ids))

        item_ids = db_api.get_items_ids(self.context, 'fake1',
                                        item_ids=[item['id'],
                                                  other_item['id']])
        self.assertThat(item_ids,
                        matchers.ListMatches(
                            [(item['id'], item['os_id']),
                             (other_item['id'], other_item['os_id'])],
                            orderless_lists=True))
        items_ids = db_api.get_items_ids(self.context, 'fake',
                                         item_ids=[item['id']])
        self.assertEqual(0, len(items_ids))

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
                                        [fakes.random_ec2_id('fake')])
        self.assertEqual(0, len(items))
        items = db_api.get_public_items(self.context, 'fake0', [])
        self.assertEqual(0, len(items))

    def test_add_tags(self):
        item1_id = fakes.random_ec2_id('fake')
        item2_id = fakes.random_ec2_id('fake')
        item3_id = fakes.random_ec2_id('fake')
        tag1_01 = {'item_id': item1_id,
                   'key': 'key1',
                   'value': None}
        tag1_1 = {'item_id': item1_id,
                  'key': 'key1',
                  'value': 'val'}
        tag1_2 = {'item_id': item1_id,
                  'key': 'key2',
                  'value': 'val'}
        tag1_3 = {'item_id': item1_id,
                  'key': 'key3',
                  'value': 'val'}
        tag2_1 = {'item_id': item2_id,
                  'key': 'key1',
                  'value': None}
        tag2_2 = {'item_id': item2_id,
                  'key': 'key2',
                  'value': 'val'}
        tag3_1 = {'item_id': item3_id,
                  'key': 'key1',
                  'value': 'val'}
        tag3_3 = {'item_id': item3_id,
                  'key': 'key3',
                  'value': 'val'}
        db_api.add_tags(self.context, [tag1_01, tag2_1,
                                       tag1_2, tag2_2])
        db_api.add_tags(self.context, [tag1_1, tag3_1,
                                       tag1_3, tag3_3])
        tags = db_api.get_tags(self.context)
        self.assertThat(tags,
                        matchers.ListMatches([tag1_1, tag1_2, tag1_3,
                                              tag2_1, tag2_2,
                                              tag3_1, tag3_3],
                                             orderless_lists=True))

    def test_add_tags_isolation(self):
        item_id = fakes.random_ec2_id('fake')
        tag1 = {'item_id': item_id,
                'key': 'key1',
                'value': 'val1'}
        tag2 = {'item_id': item_id,
                'key': 'key2',
                'value': 'val2'}
        db_api.add_tags(self.context, [tag1, tag2])
        db_api.add_tags(self.other_context, [{'item_id': item_id,
                                              'key': 'key1',
                                              'value': 'val1_1'},
                                             {'item_id': item_id,
                                              'key': 'key3',
                                              'value': 'val3'}])
        tags = db_api.get_tags(self.context)
        self.assertThat(tags, matchers.ListMatches([tag1, tag2],
                                                   orderless_lists=True))

    def test_get_tags(self):
        item1_id = fakes.random_ec2_id('fake')
        item2_id = fakes.random_ec2_id('fake')
        item3_id = fakes.random_ec2_id('fake1')
        tag1 = {'item_id': item1_id,
                'key': 'key1',
                'value': 'val1'}
        tag2 = {'item_id': item2_id,
                'key': 'key2',
                'value': 'val2'}
        tag3 = {'item_id': item3_id,
                'key': 'key3',
                'value': 'val3'}
        db_api.add_tags(self.context, [tag1, tag2, tag3])

        self.assertThat(db_api.get_tags(self.context),
                        matchers.ListMatches([tag1, tag2, tag3],
                                             orderless_lists=True))
        self.assertThat(db_api.get_tags(self.context, ('fake',)),
                        matchers.ListMatches([tag1, tag2],
                                             orderless_lists=True))
        self.assertThat(db_api.get_tags(self.context, ('fake',),
                                        [item1_id, item2_id]),
                        matchers.ListMatches([tag1, tag2],
                                             orderless_lists=True))
        self.assertThat(db_api.get_tags(self.context, ('fake',), (item1_id,)),
                        matchers.ListMatches([tag1],
                                             orderless_lists=True))
        self.assertThat(db_api.get_tags(self.context, ('fake',), (item3_id,)),
                        matchers.ListMatches([]))
        self.assertThat(db_api.get_tags(self.context,
                                        item_ids=(item1_id, item3_id)),
                        matchers.ListMatches([tag1, tag3],
                                             orderless_lists=True))
        self.assertThat(db_api.get_tags(self.context, ('fake', 'fake1'),
                                        (item2_id, item3_id)),
                        matchers.ListMatches([tag2, tag3],
                                             orderless_lists=True))

    def test_delete_tags(self):
        item1_id = fakes.random_ec2_id('fake')
        item2_id = fakes.random_ec2_id('fake')
        item3_id = fakes.random_ec2_id('fake1')
        tag1_1 = {'item_id': item1_id,
                  'key': 'key1',
                  'value': 'val_a'}
        tag1_2 = {'item_id': item1_id,
                  'key': 'key2',
                  'value': 'val_b'}
        tag2_1 = {'item_id': item2_id,
                  'key': 'key1',
                  'value': 'val_c'}
        tag2_2 = {'item_id': item2_id,
                  'key': 'key2',
                  'value': 'val_a'}
        tag3_1 = {'item_id': item3_id,
                  'key': 'key1',
                  'value': 'val_b'}
        tag3_2 = {'item_id': item3_id,
                  'key': 'key2',
                  'value': 'val_d'}
        db_api.add_tags(self.context, [tag1_1, tag2_1, tag3_1,
                                       tag1_2, tag2_2, tag3_2])

        def do_check(*tag_list):
            self.assertThat(db_api.get_tags(self.context),
                            matchers.ListMatches(tag_list,
                                                 orderless_lists=True))
            db_api.add_tags(self.context, [tag1_1, tag2_1, tag3_1,
                                           tag1_2, tag2_2, tag3_2])

        db_api.delete_tags(self.context, [])
        do_check(tag1_1, tag1_2, tag2_1, tag2_2, tag3_1, tag3_2)

        db_api.delete_tags(self.context, [item1_id])
        do_check(tag2_1, tag2_2, tag3_1, tag3_2)

        db_api.delete_tags(self.context, [item1_id, item3_id])
        do_check(tag2_1, tag2_2)

        db_api.delete_tags(self.context, [item1_id, item2_id, item3_id],
                           [{'key': 'key1'},
                            {'value': 'val_d'},
                            {'key': 'key2',
                             'value': 'val_b'}])
        do_check(tag2_2)

    def test_delete_tags_isolation(self):
        item_id = fakes.random_ec2_id('fake')
        tag1 = {'item_id': item_id,
                'key': 'key',
                'value': 'val1'}
        db_api.add_tags(self.context, [tag1])
        tag2 = {'item_id': item_id,
                'key': 'key',
                'value': 'val2'}
        db_api.add_tags(self.other_context, [tag2])
        db_api.delete_tags(self.context, [item_id])
        self.assertThat(db_api.get_tags(self.other_context),
                        matchers.ListMatches([tag2]))
