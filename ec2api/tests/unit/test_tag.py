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

from ec2api.api import ec2utils
from ec2api.api import tag as tag_api
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers


class TagTestCase(base.ApiTestCase):

    def test_create_tags(self):
        self.db_api.get_item_by_id.return_value = {'id': 'fake'}

        # NOTE(ft): check create several tags for several resources
        resp = self.execute('CreateTags',
                            {'ResourceId.1': fakes.ID_EC2_VPC_1,
                             'ResourceId.2': fakes.ID_EC2_SUBNET_1,
                             'Tag.1.Key': 'private',
                             'Tag.1.Value': '',
                             'Tag.2.Key': 'admin',
                             'Tag.2.Value': 'John Smith'})
        self.assertEqual({'return': True}, resp)
        self.assertEqual(1, self.db_api.add_tags.call_count)
        self.assertEqual(2, len(self.db_api.add_tags.call_args))
        self.assertThat(self.db_api.add_tags.call_args[0][1],
                        matchers.ListMatches(
                             [{'item_id': fakes.ID_EC2_VPC_1,
                               'key': 'private',
                               'value': ''},
                              {'item_id': fakes.ID_EC2_SUBNET_1,
                               'key': 'private',
                               'value': ''},
                              {'item_id': fakes.ID_EC2_VPC_1,
                               'key': 'admin',
                               'value': 'John Smith'},
                              {'item_id': fakes.ID_EC2_SUBNET_1,
                               'key': 'admin',
                               'value': 'John Smith'}],
                             orderless_lists=True))

        # NOTE(ft): check a tag can be created for all valid resource types
        resource_ids = [fakes.random_ec2_id(r_t)
                        for r_t in ['dopt', 'ami', 'aki', 'ari', 'cgw', 'i',
                                    'igw', 'eni', 'rtb', 'snap', 'subnet',
                                    'sg', 'vgw', 'vol', 'vpc', 'vpn']]
        self.assertEqual(len(resource_ids), len(tag_api.RESOURCE_TYPES))

        params = {'ResourceId.%s' % num: r_id
                  for num, r_id in enumerate(resource_ids)}
        params.update({'Tag.1.Key': 'tag',
                       'Tag.1.Value': 'value'})
        resp = self.execute('CreateTags', params)
        self.assertEqual({'return': True}, resp)

        # NOTE(ft): check create a tag for non-existing images
        self.db_api.get_item_by_id.return_value = None
        resp = self.execute('CreateTags',
                            {'ResourceId.1': fakes.ID_EC2_IMAGE_1,
                             'ResourceId.2': fakes.ID_EC2_IMAGE_AKI_1,
                             'ResourceId.3': fakes.ID_EC2_IMAGE_ARI_1,
                             'Tag.1.Key': 'Oracle RAC node',
                             'Tag.1.Value': ''})
        self.assertEqual({'return': True}, resp)

    def test_create_tags_invalid_parameters(self):
        # NOTE(ft): check tag validity checks
        self.assert_execution_error('InvalidParameterValue', 'CreateTags',
                                    {'ResourceId.1': fakes.ID_EC2_VPC_1,
                                     'Tag.1.Value': ''})

        self.assert_execution_error('InvalidParameterValue', 'CreateTags',
                                    {'ResourceId.1': fakes.ID_EC2_VPC_1,
                                     'Tag.1.Key': ''})

        self.assert_execution_error('InvalidParameterValue', 'CreateTags',
                                    {'ResourceId.1': fakes.ID_EC2_VPC_1,
                                     'Tag.1.Key': 'a' * 128})

        self.assert_execution_error('InvalidParameterValue', 'CreateTags',
                                    {'ResourceId.1': fakes.ID_EC2_VPC_1,
                                     'Tag.1.Key': 'fake-key',
                                     'Tag.1.Value': 'a' * 256})

        # NOTE(ft): check resource type check
        self.assert_execution_error(
            'InvalidID', 'CreateTags',
            {'ResourceId.1': fakes.random_ec2_id('fake'),
             'Tag.1.Key': 'fake-key',
             'Tag.1.Value': 'fake-value'})

        # NOTE(ft): check resource existence check
        self.db_api.get_item_by_id.return_value = None
        for r_id in tag_api.RESOURCE_TYPES:
            if r_id in ('ami', 'ari', 'aki'):
                continue
            exc_class = ec2utils.NOT_FOUND_EXCEPTION_MAP[r_id]
            try:
                error_code = exc_class.ec2_code
            except AttributeError:
                error_code = exc_class.__name__
            self.assert_execution_error(
                error_code, 'CreateTags',
                {'ResourceId.1': fakes.random_ec2_id(r_id),
                 'Tag.1.Key': 'fake-key',
                 'Tag.1.Value': 'fake-value'})

    def test_delete_tag(self):
        resp = self.execute('DeleteTags',
                            {'ResourceId.1': fakes.ID_EC2_VPC_1,
                             'ResourceId.2': fakes.ID_EC2_SUBNET_1,
                             'Tag.1.Key': 'key1',
                             'Tag.2.Value': 'value2',
                             'Tag.3.Key': 'key3',
                             'Tag.3.Value': 'value3'})
        self.assertEqual({'return': True}, resp)
        self.db_api.delete_tags.assert_called_once_with(
            mock.ANY, [fakes.ID_EC2_VPC_1, fakes.ID_EC2_SUBNET_1],
            [{'key': 'key1'},
             {'value': 'value2'},
             {'key': 'key3',
              'value': 'value3'}])

        resp = self.execute('DeleteTags',
                            {'ResourceId.1': fakes.ID_EC2_VPC_1})
        self.assertEqual({'return': True}, resp)
        self.db_api.delete_tags.assert_called_with(
            mock.ANY, [fakes.ID_EC2_VPC_1], None)

    def test_describe_tags(self):
        self.db_api.get_tags.return_value = [{'item_id': fakes.ID_EC2_VPC_1,
                                              'key': 'key1',
                                              'value': ''},
                                             {'item_id': fakes.ID_EC2_VPC_2,
                                              'key': 'key2',
                                              'value': 'value2'},
                                             {'item_id': fakes.ID_EC2_VPC_2,
                                              'key': 'key1',
                                              'value': 'value3'}
                                             ]
        resp = self.execute('DescribeTags', {})
        self.assertThat(resp,
                        matchers.DictMatches(
                            {'tagSet': [{'resourceType': 'vpc',
                                         'resourceId': fakes.ID_EC2_VPC_1,
                                         'key': 'key1',
                                         'value': None},
                                        {'resourceType': 'vpc',
                                         'resourceId': fakes.ID_EC2_VPC_2,
                                         'key': 'key2',
                                         'value': 'value2'},
                                        {'resourceType': 'vpc',
                                         'resourceId': fakes.ID_EC2_VPC_2,
                                         'key': 'key1',
                                         'value': 'value3'}
                                        ]},
                            orderless_lists=True),
                        verbose=True)

        self.check_filtering(
            'DescribeTags', 'tagSet',
            [('resource-type', 'vpc'),
             ('resource-id', fakes.ID_EC2_VPC_1),
             ('key', 'key1'),
             ('value', 'value2')])

        # NOTE(ft): check all resource types are displayed correctly
        for r_id, r_type in [('dopt', 'dhcp-options'),
                             ('ami', 'image'),
                             ('aki', 'image'),
                             ('ari', 'image'),
                             ('cgw', 'customer-gateway'),
                             ('i', 'instance'),
                             ('igw', 'internet-gateway'),
                             ('eni', 'network-interface'),
                             ('rtb', 'route-table'),
                             ('snap', 'snapshot'),
                             ('subnet', 'subnet'),
                             ('sg', 'security-group'),
                             ('vgw', 'vpn-gateway'),
                             ('vol', 'volume'),
                             ('vpc', 'vpc'),
                             ('vpn', 'vpn-connection')]:
            item_id = fakes.random_ec2_id(r_id)
            self.db_api.get_tags.return_value = [{'item_id': item_id,
                                                  'key': 'fake-key',
                                                  'value': 'fake-value'}]
            resp = self.execute('DescribeTags', {})
            self.assertEqual({'tagSet': [{'resourceType': r_type,
                                          'resourceId': item_id,
                                          'key': 'fake-key',
                                          'value': 'fake-value'}]},
                             resp)
