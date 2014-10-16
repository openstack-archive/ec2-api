#    Copyright 2014 Cloudscaling Group, Inc
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import copy

import mock
from neutronclient.common import exceptions as neutron_exception

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class SecurityGroupTestCase(base.ApiTestCase):

    def test_create_security_group(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_VPC_1
        self.db_api.add_item.return_value = fakes.DB_SECURITY_GROUP_1
        self.neutron.create_security_group.return_value = {
            'security_group': fakes.OS_SECURITY_GROUP_1}

        def check_response(resp, auto_ips=False):
            self.assertEqual(200, resp['status'])
            self.assertEqual(fakes.ID_EC2_SECURITY_GROUP_1, resp['groupId'])
            self.db_api.add_item.assert_called_once_with(
                mock.ANY, 'sg',
                tools.purge_dict(fakes.DB_SECURITY_GROUP_1, ('id',)))
            self.neutron.create_security_group.assert_called_once_with(
                {'security_group':
                    {'name': 'groupname',
                     'description': 'Group description'}})
            self.neutron.reset_mock()
            self.db_api.reset_mock()

        resp = self.execute(
            'CreateSecurityGroup',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'GroupName': 'groupname',
             'GroupDescription': 'Group description'})
        check_response(resp)

    def test_create_security_group_rollback(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_VPC_1
        self.neutron.create_security_group.return_value = {
            'security_group': fakes.OS_SECURITY_GROUP_1}
        self.db_api.add_item.side_effect = Exception()
        resp = self.execute(
            'CreateSecurityGroup',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'GroupName': 'groupname',
             'GroupDescription': 'Group description'})
        self.neutron.delete_security_group.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_1)

    def test_delete_security_group(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_SECURITY_GROUP_1
        self.db_api.get_items.return_value = []
        resp = self.execute(
            'DeleteSecurityGroup',
            {'GroupId':
             fakes.ID_EC2_SECURITY_GROUP_1})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_has_call(
            mock.ANY,
            fakes.ID_EC2_SECURITY_GROUP_1)
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY,
            fakes.ID_EC2_SECURITY_GROUP_1)
        self.neutron.delete_security_group.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_1)

    def test_delete_security_group_no_security_group(self):
        self.db_api.get_item_by_id.return_value = None
        resp = self.execute(
            'DeleteSecurityGroup',
            {'GroupId':
             fakes.ID_EC2_SECURITY_GROUP_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidGroup.NotFound',
                         resp['Error']['Code'])
        self.assertEqual(0, self.neutron.delete_port.call_count)

    def test_delete_security_group_is_in_use(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_SECURITY_GROUP_1
        self.neutron.delete_security_group.side_effect = (
            neutron_exception.Conflict())
        resp = self.execute(
            'DeleteSecurityGroup',
            {'GroupId':
             fakes.ID_EC2_SECURITY_GROUP_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('DependencyViolation', resp['Error']['Code'])
        self.assertEqual(0, self.db_api.delete_item.call_count)

    def test_describe_security_groups(self):
        self.db_api.get_items.return_value = [fakes.DB_SECURITY_GROUP_1,
                                              fakes.DB_SECURITY_GROUP_2]
        self.neutron.list_security_groups.return_value = (
            {'security_groups': [fakes.OS_SECURITY_GROUP_1,
                                 fakes.OS_SECURITY_GROUP_2]})

        resp = self.execute('DescribeSecurityGroups', {})
        self.assertEqual(200, resp['status'])
        self.assertThat(resp['securityGroupInfo'],
                        matchers.ListMatches(
                            [fakes.EC2_SECURITY_GROUP_1,
                             fakes.EC2_SECURITY_GROUP_2]))

    def test_authorize_security_group_ingress_ip_ranges(self):
        self.db_api.get_item_by_id.side_effect = copy.deepcopy(
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_SECURITY_GROUP_1: fakes.DB_SECURITY_GROUP_1,
                fakes.ID_EC2_SECURITY_GROUP_2: fakes.DB_SECURITY_GROUP_2}))
        self.neutron.create_security_group_rule.return_value = (
            {'security_group_rule': [fakes.OS_SECURITY_GROUP_RULE_1]})
        resp = self.execute(
            'AuthorizeSecurityGroupIngress',
            {'GroupId': fakes.ID_EC2_SECURITY_GROUP_2,
             'IpPermissions.1.FromPort': '10',
             'IpPermissions.1.ToPort': '10',
             'IpPermissions.1.IpProtocol': 'tcp',
             'IpPermissions.1.IpRanges.1.CidrIp': '192.168.1.0/24'})
        self.assertEqual(200, resp['status'])
        self.neutron.create_security_group_rule.assert_called_once_with(
            {'security_group_rule':
             tools.purge_dict(fakes.OS_SECURITY_GROUP_RULE_1,
                              {'id', 'remote_group_id', 'tenant_id'})})

    def test_authorize_security_group_egress_groups(self):
        self.db_api.get_item_by_id.side_effect = copy.deepcopy(
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_SECURITY_GROUP_1: fakes.DB_SECURITY_GROUP_1,
                fakes.ID_EC2_SECURITY_GROUP_2: fakes.DB_SECURITY_GROUP_2}))
        self.neutron.create_security_group_rule.return_value = (
            {'security_group_rule': [fakes.OS_SECURITY_GROUP_RULE_1]})
        resp = self.execute(
            'AuthorizeSecurityGroupEgress',
            {'GroupId': fakes.ID_EC2_SECURITY_GROUP_2,
             'IpPermissions.1.FromPort': '10',
             'IpPermissions.1.IpProtocol': '100',
             'IpPermissions.1.Groups.1.GroupId':
             fakes.ID_EC2_SECURITY_GROUP_1})
        self.assertEqual(200, resp['status'])
        self.neutron.create_security_group_rule.assert_called_once_with(
            {'security_group_rule':
             tools.purge_dict(fakes.OS_SECURITY_GROUP_RULE_2,
                              {'id', 'remote_ip_prefix', 'tenant_id',
                               'port_range_max'})})

    def test_revoke_security_group_ingress_ip_ranges(self):
        self.db_api.get_item_by_id.side_effect = copy.deepcopy(
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_SECURITY_GROUP_1: fakes.DB_SECURITY_GROUP_1,
                fakes.ID_EC2_SECURITY_GROUP_2: fakes.DB_SECURITY_GROUP_2}))
        self.neutron.show_security_group.return_value = {
            'security_group': fakes.OS_SECURITY_GROUP_2}
        self.neutron.delete_security_group_rule.return_value = True
        resp = self.execute(
            'RevokeSecurityGroupIngress',
            {'GroupId': fakes.ID_EC2_SECURITY_GROUP_2,
             'IpPermissions.1.FromPort': '10',
             'IpPermissions.1.ToPort': '10',
             'IpPermissions.1.IpProtocol': 'tcp',
             'IpPermissions.1.IpRanges.1.CidrIp': '192.168.1.0/24'})
        self.assertEqual(200, resp['status'])
        self.neutron.show_security_group.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_2)
        self.neutron.delete_security_group_rule.assert_called_once_with(
            fakes.OS_SECURITY_GROUP_RULE_1['id'])

    def test_revoke_security_group_egress_groups(self):
        self.db_api.get_item_by_id.side_effect = copy.deepcopy(
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_SECURITY_GROUP_1: fakes.DB_SECURITY_GROUP_1,
                fakes.ID_EC2_SECURITY_GROUP_2: fakes.DB_SECURITY_GROUP_2}))
        self.neutron.show_security_group.return_value = {
            'security_group': fakes.OS_SECURITY_GROUP_2}
        self.neutron.delete_security_group_rule.return_value = True
        resp = self.execute(
            'RevokeSecurityGroupEgress',
            {'GroupId': fakes.ID_EC2_SECURITY_GROUP_2,
             'IpPermissions.1.FromPort': '10',
             'IpPermissions.1.IpProtocol': '100',
             'IpPermissions.1.Groups.1.GroupId':
             fakes.ID_EC2_SECURITY_GROUP_1})
        self.assertEqual(200, resp['status'])
        self.neutron.show_security_group.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_2)
        self.neutron.delete_security_group_rule.assert_called_once_with(
            fakes.OS_SECURITY_GROUP_RULE_2['id'])
