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

import mock
from neutronclient.common import exceptions as neutron_exception
from novaclient import exceptions as nova_exception

from ec2api.api import security_group
from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


class SecurityGroupTestCase(base.ApiTestCase):

    def test_create_security_group(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
        self.db_api.get_item_by_id.return_value = fakes.DB_VPC_1
        self.db_api.add_item.return_value = fakes.DB_SECURITY_GROUP_1
        self.nova_security_groups.create.return_value = (
            fakes.NovaSecurityGroup(fakes.OS_SECURITY_GROUP_1))

        resp = self.execute(
            'CreateSecurityGroup',
            {'GroupName': 'groupname',
             'GroupDescription': 'Group description'})
        self.assertEqual(200, resp['status'])
        self.nova_security_groups.create.assert_called_once_with(
            'groupname', 'Group description')
        self.nova_security_groups.reset_mock()

        resp = self.execute(
            'CreateSecurityGroup',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'GroupName': 'groupname',
             'GroupDescription': 'Group description'})
        self.assertEqual(200, resp['status'])
        self.assertEqual(fakes.ID_EC2_SECURITY_GROUP_1, resp['groupId'])
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'sg',
            tools.purge_dict(fakes.DB_SECURITY_GROUP_1, ('id',)))
        self.nova_security_groups.create.assert_called_once_with(
            'groupname', 'Group description')

    def test_create_security_group_invalid(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())

        def check_response(resp, error_code):
            self.assertEqual(400, resp['status'])
            self.assertEqual(error_code, resp['Error']['Code'])
            self.neutron.reset_mock()
            self.db_api.reset_mock()

        self.db_api.get_item_by_id.return_value = None
        resp = self.execute(
            'CreateSecurityGroup',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'GroupName': 'groupname',
             'GroupDescription': 'Group description'})
        self.db_api.get_item_by_id.assert_called_once_with(mock.ANY, 'vpc',
                                                           fakes.ID_EC2_VPC_1)
        check_response(resp, 'InvalidVpcID.NotFound')

        resp = self.execute(
            'CreateSecurityGroup',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'GroupName': 'aa #^% -=99',
             'GroupDescription': 'Group description'})
        check_response(resp, 'ValidationError')

        resp = self.execute(
            'CreateSecurityGroup',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'GroupName': 'groupname',
             'GroupDescription': 'aa #^% -=99'})
        check_response(resp, 'ValidationError')

        resp = self.execute(
            'CreateSecurityGroup',
            {'GroupName': 'aa \t\x01\x02\x7f',
             'GroupDescription': 'Group description'})
        check_response(resp, 'ValidationError')

        resp = self.execute(
            'CreateSecurityGroup',
            {'GroupName': 'groupname',
             'GroupDescription': 'aa \t\x01\x02\x7f'})
        check_response(resp, 'ValidationError')

        resp = self.execute(
            'CreateSecurityGroup',
            {'GroupName': 'x' * 256,
             'GroupDescription': 'Group description'})
        check_response(resp, 'ValidationError')

        resp = self.execute(
            'CreateSecurityGroup',
            {'GroupName': 'groupname',
             'GroupDescription': 'x' * 256})
        check_response(resp, 'ValidationError')

        resp = self.execute(
            'CreateSecurityGroup',
            {'GroupName': 'groupname'})
        check_response(resp, 'MissingParameter')

        resp = self.execute(
            'CreateSecurityGroup',
            {'GroupDescription': 'description'})
        check_response(resp, 'MissingParameter')

    def test_create_security_group_over_quota(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
        self.nova_security_groups.create.side_effect = (
            nova_exception.OverLimit(413))
        resp = self.execute(
            'CreateSecurityGroup',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'GroupName': 'groupname',
             'GroupDescription': 'Group description'})
        self.assertEqual(400, resp['status'])
        self.assertEqual('ResourceLimitExceeded', resp['Error']['Code'])
        self.nova_security_groups.create.assert_called_once_with(
            'groupname', 'Group description')

    def test_create_security_group_rollback(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNova())
        self.db_api.get_item_by_id.return_value = fakes.DB_VPC_1
        self.db_api.add_item.side_effect = Exception()
        self.nova_security_groups.create.return_value = (
            fakes.NovaSecurityGroup(fakes.OS_SECURITY_GROUP_1))
        resp = self.execute(
            'CreateSecurityGroup',
            {'VpcId': fakes.ID_EC2_VPC_1,
             'GroupName': 'groupname',
             'GroupDescription': 'Group description'})
        self.nova_security_groups.delete.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_1)

    def test_delete_security_group(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
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

    def test_delete_security_group_nova(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNova())
        self.nova_security_groups.list.return_value = (
            [fakes.NovaSecurityGroup(fakes.OS_SECURITY_GROUP_1),
             fakes.NovaSecurityGroup(fakes.OS_SECURITY_GROUP_2)])
        resp = self.execute(
            'DeleteSecurityGroup',
            {'GroupName':
             fakes.EC2_SECURITY_GROUP_1['groupName']})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])
        self.nova_security_groups.delete.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_1)

    # NOTE(Alex) This test is disabled because it checks using non-AWS id.
    @base.skip_not_implemented
    def test_delete_security_group_nova_os_id(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNova())
        self.nova_security_groups.list.return_value = (
            [fakes.NovaSecurityGroup(fakes.OS_SECURITY_GROUP_1),
             fakes.NovaSecurityGroup(fakes.OS_SECURITY_GROUP_2)])
        resp = self.execute(
            'DeleteSecurityGroup',
            {'GroupId':
             fakes.ID_OS_SECURITY_GROUP_2})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])
        self.nova_security_groups.delete.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_2)

    def test_delete_security_group_invalid(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
        self.db_api.get_item_by_id.return_value = None
        resp = self.execute(
            'DeleteSecurityGroup',
            {'GroupId':
             fakes.ID_EC2_SECURITY_GROUP_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidGroup.NotFound',
                         resp['Error']['Code'])
        self.assertEqual(0, self.neutron.delete_port.call_count)
        resp = self.execute(
            'DeleteSecurityGroup',
            {'GroupName':
             'badname'})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidGroup.NotFound',
                         resp['Error']['Code'])
        self.assertEqual(0, self.neutron.delete_port.call_count)
        resp = self.execute(
            'DeleteSecurityGroup', {})
        self.assertEqual(400, resp['status'])
        self.assertEqual('MissingParameter',
                         resp['Error']['Code'])
        self.assertEqual(0, self.neutron.delete_port.call_count)

    def test_delete_security_group_is_in_use(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
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
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
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
                             fakes.EC2_SECURITY_GROUP_2],
                            orderless_lists=True))
        resp = self.execute('DescribeSecurityGroups',
                            {'GroupName.1': 'groupname2'})
        self.assertEqual(200, resp['status'])
        self.assertThat(resp['securityGroupInfo'],
                        matchers.ListMatches(
                            [fakes.EC2_SECURITY_GROUP_2],
                            orderless_lists=True))
        self.db_api.get_items_by_ids.return_value = [fakes.DB_SECURITY_GROUP_2]
        resp = self.execute('DescribeSecurityGroups',
                            {'GroupId.1': fakes.ID_EC2_SECURITY_GROUP_2})
        self.assertEqual(200, resp['status'])
        self.assertThat(resp['securityGroupInfo'],
                        matchers.ListMatches(
                            [fakes.EC2_SECURITY_GROUP_2],
                            orderless_lists=True))

    def test_describe_security_groups_nova(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNova())
        self.nova_security_groups.list.return_value = (
            [fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_1),
             fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_2)])
        resp = self.execute('DescribeSecurityGroups', {})
        self.assertEqual(200, resp['status'])
        self.assertThat(resp['securityGroupInfo'],
                        matchers.ListMatches(
                            [fakes.EC2_NOVA_SECURITY_GROUP_1,
                             fakes.EC2_NOVA_SECURITY_GROUP_2],
                            orderless_lists=True))

    def test_authorize_security_group_invalid(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())

        def check_response(error_code, protocol, from_port, to_port, cidr,
                           group_id=fakes.ID_EC2_SECURITY_GROUP_2):
            params = {'IpPermissions.1.FromPort': str(from_port),
                      'IpPermissions.1.ToPort': str(to_port),
                      'IpPermissions.1.IpProtocol': protocol}
            if group_id is not None:
                params['GroupId'] = group_id
            if cidr is not None:
                params['IpPermissions.1.IpRanges.1.CidrIp'] = cidr
            resp = self.execute(
                'AuthorizeSecurityGroupIngress', params)
            self.assertEqual(400, resp['status'])
            self.assertEqual(error_code, resp['Error']['Code'])
            self.neutron.reset_mock()
            self.db_api.reset_mock()

        resp = self.execute(
            'AuthorizeSecurityGroupIngress',
            {'GroupId': fakes.ID_EC2_SECURITY_GROUP_2,
             'IpPermissions.1.FromPort': '-1',
             'IpPermissions.1.ToPort': '-1',
             'IpPermissions.1.IpProtocol': 'icmp',
             'IpPermissions.1.IpRanges.1.CidrIp': '0.0.0.0/0'})
        self.assertEqual(200, resp['status'])
        # Duplicate rule
        self.db_api.get_item_by_id.side_effect = copy.deepcopy(
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_SECURITY_GROUP_1: fakes.DB_SECURITY_GROUP_1,
                fakes.ID_EC2_SECURITY_GROUP_2: fakes.DB_SECURITY_GROUP_2}))
        self.neutron.create_security_group_rule.side_effect = (
            neutron_exception.Conflict)
        check_response('InvalidPermission.Duplicate', 'icmp',
                       -1, -1, '0.0.0.0/0')
        # Over quota
        self.neutron.create_security_group_rule.side_effect = (
            neutron_exception.OverQuotaClient)
        check_response('RulesPerSecurityGroupLimitExceeded', 'icmp', -1, -1,
                       '0.0.0.0/0')
        # Invalid CIDR address
        check_response('InvalidParameterValue', 'tcp', 80, 81, '0.0.0.0/0444')
        # Missing ports
        check_response('InvalidParameterValue', 'tcp', -1, -1, '0.0.0.0/0')
        # from port cannot be greater than to port
        check_response('InvalidParameterValue', 'tcp', 100, 1, '0.0.0.0/0')
        # For tcp, negative values are not allowed
        check_response('InvalidParameterValue', 'tcp', -1, 1, '0.0.0.0/0')
        # For tcp, valid port range 1-65535
        check_response('InvalidParameterValue', 'tcp', 1, 65599, '0.0.0.0/0')
        # Invalid protocol
        check_response('InvalidParameterValue', 'xyz', 1, 14, '0.0.0.0/0')
        # Invalid port
        check_response('InvalidParameterValue', 'tcp', " ", "gg", '0.0.0.0/0')
        # Invalid icmp port
        check_response('InvalidParameterValue', 'icmp', " ", "gg", '0.0.0.0/0')
        # Invalid CIDR Address
        check_response('InvalidParameterValue', 'icmp', -1, -1, '0.0.0.0')
        # Invalid CIDR Address
        check_response('InvalidParameterValue', 'icmp', 5, 10, '0.0.0.0/')
        # Invalid Cidr ports
        check_response('InvalidParameterValue', 'icmp', 1, 256, '0.0.0.0/0')
        # Missing group
        check_response('MissingParameter', 'tcp', 1, 255, '0.0.0.0/0', None)
        # Missing cidr
        check_response('MissingParameter', 'tcp', 1, 255, None)
        # Invalid remote group
        resp = self.execute(
            'AuthorizeSecurityGroupIngress',
            {'GroupId': fakes.ID_EC2_SECURITY_GROUP_2,
             'IpPermissions.1.IpProtocol': 'icmp',
             'IpPermissions.1.Groups.1.GroupName': 'somegroup',
             'IpPermissions.1.Groups.1.UserId': 'i-99999999'})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidGroup.NotFound', resp['Error']['Code'])

    def test_authorize_security_group_ingress_ip_ranges(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
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
        # NOTE(Alex): Openstack extension, AWS-incompability
        # IPv6 is not supported by Amazon.
        resp = self.execute(
            'AuthorizeSecurityGroupIngress',
            {'GroupId': fakes.ID_EC2_SECURITY_GROUP_2,
             'IpPermissions.1.FromPort': '10',
             'IpPermissions.1.ToPort': '10',
             'IpPermissions.1.IpProtocol': 'tcp',
             'IpPermissions.1.IpRanges.1.CidrIp': '::/0'})
        self.assertEqual(200, resp['status'])
        self.neutron.create_security_group_rule.assert_called_with(
            {'security_group_rule':
             tools.patch_dict(
                fakes.OS_SECURITY_GROUP_RULE_1, {'remote_ip_prefix': '::/0'},
                {'id', 'remote_group_id', 'tenant_id'})})

    def test_authorize_security_group_ip_ranges_nova(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNova())
        self.nova_security_group_rules.create.return_value = (
            {'security_group_rule': [fakes.NOVA_SECURITY_GROUP_RULE_1]})
        self.nova_security_groups.list.return_value = (
            [fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_1),
             fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_2)])
        resp = self.execute(
            'AuthorizeSecurityGroupIngress',
            {'GroupName': fakes.EC2_NOVA_SECURITY_GROUP_2['groupName'],
             'IpPermissions.1.FromPort': '10',
             'IpPermissions.1.ToPort': '10',
             'IpPermissions.1.IpProtocol': 'tcp',
             'IpPermissions.1.IpRanges.1.CidrIp': '192.168.1.0/24'})
        self.assertEqual(200, resp['status'])
        self.nova_security_group_rules.create.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_2, 'tcp', 10, 10,
            '192.168.1.0/24', None)

    def test_authorize_security_group_egress_groups(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
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

    def test_authorize_security_group_groups_nova(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNova())
        self.nova_security_group_rules.create.return_value = (
            {'security_group_rule': [fakes.NOVA_SECURITY_GROUP_RULE_2]})
        self.nova_security_groups.list.return_value = (
            [fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_1),
             fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_2)])
        resp = self.execute(
            'AuthorizeSecurityGroupIngress',
            {'GroupName': fakes.EC2_NOVA_SECURITY_GROUP_2['groupName'],
             'IpPermissions.1.IpProtocol': 'icmp',
             'IpPermissions.1.Groups.1.GroupName':
             fakes.EC2_NOVA_SECURITY_GROUP_1['groupName']})
        self.assertEqual(200, resp['status'])
        self.nova_security_group_rules.create.assert_called_once_with(
            fakes.ID_OS_SECURITY_GROUP_2, 'icmp', -1, -1,
            None, fakes.ID_OS_SECURITY_GROUP_1)

    def test_revoke_security_group_ingress_ip_ranges(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
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

    def test_revoke_security_group_ingress_ip_ranges_nova(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNova())
        self.nova_security_groups.list.return_value = (
            [fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_1),
             fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_2)])
        self.nova_security_groups.get.return_value = (
            fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_2))
        self.nova_security_group_rules.delete.return_value = True
        resp = self.execute(
            'RevokeSecurityGroupIngress',
            {'GroupName': fakes.EC2_NOVA_SECURITY_GROUP_2['groupName'],
             'IpPermissions.1.FromPort': '10',
             'IpPermissions.1.ToPort': '10',
             'IpPermissions.1.IpProtocol': 'tcp',
             'IpPermissions.1.IpRanges.1.CidrIp': '192.168.1.0/24'})
        self.assertEqual(200, resp['status'])
        self.nova_security_group_rules.delete.assert_called_once_with(
            fakes.NOVA_SECURITY_GROUP_RULE_1['id'])

    def test_revoke_security_group_egress_groups(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNeutron())
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

    def test_revoke_security_group_groups_nova(self):
        security_group.security_group_engine = (
            security_group.SecurityGroupEngineNova())
        self.nova_security_groups.list.return_value = (
            [fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_1),
             fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_2)])
        self.nova_security_groups.get.return_value = (
            fakes.NovaSecurityGroup(fakes.NOVA_SECURITY_GROUP_2))
        self.nova_security_group_rules.delete.return_value = True
        resp = self.execute(
            'RevokeSecurityGroupIngress',
            {'GroupName': fakes.EC2_NOVA_SECURITY_GROUP_2['groupName'],
             'IpPermissions.1.IpProtocol': 'icmp',
             'IpPermissions.1.Groups.1.GroupName':
             fakes.EC2_NOVA_SECURITY_GROUP_1['groupName']})
        self.assertEqual(200, resp['status'])
        self.nova_security_group_rules.delete.assert_called_once_with(
            fakes.NOVA_SECURITY_GROUP_RULE_2['id'])
