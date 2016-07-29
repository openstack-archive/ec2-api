# Copyright 2014 OpenStack Foundation
# All Rights Reserved.
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

import time

from oslo_log import log
from tempest.lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF

LOG = log.getLogger(__name__)


class SecurityGroupBaseTest(base.EC2TestCase):

    def _test_rules(self, add_func, del_func, field, vpc_id=None):
        kwargs = dict()
        if vpc_id:
            kwargs['Filters'] = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
        data = self.client.describe_security_groups(*[], **kwargs)
        security_groups = data['SecurityGroups']
        if not vpc_id:
            # TODO(andrey-mp): remove it when fitering by None will be
            security_groups = [sg for sg in security_groups
                               if sg.get('VpcId') is None]
        default_group = security_groups[0]

        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        kwargs = {'GroupName': name, 'Description': desc}
        if vpc_id:
            kwargs['VpcId'] = vpc_id
        data = self.client.create_security_group(*[], **kwargs)
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.delete_security_group,
                                            GroupId=group_id)
        time.sleep(2)
        data = self.client.describe_security_groups(GroupIds=[group_id])
        count = len(data['SecurityGroups'][0][field])

        kwargs = {
            'GroupId': group_id,
            'IpPermissions': [{
                'IpProtocol': 'icmp',
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [{
                    'CidrIp': '10.0.0.0/8'
                }],
            }, {
                'UserIdGroupPairs': [{'GroupId': default_group['GroupId']}],
                'ToPort': 65535,
                'IpProtocol': 'tcp',
                'FromPort': 1
            }]
        }
        add_func(*[], **kwargs)

        data = self.client.describe_security_groups(GroupIds=[group_id])
        self.assertEqual(1, len(data['SecurityGroups']))
        self.assertEqual(count + 2, len(data['SecurityGroups'][0][field]))
        found = 0
        for perm in data['SecurityGroups'][0][field]:
            cidrs = [v['CidrIp'] for v in perm.get('IpRanges', [])]
            if (perm.get('FromPort') == -1 and
                    perm.get('ToPort') == -1 and
                    perm.get('IpProtocol') == 'icmp' and
                    len(perm.get('IpRanges')) == 1 and
                    '10.0.0.0/8' in cidrs):
                found = found + 1
            elif (perm.get('FromPort') == 1 and
                    perm.get('ToPort') == 65535 and
                    perm.get('IpProtocol') == 'tcp' and
                    len(perm.get('UserIdGroupPairs')) == 1 and
                    perm.get('UserIdGroupPairs')[0]['GroupId']
                    == default_group['GroupId']):
                found = found + 1
        self.assertEqual(2, found)

        del_func(*[], **kwargs)

        data = self.client.describe_security_groups(GroupIds=[group_id])
        self.assertEqual(1, len(data['SecurityGroups']))
        self.assertEqual(count, len(data['SecurityGroups'][0][field]))

        if vpc_id:
            self.assertRaises('InvalidPermission.NotFound', del_func, **kwargs)
        else:
            del_func(*[], **kwargs)

        self.client.delete_security_group(GroupId=group_id)
        self.cancelResourceCleanUp(res_clean)


class SecurityGroupInVPCTest(SecurityGroupBaseTest):

    VPC_CIDR = '10.10.0.0/20'
    vpc_id = None

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(SecurityGroupInVPCTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

        data = cls.client.create_vpc(CidrBlock=cls.VPC_CIDR)
        cls.vpc_id = data['Vpc']['VpcId']
        cls.addResourceCleanUpStatic(cls.client.delete_vpc, VpcId=cls.vpc_id)
        cls.get_vpc_waiter().wait_available(cls.vpc_id)

    def test_create_delete_security_group(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        data = self.client.create_security_group(VpcId=self.vpc_id,
                                                 GroupName=name,
                                                 Description=desc)
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.delete_security_group,
                                            GroupId=group_id)
        time.sleep(2)

        self.client.delete_security_group(GroupId=group_id)
        self.cancelResourceCleanUp(res_clean)

        self.assertRaises('InvalidGroup.NotFound',
                          self.client.describe_security_groups,
                          GroupIds=[group_id])

        self.assertRaises('InvalidGroup.NotFound',
                          self.client.delete_security_group,
                          GroupId=group_id)

    def test_create_duplicate_security_group(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        data = self.client.create_security_group(VpcId=self.vpc_id,
                                                 GroupName=name,
                                                 Description=desc)
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.delete_security_group,
                                            GroupId=group_id)
        time.sleep(2)

        self.assertRaises('InvalidGroup.Duplicate',
            self.client.create_security_group,
            VpcId=self.vpc_id, GroupName=name, Description=desc)

        data = self.client.delete_security_group(GroupId=group_id)
        self.cancelResourceCleanUp(res_clean)

    def test_create_duplicate_security_group_in_another_vpc(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        data = self.client.create_security_group(VpcId=self.vpc_id,
                                                 GroupName=name,
                                                 Description=desc)
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.delete_security_group,
                                            GroupId=group_id)
        time.sleep(2)

        data = self.client.create_vpc(CidrBlock=self.VPC_CIDR)
        vpc_id = data['Vpc']['VpcId']
        dv_clean = self.addResourceCleanUp(self.client.delete_vpc,
                                           VpcId=vpc_id)

        data = self.client.create_security_group(VpcId=vpc_id,
                                                 GroupName=name,
                                                 Description=desc)
        time.sleep(2)
        self.client.delete_security_group(GroupId=data['GroupId'])

        self.client.delete_vpc(VpcId=vpc_id)
        self.cancelResourceCleanUp(dv_clean)
        self.get_vpc_waiter().wait_delete(vpc_id)

        data = self.client.delete_security_group(GroupId=group_id)
        self.cancelResourceCleanUp(res_clean)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "MismatchError: 'InvalidParameterValue' != 'ValidationError'")
    def test_create_invalid_name_desc(self):
        valid = data_utils.rand_name('sgName')
        invalid = 'name%"'
        self.assertRaises('InvalidParameterValue',
                          self.client.create_security_group,
                          VpcId=self.vpc_id, GroupName=invalid,
                          Description=valid)

        self.assertRaises('InvalidParameterValue',
                          self.client.create_security_group,
                          VpcId=self.vpc_id, GroupName=valid,
                          Description=invalid)

        self.assertRaises('InvalidParameterValue',
                          self.client.create_security_group,
                          VpcId=self.vpc_id, GroupName='default',
                          Description='default')

        self.assertRaises('MissingParameter',
                          self.client.create_security_group,
                          VpcId=self.vpc_id, GroupName=valid, Description='')

        self.assertRaises('MissingParameter',
                          self.client.create_security_group,
                          VpcId=self.vpc_id, GroupName='', Description=valid)

    def test_ingress_rules(self):
        self._test_rules(self.client.authorize_security_group_ingress,
                         self.client.revoke_security_group_ingress,
                         'IpPermissions', self.vpc_id)

    def test_egress_rules(self):
        self._test_rules(self.client.authorize_security_group_egress,
                         self.client.revoke_security_group_egress,
                         'IpPermissionsEgress', self.vpc_id)


class SecurityGroupEC2ClassicTest(SecurityGroupBaseTest):

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(SecurityGroupEC2ClassicTest, cls).setUpClass()
        if not base.TesterStateHolder().get_ec2_enabled():
            raise cls.skipException('EC2-classic is disabled')

    def test_create_delete_security_group(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        data = self.client.create_security_group(GroupName=name,
                                                 Description=desc)
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.delete_security_group,
                                            GroupId=group_id)
        time.sleep(2)

        data = self.client.describe_security_groups(GroupNames=[name])
        self.assertEqual(1, len(data['SecurityGroups']))
        self.assertEqual(group_id, data['SecurityGroups'][0]['GroupId'])

        data = self.client.describe_security_groups(GroupIds=[group_id])
        self.assertEqual(1, len(data['SecurityGroups']))
        self.assertEqual(name, data['SecurityGroups'][0]['GroupName'])

        self.client.delete_security_group(GroupName=name)
        self.cancelResourceCleanUp(res_clean)

    def test_create_duplicate_security_group(self):
        name = data_utils.rand_name('sgName')
        desc = data_utils.rand_name('sgDesc')
        data = self.client.create_security_group(GroupName=name,
                                                 Description=desc)
        group_id = data['GroupId']
        res_clean = self.addResourceCleanUp(self.client.delete_security_group,
                                            GroupId=group_id)
        time.sleep(2)

        self.assertRaises('InvalidGroup.Duplicate',
            self.client.create_security_group,
            GroupName=name, Description=desc)

        self.client.delete_security_group(GroupId=group_id)
        self.cancelResourceCleanUp(res_clean)

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
        "MismatchError: 'MissingParameter' != 'ValidationError'")
    def test_create_invalid_name_desc(self):
        valid = data_utils.rand_name('sgName')

        self.assertRaises('MissingParameter',
            self.client.create_security_group,
            GroupName=valid, Description='')

        self.assertRaises('MissingParameter',
            self.client.create_security_group,
            GroupName='', Description=valid)

        self.assertRaises('InvalidGroup.Reserved',
            self.client.create_security_group,
            GroupName='default', Description='default')

    def test_ingress_rules(self):
        self._test_rules(self.client.authorize_security_group_ingress,
                         self.client.revoke_security_group_ingress,
                         'IpPermissions')

    def test_egress_rules(self):
        def _test():
            self._test_rules(
                self.client.authorize_security_group_egress,
                self.client.revoke_security_group_egress,
                'IpPermissionsEgress')

        self.assertRaises('InvalidParameterValue', _test)
