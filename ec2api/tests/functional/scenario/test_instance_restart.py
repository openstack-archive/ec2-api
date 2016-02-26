# Copyright 2015 OpenStack Foundation
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

from oslo_log import log
from tempest.lib.common import ssh
from tempest.lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config
from ec2api.tests.functional.scenario import base as scenario_base

CONF = config.CONF
LOG = log.getLogger(__name__)


class InstanceRestartTest(scenario_base.BaseScenarioTest):

    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.run_long_tests, 'Slow test has skipped.')
    @testtools.skipUnless(CONF.aws.image_id_ubuntu,
                          "ubuntu image id is not defined")
    def test_stop_start_instance(self):
        key_name = data_utils.rand_name('testkey')
        pkey = self.create_key_pair(key_name)
        sec_group_name = self.create_standard_security_group()
        instance_id = self.run_instance(KeyName=key_name,
                                        ImageId=CONF.aws.image_id_ubuntu,
                                        SecurityGroups=[sec_group_name])

        ip_address = self.get_instance_ip(instance_id)
        ssh_client = ssh.Client(ip_address, CONF.aws.image_user_ubuntu,
                                pkey=pkey)
        ssh_client.exec_command('last -x')

        self.client.stop_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('stopped'))

        self.client.start_instances(InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        # Amazon can change auto-assigned public ip
        ip_address = self.get_instance_ip(instance_id)
        ssh_client = ssh.Client(ip_address, CONF.aws.image_user_ubuntu,
                                pkey=pkey)
        data = ssh_client.exec_command('last -x')
        self.assertIn("shutdown", data)

    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.run_long_tests, 'Slow test has skipped.')
    @testtools.skipUnless(CONF.aws.image_id_ubuntu,
                          "ubuntu image id is not defined")
    def test_reboot_instance(self):
        key_name = data_utils.rand_name('testkey')
        pkey = self.create_key_pair(key_name)
        sec_group_name = self.create_standard_security_group()
        instance_id = self.run_instance(KeyName=key_name,
                                        ImageId=CONF.aws.image_id_ubuntu,
                                        SecurityGroups=[sec_group_name])
        ip_address = self.get_instance_ip(instance_id)

        ssh_client = ssh.Client(ip_address, CONF.aws.image_user_ubuntu,
                                pkey=pkey)
        last_lines = ssh_client.exec_command('last -x').split('\n')

        self.client.reboot_instances(InstanceIds=[instance_id])

        def _last_state():
            current = ssh_client.exec_command('last -x').split('\n')
            if len(current) > len(last_lines):
                return
            raise Exception()

        waiter = base.EC2Waiter(_last_state)
        waiter.wait_no_exception()

        data = ssh_client.exec_command('last -x')
        self.assertIn("shutdown", data)
