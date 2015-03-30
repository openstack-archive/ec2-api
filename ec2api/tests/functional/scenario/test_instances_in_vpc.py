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

import netaddr
from oslo_log import log
from tempest_lib.common.utils import data_utils

from ec2api.tests.functional import base
from ec2api.tests.functional import config
from ec2api.tests.functional.scenario import base as scenario_base
from ec2api.tests.functional import ssh

CONF = config.CONF
LOG = log.getLogger(__name__)


class InstancesInVPCTest(scenario_base.BaseScenarioTest):

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(InstancesInVPCTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')
        if not CONF.aws.image_id:
            raise cls.skipException('aws image_id does not provided')

    def _test_instances(self, subnet_size):
        cidr = netaddr.IPNetwork('10.20.0.0/8')
        cidr.prefixlen = subnet_size
        vpc_id, subnet_id = self.create_vpc_and_subnet(str(cidr))
        gw_id = self.create_and_attach_internet_gateway(vpc_id)
        self.prepare_vpc_default_security_group(vpc_id)
        self.prepare_route(vpc_id, gw_id)

        key_name = data_utils.rand_name('testkey')
        pkey = self.create_key_pair(key_name)

        first_ip = str(netaddr.IPAddress(cidr.first + 4))
        last_ip = str(netaddr.IPAddress(cidr.last - 1))
        instance_id1 = self.run_instance(KeyName=key_name, SubnetId=subnet_id,
            PrivateIpAddress=first_ip)
        instance_id2 = self.run_instance(KeyName=key_name, SubnetId=subnet_id,
            PrivateIpAddress=last_ip)
        instance = self.get_instance(instance_id1)
        self.assertEqual(first_ip, instance['PrivateIpAddress'])
        instance = self.get_instance(instance_id2)
        self.assertEqual(last_ip, instance['PrivateIpAddress'])

        ip_address = self.get_instance_ip(instance_id1)
        ssh_client = ssh.Client(ip_address, CONF.aws.image_user, pkey=pkey)

        waiter = base.EC2Waiter(ssh_client.exec_command)
        waiter.wait_no_exception('ping %s -c 1' % last_ip)

    def test_instances_in_min_subnet(self):
        self._test_instances(28)

    def test_instances_in_max_subnet(self):
        self._test_instances(16)
