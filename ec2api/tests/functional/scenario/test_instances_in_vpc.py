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
from tempest.lib.common import ssh
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config
from ec2api.tests.functional.scenario import base as scenario_base

CONF = config.CONF
LOG = log.getLogger(__name__)


class InstancesInVPCTest(scenario_base.BaseScenarioTest):

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

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_instances_in_min_subnet(self):
        self._test_instances(28)

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_instances_in_max_subnet(self):
        self._test_instances(16)

    @base.skip_without_vpc()
    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_default_gateway(self):
        novpc_group = self.create_standard_security_group()
        novpc_instance_id = self.run_instance(SecurityGroups=[novpc_group])
        ping_destination = self.get_instance_ip(novpc_instance_id)

        data = self.client.create_vpc(CidrBlock='10.10.0.0/16')
        vpc_id = data['Vpc']['VpcId']
        self.addResourceCleanUp(self.client.delete_vpc, VpcId=vpc_id)
        self.get_vpc_waiter().wait_available(vpc_id)

        data = self.client.create_subnet(
            VpcId=vpc_id, CidrBlock='10.10.1.0/24',
            AvailabilityZone=CONF.aws.aws_zone)
        subnet_1_id = data['Subnet']['SubnetId']
        self.addResourceCleanUp(self.client.delete_subnet,
                                SubnetId=subnet_1_id)

        data = self.client.create_subnet(
            VpcId=vpc_id, CidrBlock='10.10.2.0/24',
            AvailabilityZone=CONF.aws.aws_zone)
        subnet_2_id = data['Subnet']['SubnetId']
        self.addResourceCleanUp(self.client.delete_subnet,
                                SubnetId=subnet_2_id)

        data = self.client.create_internet_gateway()
        gw_id = data['InternetGateway']['InternetGatewayId']
        self.addResourceCleanUp(self.client.delete_internet_gateway,
                                InternetGatewayId=gw_id)
        data = self.client.attach_internet_gateway(VpcId=vpc_id,
                                                   InternetGatewayId=gw_id)
        self.addResourceCleanUp(self.client.detach_internet_gateway,
                                VpcId=vpc_id, InternetGatewayId=gw_id)

        self.prepare_route(vpc_id, gw_id)

        data = self.client.create_route_table(VpcId=vpc_id)
        rt_id = data['RouteTable']['RouteTableId']
        self.addResourceCleanUp(self.client.delete_route_table,
                                RouteTableId=rt_id)
        data = self.client.associate_route_table(RouteTableId=rt_id,
                                                 SubnetId=subnet_2_id)
        assoc_id = data['AssociationId']
        self.addResourceCleanUp(self.client.disassociate_route_table,
                                AssociationId=assoc_id)

        self.prepare_vpc_default_security_group(vpc_id)
        key_name = data_utils.rand_name('testkey')
        pkey = self.create_key_pair(key_name)

        instance_2_id = self.run_instance(KeyName=key_name,
                                          SubnetId=subnet_2_id)
        instance_1_id = self.run_instance(KeyName=key_name,
                                          SubnetId=subnet_1_id,
                                          UserData=pkey)
        ip_address = self.get_instance_ip(instance_1_id)
        ip_private_address_1 = self.get_instance(
            instance_1_id)['PrivateIpAddress']
        ip_private_address_2 = self.get_instance(
            instance_2_id)['PrivateIpAddress']

        ssh_client = ssh.Client(ip_address, CONF.aws.image_user, pkey=pkey,
                                channel_timeout=30)

        ssh_client.exec_command(
            'curl http://169.254.169.254/latest/user-data > key.pem && '
            'chmod 400 key.pem')
        if 'cirros' in ssh_client.exec_command('cat /etc/issue'):
            ssh_client.exec_command(
                'dropbearconvert openssh dropbear key.pem key.db && '
                'mv key.db key.pem')
            extra_ssh_opts = '-y'
        else:
            extra_ssh_opts = ('-o UserKnownHostsFile=/dev/null '
                              '-o StrictHostKeyChecking=no')

        ssh_client.exec_command('ping -c 1 %s' % ip_private_address_2)
        ssh_client.exec_command('ping -c 1 %s' % ping_destination)
        remote_ping_template = (
            'ssh -i key.pem %(extra_opts)s %(user)s@%(ip)s '
            'ping -c 1 %%s' %
            {'extra_opts': extra_ssh_opts,
             'user': CONF.aws.image_user,
             'ip': ip_private_address_2})
        ssh_client.exec_command(remote_ping_template % ip_private_address_1)
        try:
            resp = ssh_client.exec_command(remote_ping_template %
                                           ping_destination)
        except exceptions.SSHExecCommandFailed:
            pass
        else:
            self.assertEqual('', resp)
