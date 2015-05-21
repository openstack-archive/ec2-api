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

import threading

import boto.exception
import netaddr

from tempest.cloudscaling import base
import tempest.cloudscaling.thirdparty.scenario.aws_compat.base as aws_base
from tempest.common.utils.linux import remote_client
from tempest import test
from tempest.thirdparty.boto.utils import wait as boto_wait

import logging
logging.getLogger('boto').setLevel(logging.CRITICAL)


class VPC_Behavior_Base(aws_base.BaseVPCTest):
    """Base class for AWS VPC behavior tests."""

    @classmethod
    def _run_instance(cls, subnet, private_ip=None):
        params = {
            "key_name": cls.keypair.name,
            "instance_type": cls.instance_type,
            "placement": cls.zone,
            "subnet_id": subnet.id,
        }
        if private_ip:
            params["private_ip_address"] = str(private_ip)
        reservation = cls.vpc_client.run_instances(cls.image_id,
                                                   **params)
        if reservation is None:
            raise base.TestCasePreparationError()
        cls.addResourceCleanUp(cls.destroy_reservation, reservation)
        if len(reservation.instances) != 1:
            raise base.TestCasePreparationError()
        instance = reservation.instances[0]
        return instance


class VPC_Behavior(VPC_Behavior_Base):
    """Test various behavior of VPC network."""

    class TcpDumpRunner(object):
        timeout = None

        def __init__(self, instance, ssh_user, ssh_keypair, parameters):
            ssh = remote_client.RemoteClient(instance.ip_address,
                                             ssh_user,
                                             pkey=ssh_keypair.material)
            ssh.ssh_client.channel_timeout = float(self.timeout)
            self.ssh = ssh
            self.parameters = parameters
            self.thread = None

        def __enter__(self):
            self.ssh.exec_command("rm -f tcpdump.log")
            thread = threading.Thread(target=self._run_tcpdump)
            thread.start()
            self._sync()
            self.thread = thread
            return self

        def __exit__(self, ex_type, ex_value, ex_traceback):
            self.stop()

        def _run_tcpdump(self):
            self.ssh.exec_command("sudo tcpdump %s >tcpdump.log 2>&1" %
                                  self.parameters)

        def _sync(self):
            def check_tcpdump_is_ready():
                resp = self.ssh.exec_command("test -f tcpdump.log && echo 1 "
                                             "|| echo 0")
                return int(resp) == 1
            boto_wait.state_wait(check_tcpdump_is_ready, True)

        def stop(self):
            if self.thread is None:
                return
            self.ssh.exec_command("sudo pkill -SIGINT tcpdump")
            thread = self.thread
            self.thread = None
            thread.join(float(self.timeout))
            return not thread.is_alive()

        def get_result(self):
            resp = self.ssh.exec_command("cat tcpdump.log")
            return resp

    class Context(object):
        instance3 = None
        lease_file = None
        gateway = None

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(VPC_Behavior, cls).setUpClass()
        cls.TcpDumpRunner.timeout = cls.config.boto.build_timeout
        cls.subnet = cls._prepare_vpc(cls.vpc_cidr, cls.subnet_cidr)
        cls.instance1 = cls._run_instance(cls.subnet)
        cls.instance2 = cls._run_instance(cls.subnet)
        cls._wait_instance_state(cls.instance1, "running")
        cls._wait_instance_state(cls.instance2, "running")
        cls.instance1.ip_address = cls._prepare_public_ip(cls.instance1)
        ssh = remote_client.RemoteClient(cls.instance1.ip_address,
                                         cls.ssh_user,
                                         pkey=cls.keypair.material)
        ssh.exec_command("sudo apt-get update")
        ssh.exec_command("sudo DEBIAN_FRONTEND=noninteractive apt-get -fqy "
                         "install socat nmap")
        cls.ctx = cls.Context()

    def test_011_check_network_gateway(self):
        """Is gateway local to subnet?"""
        ssh = remote_client.RemoteClient(self.instance1.ip_address,
                                         self.ssh_user,
                                         pkey=self.keypair.material)
        resp = ssh.exec_command("route -n | awk '{ if ($1==\"0.0.0.0\" && "
                                "$4 ~ /.*G.*/) print $2 }'")
        lines = resp.splitlines()
        self.assertEqual(1, len(lines))
        gateway = netaddr.IPAddress(lines[0])
        self.ctx.gateway = gateway
        self.assertTrue(gateway in self.subnet_cidr)

    def test_012_check_dhcp_grant_ip(self):
        """Whether dhcp provide IP address?"""
        instance = self._run_instance(self.subnet)
        state = self.waitInstanceState(instance, "running")
        if state != "running":
            raise base.TestCasePreparationError()
        self.assertTrue(instance.private_ip_address)
        instance.ip_address = self._prepare_public_ip(instance)
        self.ctx.instance3 = instance

    def test_013_check_dhcp_lease(self):
        """Whether IP address was obtained by dhcp?"""
        if self.ctx.instance3 is None:
            self.skipTest("Instance 3 was not initialized")
        ssh = remote_client.RemoteClient(self.ctx.instance3.ip_address,
                                         self.ssh_user,
                                         pkey=self.keypair.material)
        resp = ssh.exec_command("ps -eo comm,args | grep -m 1 dhclient")
        args = resp.split()
        if len(args) <= 2 or not args[0].startswith('dhclient'):
            raise base.TestCasePreparationError()
        is_lf = False
        lease_file = "/var/lib/dhcp/dhclient.leases"
        for arg in args:
            if is_lf:
                lease_file = arg
                is_lf = False
            elif arg == "-lf":
                is_lf = True
        resp = ssh.exec_command("test -f %s && echo 1 || echo 0" % lease_file)
        self.assertEqual(1, int(resp))
        self.ctx.lease_file = lease_file
        resp = ssh.exec_command("grep 'fixed-address ' %s | tail -n 1 | "
                                "awk '{ print $2 }' | sed -e 's/;//'" %
                                lease_file)
        lines = resp.splitlines()
        self.assertEqual(1, len(lines))
        self.assertEqual(self.ctx.instance3.private_ip_address, lines[0])
        date = ssh.exec_command("date -u +%Y/%m/%d%H:%M:%S")
        self.assertTrue(date)
        resp = ssh.exec_command("grep 'renew ' %s | tail -n 1 | "
                                "awk '{ print $3$4 }' | sed -e 's/;//'" %
                                lease_file)
        self.assertLess(date, resp)

    def test_014_check_dhcp_sends_mtu_size(self):
        """Check DHCP sends MTU size."""
        if self.ctx.lease_file is None:
            self.skipTest("Dhcp lease file was not found")
        ssh = remote_client.RemoteClient(self.ctx.instance3.ip_address,
                                         self.ssh_user,
                                         pkey=self.keypair.material)
        resp = ssh.exec_command("grep 'option interface-mtu ' %s" %
                                self.ctx.lease_file)
        self.assertLess(0, len(resp.splitlines()))

    def test_015_check_dhcp_distribute_host_name_size(self):
        """Check DHCP distributes host hame."""
        if self.ctx.lease_file is None:
            self.skipTest("Dhcp lease file was not found")
        ssh = remote_client.RemoteClient(self.ctx.instance3.ip_address,
                                         self.ssh_user,
                                         pkey=self.keypair.material)
        resp = ssh.exec_command("grep 'option host-name ' %s" %
                                self.ctx.lease_file)
        self.assertLess(0, len(resp.splitlines()))

    def test_021_check_traffic_visibility(self):
        """Are other VMs visible?"""
        if self.ctx.instance3 is None:
            self.skipTest("Instance 3 was not initialized")
        with self.TcpDumpRunner(self.ctx.instance3,
                                self.ssh_user,
                                self.keypair,
                                "ip proto \\\\icmp") as tdump:
            ssh = remote_client.RemoteClient(self.instance1.ip_address,
                                             self.ssh_user,
                                             pkey=self.keypair.material)
            ssh.exec_command("ping -c 1 %s" %
                             self.instance2.private_ip_address)
            if not tdump.stop():
                raise base.TestCasePreparationError()
            resp = tdump.get_result()
        for line in resp.splitlines():
            if line.endswith("packets captured"):
                captured = line
                break
        tokens = captured.split()
        packets = int(tokens[0])
        self.assertEqual(0, packets)

    def test_022_check_broadcast_visible(self):
        """Is broadcast traffic visible?"""
        if self.ctx.instance3 is None:
            self.skipTest("Instance 3 was not initialized")
        with self.TcpDumpRunner(self.ctx.instance3,
                                self.ssh_user,
                                self.keypair,
                                "ip broadcast") as tdump:
            ssh = remote_client.RemoteClient(self.instance1.ip_address,
                                             self.ssh_user,
                                             pkey=self.keypair.material)
            ssh.exec_command("echo ping |"
                             "socat - UDP4-DATAGRAM:255.255.255.255:6666,"
                             "broadcast")
            if not tdump.stop():
                raise base.TestCasePreparationError()
            resp = tdump.get_result()
        captured = ""
        for line in resp.splitlines():
            if line.endswith(" captured"):
                captured = line
                break
        tokens = captured.split()
        packets = int(tokens[0])
        self.assertEqual(0, packets)

    def test_023_check_multicast_visible(self):
        """Is multicast traffic visible?"""
        if self.ctx.instance3 is None:
            self.skipTest("Instance 3 was not initialized")
        with self.TcpDumpRunner(self.ctx.instance3,
                                self.ssh_user,
                                self.keypair,
                                "ip multicast") as tdump:
            ssh = remote_client.RemoteClient(self.instance1.ip_address,
                                             self.ssh_user,
                                             pkey=self.keypair.material)
            ssh.exec_command("echo ping |"
                             "socat - UDP4-DATAGRAM:239.1.1.1:6666")
            if not tdump.stop():
                raise base.TestCasePreparationError()
            resp = tdump.get_result()
        captured = ""
        for line in resp.splitlines():
            if line.endswith(" captured"):
                captured = line
                break
        tokens = captured.split()
        packets = int(tokens[0])
        self.assertEqual(0, packets)

    def test_031_scan_gateway_ports(self):
        """Are gateway ports closed?"""
        if self.ctx.gateway is None:
            self.skipTest("Subnet's gateway was not found")
        ssh = remote_client.RemoteClient(self.instance1.ip_address,
                                         self.ssh_user,
                                         pkey=self.keypair.material)
        ssh.ssh_client.channel_timeout = 600
        resp = ssh.exec_command("sudo nmap -PN %s" % str(self.ctx.gateway))
        all_closed_msg = ("All 1000 scanned ports on %s are " %
                          str(self.ctx.gateway))
        for line in resp.splitlines():
            if line.startswith(all_closed_msg):
                return
        self.fail("Some gateway ports are open")
