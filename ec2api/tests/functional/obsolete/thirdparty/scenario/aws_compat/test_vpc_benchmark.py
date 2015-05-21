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

import select

from testtools import content as test_content

from tempest.cloudscaling import base
import tempest.cloudscaling.thirdparty.scenario.aws_compat.base as aws_base
from tempest.common.utils.linux import remote_client
from tempest import exceptions
from tempest import test

import logging
logging.getLogger('boto').setLevel(logging.CRITICAL)


class IPerfServer(object):
    """Wrapper to use iperf server in tests."""
    cmd = "iperf -s"

    def __init__(self, instance, ssh_user, ssh_keypair):
        self.instance = instance
        self.ssh_user = ssh_user
        self.ssh_keypair = ssh_keypair

    def __enter__(self):
        # NOTE(ft): Iperf doesn't close stdout in server mode
        # but standard exec_command waits for it
        # so instead of use it we waits for some string in output
        ssh = remote_client.RemoteClient(self.instance.ip_address,
                                         self.ssh_user,
                                         pkey=self.ssh_keypair.material)
        ssh_conn = ssh.ssh_client._get_ssh_connection()
        chan = ssh_conn.get_transport().open_session()
        chan.get_pty()  # NOTE(ft): to stop iperf with session end
        chan.fileno()
        chan.exec_command(self.cmd)

        started = False
        out_data = []
        err_data = []
        select_params = [chan], [], [], ssh.ssh_client.channel_timeout
        while True:
            ready = select.select(*select_params)
            if not any(ready):
                raise exceptions.TimeoutException(
                    "Cannot start iperf server on host '{1}'.".format(
                        self.host))
            if not ready[0]:
                continue
            out_chunk = err_chunk = None
            if chan.recv_ready():
                out_chunk = chan.recv(ssh.ssh_client.buf_size)
                out_data += out_chunk,
            if chan.recv_stderr_ready():
                err_chunk = chan.recv_stderr(ssh.ssh_client.buf_size)
                err_data += err_chunk,
            if chan.exit_status_ready():
                exit_status = chan.recv_exit_status()
                if 0 != exit_status or len(err_data) > 0:
                    raise exceptions.SSHExecCommandFailed(
                        command=self.cmd, exit_status=exit_status,
                        strerror=''.join(err_data))
            lines = ''.join(out_data).splitlines()
            for line in lines:
                if line.startswith("Server listening"):
                    started = True
                    break
            if (started or
                    chan.closed and not err_chunk and not out_chunk):
                break
        self.ssh = ssh
        self.ssh_conn = ssh_conn
        self.chan = chan

    def __exit__(self, ex_type, ex_value, ex_traceback):
        self.chan.close()
        self.ssh_conn.close()


class VPC_Benchmark(aws_base.BaseVPCTest, base.BaseBenchmarkTest):
    """Benchmark VPC network throughput."""

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(VPC_Benchmark, cls).setUpClass()
        cls.keypair = cls._prepare_key_pair()
        subnet = cls._prepare_vpc(cls.vpc_cidr, cls.subnet_cidr)

        reservation = cls.vpc_client.run_instances(
            cls.image_id,
            min_count=2, max_count=2,
            key_name=cls.keypair.name,
            instance_type=cls.instance_type,
            placement=cls.zone,
            subnet_id=subnet.id)
        if reservation is None:
            raise base.TestCasePreparationError()
        cls.addResourceCleanUp(cls.destroy_reservation, reservation)
        if len(reservation.instances) != 2:
            raise base.TestCasePreparationError()
        cls.instance1 = reservation.instances[0]
        cls.instance2 = reservation.instances[1]
        cls._wait_instance_state(cls.instance1, "running")
        cls._wait_instance_state(cls.instance2, "running")
        cls._prepare_public_ip(cls.instance1)
        cls._prepare_public_ip(cls.instance2)

        def install_iperf(instance):
            try:
                ssh = remote_client.RemoteClient(instance.ip_address,
                                                 cls.ssh_user,
                                                 pkey=cls.keypair.material)
            except exceptions.SSHTimeout:
                raise base.TestCasePreparationError()
            ssh.exec_command("sudo apt-get update && sudo apt-get upgrade -y")
            ssh.exec_command("sudo apt-get update")
            ssh.exec_command("sudo apt-get install iperf")
        install_iperf(cls.instance1)
        install_iperf(cls.instance2)

        cfg = cls.config.cloudscaling
        cls.network_performance_class = cfg.network_performance_class
        cls._load_benchmark_data("AWS_VPC_Benchmark")

    def _get_rate(self, resp):
        resp_items = resp.split(",")
        rate = resp_items[len(resp_items) - 1]
        return int(rate) / 1000000

    def _check_test(self, rate):
        if not self.network_performance_class:
            return
        reference = self._get_benchmark_result(self.network_performance_class)
        if reference is not None:
            content = test_content.text_content(
                "Min rate: %sMbits/sec, Max rate: %sMBits/sec" %
                (reference[0], reference[1]))
            self.addDetail("AWS", content)
            self.assertGreaterEqual(rate, float(reference[0]),
                "%sMbits/sec (current) < %sMbits/sec (AWS)" %
                (rate, reference[0]))

    @test.attr(type='benchmark')
    def test_001_internal_vpc_tcp_150MB_throughput(self):
        """Measure internal VPC network throughput for 150 MBytes transmit."""
        if self.keypair is None:
            self.skipTest("Environment was not initialized")
        with IPerfServer(self.instance1, self.ssh_user, self.keypair):
            ssh = remote_client.RemoteClient(self.instance2.ip_address,
                                             self.ssh_user,
                                             pkey=self.keypair.material)
            resp = ssh.exec_command("iperf -c %s -n 150M -x CMSV -y C" %
                                    self.instance1.private_ip_address)
        rate = self._get_rate(resp)
        self.addDetail("Current", test_content.text_content(
            "150 MBytes throughput: %s Mbits/sec" % rate))
        self._check_test(rate)

    @test.attr(type='benchmark')
    def test_002_internal_vpc_tcp_2mins_throughput(self):
        """Measure internal VPC network throughput for 2 mins transmit."""
        if self.keypair is None:
            self.skipTest("Environment was not initialized")
        with IPerfServer(self.instance1, self.ssh_user, self.keypair):
            ssh = remote_client.RemoteClient(self.instance2.ip_address,
                                             self.ssh_user,
                                             pkey=self.keypair.material)
            ssh.ssh_client.channel_timeout = 130
            resp = ssh.exec_command("iperf -c %s -t 120 -x CMSV -y C" %
                                    self.instance1.private_ip_address)
        rate = self._get_rate(resp)
        self.addDetail("Current", test_content.text_content(
            "2 mins throughput: %s Mbits/sec" % rate))
        self._check_test(rate)
