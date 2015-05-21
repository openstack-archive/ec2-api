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

from testtools import content as test_content

import tempest.cloudscaling.base as base
import tempest.cloudscaling.thirdparty.scenario.aws_compat.base as aws_base
from tempest.common.utils.linux import remote_client
from tempest import test

import logging
logging.getLogger('boto').setLevel(logging.CRITICAL)
LOG = logging.getLogger(__name__)


class UnixBenchTest(base.BaseBenchmarkTest, aws_base.BaseAWSTest):
    """UnixBench set of tests used to test performance compatibility to AWS"""

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(UnixBenchTest, cls).setUpClass()

        cls._load_benchmark_data("UnixBenchTest")

        cfg = cls.config.cloudscaling
        image_name = cfg.general_image_name
        cls.ssh_user = cfg.general_ssh_user_name

        cls.image_id = cls._prepare_image_id(image_name)

        cls.keypair = cls._prepare_key_pair()
        sg = cls._prepare_security_group()
        cls.sec_group_name = sg.name
        # NOTE(apavlov): ec2-run-instances --key KEYPAIR IMAGE
        reservation = cls.ec2_client.run_instances(cls.image_id,
            instance_type=cls.instance_type,
            key_name=cls.keypair.name,
            security_groups=(cls.sec_group_name,))
        cls.addResourceCleanUp(cls.destroy_reservation, reservation)
        cls.instance = reservation.instances[0]
        LOG.info("state: %s", cls.instance.state)
        # NOTE(apavlov): wait until it runs (ec2-describe-instances INSTANCE)
        cls._wait_instance_state(cls.instance, "running")
        cls._prepare_public_ip(cls.instance)

        ip_address = cls._prepare_public_ip(cls.instance)
        cls.ssh = remote_client.RemoteClient(ip_address,
                                             cls.ssh_user,
                                             pkey=cls.keypair.material)

    @test.attr(type='benchmark')
    def test_run_benchmark(self):
        """Run UnixBench test on prepared instance"""
        if self.ssh is None:
            raise self.skipException("Booting failed")
        ssh = self.ssh

        self._correct_ns_if_needed(ssh)

        ssh.exec_command("sudo apt-get update && sudo apt-get upgrade -fy")
        ssh.exec_command("sudo apt-get update")
        ssh.exec_command("sudo apt-get install -y make gcc")
        ssh.exec_command("sudo apt-get install -y libx11-dev libgl1-mesa-dev "
                         "libxext-dev perl perl-modules")
        ssh.exec_command("wget http://byte-unixbench.googlecode.com/files"
                         "/UnixBench5.1.3.tgz")
        ssh.exec_command("tar xvf UnixBench5.1.3.tgz")
        resp = ssh.exec_command("cd UnixBench && ./Run")

        i = resp.find("---------------")
        if i != -1:
            resp = resp[i:]
        resp = "zone: " + self.instance.placement + "\n" + resp

        fail = None
        reference = self._get_benchmark_data()
        for k, v in reference.iteritems():
            i1 = resp.lower().find(k)
            if i1 == -1:
                continue

            k = resp[i1:i1 + len(k)]
            i2 = resp.find("\n", i1)
            outp = resp[i1 + len(k):i2].split()[:2]
            if len(outp) < 2:
                continue

            self.addDetail(k, test_content.text_content(
                outp[1] + "|" + outp[0] + "|Min: " + v[0] + "|Max: " + v[1]))

            if fail is None and float(outp[0]) < float(v[0]):
                fail = (outp[0], outp[1], k, v[0])

        if fail is not None:
            self.assertGreaterEqual(fail[0], fail[1],
                fail[2] + ": " +
                fail[0] + " " + fail[1] + " (current) < " +
                fail[3] + " " + fail[1] + " (AWS)")
