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

import time

from testtools import content as test_content

import tempest.cloudscaling.base as base
import tempest.cloudscaling.thirdparty.scenario.aws_compat.base as aws_base
import tempest.cloudscaling.utils as utils
from tempest.common.utils.linux import remote_client
from tempest import test
from tempest.thirdparty.boto.utils import wait as boto_wait

import logging
logging.getLogger('boto').setLevel(logging.CRITICAL)
LOG = logging.getLogger(__name__)


class VolumeBenchmarkTest(base.BaseBenchmarkTest, aws_base.BaseAWSTest):

    class Context:
        instance = None
        ssh = None
        volume = None
        part_lines = None
        volume_ready = False
        volume_filled = False
        snapshot = None

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(VolumeBenchmarkTest, cls).setUpClass()

        cls._load_benchmark_data("VolumeBenchmarkTest")

        cfg = cls.config.cloudscaling
        image_name = cfg.general_image_name
        cls.ssh_user = cfg.general_ssh_user_name
        cls.volume_size = cfg.volume_benchmark_volume_size_gb
        cls.volume_fill = cfg.volume_benchmark_volume_fill_percent
        cls.volume_attach_name = "sdh"
        cls.ctx = cls.Context()

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
        instance = reservation.instances[0]
        LOG.info("state: %s", instance.state)
        # NOTE(apavlov): wait until it runs (ec2-describe-instances INSTANCE)
        cls._wait_instance_state(instance, "running")
        cls.ctx.instance = instance

        ip_address = cls._prepare_public_ip(instance)
        ssh = remote_client.RemoteClient(ip_address,
                                         cls.ssh_user,
                                         pkey=cls.keypair.material)
        cls.ctx.ssh = ssh

    def _volume_state(self):
        self.ctx.volume.update(validate=True)
        return self.ctx.volume.status

    def _part_state(self):
        current = self.ctx.ssh.get_partitions().split('\n')
        if len(current) > len(self.ctx.part_lines):
            return 1
        if len(current) < len(self.ctx.part_lines):
            return -1
        return 0

    def _start_test(self):
        self.start_time = time.time()

    def _end_test(self, detail_description):
        end_time = time.time()
        self.test_time = end_time - self.start_time
        content = test_content.text_content(
            detail_description + " time: " + str(self.test_time) + "s")
        self.addDetail("Current", content)
        reference_time = self._get_benchmark_result()
        if reference_time is not None:
            content = test_content.text_content(
                "Min time: " + str(reference_time[0]) + "s, " +
                "Max time: " + str(reference_time[1]) + "s")
            self.addDetail("AWS", content)

    def _check_test(self):
        reference_time = self._get_benchmark_result()
        if reference_time is not None:
            self.assertLessEqual(self.test_time, float(reference_time[1]),
                str(self.test_time) + "s (current) > " +
                reference_time[1] + "s (AWS)")

    @test.attr(type='benchmark')
    def test_001_attach_volume(self):
        """Attach volume"""

        if self.ctx.ssh is None:
            raise self.skipException("Booting failed")

        self._start_test()

        # NOTE(apavlov): ec2-create-volume -z ZONE -s SIZE_GB
        zone = self.ctx.instance.placement
        volume = self.ec2_client.create_volume(self.volume_size, zone)
        self.addResourceCleanUp(self.destroy_volume_wait, volume)
        self.ctx.volume = volume
        # NOTE(apavlov): wait it (ec2-describe-volumes VOLUME)
        self.assertVolumeStatusWait(volume, "available")

        # NOTE(apavlov): ec2-attach-volume -d /dev/XXX -i INSTANCE VOLUME
        # and wait until it will be available
        self.ctx.part_lines = self.ctx.ssh.get_partitions().split('\n')
        volume.attach(self.ctx.instance.id, "/dev/" + self.volume_attach_name)

        # NOTE(apavlov): "attaching" invalid EC2 status #1074901
        self.assertVolumeStatusWait(self._volume_state, "in-use")
        boto_wait.re_search_wait(self._volume_state, "in-use")

        boto_wait.state_wait(self._part_state, 1)
        part_lines_new = self.ctx.ssh.get_partitions().split('\n')
        volume_name = utils.detect_new_volume(self.ctx.part_lines,
                                              part_lines_new)
        self.ctx.part_lines = part_lines_new

        self._end_test("Create and attach volume")

        self.ctx.ssh.exec_command("PATH=$PATH:/usr/sbin:/usr/bin "
            "&& sudo mkfs.ext3 /dev/" + volume_name)
        self.ctx.ssh.exec_command("sudo mkdir -m 777 /vol "
            "&& sudo mount /dev/" + volume_name + " /vol")
        self.ctx.volume_ready = True

        self._check_test()

    @test.attr(type='benchmark')
    def test_002_fill_volume(self):
        """Fill volume with data"""

        if self.ctx.ssh is None:
            raise self.skipException("Booting failed")
        if not self.ctx.volume_ready:
            raise self.skipException("Volume preparation failed")

        self._start_test()

        self.ctx.ssh.exec_command("sudo mkdir -m 777 /vol/data")
        file_lines = 102 * int(self.volume_size)
        for i in xrange(int(self.volume_fill)):
            self.ctx.ssh.exec_command("cat /dev/urandom "
                                      "| tr -d -c 'a-zA-Z0-9' "
                                      "| fold -w 1020 "
                                      "| head -n " + str(file_lines) +
                                      " > /vol/data/file" + str(i))

        self._end_test("Volume filling")

        self.ctx.volume_filled = True

        self._check_test()

    @test.attr(type='benchmark')
    def test_003_snapshot_volume(self):
        """Snapshot volume"""

        if self.ctx.ssh is None:
            raise self.skipException("Booting failed")
        if not self.ctx.volume_filled:
            raise self.skipException("Volume filling failed")

        self._start_test()

        snapshot = self.ec2_client.create_snapshot(self.ctx.volume.id)
        self.addResourceCleanUp(self.destroy_snapshot_wait, snapshot)
        self.assertSnapshotStatusWait(snapshot, "completed")

        self._end_test("Snapshot creation")

        self.ctx.snapshot = snapshot

        self._check_test()

    @test.attr(type='benchmark')
    def test_004_clone_volume_snapshot(self):
        """Clone volume"""

        if self.ctx.ssh is None:
            raise self.skipException("Booting failed")
        if self.ctx.snapshot is None:
            raise self.skipException("Snapshot of volume failed")

        self._start_test()

        zone = self.ctx.instance.placement
        volume2 = self.ec2_client.create_volume(
            self.volume_size, zone, snapshot=self.ctx.snapshot)
        self.addResourceCleanUp(self.destroy_volume_wait, volume2)
        # NOTE(apavlov): wait it (ec2-describe-volumes VOLUME)
        self.assertVolumeStatusWait(volume2, "available")

        self._end_test("Volume creation by snapshot")

        self._check_test()

    @test.attr(type='benchmark')
    def test_005_detach_volume(self):
        """Detach volume"""

        if self.ctx.ssh is None:
            raise self.skipException("Booting failed")
        if not self.ctx.volume_ready:
            raise self.skipException("Volume preparation failed")

        self._start_test()

        self.ctx.ssh.exec_command("sudo umount /vol")

        self.ctx.volume.detach()

        # NOTE(apavlov): "detaching" invalid EC2 status #1074901
        self.assertVolumeStatusWait(self._volume_state, "available")
        boto_wait.re_search_wait(self._volume_state, "available")

        self._end_test("Detach volume")

        boto_wait.state_wait(self._part_state, -1)

        self._check_test()
