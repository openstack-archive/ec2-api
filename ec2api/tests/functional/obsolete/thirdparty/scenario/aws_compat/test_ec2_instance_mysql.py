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

import tempest.cloudscaling.thirdparty.scenario.aws_compat.base as aws_base
import tempest.cloudscaling.utils as utils
from tempest.common.utils.linux import remote_client
from tempest import test
from tempest.thirdparty.boto.utils import wait as boto_wait

import logging
logging.getLogger('boto').setLevel(logging.CRITICAL)
LOG = logging.getLogger(__name__)


class InstanceMySQLTest(aws_base.BaseAWSTest):
    """
    Test 'Running MySQL on Amazon' (http://aws.amazon.com/articles/1663)
    """
    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(InstanceMySQLTest, cls).setUpClass()

        cfg = cls.config.cloudscaling
        image_name = cfg.mysql_image_name
        cls.ssh_user = cfg.mysql_ssh_user_name
        cls.volume_attach_name = "sdh"

        cls.image_id = cls._prepare_image_id(image_name)

        cls.keypair = cls._prepare_key_pair()
        sg = cls._prepare_security_group()
        cls.sec_group_name = sg.name

    def test_integration_mysql(self):
        """Test based on http://aws.amazon.com/articles/1663"""

        snapshot = self._run_scenario(self._create_mysql_db)

        self._run_scenario(self._restore_mysql_db, snapshot=snapshot)

    def _run_scenario(self, scenario_func, snapshot=None):
        # NOTE(apavlov): ec2-run-instances --key KEYPAIR IMAGE
        reservation = self.ec2_client.run_instances(self.image_id,
            instance_type=self.instance_type,
            key_name=self.keypair.name,
            security_groups=(self.sec_group_name,))
        self.addResourceCleanUp(self.destroy_reservation, reservation)
        instance = reservation.instances[0]
        LOG.info("state: %s", instance.state)
        # NOTE(apavlov): wait until it runs (ec2-describe-instances INSTANCE)
        if instance.state != "running":
            self.assertInstanceStateWait(instance, "running")

        # NOTE(apavlov): ec2-create-volume -z ZONE -s SIZE_GB
        zone = instance.placement
        volume = self.ec2_client.create_volume(1, zone, snapshot=snapshot)
        self.addResourceCleanUp(self.destroy_volume_wait, volume)
        # NOTE(apavlov): wait it (ec2-describe-volumes VOLUME)
        self.assertVolumeStatusWait(volume, "available")

        ip_address = self._prepare_public_ip(instance)
        ssh = remote_client.RemoteClient(ip_address,
                                         self.ssh_user,
                                         pkey=self.keypair.material)

        # NOTE(apavlov): ec2-attach-volume -d /dev/XXX -i INSTANCE VOLUME
        # and wait until it will be available
        part_lines = ssh.get_partitions().split('\n')
        volume.attach(instance.id, "/dev/" + self.volume_attach_name)

        def _volume_state():
            volume.update(validate=True)
            return volume.status

        self.assertVolumeStatusWait(_volume_state, "in-use")
        boto_wait.re_search_wait(_volume_state, "in-use")

        def _part_state():
            current = ssh.get_partitions().split('\n')
            if len(current) > len(part_lines):
                return 1
            if len(current) < len(part_lines):
                return -1
            return 0

        boto_wait.state_wait(_part_state, 1)
        part_lines_new = ssh.get_partitions().split('\n')
        self.volume_name = utils.detect_new_volume(part_lines, part_lines_new)
        part_lines = part_lines_new

        self._correct_ns_if_needed(ssh)

        snapshot = scenario_func(ssh, volume.id)

        # NOTE(apavlov): stop this instance(imagine that it will be used)
        instance.stop()
        LOG.info("state: %s", instance.state)
        if instance.state != "stopped":
            self.assertInstanceStateWait(instance, "stopped")

        return snapshot

    def _create_mysql_db(self, ssh, volume_id):
        ssh.exec_command("sudo apt-get update && sudo apt-get upgrade -fy")

        # install mysql
        ssh.exec_command("echo mysql-server-5.1 mysql-server/"
            "root_password password rootpass | sudo debconf-set-selections"
            "&& echo mysql-server-5.1 mysql-server/"
            "root_password_again password rootpass "
            "| sudo debconf-set-selections"
            "&& echo mysql-server-5.1 mysql-server/"
            "start_on_boot boolean true | sudo debconf-set-selections")
        ssh.exec_command("sudo apt-get install -y xfsprogs mysql-server")

        ssh.exec_command("grep -q xfs /proc/filesystems || sudo modprobe xfs")
        ssh.exec_command("sudo mkfs.xfs /dev/" + self.volume_name)
        ssh.exec_command("echo '/dev/" + self.volume_name
                         + " /vol xfs noatime 0 0' "
                         "| sudo tee -a /etc/fstab")
        ssh.exec_command("sudo mkdir -m 000 /vol && sudo mount /vol")

        # NOTE(apavlov): Move the existing database files to the EBS volume.
        ssh.exec_command("sudo /etc/init.d/mysql stop"
            "&& sudo mkdir /vol/etc /vol/lib /vol/log"
            "&& sudo mv /etc/mysql     /vol/etc/"
            "&& sudo mv /var/lib/mysql /vol/lib/"
            "&& sudo mv /var/log/mysql /vol/log/")

        ssh.exec_command("sudo mkdir /etc/mysql"
            "&& sudo mkdir /var/lib/mysql"
            "&& sudo mkdir /var/log/mysql")

        ssh.exec_command("echo '/vol/etc/mysql /etc/mysql     none bind' "
            "| sudo tee -a /etc/fstab"
            "&& sudo mount /etc/mysql")

        ssh.exec_command("echo '/vol/lib/mysql /var/lib/mysql none bind' "
            "| sudo tee -a /etc/fstab"
            "&& sudo mount /var/lib/mysql")

        ssh.exec_command("echo '/vol/log/mysql /var/log/mysql none bind' "
            "| sudo tee -a /etc/fstab"
            "&& sudo mount /var/log/mysql")
        ssh.exec_command("sudo /etc/init.d/mysql start")

        # NOTE(apavlov): add test DB
        ssh.exec_command("mysql -u root --password=rootpass -e "
                         "'CREATE DATABASE tutorial_sample'")

        resp = ssh.exec_command("mysql -u root --password=rootpass "
                                "-e 'SHOW DATABASES'")
        self.assertIn("tutorial_sample", resp)

        # NOTE(apavlov): make snapshot
        ssh.exec_command("mysql -u root --password=rootpass -e '"
            "FLUSH TABLES WITH READ LOCK;"
            "SHOW MASTER STATUS;"
            "SYSTEM sudo xfs_freeze -f /vol;'")

        snapshot = self.ec2_client.create_snapshot(volume_id)
        self.addResourceCleanUp(self.destroy_snapshot_wait, snapshot)
        self.assertSnapshotStatusWait(snapshot, "completed")

        ssh.exec_command("mysql -u root --password=rootpass -e '"
            "SYSTEM sudo xfs_freeze -u /vol;"
            "UNLOCK TABLES;'")

        # NOTE(apavlov): cleanup
        ssh.exec_command("sudo /etc/init.d/mysql stop"
            "&& sudo umount /etc/mysql /var/lib/mysql /var/log/mysql /vol")

        return snapshot

    def _restore_mysql_db(self, ssh, volume_id):
        ssh.exec_command("sudo apt-get update")
        ssh.exec_command("sudo apt-get upgrade -y")

        # install mysql
        ssh.exec_command("export DEBIAN_FRONTEND=noninteractive")
        ssh.exec_command("sudo -E apt-get install -y xfsprogs mysql-server")

        ssh.exec_command("echo '/dev/" + self.volume_name
                         + " /vol xfs noatime 0 0' "
                         "| sudo tee -a /etc/fstab")
        ssh.exec_command("sudo mkdir -m 000 /vol")
        ssh.exec_command("sudo mount /vol")

        ssh.exec_command("sudo find /vol/{lib,log}/mysql/ ! -user root -print0"
                         " | sudo xargs -0 -r chown mysql")
        ssh.exec_command("sudo find /vol/{lib,log}/mysql/ ! -group root -a !"
                         " -group adm -print0 | sudo xargs -0 -r chgrp mysql")
        ssh.exec_command("sudo /etc/init.d/mysql stop")
        ssh.exec_command("echo '/vol/etc/mysql /etc/mysql     none bind' "
                         "| sudo tee -a /etc/fstab")
        ssh.exec_command("sudo mount /etc/mysql")
        ssh.exec_command("echo '/vol/lib/mysql /var/lib/mysql none bind' "
                         "| sudo tee -a /etc/fstab")
        ssh.exec_command("sudo mount /var/lib/mysql")
        ssh.exec_command("echo '/vol/log/mysql /var/log/mysql none bind' "
                         "| sudo tee -a /etc/fstab")
        ssh.exec_command("sudo mount /var/log/mysql")
        ssh.exec_command("sudo /etc/init.d/mysql start")

        resp = ssh.exec_command("mysql -u root --password=rootpass "
                                "-e 'SHOW DATABASES'")
        self.assertIn("tutorial_sample", resp)

        # NOTE(apavlov): cleanup
        ssh.exec_command("sudo /etc/init.d/mysql stop"
            "&& sudo umount /etc/mysql /var/lib/mysql /var/log/mysql /vol")

        return None
