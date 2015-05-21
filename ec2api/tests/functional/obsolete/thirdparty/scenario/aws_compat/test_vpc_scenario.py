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

import netaddr

import tempest.cloudscaling.thirdparty.scenario.aws_compat.base as aws_base
from tempest.common.utils import data_utils
from tempest.common.utils.linux import remote_client
from tempest import test

import logging
logging.getLogger('boto').setLevel(logging.CRITICAL)


class VPC_Scenario(aws_base.BaseAWSTest):
    """
    Reproduce 'VPC with Public and Private Subnets' scenario
    (http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Scenario2.html)
    """
    class Context(object):
        vpc = None
        internet_gateway = None
        web_subnet = None
        db_subnet = None
        main_route_table = None
        custom_route_table = None
        web_security_group = None
        nat_security_group = None
        db_security_group = None
        web_instance = None
        db_instance = None
        nat_instance = None

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(VPC_Scenario, cls).setUpClass()
        cls.ctx = cls.Context()
        cls.zone = cls.config.boto.aws_zone
        cfg = cls.config.cloudscaling
        cls.ssh_user = cfg.general_ssh_user_name
        cls.vpc_cidr = netaddr.IPNetwork(cfg.vpc_cidr)
        cls.web_subnet, cls.db_subnet = cls.vpc_cidr.subnet(
            cfg.vpc_subnet_prefix, 2)
        cls.test_client_cidr = netaddr.IPNetwork(cfg.test_client_cidr)
        cls.image_id = cls._prepare_image_id(cfg.general_image_name)
        cls.keypair = cls._prepare_key_pair()

    @classmethod
    def tearDownClass(cls):
        if cls.ctx is not None:
            for group in [cls.ctx.web_security_group,
                          cls.ctx.nat_security_group,
                          cls.ctx.db_security_group]:
                if not group:
                    continue
                try:
                    cls._revoke_security_group_linked_rules(group)
                except Exception:
                    pass
        super(VPC_Scenario, cls).tearDownClass()

    @classmethod
    def _revoke_security_group_linked_rules(cls, group):
        groups = cls.vpc_client.get_all_security_groups(group_ids=[group.id])
        if len(groups) == 0:
            return
        sg = groups[0]
        for rule in sg.rules:
            for grant in rule.grants:
                if not grant.cidr_ip:
                    cls.vpc_client.revoke_security_group(
                        group_id=sg.id,
                        ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        src_security_group_group_id=grant.groupId)
        for rule in sg.rules_egress:
            for grant in rule.grants:
                if not grant.cidr_ip:
                    cls.vpc_client.revoke_security_group_egress(
                        sg.id,
                        rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        src_group_id=grant.groupId)

    def test_000_create_vpc(self):
        """Create VPC"""
        vpc = self.vpc_client.create_vpc(str(self.vpc_cidr))
        self.assertIsNotNone(vpc)
        self.assertTrue(vpc.id)
        self.addResourceCleanUp(self.vpc_client.delete_vpc, vpc.id)
        self.ctx.vpc = vpc

    def test_001_create_internet_gateway(self):
        """Create internet gateway"""
        ig = self.vpc_client.create_internet_gateway()
        self.assertIsNotNone(ig)
        self.assertTrue(ig.id)
        self.addResourceCleanUp(self._destroy_internet_gateway, ig)
        status = self.vpc_client.attach_internet_gateway(ig.id,
                                                         self.ctx.vpc.id)
        self.assertTrue(status)
        self.ctx.internet_gateway = ig

    def test_010_create_subnets(self):
        """Create subnets"""
        sn = self.vpc_client.create_subnet(self.ctx.vpc.id,
                                           str(self.web_subnet),
                                           self.zone)
        self.assertIsNotNone(sn)
        self.assertTrue(sn.id)
        self.addResourceCleanUp(self.vpc_client.delete_subnet, sn.id)
        self.ctx.web_subnet = sn
        sn = self.vpc_client.create_subnet(self.ctx.vpc.id,
                                           str(self.db_subnet),
                                           self.zone)
        self.assertIsNotNone(sn)
        self.assertTrue(sn.id)
        self.addResourceCleanUp(self.vpc_client.delete_subnet, sn.id)
        self.ctx.db_subnet = sn

    def test_020_get_main_route_table(self):
        """Describe auto created route table"""
        rtables = self.vpc_client.get_all_route_tables(
            filters=[("vpc-id", self.ctx.vpc.id)])
        self.assertIsNotNone(rtables)
        self.assertEqual(1, len(rtables))
        self.ctx.main_route_table = rtables[0]

    def test_025_create_custom_route_table(self):
        """Create route table for web servers"""
        rtable = self.vpc_client.create_route_table(self.ctx.vpc.id)
        self.assertIsNotNone(rtable)
        self.assertTrue(rtable.id)
        self.addResourceCleanUp(self.vpc_client.delete_route_table, rtable.id)
        ig = self.ctx.internet_gateway
        status = self.vpc_client.create_route(rtable.id, "0.0.0.0/0",
                                              gateway_id=ig.id)
        self.assertTrue(status)
        association_id = self.vpc_client.associate_route_table(
            rtable.id, self.ctx.web_subnet.id)
        self.assertTrue(association_id)
        self.addResourceCleanUp(self.vpc_client.disassociate_route_table,
                                association_id)
        self.ctx.custom_route_table = rtable

    def test_050_create_security_groups(self):
        """Create and tune security groups"""
        sg = self.vpc_client.create_security_group(
            data_utils.rand_name("WebServerSG-"),
            data_utils.rand_name("description "),
            self.ctx.vpc.id)
        self.assertIsNotNone(sg)
        self.assertTrue(sg.id)
        self.addResourceCleanUp(self._destroy_security_group_wait, sg)
        self.ctx.web_security_group = sg
        sg = self.vpc_client.create_security_group(
            data_utils.rand_name("NATSG-"),
            data_utils.rand_name("description "),
            self.ctx.vpc.id)
        self.assertIsNotNone(sg)
        self.assertTrue(sg.id)
        self.addResourceCleanUp(self._destroy_security_group_wait, sg)
        self.ctx.nat_security_group = sg
        sg = self.vpc_client.create_security_group(
            data_utils.rand_name("DBServerSG-"),
            data_utils.rand_name("description "),
            self.ctx.vpc.id)
        self.assertIsNotNone(sg)
        self.assertTrue(sg.id)
        self.addResourceCleanUp(self._destroy_security_group_wait, sg)
        self.ctx.db_security_group = sg

        sg = self.ctx.web_security_group
        status = self.vpc_client.revoke_security_group_egress(
            sg.id, "-1", cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group_egress(
            sg.id, "tcp", 1433, 1433,
            src_group_id=self.ctx.db_security_group.id)
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group_egress(
            sg.id, "tcp", 3306, 3306,
            src_group_id=self.ctx.db_security_group.id)
        self.assertTrue(status)
        # NOTE(ft): especially for connectivity test
        status = self.vpc_client.authorize_security_group_egress(
            sg.id, "tcp", 80, 80, cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        # NOTE(ft): especially for connectivity test
        status = self.vpc_client.authorize_security_group_egress(
            sg.id, "tcp", 22, 22,
            src_group_id=self.ctx.db_security_group.id)
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp", from_port=80, to_port=80,
            cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp", from_port=443, to_port=443,
            cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp", from_port=22, to_port=22,
            cidr_ip=str(self.test_client_cidr))
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp", from_port=3389,
            to_port=3389, cidr_ip=str(self.test_client_cidr))
        self.assertTrue(status)

        sg = self.ctx.nat_security_group
        status = self.vpc_client.revoke_security_group_egress(
            sg.id, "-1", cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group_egress(
            sg.id, "tcp", 80, 80, cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group_egress(
            sg.id, "tcp", 443, 443, cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp", from_port=80, to_port=80,
            cidr_ip=str(self.db_subnet))
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp", from_port=443, to_port=443,
            cidr_ip=str(self.db_subnet))
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp", from_port=22, to_port=22,
            cidr_ip=str(self.test_client_cidr))
        self.assertTrue(status)

        sg = self.ctx.db_security_group
        status = self.vpc_client.revoke_security_group_egress(
            sg.id, "-1", cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group_egress(
            sg.id, "tcp", 80, 80, cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group_egress(
            sg.id, "tcp", 443, 443, cidr_ip="0.0.0.0/0")
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp",
            from_port=1433,
            to_port=1433,
            src_security_group_group_id=self.ctx.web_security_group.id)
        self.assertTrue(status)
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp",
            from_port=3306,
            to_port=3306,
            src_security_group_group_id=self.ctx.web_security_group.id)
        self.assertTrue(status)
        # NOTE(ft): especially for connectivity test
        status = self.vpc_client.authorize_security_group(
            group_id=sg.id, ip_protocol="tcp",
            from_port=22,
            to_port=22,
            src_security_group_group_id=self.ctx.web_security_group.id)
        self.assertTrue(status)

    def test_100_launch_nat_instance(self):
        """Launch instances for NAT server"""
        reservation = self.vpc_client.run_instances(
            self.image_id,
            key_name=self.keypair.name,
            security_group_ids=[self.ctx.nat_security_group.id],
            instance_type=self.instance_type,
            placement=self.zone,
            subnet_id=self.ctx.web_subnet.id)
        self.assertIsNotNone(reservation)
        self.addResourceCleanUp(self.destroy_reservation, reservation)
        self.assertEqual(1, len(reservation.instances))
        instance = reservation.instances[0]
        if instance.state != "running":
            self.assertInstanceStateWait(instance, "running")
        self._prepare_public_ip(instance)
        status = self.vpc_client.modify_instance_attribute(
            instance.id, 'sourceDestCheck', False)
        self.assertTrue(status)

        rtable = self.ctx.main_route_table
        status = self.vpc_client.create_route(rtable.id, "0.0.0.0/0",
                                              instance_id=instance.id)
        self.assertTrue(status)
        self.ctx.nat_instance = instance

    def test_101_launch_instances(self):
        """Launch instances for web server and db server"""
        reservation = self.vpc_client.run_instances(
            self.image_id,
            key_name=self.keypair.name,
            security_group_ids=[self.ctx.web_security_group.id],
            instance_type=self.instance_type,
            placement=self.zone,
            subnet_id=self.ctx.web_subnet.id)
        self.assertIsNotNone(reservation)
        self.addResourceCleanUp(self.destroy_reservation, reservation)
        self.assertEqual(1, len(reservation.instances))
        instance = reservation.instances[0]
        if instance.state != "running":
            self.assertInstanceStateWait(instance, "running")
        self._prepare_public_ip(instance)
        self.ctx.web_instance = instance

        reservation = self.vpc_client.run_instances(
            self.image_id,
            key_name=self.keypair.name,
            security_group_ids=[self.ctx.db_security_group.id],
            instance_type=self.instance_type,
            placement=self.zone,
            subnet_id=self.ctx.db_subnet.id)
        self.assertIsNotNone(reservation)
        self.addResourceCleanUp(self.destroy_reservation, reservation)
        self.assertEqual(1, len(reservation.instances))
        instance = reservation.instances[0]
        if instance.state != "running":
            self.assertInstanceStateWait(instance, "running")
        self.ctx.db_instance = instance

    def test_102_tune_nat_instance(self):
        """Tune NAT in NAT instance"""
        instance = self.ctx.nat_instance
        address = instance.ip_address
        ssh = remote_client.RemoteClient(address,
                                         self.ssh_user,
                                         pkey=self.keypair.material)

        # NOTE(ft): We must use tty mode, because some images (like Amazon
        # Linux) has restrictions (requiretty flag in /etc/sudoers)
        ssh_conn = ssh.ssh_client._get_ssh_connection()
        chan = ssh_conn.get_transport().open_session()
        chan.get_pty()
        chan.exec_command("sudo iptables -t nat -A POSTROUTING -s %s "
                          "-o eth0 -j MASQUERADE" % str(self.vpc_cidr))
        chan.close()
        chan = ssh_conn.get_transport().open_session()
        chan.get_pty()
        chan.exec_command("sudo sysctl -w net.ipv4.ip_forward=1")
        chan.close()
        ssh_conn.close()

    def test_200_check_connectivity(self):
        """Check inside and outside connectivities"""
        web_ip = self.ctx.web_instance.ip_address
        db_ip = self.ctx.db_instance.private_ip_address
        ssh = remote_client.RemoteClient(web_ip,
                                         self.ssh_user,
                                         pkey=self.keypair.material)
        ssh.exec_command("curl -s http://google.com")

        ssh_conn = ssh.ssh_client._get_ssh_connection()
        sftp = ssh_conn.open_sftp()
        fr = sftp.file("key.pem", 'wb')
        fr.set_pipelined(True)
        fr.write(self.keypair.material)
        fr.close()
        ssh_conn.close()
        ssh.exec_command('chmod 400 key.pem')
        ssh.exec_command("ssh -i key.pem -o UserKnownHostsFile=/dev/null "
                         "-o StrictHostKeyChecking=no %(user)s@%(ip)s "
                         "curl -s http://google.com" %
                         {"user": self.ssh_user, "ip": db_ip})
