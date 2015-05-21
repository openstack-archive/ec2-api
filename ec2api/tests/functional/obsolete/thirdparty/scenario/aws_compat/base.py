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

import fnmatch

from boto import exception as boto_exception
import netaddr

from tempest import auth
from tempest import clients as base_clients
from tempest.cloudscaling import base
from tempest.cloudscaling.thirdparty.scenario.aws_compat import clients
from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions
from tempest import test as base_test
from tempest.thirdparty.boto import test
from tempest.thirdparty.boto.utils import wait as boto_wait


VOLUME_SIZE = 1


class BaseAWSTest(base.BaseTest, test.BotoTestCase):
    """Base class for AWS compat Cloudscaling tests"""

    @classmethod
    def setUpClass(cls):
        super(BaseAWSTest, cls).setUpClass()

        cls.os = clients.Manager()
        cls.ec2_client = cls.os.ec2api_client
        cls.vpc_client = cls.os.vpc_client

        cls.config = config.CONF
        cls.instance_type = cls.config.boto.instance_type

    @classmethod
    def _processException(cls, exc):
        if isinstance(exc, boto_exception.EC2ResponseError):
            value = getattr(exc, "message", None)
            if not value:
                value = getattr(exc, "error_message", None)
            msg = str(exc.error_code) + ": " + str(value)
            return (base_test.TestResultLabel.ERROR, msg)
        return super(BaseAWSTest, cls)._processException(exc)

    @classmethod
    def _prepare_image_id(cls, image_name):
        """Searches existing available image ID by given name pattern"""

        images = cls.ec2_client.get_all_images(filters={
            "name": image_name,
            "image-type": "machine",
            "is-public": "true"})
        # NOTE(apavlov) There is no filtering in nova-api-ec2. Filter here.
        filtered_images = []
        for image in images:
            if not fnmatch.fnmatch(image.name, image_name):
                continue
            if image.type != "machine":
                continue
            if not image.is_public:
                continue
            filtered_images.append(image)
        if len(filtered_images) > 0:
            return filtered_images[0].id

        return image_name

    @classmethod
    def _prepare_key_pair(cls):
        """Key-pair preparation"""

        keypair_name = data_utils.rand_name("keypair-")
        keypair = cls.ec2_client.create_key_pair(keypair_name)
        if keypair is None or keypair.name is None:
            raise base.TestCasePreparationError("Can`t create keypair")
        cls.addResourceCleanUp(cls.ec2_client.delete_key_pair,
                               keypair_name)
        return keypair

    @classmethod
    def _prepare_security_group(cls):
        """Security-group preparation"""

        sec_group_name = data_utils.rand_name("securitygroup-")
        group_desc = sec_group_name + " security group description "
        security_group = cls.ec2_client.create_security_group(
            sec_group_name, group_desc)
        if security_group is None or security_group.name is None:
            raise base.TestCasePreparationError("Can't create security group")
        cls.addResourceCleanUp(cls.destroy_security_group_wait,
                               security_group)
        result = cls.ec2_client.authorize_security_group(
            sec_group_name,
            ip_protocol="icmp",
            cidr_ip="0.0.0.0/0",
            from_port=-1,
            to_port=-1)
        if not result:
            raise base.TestCasePreparationError(
                "Can`t authorize security group")

        result = cls.ec2_client.authorize_security_group(
            sec_group_name,
            ip_protocol="tcp",
            cidr_ip="0.0.0.0/0",
            from_port=22,
            to_port=22)
        if not result:
            raise base.TestCasePreparationError(
                "Can`t authorize security group")
        return security_group

    @classmethod
    def _destroy_security_group_wait(cls, group):
        def _delete():
            cls.ec2_client.delete_security_group(group_id=group.id)

        boto_wait.wait_no_exception(_delete)

    @classmethod
    def _destroy_internet_gateway(cls, internet_gateway):
        igs = cls.vpc_client.get_all_internet_gateways(
            internet_gateway_ids=[internet_gateway.id])
        if len(igs) == 0:
            return
        ig = igs[0]
        for attachment in ig.attachments:
            cls.vpc_client.detach_internet_gateway(ig.id, attachment.vpc_id)
        cls.vpc_client.delete_internet_gateway(ig.id)

    @classmethod
    def _delete_subnet_wait(cls, subnet):
        def _delete():
            cls.vpc_client.delete_subnet(subnet.id)

        boto_wait.wait_no_exception(_delete)

    @classmethod
    def _prepare_public_ip(cls, instance, network_interface_id=None):
        """Public IP preparation"""

        ip_address = instance.ip_address

        if ip_address is None or ip_address == instance.private_ip_address:
            domain = "vpc" if instance.vpc_id is not None else None
            address = cls.ec2_client.allocate_address(domain)
            if address is None or not address.public_ip:
                raise base.TestCasePreparationError(
                    "Can't allocate public IP")
            if domain is None:
                # NOTE(ft): this is temporary workaround for OS
                # it must be removed after VPC integration
                cls.addResourceCleanUp(address.delete)
                status = address.associate(instance.id)
                if not status:
                    raise base.TestCasePreparationError(
                        "Can't associate IP with instance")
                cls.addResourceCleanUp(address.disassociate)
            else:
                cls.addResourceCleanUp(cls.ec2_client.release_address,
                                       allocation_id=address.allocation_id)
                if network_interface_id:
                    status = cls.ec2_client.associate_address(
                        allocation_id=address.allocation_id,
                        network_interface_id=network_interface_id)
                else:
                    status = cls.ec2_client.associate_address(
                        instance.id, allocation_id=address.allocation_id)
                if not status:
                    raise base.TestCasePreparationError(
                        "Can't associate IP with instance")
                addresses = cls.ec2_client.get_all_addresses(
                    allocation_ids=[address.allocation_id])
                if addresses is None or len(addresses) != 1:
                    raise base.TestCasePreparationError(
                        "Can't get address by allocation_id")
                address = addresses[0]
                cls.addResourceCleanUp(cls.ec2_client.disassociate_address,
                                       association_id=address.association_id)
            instance.update()
            ip_address = address.public_ip

        return ip_address

    @classmethod
    def _wait_instance_state(cls, instance, final_set):
        if not isinstance(final_set, set):
            final_set = set((final_set,))
        final_set |= cls.gone_set
        lfunction = cls.get_lfunction_gone(instance)
        state = boto_wait.state_wait(lfunction, final_set,
                                     cls.valid_instance_state)
        if state not in final_set:
            raise base.TestCasePreparationError("Error in waiting for "
                "instance(state = '%s')" % state)

    @classmethod
    def _correct_ns_if_needed(cls, ssh):
        try:
            ssh.exec_command("host www.com")
        except exceptions.SSHExecCommandFailed:
            # NOTE(apavlov) update nameservers (mandatory for local devstack)
            ssh.exec_command("sudo su -c 'echo nameserver 8.8.8.8 "
                             "> /etc/resolv.conf'")
            ssh.exec_command("host www.com")

    @classmethod
    def _prepare_ebs_image(cls):
        if cls.config.cloudscaling.ebs_image_id:
            return cls.config.cloudscaling.ebs_image_id

        if not cls.config.cloudscaling.image_id_ami:
            raise cls.skipException("".join(("EC2 ", cls.__name__,
                                    ": requires image_id_ami setting")))

        if not cls.config.service_available.cinder:
            skip_msg = ("%s skipped as Cinder is not available" % cls.__name__)
            raise cls.skipException(skip_msg)
        if not cls.config.service_available.nova:
            skip_msg = ("%s skipped as nova is not available" % cls.__name__)
            raise cls.skipException(skip_msg)

        admin_creds = auth.get_default_credentials('compute_admin')
        os = base_clients.Manager(admin_creds, interface='json')
        cls.os = os
        cls.volumes_client = os.volumes_client
        cls.servers_client = os.servers_client
        cls.images_client = os.images_client
        cls.snapshots_client = os.snapshots_client

        # NOTE(apavlov): create volume
        resp, volume = cls.volumes_client.create_volume(VOLUME_SIZE,
                                                    display_name="aws_volume")
        assert 200 == resp.status
        cls.addResourceCleanUp(cls._delete_volume, volume['id'])
        cls.volumes_client.wait_for_volume_status(volume['id'], 'available')

        # NOTE(apavlov): boot instance
        bdm = [{
            "volume_id": volume['id'],
            "delete_on_termination": "1",
            "device_name": "/dev/vda"}]
        resp, server = cls.servers_client.create_server(
            "aws_instance",
            cls.config.cloudscaling.image_id_ami,
            cls.config.compute.flavor_ref,
            block_device_mapping=bdm)
        assert 202 == resp.status
        rc_server = cls.addResourceCleanUp(cls.servers_client.delete_server,
                                           server['id'])
        cls.servers_client.wait_for_server_status(server['id'], 'ACTIVE')
        # NOTE(apavlov): create image from instance
        image_name = data_utils.rand_name("aws_ebs_image-")
        resp, _ = cls.images_client.create_image(server['id'],
                                                 image_name)
        assert 202 == resp.status
        cls.image_id = resp["location"].split('/')[-1]
        cls.addResourceCleanUp(cls.images_client.delete_image,
                               cls.image_id)
        # NOTE(apavlov): delete instance
        cls.cancelResourceCleanUp(rc_server)
        cls.servers_client.delete_server(server['id'])
        cls.servers_client.wait_for_server_termination(server['id'])

        images = cls.ec2_client.get_all_images()
        for image in images:
            if image_name in image.location:
                return image.id

        raise base.TestCasePreparationError("Can't find ebs image.")

    @classmethod
    def _delete_volume(cls, volume_id):
        resp, result = cls.snapshots_client.list_snapshots(
            {"volume_id": volume_id})
        if 200 == resp.status:
            for snapshot in result:
                cls.snapshots_client.delete_snapshot(snapshot['id'])
                cls.snapshots_client.wait_for_resource_deletion(snapshot['id'])
        cls.volumes_client.delete_volume(volume_id)


class BaseVPCTest(BaseAWSTest):
    """Base class for AWS VPC behavior tests."""

    @classmethod
    @base_test.safe_setup
    def setUpClass(cls):
        super(BaseVPCTest, cls).setUpClass()
        cls.zone = cls.config.boto.aws_zone
        cfg = cls.config.cloudscaling
        cls.ssh_user = cfg.general_ssh_user_name
        cls.vpc_cidr = netaddr.IPNetwork(cfg.vpc_cidr)
        (cls.subnet_cidr,) = cls.vpc_cidr.subnet(cfg.vpc_subnet_prefix, 1)
        cls.image_id = cls._prepare_image_id(cfg.general_image_name)
        cls.keypair = cls._prepare_key_pair()

    @classmethod
    def _tune_vpc(cls, vpc):
        ig = cls.vpc_client.create_internet_gateway()
        if ig is None or not ig.id:
            raise base.TestCasePreparationError()
        cls.addResourceCleanUp(cls._destroy_internet_gateway, ig)
        status = cls.vpc_client.attach_internet_gateway(ig.id, vpc.id)
        if not status:
            raise base.TestCasePreparationError()
        rtables = cls.vpc_client.get_all_route_tables(
            filters=[("vpc-id", vpc.id)])
        if rtables is None or len(rtables) != 1:
            raise base.TestCasePreparationError()
        status = cls.vpc_client.create_route(rtables[0].id, "0.0.0.0/0",
                                             gateway_id=ig.id)
        if not status:
            raise base.TestCasePreparationError()
        secgroups = cls.vpc_client.get_all_security_groups(
            filters={"vpc-id": vpc.id})
        if secgroups is None or len(secgroups) != 1:
            raise base.TestCasePreparationError()
        status = cls.vpc_client.authorize_security_group(
            group_id=secgroups[0].id, ip_protocol="-1",
            from_port=-1, to_port=-1, cidr_ip="0.0.0.0/0")
        if not status:
            raise base.TestCasePreparationError()

    @classmethod
    def _prepare_vpc(cls, vpc_cidr, sn_cidr):
        # NOTE(Alex) The following code is introduced for OpenStack
        # and potentially requires fix in boto. See details in
        # test_vpc_nat_scenario.
        dhcp_opts = cls.vpc_client.create_dhcp_options(
            domain_name_servers=['8.8.8.8'])
        if dhcp_opts is None or not dhcp_opts.id:
            raise base.TestCasePreparationError()
        cls.addResourceCleanUp(cls.vpc_client.delete_dhcp_options,
                               dhcp_opts.id)
        vpc = cls.vpc_client.create_vpc(str(vpc_cidr))
        if vpc is None or not vpc.id:
            raise base.TestCasePreparationError()
        cls.addResourceCleanUp(cls.vpc_client.delete_vpc, vpc.id)
        if not cls.vpc_client.associate_dhcp_options(dhcp_opts.id, vpc.id):
            raise base.TestCasePreparationError()
        cls._tune_vpc(vpc)
        sn = cls.vpc_client.create_subnet(vpc.id, str(sn_cidr), cls.zone)
        if sn is None or not sn.id:
            raise base.TestCasePreparationError()
        cls.addResourceCleanUp(cls._delete_subnet_wait, sn)
        return sn
