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


"""
Cloud Controller: Implementation of EC2 REST API calls, which are
dispatched to other nodes via AMQP RPC. State is via distributed
datastore.
"""

import collections

from oslo_config import cfg
from oslo_log import log as logging
import six
import six.moves

from ec2api.api import address
from ec2api.api import availability_zone
from ec2api.api import customer_gateway
from ec2api.api import dhcp_options
from ec2api.api import image
from ec2api.api import instance
from ec2api.api import internet_gateway
from ec2api.api import key_pair
from ec2api.api import network_interface
from ec2api.api import route_table
from ec2api.api import security_group
from ec2api.api import snapshot
from ec2api.api import subnet
from ec2api.api import tag
from ec2api.api import volume
from ec2api.api import vpc
from ec2api.api import vpn_connection
from ec2api.api import vpn_gateway
from ec2api import exception

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def module_and_param_types(module, *args, **kwargs):
    """Decorator to check types and call function."""

    param_types = args

    def wrapped(func):

        def func_wrapped(*args, **kwargs):
            impl_func = getattr(module, func.__name__)
            context = args[1]
            params = collections.OrderedDict(six.moves.zip(
                func.__code__.co_varnames[2:], param_types))
            param_num = 0
            mandatory_params_num = (func.__code__.co_argcount - 2 -
                                    len(func.__defaults__ or []))
            for param_name, param_type in params.items():
                param_value = kwargs.get(param_name)
                if param_value is not None:
                    validator = module.Validator(param_name, func.__name__,
                                                 params)
                    validation_func = getattr(validator, param_type)
                    validation_func(param_value)
                    param_num += 1
                elif param_num < mandatory_params_num:
                    raise exception.MissingParameter(param=param_name)
            return impl_func(context, **kwargs)
        return func_wrapped

    return wrapped


class CloudController(object):

    """Cloud Controller

        Provides the critical dispatch between
        inbound API calls through the endpoint and messages
        sent to the other nodes.
    """

    def __init__(self):
        pass

    def __str__(self):
        return 'CloudController'

    @module_and_param_types(address, 'str255')
    def allocate_address(self, context, domain=None):
        """Acquires an Elastic IP address.

        Args:
            context (RequestContext): The request context.
            domain (str): Set to vpc to allocate the address for use with
                instances in a VPC.
                Default: The address is for use in EC2-Classic.
                Valid values: vpc

        Returns:
            The Elastic IP address information.

        An Elastic IP address is for use either in the EC2-Classic platform
        or in a VPC.
        """

    @module_and_param_types(address, 'ip', 'i_id',
                            'eipalloc_id', 'eni_id',
                            'ip', 'bool')
    def associate_address(self, context, public_ip=None, instance_id=None,
                          allocation_id=None, network_interface_id=None,
                          private_ip_address=None, allow_reassociation=False):
        """Associates an Elastic IP with an instance or a network interface.

        Args:
            context (RequestContext): The request context.
            public_ip (str): The Elastic IP address.
                Required for Elastic IP addresses for use with instances
                in EC2-Classic.
            instance_id (str): The ID of the instance.
                The operation fails if you specify an instance ID unless
                exactly one network interface is attached.
                Required for EC2-Classic.
            allocation_id (str): The allocation ID.
                Required for EC2-VPC.
            network_interface_id (str): The ID of the network interface.
            private_ip_address (str): The primary or secondary private IP.
            allow_reassociation (boolean): Allows an Elastic IP address that is
                already associated to be re-associated.
                Otherwise, the operation fails.

        Returns:
            true if the request succeeds.
            [EC2-VPC] The ID that represents the association of the Elastic IP.

        For a VPC, you can specify either instance_id or network_interface_id,
        but not both.
        If the instance has more than one network interface, you must specify
        a network interface ID.
        If no private IP address is specified, the Elastic IP address
        is associated with the primary private IP address.
        [EC2-Classic, default VPC] If the Elastic IP address is already
        associated with a different instance, it is disassociated from that
        instance and associated with the specified instance.
        This is an idempotent operation.
        """

    @module_and_param_types(address, 'ip',
                            'eipassoc_id')
    def disassociate_address(self, context, public_ip=None,
                             association_id=None):
        """Disassociates an Elastic IP address.

        Args:
            context (RequestContext): The request context.
            public_ip (str): The Elastic IP address.
                Required for EC2-Classic.
            assossiation_id (str): The association ID.
                Required for EC2-VPC

        Returns:
            true if the request succeeds.

        Disassociates an Elastic IP address from the instance or network
        interface it's associated with.
        This is an idempotent action.
        """

    @module_and_param_types(address, 'ip',
                            'eipalloc_id')
    def release_address(self, context, public_ip=None, allocation_id=None):
        """Releases the specified Elastic IP address.

        Args:
            context (RequestContext): The request context.
            public_ip (str): The Elastic IP address.
            allocation_id (str): The allocation ID.

        Returns:
            true if the requests succeeds.

        If you attempt to release an Elastic IP address that you already
        released, you'll get an AuthFailure error if the address is already
        allocated to another AWS account.
        [EC2-Classic, default VPC] Releasing an Elastic IP address
        automatically disassociates it from any instance that it's associated
        with.
        [Nondefault VPC] You must use DisassociateAddress to disassociate the
        Elastic IP address before you try to release it.
        """

    @module_and_param_types(address, 'ips', 'eipalloc_ids',
                            'filter')
    def describe_addresses(self, context, public_ip=None, allocation_id=None,
                           filter=None):
        """Describes one or more of your Elastic IP addresses.

        Args:
            context (RequestContext): The request context.
            public_ip (list of str): One or more Elastic IP addresses.
            allocation_id (list of str): One or more allocation IDs.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain Elastic IP
                addresses.

        Returns:
            A list of Elastic IP addresses.
        """

    @module_and_param_types(security_group, 'security_group_strs',
                            'sg_ids', 'filter')
    def describe_security_groups(self, context, group_name=None,
                                 group_id=None, filter=None):
        """Describes one or more of your security groups.

        Args:
            context (RequestContext): The request context.
            group_name (list of str): One or more security group names.
            group_id (list of str): One or more security group IDs.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain security groups.

        Returns:
            A list of security groups.
        """

    @module_and_param_types(security_group, 'security_group_str',
                            'security_group_str', 'vpc_id')
    def create_security_group(self, context, group_name,
                              group_description, vpc_id=None):
        """Creates a security group.

        Args:
            context (RequestContext): The request context.
            group_name (str): The name of the security group.
            group_description (str): A description for the security group.
            vpc_id (str): [EC2-VPC] The ID of the VPC.

        Returns:
            true if the requests succeeds.
            The ID of the security group.

        You can have a security group for use in EC2-Classic with the same name
        as a security group for use in a VPC. However, you can't have two
        security groups for use in EC2-Classic with the same name or two
        security groups for use in a VPC with the same name.
        You have a default security group for use in EC2-Classic and a default
        security group for use in your VPC. If you don't specify a security
        group when you launch an instance, the instance is launched into the
        appropriate default security group. A default security group includes
        a default rule that grants instances unrestricted network access to
        each other.
        group_name and group_description restrictions:
        up to 255 characters in length,
        EC2-Classic: ASCII characters,
        EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
        """

    @module_and_param_types(security_group, 'security_group_str', 'sg_id')
    def delete_security_group(self, context, group_name=None, group_id=None):
        """Deletes a security group.

        Args:
            context (RequestContext): The request context.
            group_name (str): The name of the security group.
            group_id (str): The ID of the security group.

        Returns:
            true if the requests succeeds.

        [EC2-Classic, default VPC] You can specify either GroupName or GroupId
        If you attempt to delete a security group that is associated with an
        instance, or is referenced by another security group, the operation
        fails.
        """

    @module_and_param_types(security_group, 'sg_id',
                            'security_group_str', 'dummy')
    def authorize_security_group_ingress(self, context, group_id=None,
                                         group_name=None, ip_permissions=None):
        """Adds one or more ingress rules to a security group.

        Args:
            context (RequestContext): The request context.
            group_id (str): The ID of the security group.
            group_name (str): [EC2-Classic, default VPC] The name of the
                security group.
            ip_permissions (list of dicts): Dict can contain:
                ip_protocol (str): The IP protocol name or number.
                    Use -1 to specify all.
                    For EC2-Classic, security groups can have rules only for
                    TCP, UDP, and ICMP.
                from_port (str): The start of port range for the TCP and UDP
                    protocols, or an ICMP type number. For the ICMP type
                    number, you can use -1 to specify all ICMP types.
                to_port (str): The end of port range for the TCP and UDP
                    protocols, or an ICMP code number. For the ICMP code
                    number, you can use -1 to specify all ICMP codes for the
                    ICMP type.
                groups (list of dicts): Dict can contain:
                    group_id (str): The ID of the source security group. You
                        can't specify a source security group and a CIDR IP
                        address range.
                    user_id (str): [EC2-Classic] The ID of the AWS account that
                        owns the source security group, if it's not the current
                        AWS account.
                    cidr_ip (str): The CIDR IP address range. You can't specify
                    this parameter when specifying a source security group.

        Returns:
            true if the requests succeeds.
        """

    @module_and_param_types(security_group, 'sg_id',
                            'security_group_str', 'dummy')
    def revoke_security_group_ingress(self, context, group_id=None,
                                      group_name=None, ip_permissions=None):
        """Removes one or more ingress rules from a security group.

        Args:
            context (RequestContext): The request context.
            group_id (str): The ID of the security group.
            group_name (str): [EC2-Classic, default VPC] The name of the
                security group.
            ip_permissions (list of dicts): See
                authorize_security_group_ingress

        Returns:
            true if the requests succeeds.

        The values that you specify in the revoke request (for example, ports)
        must match the existing rule's values for the rule to be removed.
        """

    @module_and_param_types(security_group, 'sg_id', 'dummy')
    def authorize_security_group_egress(self, context, group_id,
                                        ip_permissions=None):
        """Adds one or more egress rules to a security group for use with a VPC.

        Args:
            context (RequestContext): The request context.
            group_id (str): The ID of the security group.
            ip_permissions (list of dicts): See
                authorize_security_group_ingress

        Returns:
            true if the requests succeeds.

        This action doesn't apply to security groups for use in EC2-Classic.
        """

    @module_and_param_types(security_group, 'sg_id', 'dummy')
    def revoke_security_group_egress(self, context, group_id,
                                     ip_permissions=None):
        """Removes one or more egress rules from a security group for EC2-VPC.

        Args:
            context (RequestContext): The request context.
            group_id (str): The ID of the security group.
            ip_permissions (list of dicts): See
                authorize_security_group_ingress

        Returns:
            true if the requests succeeds.

        The values that you specify in the revoke request (for example, ports)
        must match the existing rule's values for the rule to be revoked.
        This action doesn't apply to security groups for use in EC2-Classic.
        """

    @module_and_param_types(instance, 'ami_id', 'int', 'int',
                            'str255', 'sg_ids',
                            'security_group_strs', 'str', 'str',
                            'dummy', 'aki_id', 'ari_id',
                            'dummy', 'dummy',
                            'subnet_id', 'bool',
                            'str',
                            'ip', 'str64',
                            'dummy', 'dummy',
                            'bool')
    def run_instances(self, context, image_id, min_count, max_count,
                      key_name=None, security_group_id=None,
                      security_group=None, user_data=None, instance_type=None,
                      placement=None, kernel_id=None, ramdisk_id=None,
                      block_device_mapping=None, monitoring=None,
                      subnet_id=None, disable_api_termination=None,
                      instance_initiated_shutdown_behavior=None,
                      private_ip_address=None, client_token=None,
                      network_interface=None, iam_instance_profile=None,
                      ebs_optimized=None):
        """Launches the specified number of instances using an AMI.

        Args:
            context (RequestContext): The request context.
            image_id (str): The ID of the AMI.
            min_count (int): The minimum number of instances to launch.
                If you specify a minimum that is more instances than EC2 can
                launch in the target Availability Zone, EC2 launches no
                instances.
            max_count (int): The maximum number of instances to launch.
                If you specify more instances than EC2 can launch in the target
                Availability Zone, EC2 launches the largest possible number
                of instances above max_count.
            key_name (str): The name of the key pair.
            security_group_id (list of str): One or more security group IDs.
            security_group (list of str): One or more security group names.
                For VPC mode, you must use security_group_id.
            user_data (str): Base64-encoded MIME user data for the instances.
            instance_type (str): The instance type.
            placement (dict): Dict can contain:
                availability_zone (str): Availability Zone for the instance.
                group_name (str): The name of an existing placement group.
                    Not used now.
                tenancy (str): The tenancy of the instance.
                    Not used now.
            kernel_id (str): The ID of the kernel.
            ramdisk_id (str): The ID of the RAM disk.
            block_device_mapping (list of dict): Dict can contain:
                device_name (str): The device name exposed to the instance
                    (for example, /dev/sdh or xvdh).
                virtual_name (str): The virtual device name (ephemeral[0..3]).
                ebs (dict): Dict can contain:
                    volume_id (str): The ID of the volume (Nova extension).
                    snapshot_id (str): The ID of the snapshot.
                    volume_size (str): The size of the volume, in GiBs.
                    volume_type (str): The volume type.
                        Not used now.
                    delete_on_termination (bool): Indicates whether to delete
                        the volume on instance termination.
                    iops (int): he number of IOPS to provision for the volume.
                        Not used now.
                    encrypted (boolean): Whether the volume is encrypted.
                        Not used now.
                no_device (str): Suppresses the device mapping.
            monitoring (dict): Dict can contains:
                enabled (boolean): Enables monitoring for the instance.
                        Not used now.
            subnet_id (str): The ID of the subnet to launch the instance into.
            disable_api_termination (boolean): If you set this parameter to
                true, you can't terminate the instance using the GUI console,
                CLI, or API.
                Not used now.
            instance_initiated_shutdown_behavior (str): Indicates whether an
                instance stops or terminates when you initiate shutdown from
                the instance.
                Not used now.
            private_ip_address (str): The primary IP address.
                You must specify a value from the IP address range
                of the subnet.
            client_token (str): Unique, case-sensitive identifier you provide
                to ensure idempotency of the request.
            network_interface (list of dicts): Dict can contain:
                network_interface_id (str): An existing interface to attach
                    to a single instance. Requires n=1 instances.
                device_index (int): The device index. If you are specifying
                    a network interface in the request, you must provide the
                    device index.
                subnet_id (str): The subnet ID. Applies only when creating
                    a network interface.
                description (str): A description. Applies only when creating
                    a network interface.
                private_ip_address (str): The primary private IP address.
                    Applies only when creating a network interface.
                    Requires n=1 network interfaces in launch.
                security_group_id (str): The ID of the security group.
                    Applies only when creating a network interface.
                delete_on_termination (str): Indicates whether to delete
                    the network interface on instance termination.
                private_ip_addresses (list of dicts): Dict can contain:
                    private_ip_address (str): The private IP address.
                    primary (boolean): Indicates whether the private IP address
                        is the primary private IP address.
                    secondary_private_ip_address_count (int): The number of
                        private IP addresses to assign to the network
                        interface. For a single network interface, you can't
                        specify this option and specify more than one private
                        IP address using private_ip_address.
                associate_public_ip_address (boolean): Indicates whether
                    to assign a public IP address to an instance in a VPC.
            iam_instance_profile (dict): Dict can contains:
                arn (str): ARN to associate with the instances.
                    Not used now.
                name (str): Name of the IIP to associate with the instances.
                    Not used now.
            ebs_optimized (boolean): Whether the instance is optimized for EBS.
                Not used now.

        Returns:
            The instance reservation that was created.

        If you don't specify a security group when launching an instance, EC2
        uses the default security group.
        """

    @module_and_param_types(instance, 'i_ids')
    def terminate_instances(self, context, instance_id):
        """Shuts down one or more instances.

        Args:
            context (RequestContext): The request context.
            instance_id (list of str): One or more instance IDs.

        Returns:
            A list of instance state changes.

        This operation is idempotent; if you terminate an instance more than
        once, each call succeeds.
        """

    @module_and_param_types(instance, 'i_ids', 'filter',
                            'int', 'str')
    def describe_instances(self, context, instance_id=None, filter=None,
                           max_results=None, next_token=None):
        """Describes one or more of your instances.

        Args:
            context (RequestContext): The request context.
            instance_id (list of str): One or more instance IDs.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain instances.
            max_results (int): The maximum number of items to return.
            next_token (str): The token for the next set of items to return.

        Returns:
            A list of reservations.

        If you specify one or more instance IDs, Amazon EC2 returns information
        for those instances. If you do not specify instance IDs, you receive
        information for all relevant instances. If you specify an invalid
        instance ID, you receive an error. If you specify an instance that you
        don't own, we don't include it in the results.
        """

    @module_and_param_types(instance, 'i_ids')
    def reboot_instances(self, context, instance_id):
        """Requests a reboot of one or more instances.

        Args:
            context (RequestContext): The request context.
            instance_id (list of str): One or more instance IDs.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(instance, 'i_ids', 'bool')
    def stop_instances(self, context, instance_id, force=False):
        """Stops one or more instances.

        Args:
            context (RequestContext): The request context.
            instance_id (list of str): One or more instance IDs.
            force (boolean): Forces the instances to stop. The instances do not
                have an opportunity to flush file system caches or file system
                metadata.
                Not used now. Equivalent value is True.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(instance, 'i_ids')
    def start_instances(self, context, instance_id):
        """Starts one or more instances.

        Args:
            context (RequestContext): The request context.
            instance_id (list of str): One or more instance IDs.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(instance, 'i_id', 'str255')
    def describe_instance_attribute(self, context, instance_id, attribute):
        """Describes the specified attribute of the specified instance.

        Args:
            context (RequestContext): The request context.
            instance_id (str): The ID of the instance.
            attribute (str): The instance attribute.
                Valid values: blockDeviceMapping | disableApiTermination |
                ebsOptimized (unsupported now) | groupSet |
                instanceInitiatedShutdownBehavior | instanceType | kernel |
                productCodes (unsupported now) | ramdisk | rootDeviceName |
                sourceDestCheck (unsupported now) |
                sriovNetSupport (unsupported now) | userData

        Returns:
            Specified attribute.
        """

    @module_and_param_types(instance, 'i_id', 'str',
                            'dummy', 'bool',
                            'dummy',
                            'bool',
                            'bool', 'sg_ids',
                            'str',
                            'str', 'str',
                            'str', 'str',
                            'str')
    def modify_instance_attribute(self, context, instance_id, attribute=None,
                                  value=None, source_dest_check=None,
                                  block_device_mapping=None,
                                  disable_api_termination=None,
                                  ebs_optimized=None, group_id=None,
                                  instance_initiated_shutdown_behavior=None,
                                  instance_type=None, kernel=None,
                                  ramdisk=None, sriov_net_support=None,
                                  user_data=None):
        """Modifies the specified attribute of the specified instance.

        Args:
            context (RequestContext): The request context.
            instance_id (str): The ID of the instance.
            attribute (str): The name of the attribute.
            value: The value of the attribute being modified.
            source_dest_check: Indicates whether source/destination checking is
                enabled. A value of true means checking is enabled, and false
                means checking is disabled.
                This value must be false for a NAT instance to perform NAT.
                Unsupported now.
            block_device_mapping (list of dict):
                Modifies the DeleteOnTermination attribute for volumes that are
                currently attached. The volume must be owned by the caller. If
                no value is specified for DeleteOnTermination, the default is
                true and the volume is deleted when the instance is terminated.
                Dict can contain:
                device_name (str): The device name exposed to the instance
                    (for example, /dev/sdh or xvdh).
                virtual_name (str): The virtual device name (ephemeral[0..3]).
                ebs (dict): Dict can contain:
                    volume_id (str): The ID of the volume (Nova extension).
                    delete_on_termination (bool): Indicates whether to delete
                        the volume on instance termination.
                no_device (str): Suppresses the device mapping.
                Unsupported now.
            disable_api_termination (boolean): If the value is true, you can't
                terminate the instance using the Amazon EC2 console, CLI, or
                API; otherwise, you can.
            ebs_optimized (boolean): Whether the instance is optimized for EBS.
                Unsupported now.
            group_id (list of str): [EC2-VPC] Changes the security
                groups of the instance. You must specify at least one security
                group, even if it's just the default security group for the
                VPC. You must specify the security group ID, not the security
                group name.
                Unsupported now.
            instance_initiated_shutdown_behavior (str): Indicates whether an
                instance stops or terminates when you initiate shutdown from
                the instance.
                Unsupported now.
            instance_type (str): Changes the instance type to the specified
                value. For more information, see Instance Types. If the
                instance type is not valid, the error returned is
                InvalidInstanceAttributeValue.
                Unsupported now.
            kernel (str): Changes the instance's kernel to the specified value.
                Unsupported now.
            ramdisk (str): Changes the instance's RAM disk.
                Unsupported now.
            sriov_net_support (str): SR-IOV mode for networking.
                Unsupported now.
            user_data (str): Changes the instance's user data.
                Unsupported now.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(instance, 'i_id', 'str')
    def reset_instance_attribute(self, context, instance_id, attribute):
        """Resets an attribute of an instance to its default value.

        To reset the kernel or ramdisk, the instance must be in a stopped
        state. To reset the SourceDestCheck, the instance can be either
        running or stopped.

        Args:
            context (RequestContext): The request context.
            instance_id (str): The ID of the instance.
            attribute (str): The attribute to reset.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(key_pair, 'str255s', 'filter')
    def describe_key_pairs(self, context, key_name=None, filter=None):
        """Describes one or more of your key pairs.

        Args:
            context (RequestContext): The request context.
            key_name (list of str): On or more keypair names.
            filter (list of filter dict): On or more filters.

        Returns:
            Specified keypairs.
        """

    @module_and_param_types(key_pair, 'str255')
    def create_key_pair(self, context, key_name):
        """Creates a 2048-bit RSA key pair with the specified name.

        Args:
            context (RequestContext): The request context.
            key_name (str): A unique name for the key pair.

        Returns:
            Created keypair.
        """

    @module_and_param_types(key_pair, 'str255')
    def delete_key_pair(self, context, key_name):
        """Deletes the specified key pair.

        Args:
            context (RequestContext): The request context.
            key_name (str): Name of the keypair.

        Returns:
            Returns true if the request succeeds.
        """

    @module_and_param_types(key_pair, 'str255', 'str')
    def import_key_pair(self, context, key_name, public_key_material):
        """Imports the public key from an existing RSA key pair.

        Args:
            context (RequestContext): The request context.
            key_name (str): A unique name for the key pair.
            public_key_material (str): The public key. You must base64 encode
                the public key material before sending it.

        Returns:
            Imported keypair.
        """

    @module_and_param_types(availability_zone, 'strs', 'filter')
    def describe_availability_zones(self, context, zone_name=None,
                                    filter=None):
        """Describes one or more of the available Availability Zones.

        Args:
            context (RequestContext): The request context.
            zone_name (list of str): On or more zone names.
            filter (list of filter dict): On or more filters.

        Returns:
            Specified availability zones.
        """

    @module_and_param_types(availability_zone, 'strs', 'filter')
    def describe_regions(self, context, region_name=None, filter=None):
        """Describes one or more regions that are currently available to you.

        Args:
            context (RequestContext): The request context.
            region_name (list of str): On or more region names.
            filter (list of filter dict): On or more filters.

        Returns:
            Specified regions.
        """

    @module_and_param_types(availability_zone, 'strs')
    def describe_account_attributes(self, context, attribute_name=None):
        """Describes attributes of your EC2 account.

        Args:
            context (RequestContext): The request context.
            attribute_name (list of str): One or more account attribute names.
                The following are the supported account attributes:
                    supported-platforms | default-vpc | max-instances |
                    vpc-max-security-groups-per-interface (unsupported now) |
                    max-elastic-ips (unsupported now) |
                    vpc-max-elastic-ips (unsupported now)

        Returns:
            Information about one or more account attributes.
        """

    @module_and_param_types(instance, 'i_id_or_ids')
    def get_password_data(self, context, instance_id):
        """Retrieves the encrypted administrator password for Windows instance.

        Args:
            context (RequestContext): The request context.
            instance_id (str): ID of the Windows instance

        Returns:
            The password of the instance, timestamp and instance id.

        The password is encrypted using the key pair that you specified when
        you launched the instance.
        """

    @module_and_param_types(instance, 'i_id_or_ids')
    def get_console_output(self, context, instance_id):
        """Gets the console output for the specified instance.

        Args:
            context (RequestContext): The request context.
            instance_id (str): ID of the instance

        Returns:
            The console output of the instance, timestamp and instance id.
        """

    @module_and_param_types(volume, 'str', 'int',
                            'snap_id', 'str', 'int',
                            'bool', 'str')
    def create_volume(self, context, availability_zone=None, size=None,
                      snapshot_id=None, volume_type=None, iops=None,
                      encrypted=None, kms_key_id=None):
        """Creates an EBS volume.

        Args:
            context (RequestContext): The request context.
            availability_zone (str): The Availability Zone in which to create
                the volume.
                It's required by AWS but optional for legacy Nova EC2 API.
            instance_id (str): The size of the volume, in GiBs.
                Valid values: 1-1024
                If you're creating the volume from a snapshot and don't specify
                a volume size, the default is the snapshot size.
            snapshot_id (str): The snapshot from which to create the volume.
                Required if you are creating a volume from a snapshot.
            volume_type (str): The volume type. One of volume types created
                in used Block Storage.
            iops (int): The number of IOPS to provision for the volume.
                Valid values: Range is 100 to 4,000.
                Not used now.
            encrypted (boolean): Whether the volume should be encrypted.
                Not used now.
            kms_key_id (str): The full ARN of AWS KMS master key to use when
                creating the encrypted volume.
                Not used now.

        Returns:
            Information about the volume.

        You can create a new empty volume or restore a volume from an EBS
        snapshot.
        """

    @module_and_param_types(volume, 'vol_id', 'i_id', 'str')
    def attach_volume(self, context, volume_id, instance_id, device):
        """Attaches an EBS volume to a running or stopped instance.

        Args:
            context (RequestContext): The request context.
            volume_id (str): The ID of the volume.
            instance_id (str): The ID of the instance.
            device_name (str): The device name to expose to the instance.

        Returns:
            Information about the attachment.

        The instance and volume must be in the same Availability Zone.
        """

    @module_and_param_types(volume, 'vol_id', 'i_id', 'str')
    def detach_volume(self, context, volume_id, instance_id=None, device=None,
                      force=None):
        """Detaches an EBS volume from an instance.

        Args:
            context (RequestContext): The request context.
            volume_id (str): The ID of the volume.
            instance_id (str): The ID of the instance.
                Not used now.
            device (str): The device name.
                Not used now.
            force (boolean): Forces detachment.
                Not used now.

        Returns:
            Information about the detachment.
        """

    @module_and_param_types(volume, 'vol_id')
    def delete_volume(self, context, volume_id):
        """Deletes the specified EBS volume.

        Args:
            context (RequestContext): The request context.
            volume_id (str): The ID of the volume.

        Returns:
            Returns true if the request succeeds.

        The volume must be in the available state.
        """

    @module_and_param_types(volume, 'vol_ids', 'filter',
                            'int', 'str')
    def describe_volumes(self, context, volume_id=None, filter=None,
                         max_results=None, next_token=None):
        """Describes the specified EBS volumes.

        Args:
            context (RequestContext): The request context.
            volume_id (list of str): One or more volume IDs.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain volumes.
            max_results (int): The maximum number of items to return.
            next_token (str): The token for the next set of items to return.

        Returns:
            A list of volumes.
        """

    @module_and_param_types(snapshot, 'vol_id', 'str')
    def create_snapshot(self, context, volume_id, description=None):
        """Creates a snapshot of an EBS volume.

        Args:
            context (RequestContext): The request context.
            volume_id (str): The ID of the volume.
            description (str): A description for the snapshot.

        Returns:
            Information about the snapshot.
        """

    @module_and_param_types(snapshot, 'snap_id')
    def delete_snapshot(self, context, snapshot_id):
        """Deletes the specified snapshot.

        Args:
            context (RequestContext): The request context.
            snapshot_id (str): The ID of the snapshot.

        Returns:
            Returns true if the request succeeds.
        """

    @module_and_param_types(snapshot, 'snap_ids', 'strs',
                            'strs', 'filter',
                            'int', 'str')
    def describe_snapshots(self, context, snapshot_id=None, owner=None,
                           restorable_by=None, filter=None,
                           max_results=None, next_token=None):
        """Describes one or more of the snapshots available to you.

        Args:
            context (RequestContext): The request context.
            snapshot_id (list of str): One or more snapshot IDs.
            owner (list of str): Returns the snapshots owned by the specified
                owner.
                Not used now.
            restorable_by (list of str): One or more accounts IDs that can
                create volumes from the snapshot.
                Not used now.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain snapshots.
            max_results (int): The maximum number of items to return.
            next_token (str): The token for the next set of items to return.

        Returns:
            A list of snapshots.
        """

    @module_and_param_types(image, 'i_id', 'str', 'str',
                            'bool', 'dummy')
    def create_image(self, context, instance_id, name=None, description=None,
                     no_reboot=False, block_device_mapping=None):
        """Creates an EBS-backed AMI from an EBS-backed instance.

        Args:
            context (RequestContext): The request context.
            instance_id (str): The ID of the instance.
            name (str): A name for the new image.
                It's required by AWS but optional for legacy Nova EC2 API.
            description (str): A description for the new image.
                Not used now.
            no_reboot (boolean): When the parameter is set to false, EC2
                attempts to shut down the instance cleanly before image
                creation and then reboots the instance.
            block_device_mapping (list of dict): Dict can contain:
                device_name (str): The device name exposed to the instance
                    (for example, /dev/sdh or xvdh).
                virtual_name (str): The virtual device name (ephemeral[0..3]).
                ebs (dict): Dict can contain:
                    volume_id (str): The ID of the volume (Nova extension).
                    snapshot_id (str): The ID of the snapshot.
                    volume_size (str): The size of the volume, in GiBs.
                    volume_type (str): The volume type.
                        Not used now.
                    delete_on_termination (bool): Indicates whether to delete
                        the volume on instance termination.
                    iops (int): he number of IOPS to provision for the volume.
                        Not used now.
                    encrypted (boolean): Whether the volume is encrypted.
                        Not used now.
                no_device (str): Suppresses the device mapping.

        Returns:
            The ID of the new AMI.
        """
        return image.create_image(context, instance_id, name, description,
                                  no_reboot, block_device_mapping)

    @module_and_param_types(image, 'str', 'str',
                            'str', 'str',
                            'str', 'dummy',
                            'str', 'aki_id',
                            'ari_id', 'str')
    def register_image(self, context, name=None, image_location=None,
                       description=None, architecture=None,
                       root_device_name=None, block_device_mapping=None,
                       virtualization_type=None, kernel_id=None,
                       ramdisk_id=None, sriov_net_support=None):
        """Registers an AMI.

        Args:
            context (RequestContext): The request context.
            name (str): A name for your AMI.
                It's required by AWS but optional for legacy Nova EC2 API.
            image_location (str): The full path to AMI manifest in S3 storage.
            description (str): A description for your AMI.
                Not used now.
            architecture (str): The architecture of the AMI.
                Not used now.
            root_device_name (str): The name of the root device
            block_device_mapping (list of dict): Dict can contain:
                device_name (str): The device name exposed to the instance
                    (for example, /dev/sdh or xvdh).
                virtual_name (str): The virtual device name (ephemeral[0..3]).
                ebs (dict): Dict can contain:
                    volume_id (str): The ID of the volume (Nova extension).
                    snapshot_id (str): The ID of the snapshot.
                    volume_size (str): The size of the volume, in GiBs.
                    volume_type (str): The volume type.
                        Not used now.
                    delete_on_termination (bool): Indicates whether to delete
                        the volume on instance termination.
                    iops (int): he number of IOPS to provision for the volume.
                        Not used now.
                    encrypted (boolean): Whether the volume is encrypted.
                        Not used now.
                no_device (str): Suppresses the device mapping.
            virtualization_type (str): The type of virtualization.
                Not used now.
            kernel_id (str): The ID of the kernel.
                Not used now.
            ramdisk_id (str): The ID of the RAM disk.
                Not used now.
            sriov_net_support (str): SR-IOV mode for networking.
                Not used now.

        Returns:
            The ID of the new AMI.
        """

    @module_and_param_types(image, 'amiariaki_id')
    def deregister_image(self, context, image_id):
        """Deregisters the specified AMI.

        Args:
            context (RequestContext): The request context.
            image_id (str): The ID of the AMI.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(image, 'strs', 'amiariaki_ids',
                            'strs', 'filter')
    def describe_images(self, context, executable_by=None, image_id=None,
                        owner=None, filter=None):
        """Describes one or more of the images available to you.

        Args:
            context (RequestContext): The request context.
            executable_by (list of str): Filters the images by users with
                explicit launch permissions.
                Not used now.
            image_id (list of str): One or more image IDs.
            owner (list of str): Filters the images by the owner.
                Not used now.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain images.

        Returns:
            A list of images.
        """

    @module_and_param_types(image, 'amiariaki_id', 'str')
    def describe_image_attribute(self, context, image_id, attribute):
        """Describes the specified attribute of the specified AMI.

        Args:
            context (RequestContext): The request context.
            image_id (str): The ID of the image.
            attribute (str): The attribute of the network interface.
                Valid values: description (unsupported now)| kernel | ramdisk |
                    launchPermission | productCodes (unsupported now)|
                    blockDeviceMapping | rootDeviceName (Nova EC2 extension)

        Returns:
            Specified attribute.
        """
        return image.describe_image_attribute(context, image_id, attribute)

    @module_and_param_types(image, 'amiariaki_id', 'str',
                            'strs', 'str',
                            'str', 'dummy',
                            'dummy', 'dummy', 'str')
    def modify_image_attribute(self, context, image_id, attribute=None,
                               user_group=None, operation_type=None,
                               description=None, launch_permission=None,
                               product_code=None, user_id=None, value=None):
        """Modifies the specified attribute of the specified AMI.

        Args:
            context (RequestContext): The request context.
            image_id (str): The ID of the image.
            attribute (str): The name of the attribute to modify.
            user_group (list of str): One or more user groups.
                Only 'all' group is supported now.
            operation_type (str): The operation type.
                Only 'add' and 'remove' operation types are supported now.
            description: A description for the AMI.
            launch_permission: : A launch permission modification.
            product_code: : Not supported now.
            user_id: : Not supported now.
            value: : The value of the attribute being modified.
                This is only valid when modifying the description attribute.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(image, 'amiariaki_id', 'str')
    def reset_image_attribute(self, context, image_id, attribute):
        """Resets an attribute of an AMI to its default value.

        Args:
            context (RequestContext): The request context.
            image_id (str): The ID of the image.
            attribute (str): The attribute to reset (currently you can only
                reset the launch permission attribute).

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(tag, 'ec2_ids', 'key_value_dict_list')
    def create_tags(self, context, resource_id, tag):
        """Adds or overwrites one or more tags for the specified resources.

        Args:
            context (RequestContext): The request context.
            resource_id (list of str): The IDs of one or more resources to tag.
            tag (list of dict): Dict can contain:
                key (str): The key of the tag.
                value (str): The value of the tag.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(tag, 'ec2_ids', 'dummy')
    def delete_tags(self, context, resource_id, tag=None):
        """Deletes the specified tags from the specified resources.

        Args:
            context (RequestContext): The request context.
            resource_id (list of str): The IDs of one or more resources to tag.
            tag (list of dict): One or more tags to delete.
                Dict can contain:
                key (str): The key of the tag.
                value (str): The value of the tag.

        Returns:
            true if the request succeeds.

        If you omit the value in tag parameter, we delete the tag regardless of
        its value. If you specify this parameter with an empty string as the
        value, we delete the key only if its value is an empty string.
        """

    @module_and_param_types(tag, 'filter', 'int',
                            'str')
    def describe_tags(self, context, filter=None, max_results=None,
                      next_token=None):
        """Describes one or more of the tags for your EC2 resources.

        Args:
            context (RequestContext): The request context.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain tags.
            max_results (int): The maximum number of items to return.
            next_token (str): The token for the next set of items to return.

        Returns:
            A list of tags.
        """


class VpcCloudController(CloudController):

    """VPC Cloud Controller

        Adds full VPC functionality which requires Neutron to work.
    """

    @module_and_param_types(vpc, 'vpc_cidr', 'str255')
    def create_vpc(self, context, cidr_block, instance_tenancy='default'):
        """Creates a VPC with the specified CIDR block.

        Args:
            context (RequestContext): The request context.
            cidr_block (str): The CIDR block for the VPC
                (for example, 10.0.0.0/16).
            instance_tenancy (str): The supported tenancy options for
                instances launched into the VPC.
                Valid values: default | dedicated
                Not used now.

        Returns:
            Information about the VPC.

        The smallest VPC you can create uses a /28 netmask (16 IP addresses),
        and the largest uses a /16 netmask.
        """

    @module_and_param_types(vpc, 'vpc_id')
    def delete_vpc(self, context, vpc_id):
        """Deletes the specified VPC.

        Args:
            context (RequestContext): The request context.
            vpc_id (str): The ID of the VPC.

        Returns:
            true if the request succeeds.

        You must detach or delete all gateways and resources that are
        associated with the VPC before you can delete it. For example, you must
        terminate all instances running in the VPC, delete all security groups
        associated with the VPC (except the default one), delete all route
        tables associated with the VPC (except the default one), and so on.
        """
        return vpc.delete_vpc(context, vpc_id)

    @module_and_param_types(vpc, 'vpc_ids', 'filter')
    def describe_vpcs(self, context, vpc_id=None, filter=None):
        """Describes one or more of your VPCs.

        Args:
            context (RequestContext): The request context.
            vpc_id (list of str): One or more VPC IDs.
                Default: Describes all your VPCs.
            filter (list of filter dict): You can specify filters so that
                the response includes information for only certain VPCs.

        Returns:
            A list of VPCs.
        """
        return vpc.describe_vpcs(context, vpc_id, filter)

    @module_and_param_types(internet_gateway)
    def create_internet_gateway(self, context):
        """Creates an Internet gateway for use with a VPC.

        Args:
            context (RequestContext): The request context.

        Returns:
            Information about the Internet gateway.
        """

    @module_and_param_types(internet_gateway, 'igw_id', 'vpc_id')
    def attach_internet_gateway(self, context, internet_gateway_id, vpc_id):
        """Attaches an Internet gateway to a VPC.

        Args:
            context (RequestContext): The request context.
            internet_gateway_id (str): The ID of the Internet gateway.
            vpc_id (str): The ID of the VPC.

        Returns:
            Returns true if the request succeeds.

        Attaches an Internet gateway to a VPC, enabling connectivity between
        the Internet and the VPC.
        """

    @module_and_param_types(internet_gateway, 'igw_id', 'vpc_id')
    def detach_internet_gateway(self, context, internet_gateway_id, vpc_id):
        """Detaches an Internet gateway from a VPC.

        Args:
            context (RequestContext): The request context.
            internet_gateway_id (str): The ID of the Internet gateway.
            vpc_id (str): The ID of the VPC.

        Returns:
            Returns true if the request succeeds.

        Detaches an Internet gateway from a VPC, disabling connectivity between
        the Internet and the VPC. The VPC must not contain any running
        instances with Elastic IP addresses.
        """

    @module_and_param_types(internet_gateway, 'igw_id')
    def delete_internet_gateway(self, context, internet_gateway_id):
        """Deletes the specified Internet gateway.

        Args:
            context (RequestContext): The request context.
            internet_gateway_id (str): The ID of the Internet gateway.

        Returns:
            Returns true if the request succeeds.

        You must detach the Internet gateway from the VPC before you can
        delete it.
        """

    @module_and_param_types(internet_gateway, 'igw_ids',
                            'filter')
    def describe_internet_gateways(self, context, internet_gateway_id=None,
                                   filter=None):
        """Describes one or more of your Internet gateways.

        Args:
            context (RequestContext): The request context.
            internet_gateway_id (list of str): One or more Internet gateway
                IDs.
                Default: Describes all your Internet gateways.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain Internet
                gateways.

        Returns:
            A list of Internet gateways.
        """

    @module_and_param_types(subnet, 'vpc_id', 'subnet_cidr',
                            'str255')
    def create_subnet(self, context, vpc_id, cidr_block,
                      availability_zone=None):
        """Creates a subnet in an existing VPC.

        Args:
            context (RequestContext): The request context.
            vpc_id (str): The ID of the VPC.
            cidr_block (str): The CIDR block for the subnet.
                For example, 10.0.0.0/24.
            availability_zone (str): The Availability Zone for the subnet.
                If None or empty EC2 selects one for you.

        Returns:
            Information about the subnet.

        The subnet's CIDR block can be the same as the VPC's CIDR block,
        or a subset of the VPC's CIDR block. If you create more than one subnet
        in a VPC, the subnets' CIDR blocks must not overlap. The smallest
        subnet you can create uses a /28 netmask (16 IP addresses),
        and the largest uses a /16 netmask.

        EC2 reserves both the first four and the last IP address
        in each subnet's CIDR block. They're not available for use.

        If you add more than one subnet to a VPC, they're set up
        in a star topology with a logical router in the middle.
        """

    @module_and_param_types(subnet, 'subnet_id')
    def delete_subnet(self, context, subnet_id):
        """Deletes the specified subnet.

        Args:
            context (RequestContext): The request context.
            subnet_id (str): The ID of the subnet.

        Returns:
            true if the request succeeds.

        You must terminate all running instances in the subnet before
        you can delete the subnet.
        """

    @module_and_param_types(subnet, 'subnet_ids', 'filter')
    def describe_subnets(self, context, subnet_id=None, filter=None):
        """Describes one or more of your subnets.


        Args:
            context (RequestContext): The request context.
            subnet_id (list of str): One or more subnet IDs.
                Default: Describes all your subnets.
            filter (list of filter dict): You can specify filters so that
                the response includes information for only certain subnets.

        Returns:
            A list of subnets.
        """

    @module_and_param_types(route_table, 'vpc_id')
    def create_route_table(self, context, vpc_id):
        """Creates a route table for the specified VPC.

        Args:
            context (RequestContext): The request context.
            vpc_id (str): The ID of the VPC.

        Returns:
            Information about the route table.

        After you create a route table, you can add routes and associate the
        table with a subnet.
        """

    @module_and_param_types(route_table, 'rtb_id', 'cidr',
                            'igw_or_vgw_id', 'i_id',
                            'eni_id',
                            'dummy')
    def create_route(self, context, route_table_id, destination_cidr_block,
                     gateway_id=None, instance_id=None,
                     network_interface_id=None,
                     vpc_peering_connection_id=None):
        """Creates a route in a route table within a VPC.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table for the route.
            destination_cidr_block (str): The CIDR address block used for the
                destination match. Routing decisions are based on the most
                specific match.
            gateway_id (str): The ID of an Internet gateway or virtual private
                gateway attached to your VPC.
            instance_id (str): The ID of a NAT instance in your VPC.
                The operation fails if you specify an instance ID unless
                exactly one network interface is attached.
            network_interface_id (str): The ID of a network interface.
            vpc_peering_connection_id (str): The ID of a VPC peering
                connection.

        Returns:
            true if the requests succeeds.

        The route's target can be an Internet gateway or virtual private
        gateway attached to the VPC, a VPC peering connection, or a NAT
        instance in the VPC.
        """

    @module_and_param_types(route_table, 'rtb_id', 'cidr',
                            'igw_or_vgw_id', 'i_id',
                            'eni_id',
                            'dummy')
    def replace_route(self, context, route_table_id, destination_cidr_block,
                      gateway_id=None, instance_id=None,
                      network_interface_id=None,
                      vpc_peering_connection_id=None):
        """Replaces an existing route within a route table in a VPC.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table for the route.
            destination_cidr_block (str): The CIDR address block used for the
                destination match. Routing decisions are based on the most
                specific match.
            gateway_id (str): The ID of an Internet gateway or virtual private
                gateway attached to your VPC.
            instance_id (str): The ID of a NAT instance in your VPC.
                The operation fails if you specify an instance ID unless
                exactly one network interface is attached.
            network_interface_id (str): The ID of a network interface.
            vpc_peering_connection_id (str): The ID of a VPC peering
                connection.

        Returns:
            true if the requests succeeds.
        """

    @module_and_param_types(route_table, 'rtb_id', 'cidr')
    def delete_route(self, context, route_table_id, destination_cidr_block):
        """Deletes the specified route from the specified route table.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table.
            destination_cidr_block (str): The CIDR range for the route.
                The value you specify must match the CIDR for the route
                exactly.

        Returns:
            true if the requests succeeds.
        """

    @module_and_param_types(route_table, 'rtb_id',
                            'vgw_id')
    def enable_vgw_route_propagation(self, context, route_table_id,
                                     gateway_id):
        """Enables a VGW to propagate routes to the specified route table.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table.
            gateway_id (str): The ID of the virtual private gateway.

        Returns:
            true if the requests succeeds.
        """

    @module_and_param_types(route_table, 'rtb_id',
                            'vgw_id')
    def disable_vgw_route_propagation(self, context, route_table_id,
                                      gateway_id):
        """Disables a (VGW) from propagating routes to a specified route table.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table.
            gateway_id (str): The ID of the virtual private gateway.

        Returns:
            true if the requests succeeds.
        """

    @module_and_param_types(route_table, 'rtb_id', 'subnet_id')
    def associate_route_table(self, context, route_table_id, subnet_id):
        """Associates a subnet with a route table.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table.
            subnet_id (str): The ID of the subnet.

        Returns:
            The route table association ID

        The subnet and route table must be in the same VPC. This association
        causes traffic originating from the subnet to be routed according to
        the routes in the route table. The action returns an association ID,
        which you need in order to disassociate the route table from the subnet
        later. A route table can be associated with multiple subnets.
        """

    @module_and_param_types(route_table, 'rtbassoc_id',
                            'rtb_id')
    def replace_route_table_association(self, context, association_id,
                                        route_table_id):
        """Changes the route table associated with a given subnet in a VPC.

        Args:
            context (RequestContext): The request context.
            association_id (str): The association ID.
            route_table_id (str): The ID of the new route table to associate
                with the subnet.

        Returns:
            The ID of the new association.

        After the operation completes, the subnet uses the routes in the new
        route table it's associated with.
        You can also use this action to change which table is the main route
        table in the VPC.
        """

    @module_and_param_types(route_table, 'rtbassoc_id')
    def disassociate_route_table(self, context, association_id):
        """Disassociates a subnet from a route table.

        Args:
            context (RequestContext): The request context.
            association_id (str): The association ID.

        Returns:
            true if the requests succeeds.

        After you perform this action, the subnet no longer uses the routes in
        the route table. Instead, it uses the routes in the VPC's main route
        table.
        """

    @module_and_param_types(route_table, 'rtb_id')
    def delete_route_table(self, context, route_table_id):
        """Deletes the specified route table.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): The ID of the route table.

        You must disassociate the route table from any subnets before you can
        delete it. You can't delete the main route table.

        Returns:
            true if the requests succeeds.
        """

    @module_and_param_types(route_table, 'rtb_ids', 'filter')
    def describe_route_tables(self, context, route_table_id=None, filter=None):
        """Describes one or more of your route tables.

        Args:
            context (RequestContext): The request context.
            route_table_id (str): One or more route table IDs.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain tables.

        Returns:
            A list of route tables
        """

    @module_and_param_types(dhcp_options, 'key_value_dict_list')
    def create_dhcp_options(self, context, dhcp_configuration):
        """Creates a set of DHCP options for your VPC.

        Args:
            context (RequestContext): The request context.
            dhcp_configuration (list of dict): Dict can contain
                'key' (str) and
                'value' (str) for each option.
                You can specify the following options:
                - domain-name-servers: up to 4 DNS servers,
                    IPs are in value separated by commas
                - domain-name: domain name
                - ntp-servers: up to 4 NTP servers
                - netbios-name-servers: up to 4 NetBIOS name servers
                - netbios-node-type: the NetBIOS node type (1,2,4 or 8)
        Returns:
            A set of DHCP options

        """

    @module_and_param_types(dhcp_options, 'dopt_ids',
                            'filter')
    def describe_dhcp_options(self, context, dhcp_options_id=None,
                              filter=None):
        """Describes the specified DHCP options.


        Args:
            context (RequestContext): The request context.
            dhcp_options_id (list of str): DHCP options id.
            filter (list of filter dict): You can specify filters so that
                the response includes information for only certain DHCP
                options.

        Returns:
            DHCP options.
        """

    @module_and_param_types(dhcp_options, 'dopt_id')
    def delete_dhcp_options(self, context, dhcp_options_id):
        """Deletes the specified set of DHCP options

        Args:
            context (RequestContext): The request context.
            dhcp_options_id (str): DHCP options id

        Returns:
            true if the request succeeds

        You must disassociate the set of DHCP options before you can delete it.
        You can disassociate the set of DHCP options by associating either a
        new set of options or the default set of options with the VPC.
        """

    @module_and_param_types(dhcp_options, 'dopt_id_or_default', 'vpc_id')
    def associate_dhcp_options(self, context, dhcp_options_id, vpc_id):
        """Associates a set of DHCP options with the specified VPC.

        Args:
            context (RequestContext): The request context.
            dhcp_options_id (str): DHCP options id or "default" to associate no
                DHCP options with the VPC

        Returns:
            true if the request succeeds
        """

    @module_and_param_types(network_interface, 'subnet_id',
                            'ip',
                            'dummy',
                            'int',
                            'str',
                            'sg_ids')
    def create_network_interface(self, context, subnet_id,
                                 private_ip_address=None,
                                 private_ip_addresses=None,
                                 secondary_private_ip_address_count=None,
                                 description=None,
                                 security_group_id=None):
        """Creates a network interface in the specified subnet.

        Args:
            subnet_id (str): The ID of the subnet to associate with the
                network interface.
            private_ip_address (str): The primary private IP address of the
                network interface. If you don't specify an IP address,
                EC2 selects one for you from the subnet range.
            private_ip_addresses (list of dict): Dict can contain
                'private_ip_address' (str) and
                'primary' (boolean) for each address.
                The private IP addresses of the specified network interface and
                indicators which one is primary. Only one private IP address
                can be designated as primary.
                You can't specify this parameter when
                private_ip_addresses['primary'] is true if you specify
                private_ip_address.
            secondary_private_ip_address_count (integer): The number of
                secondary private IP addresses to assign to a network
                interface. EC2 selects these IP addresses within the subnet
                range. For a single network interface, you can't specify this
                option and specify more than one private IP address using
                private_ip_address and/or private_ip_addresses.
            description (str): A description for the network interface.
            security_group_id (list of str): The list of security group IDs
                for the network interface.

        Returns:
            The network interface that was created.
        """

    @module_and_param_types(network_interface, 'eni_id')
    def delete_network_interface(self, context, network_interface_id):
        """Deletes the specified network interface.


        Args:
            context (RequestContext): The request context.
            network_interface_id (str): The ID of the network interface.

        Returns:
            true if the request succeeds.

        You must detach the network interface before you can delete it.
        """

    @module_and_param_types(network_interface, 'eni_ids',
                            'filter')
    def describe_network_interfaces(self, context, network_interface_id=None,
                                    filter=None):
        """Describes one or more of your network interfaces.


        Args:
            context (RequestContext): The request context.
            network_interface_id (list of str): One or more network interface
                IDs.
                Default: Describes all your network interfaces.
            filter (list of filter dict): You can specify filters so that
                the response includes information for only certain interfaces.

        Returns:
            A list of network interfaces.
        """
        return network_interface.describe_network_interfaces(
                                    context, network_interface_id, filter)

    @module_and_param_types(network_interface, 'eni_id',
                            'str')
    def describe_network_interface_attribute(self, context,
                                             network_interface_id,
                                             attribute=None):
        """Describes the specified attribute of the specified network interface.


        Args:
            context (RequestContext): The request context.
            network_interface_id: Network interface ID.
            attribute: The attribute of the network interface.

        Returns:
            Specified attribute.

        You can specify only one attribute at a time.
        """
        return network_interface.describe_network_interface_attribute(
                context, network_interface_id, attribute)

    @module_and_param_types(network_interface, 'eni_id',
                            'str',
                            'bool',
                            'sg_ids',
                            'dummy')
    def modify_network_interface_attribute(self, context,
                                           network_interface_id,
                                           description=None,
                                           source_dest_check=None,
                                           security_group_id=None,
                                           attachment=None):
        """Modifies the specified attribute of the specified network interface.


        Args:
            context (RequestContext): The request context.
            network_interface_id: Network interface ID.
            description: New description.
            source_dest_check: Indicates whether source/destination checking is
                enabled. A value of true means checking is enabled, and false
                means checking is disabled.
                This value must be false for a NAT instance to perform NAT.
            security_group_id [list of str]: List of secuirity groups to attach
            attachment: Information about the interface attachment. If
                modifying the 'delete on termination' attribute, you must
                specify the ID of the interface attachment.

        Returns:
            true if the request succeeds.

        You can specify only one attribute at a time.
        """

    @module_and_param_types(network_interface, 'eni_id',
                            'str')
    def reset_network_interface_attribute(self, context,
                                          network_interface_id,
                                          attribute):
        """Resets the specified attribute of the specified network interface.


        Args:
            context (RequestContext): The request context.
            network_interface_id: Network interface ID.
            attribute: The attribute to reset. Valid values "SourceDestCheck"
                (reset to True)

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(network_interface, 'eni_id',
                            'i_id', 'int')
    def attach_network_interface(self, context, network_interface_id,
                                 instance_id, device_index):
        """Attach a network interface to an instance.

        Args:
            context (RequestContext): The request context.
            network_interface_id (str): The ID of the network interface.
            instance_id (str): The ID of the instance.
            device_index (int): The index of the device for the network
                interface attachment.

        Returns:
            Attachment Id
        """

    @module_and_param_types(network_interface, 'eni_attach_id',
                            'bool')
    def detach_network_interface(self, context, attachment_id,
                                 force=None):
        """Detach a network interface from an instance.

        Args:
            context (RequestContext): The request context.
            attachment_id (str): The ID of the attachment.
            force (boolean): Specifies whether to force a detachment

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(network_interface, 'eni_id',
                            'ips',
                            'int',
                            'bool')
    def assign_private_ip_addresses(self, context, network_interface_id,
                                    private_ip_address=None,
                                    secondary_private_ip_address_count=None,
                                    allow_reassignment=False):
        """Assigns secondary private IP addresses to the network interface.

         Args:
            network_interface_id (str): The ID of the network interface.
            private_ip_address (list of str): List of IP addresses to assign.
            secondary_private_ip_address_count (integer): The number of
                secondary private IP addresses to assign. EC2 selects these
                IP addresses within the subnet range.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(network_interface, 'eni_id',
                            'ips')
    def unassign_private_ip_addresses(self, context, network_interface_id,
                                      private_ip_address=None):
        """Unassigns secondary IP addresses from the network interface.

         Args:
            network_interface_id (str): The ID of the network interface.
            private_ip_address (list of str): List of secondary private IP
            addresses to unassign.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(vpn_gateway, 'vpn_connection_type', 'str')
    def create_vpn_gateway(self, context, type, availability_zone=None):
        """Creates a virtual private gateway.

        Args:
            context (RequestContext): The request context.
            type (str): The type of VPN connection this virtual private
                gateway supports (ipsec.1).
            availability_zone (str): The Availability Zone for the virtual
                private gateway.

        Returns:
            Information about the virtual private gateway.
        """

    @module_and_param_types(vpn_gateway, 'vpc_id', 'vgw_id')
    def attach_vpn_gateway(self, context, vpc_id, vpn_gateway_id):
        """Attaches a virtual private gateway to a VPC.

        Args:
            context (RequestContext): The request context.
            vpc_id (str): The ID of the VPC.
            vpn_gateway_id (str): he ID of the virtual private gateway.

        Returns:
            Information about the attachment.
        """

    @module_and_param_types(vpn_gateway, 'vpc_id', 'vgw_id')
    def detach_vpn_gateway(self, context, vpc_id, vpn_gateway_id):
        """Detaches a virtual private gateway from a VPC.

        Args:
            context (RequestContext): The request context.
            vpc_id (str): The ID of the VPC.
            vpn_gateway_id (str): he ID of the virtual private gateway.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(vpn_gateway, 'vgw_id')
    def delete_vpn_gateway(self, context, vpn_gateway_id):
        """Deletes the specified virtual private gateway.

        Args:
            context (RequestContext): The request context.
            vpn_gateway_id (str): The ID of the virtual private gateway.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(vpn_gateway, 'vgw_ids', 'filter')
    def describe_vpn_gateways(self, context, vpn_gateway_id=None, filter=None):
        """Describes one or more of your virtual private gateways.

        Args:
            context (RequestContext): The request context.
            vpn_gateway_id (list of str): One or more virtual private gateway
                IDs.
            filter (list of filter dict): One or more filters.

        Returns:
            Information about one or more virtual private gateways.
        """

    @module_and_param_types(customer_gateway, 'ip', 'vpn_connection_type',
                            'int')
    def create_customer_gateway(self, context, ip_address, type,
                                bgp_asn=None):
        """Provides information to EC2 API about VPN customer gateway device.

        Args:
            context (RequestContext): The request context.
            ip_address (str): The Internet-routable IP address for the
                customer gateway's outside interface.
            type (str): The type of VPN connection that this customer gateway
                supports (ipsec.1).
            bgp_asn (int): For devices that support BGP,
                the customer gateway's BGP ASN (65000 otherwise).

        Returns:
            Information about the customer gateway.

        You cannot create more than one customer gateway with the same VPN
        type, IP address, and BGP ASN parameter values. If you run an
        identical request more than one time, subsequent requests return
        information about the existing customer gateway.
        """

    @module_and_param_types(customer_gateway, 'cgw_id')
    def delete_customer_gateway(self, context, customer_gateway_id):
        """Deletes the specified customer gateway.

        Args:
            context (RequestContext): The request context.
            customer_gateway_id (str): The ID of the customer gateway.

        Returns:
            true if the request succeeds.

        You must delete the VPN connection before you can delete the customer
        gateway.
        """

    @module_and_param_types(customer_gateway, 'cgw_ids',
                            'filter')
    def describe_customer_gateways(self, context, customer_gateway_id=None,
                                   filter=None):
        """Describes one or more of your VPN customer gateways.

        Args:
            context (RequestContext): The request context.
            customer_gateway_id (list of str): One or more customer gateway
                IDs.
            filter (list of filter dict): One or more filters.

        Returns:
            Information about one or more customer gateways.
        """

    @module_and_param_types(vpn_connection, 'cgw_id',
                            'vgw_id', 'vpn_connection_type', 'dummy')
    def create_vpn_connection(self, context, customer_gateway_id,
                              vpn_gateway_id, type, options=None):
        """Creates a VPN connection.

        Args:
            context (RequestContext): The request context.
            customer_gateway_id (str): The ID of the customer gateway.
            vpn_gateway_id (str): The ID of the virtual private gateway.
            type (str): The type of VPN connection (ipsec.1).
            options (dict of options): Indicates whether the VPN connection
                requires static routes.

        Returns:
            Information about the VPN connection.

        Creates a VPN connection between an existing virtual private gateway
        and a VPN customer gateway.
        """

    @module_and_param_types(vpn_connection, 'vpn_id',
                            'cidr')
    def create_vpn_connection_route(self, context, vpn_connection_id,
                                    destination_cidr_block):
        """Creates a static route associated with a VPN connection.

        Args:
            context (RequestContext): The request context.
            vpn_connection_id (str): The ID of the VPN connection.
            destination_cidr_block (str): The CIDR block associated with the
                local subnet of the customer network.

        Returns:
            true if the request succeeds.

        The static route allows traffic to be routed from the virtual private
        gateway to the VPN customer gateway.
        """

    @module_and_param_types(vpn_connection, 'vpn_id',
                            'cidr')
    def delete_vpn_connection_route(self, context, vpn_connection_id,
                                    destination_cidr_block):
        """Deletes the specified static route associated with a VPN connection.

        Args:
            context (RequestContext): The request context.
            vpn_connection_id (str): The ID of the VPN connection.
            destination_cidr_block (str): The CIDR block associated with the
                local subnet of the customer network.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(vpn_connection, 'vpn_id')
    def delete_vpn_connection(self, context, vpn_connection_id):
        """Deletes the specified VPN connection.

        Args:
            context (RequestContext): The request context.
            vpn_connection_id (str): The ID of the VPN connection.

        Returns:
            true if the request succeeds.
        """

    @module_and_param_types(vpn_connection, 'vpn_ids',
                            'filter')
    def describe_vpn_connections(self, context, vpn_connection_id=None,
                                 filter=None):
        """Describes one or more of your VPN connections.

        Args:
            context (RequestContext): The request context.
            vpn_connection_id (list of str): One or more VPN connection IDs.
            filter (list of filter dict): One or more filters.

        Returns:
            Information about one or more VPN connections.
        """
