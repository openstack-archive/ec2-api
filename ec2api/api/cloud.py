#    Copyright 2014 Cloudscaling Group, Inc
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


"""
Cloud Controller: Implementation of EC2 REST API calls, which are
dispatched to other nodes via AMQP RPC. State is via distributed
datastore.
"""

from oslo.config import cfg

from ec2api.api import address
from ec2api.api import dhcp_options
from ec2api.api import instance
from ec2api.api import internet_gateway
from ec2api.api import network_interface
from ec2api.api import route_table
from ec2api.api import security_group
from ec2api.api import subnet
from ec2api.api import vpc
from ec2api.openstack.common import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


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
        return vpc.create_vpc(context, cidr_block, instance_tenancy)

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

    def create_internet_gateway(self, context):
        """Creates an Internet gateway for use with a VPC.

        Args:
            context (RequestContext): The request context.

        Returns:
            Information about the Internet gateway.
        """
        return internet_gateway.create_internet_gateway(context)

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
        return internet_gateway.attach_internet_gateway(context,
                                                       internet_gateway_id,
                                                       vpc_id)

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
        return internet_gateway.detach_internet_gateway(context,
                                                       internet_gateway_id,
                                                       vpc_id)

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
        return internet_gateway.delete_internet_gateway(context,
                                                       internet_gateway_id)

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
        return internet_gateway.describe_internet_gateways(context,
                                                          internet_gateway_id,
                                                          filter)

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
        return subnet.create_subnet(context, vpc_id,
                                    cidr_block, availability_zone)

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
        return subnet.delete_subnet(context, subnet_id)

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
        return subnet.describe_subnets(context, subnet_id, filter)

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
        return route_table.create_route_table(context, vpc_id)

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
        return route_table.create_route(context, route_table_id,
                                        destination_cidr_block, gateway_id,
                                        instance_id, network_interface_id,
                                        vpc_peering_connection_id)

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
        return route_table.replace_route(context, route_table_id,
                                         destination_cidr_block,
                                         gateway_id, instance_id,
                                         network_interface_id,
                                         vpc_peering_connection_id)

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
        return route_table.delete_route(context, route_table_id,
                                        destination_cidr_block)

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
        return route_table.associate_route_table(context, route_table_id,
                                                 subnet_id)

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
        return route_table.replace_route_table_association(context,
                                                           association_id,
                                                           route_table_id)

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
        return route_table.disassociate_route_table(context, association_id)

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
        return route_table.delete_route_table(context, route_table_id)

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
        return route_table.describe_route_tables(context, route_table_id,
                                                 filter)

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
        return dhcp_options.create_dhcp_options(context, dhcp_configuration)

    def describe_dhcp_options(self, context, dhcp_options_id=None,
                              filter=None):
        """Describes the specified DHCP options.


        Args:
            context (RequestContext): The request context.
            dhcp_options_id: DHCP options id.
            filter (list of filter dict): You can specify filters so that
                the response includes information for only certain DHCP
                options.

        Returns:
            DHCP options.
        """
        return dhcp_options.describe_dhcp_options(context, dhcp_options_id,
                                                  filter)

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
        return dhcp_options.delete_dhcp_options(context, dhcp_options_id)

    def associate_dhcp_options(self, context, dhcp_options_id, vpc_id):
        """Associates a set of DHCP options with the specified VPC.

        Args:
            context (RequestContext): The request context.
            dhcp_options_id (str): DHCP options id or "default" to associate no
                DHCP options with the VPC

        Returns:
            true if the request succeeds
        """
        return dhcp_options.associate_dhcp_options(context, dhcp_options_id,
                                                   vpc_id)

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
        return address.allocate_address(context, domain)

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
        return address.associate_address(
                context, public_ip, instance_id, allocation_id,
                network_interface_id, private_ip_address, allow_reassociation)

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
        return address.disassociate_address(context, public_ip,
                                               association_id)

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
        return address.release_address(context, public_ip, allocation_id)

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
        return address.describe_addresses(context, public_ip, allocation_id,
                                             filter)

    def describe_security_groups(self, context, group_name=None, group_id=None,
                                 filter=None):
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
        return security_group.describe_security_groups(context, group_name,
                                                       group_id, filter)

    def create_security_group(self, context, group_name=None,
                              group_description=None, vpc_id=None):
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
        return security_group.create_security_group(context, group_name,
                                                    group_description, vpc_id)

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
        return security_group.delete_security_group(context, group_name,
                                                    group_id)

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
        return security_group.authorize_security_group_ingress(
                                                context, group_id,
                                                group_name, ip_permissions)

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
        return security_group.authorize_security_group_egress(
                                                context, group_id,
                                                ip_permissions)

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
        return security_group.revoke_security_group_ingress(
                                                context, group_id,
                                                group_name, ip_permissions)

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
        return security_group.revoke_security_group_egress(
                                                context, group_id,
                                                ip_permissions)

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
            security_group_id (str): The list of security group IDs for the
                network interface.

        Returns:
            The network interface that was created.
        """
        return network_interface.create_network_interface(context, subnet_id,
                    private_ip_address, private_ip_addresses,
                    secondary_private_ip_address_count, description,
                    security_group_id)

    def delete_network_interface(self, context, network_interface_id):
        """Deletes the specified network interface.


        Args:
            context (RequestContext): The request context.
            network_interface_id (str): The ID of the network interface.

        Returns:
            true if the request succeeds.

        You must detach the network interface before you can delete it.
        """
        return network_interface.delete_network_interface(context,
                                                         network_interface_id)

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
        return network_interface.describe_network_interfaces(context,
                                                network_interface_id, filter)

    def describe_network_interface_attribute(self, context,
                                             network_interface_id,
                                             attribute):
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

    def modify_network_interface_attribute(self, context,
                                             network_interface_id,
                                             description=None,
                                             source_dest_check=None,
                                             security_group_id=None):
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

        Returns:
            true if the request succeeds.

        You can specify only one attribute at a time.
        """
        return network_interface.modify_network_interface_attribute(context,
                                            network_interface_id, description,
                                            source_dest_check,
                                            security_group_id)

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
        return network_interface.reset_network_interface_attribute(context,
                                            network_interface_id, attribute)

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
        return network_interface.attach_network_interface(context,
                                                          network_interface_id,
                                                          instance_id,
                                                          device_index)

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
        return network_interface.detach_network_interface(context,
                                                         attachment_id,
                                                         force)

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
        return network_interface.assign_private_ip_addresses(
            context,
            network_interface_id,
            private_ip_address,
            secondary_private_ip_address_count,
            allow_reassignment)

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
        return network_interface.unassign_private_ip_addresses(
            context,
            network_interface_id,
            private_ip_address)

    def run_instances(self, context, image_id, min_count, max_count,
                      key_name=None, security_group_id=None,
                      security_group=None, user_data=None, instance_type=None,
                      placement=None, kernel_id=None, ramdisk_id=None,
                      block_device_mapping=None, subnet_id=None,
                      private_ip_address=None, client_token=None,
                      network_interface=None, **kwargs):
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
                    delete_on_termination (bool): Indicates whether to delete
                        the volume on instance termination.
                no_device (str): Suppresses the device mapping.
            subnet_id (str): The ID of the subnet to launch the instance into.
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
            kwargs: Other arguments supported by AWS EC2.

        Returns:
            The instance reservation that was created.

        If you don't specify a security group when launching an instance, EC2
        uses the default security group.
        """
        return instance.run_instances(context, image_id, min_count, max_count,
                                      key_name, security_group_id,
                                      security_group, user_data, instance_type,
                                      placement, kernel_id, ramdisk_id,
                                      block_device_mapping, subnet_id,
                                      private_ip_address, client_token,
                                      network_interface, **kwargs)

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
        return instance.terminate_instances(context, instance_id)

    def describe_instances(self, context, instance_id=None, filter=None,
                           **kwargs):
        """Describes one or more of your instances.

        Args:
            context (RequestContext): The request context.
            instance_id (list of str): One or more instance IDs.
            filter (list of filter dict): You can specify filters so that the
                response includes information for only certain instances.

        Returns:
            A list of reservations.

        If you specify one or more instance IDs, Amazon EC2 returns information
        for those instances. If you do not specify instance IDs, you receive
        information for all relevant instances. If you specify an invalid
        instance ID, you receive an error. If you specify an instance that you
        don't own, we don't include it in the results.
        """
        return instance.describe_instances(context, instance_id, filter,
                                           **kwargs)
