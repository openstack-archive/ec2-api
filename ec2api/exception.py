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

"""ec2api base exception handling.

Includes decorator for re-raising ec2api-type exceptions.

SHOULD include dedicated exception logging.

"""

import sys

from oslo_config import cfg
from oslo_log import log as logging
import six

from ec2api.i18n import _

LOG = logging.getLogger(__name__)

exc_log_opts = [
    cfg.BoolOpt('fatal_exception_format_errors',
                default=False,
                help='Make exception message format errors fatal'),
]

CONF = cfg.CONF
CONF.register_opts(exc_log_opts)


class EC2APIException(Exception):
    """Base EC2 API Exception

    To correctly use this class, inherit from it and define
    a 'msg_fmt' property. That msg_fmt will get printf'd
    with the keyword arguments provided to the constructor.
    """
    msg_fmt = _('An unknown exception occurred.')

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs

        if not message:
            try:
                message = self.msg_fmt % kwargs
            except Exception:
                exc_info = sys.exc_info()
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception('Exception in string format operation for '
                              '%s exception', self.__class__.__name__)
                for name, value in kwargs.items():
                    LOG.error('%s: %s' % (name, value))

                if CONF.fatal_exception_format_errors:
                    six.reraise(*exc_info)
                else:
                    # at least get the core message out if something happened
                    message = self.msg_fmt
        elif not isinstance(message, six.string_types):
            LOG.error("Message '%(msg)s' for %(ex)s exception is not "
                      "a string",
                      {'msg': message, 'ex': self.__class__.__name__})
            if CONF.fatal_exception_format_errors:
                raise TypeError(_('Invalid exception message format'))
            else:
                message = self.msg_fmt

        super(EC2APIException, self).__init__(message)

    def format_message(self):
        # NOTE(mrodden): use the first argument to the python Exception object
        # which should be our full EC2APIException message, (see __init__)
        return self.args[0]


# Internal ec2api exceptions

class EC2APIConfigNotFound(EC2APIException):
    msg_fmt = _("Could not find config at %(path)s")


class EC2APIPasteAppNotFound(EC2APIException):
    msg_fmt = _("Could not load paste app '%(name)s' from %(path)s")


class EC2KeystoneDiscoverFailure(EC2APIException):
    msg_fmt = _("Could not discover keystone versions.")


class EC2DBInvalidOsIdUpdate(EC2APIException):
    msg_fmt = _('Invalid update of os_id of %(item_id)s item '
                'from %(old_os_id)s to %(new_os_id)s')


class EC2DBDuplicateEntry(EC2APIException):
    msg_fmt = _('Entry %(id)s already exists in DB.')


# Internal ec2api metadata exceptions

class EC2MetadataException(EC2APIException):
    pass


class EC2MetadataNotFound(EC2MetadataException):
    pass


class EC2MetadataInvalidAddress(EC2MetadataException):
    pass


# Intermediate exception classes to organize AWS exception hierarchy

class EC2Exception(EC2APIException):
    """Base EC2 compliant exception

    To correctly use this class, inherit from it and define
    a 'ec2_code' property if a new class name doesn't coincide with
    AWS Error Code.
    """
    code = 400


class EC2InvalidException(EC2Exception):
    pass


class EC2IncorrectStateException(EC2Exception):
    pass


class EC2DuplicateException(EC2InvalidException):
    pass


class EC2InUseException(EC2InvalidException):
    pass


class EC2NotFoundException(EC2InvalidException):
    pass


class EC2OverlimitException(EC2Exception):
    pass


# AWS compliant exceptions

class Unsupported(EC2Exception):
    msg_fmt = _("The specified request is unsupported. %(reason)s")


class UnsupportedOperation(EC2Exception):
    msg_fmt = _('The specified request includes an unsupported operation.')


class OperationNotPermitted(EC2Exception):
    msg_fmt = _('The specified operation is not allowed.')


class InvalidRequest(EC2InvalidException):
    msg_fmt = _('The request received was invalid.')


class InvalidAttribute(EC2InvalidException):
    msg_fmt = _("Attribute not supported: %(attr)s")


class InvalidID(EC2InvalidException):
    msg_fmt = _("The ID '%(id)s' is not valid")


class InvalidInput(EC2InvalidException):
    msg_fmt = _("Invalid input received: %(reason)s")


class AuthFailure(EC2InvalidException):
    msg_fmt = _('Not authorized.')


class ValidationError(EC2InvalidException):
    msg_fmt = _("The input fails to satisfy the constraints "
                "specified by an AWS service: '%(reason)s'")


class MissingInput(EC2InvalidException):
    pass


class MissingParameter(EC2InvalidException):
    msg_fmt = _("The required parameter '%(param)s' is missing")


class InvalidParameter(EC2InvalidException):
    msg_fmt = _("The property '%(name)s' is not valid")


class InvalidParameterValue(EC2InvalidException):
    msg_fmt = _("Value (%(value)s) for parameter %(parameter)s is invalid. "
                "%(reason)s")


class InvalidFilter(EC2InvalidException):
    msg_fmt = _('The filter is invalid.')


class InvalidParameterCombination(EC2InvalidException):
    msg_fmt = _('The combination of parameters in incorrect')


class InvalidVpcRange(EC2InvalidException):
    ec2_code = 'InvalidVpc.Range'
    msg_fmt = _("The CIDR '%(cidr_block)s' is invalid.")


class InvalidVpcState(EC2InvalidException):
    msg_fmt = _('VPC %(vpc_id)s is currently attached to '
                'the Virtual Private Gateway %(vgw_id)s')


class InvalidSubnetRange(EC2InvalidException):
    ec2_code = 'InvalidSubnet.Range'
    msg_fmt = _("The CIDR '%(cidr_block)s' is invalid.")


class InvalidSubnetConflict(EC2InvalidException):
    ec2_code = 'InvalidSubnet.Conflict'
    msg_fmt = _("The CIDR '%(cidr_block)s' conflicts with another subnet")


class InvalidInstanceId(EC2InvalidException):
    ec2_code = 'InvalidInstanceID'
    msg_fmt = _("There are multiple interfaces attached to instance "
                "'%(instance_id)s'. Please specify an interface ID for "
                "the operation instead.")


class InvalidSnapshotIDMalformed(EC2InvalidException):
    ec2_code = 'InvalidSnapshotID.Malformed'
    # TODO(ft): Change the message with the real AWS message
    msg_fmg = _('The snapshot %(id)s ID is not valid')


class InvalidBlockDeviceMapping(EC2InvalidException):
    pass


class IncorrectState(EC2IncorrectStateException):
    msg_fmt = _("The resource is in incorrect state for the request - reason: "
                "'%(reason)s'")


class DependencyViolation(EC2IncorrectStateException):
    msg_fmt = _('Object %(obj1_id)s has dependent resource %(obj2_id)s')


class CannotDelete(EC2IncorrectStateException):
    msg_fmt = _('Cannot delete the default VPC security group')


class ResourceAlreadyAssociated(EC2IncorrectStateException):
    ec2_code = 'Resource.AlreadyAssociated'


class GatewayNotAttached(EC2IncorrectStateException):
    ec2_code = 'Gateway.NotAttached'
    msg_fmt = _("resource %(gw_id)s is not attached to network %(vpc_id)s")


class IncorrectInstanceState(EC2IncorrectStateException):
    msg_fmt = _("The instance '%(instance_id)s' is not in a state from which "
                "the requested operation can be performed.")


class InvalidAMIIDUnavailable(EC2IncorrectStateException):
    ec2_code = 'InvalidAMIID.Unavailable'
    # TODO(ft): Change the message with the real AWS message
    msg_fmt = _("Image %(image_id)s is not active.")


class InvalidNetworkInterfaceInUse(EC2InUseException):
    ec2_code = 'InvalidNetworkInterface.InUse'
    msg_fmt = _('Interface: %(interface_ids)s in use.')


class InvalidIPAddressInUse(EC2InUseException):
    ec2_code = 'InvalidIPAddress.InUse'
    msg_fmt = _('Address %(ip_address)s is in use.')


class InvalidKeyPairDuplicate(EC2DuplicateException):
    ec2_code = 'InvalidKeyPair.Duplicate'
    msg_fmt = _("Key pair '%(key_name)s' already exists.")


class InvalidPermissionDuplicate(EC2DuplicateException):
    ec2_code = 'InvalidPermission.Duplicate'
    msg_fmt = _('The specified rule already exists for that security group.')


class InvalidGroupDuplicate(EC2DuplicateException):
    ec2_code = 'InvalidGroup.Duplicate'
    msg_fmt = _("Security group '%(name)s' already exists.")


class RouteAlreadyExists(EC2DuplicateException):
    msg_fmt = _('The route identified by %(destination_cidr_block)s '
                'already exists.')


class InvalidCustomerGatewayDuplicateIpAddress(EC2DuplicateException):
    ec2_code = 'InvalidCustomerGateway.DuplicateIpAddress'
    msg_fmt = _('Conflict among chosen gateway IP addresses.')


class InvalidVpcIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidVpcID.NotFound'
    msg_fmt = _("The vpc ID '%(id)s' does not exist")


class InvalidInternetGatewayIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidInternetGatewayID.NotFound'
    msg_fmt = _("The internetGateway ID '%(id)s' does not exist")


class InvalidSubnetIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidSubnetID.NotFound'
    msg_fmt = _("The subnet ID '%(id)s' does not exist")


class InvalidNetworkInterfaceIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidNetworkInterfaceID.NotFound'
    msg_fmt = _("Network interface %(id)s could not "
                "be found.")


class InvalidAttachmentIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidAttachmentID.NotFound'
    msg_fmt = _("Attachment %(id)s could not "
                "be found.")


class InvalidInstanceIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidInstanceID.NotFound'
    msg_fmt = _("The instance ID '%(id)s' does not exist")


class InvalidDhcpOptionsIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidDhcpOptionsID.NotFound'
    msg_fmt = _("The dhcp options ID '%(id)s' does not exist")


class InvalidAddressNotFound(EC2NotFoundException):
    ec2_code = 'InvalidAddress.NotFound'
    msg_fmt = _('The specified elastic IP address %(ip)s cannot be found.')


class InvalidAllocationIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidAllocationID.NotFound'
    msg_fmt = _("The allocation ID '%(id)s' does not exist")


class InvalidAssociationIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidAssociationID.NotFound'
    msg_fmt = _("The association ID '%(id)s' does not exist")


class InvalidSecurityGroupIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidSecurityGroupID.NotFound'
    msg_fmt = _("The securityGroup ID '%(id)s' does not exist")


class InvalidGroupNotFound(EC2NotFoundException):
    ec2_code = 'InvalidGroup.NotFound'
    msg_fmt = _("The security group ID '%(id)s' does not exist")


class InvalidPermissionNotFound(EC2NotFoundException):
    ec2_code = 'InvalidPermission.NotFound'
    msg_fmg = _('The specified permission does not exist')


class InvalidRouteTableIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidRouteTableID.NotFound'
    msg_fmt = _("The routeTable ID '%(id)s' does not exist")


class InvalidRouteNotFound(EC2NotFoundException):
    ec2_code = 'InvalidRoute.NotFound'
    msg_fmt = _('No route with destination-cidr-block '
                '%(destination_cidr_block)s in route table %(route_table_id)s')


class InvalidAMIIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidAMIID.NotFound'
    msg_fmt = _("The image id '[%(id)s]' does not exist")


class InvalidVolumeNotFound(EC2NotFoundException):
    ec2_code = 'InvalidVolume.NotFound'
    msg_fmt = _("The volume '%(id)s' does not exist.")


class InvalidSnapshotNotFound(EC2NotFoundException):
    ec2_code = 'InvalidSnapshot.NotFound'
    msg_fmt = _("Snapshot %(id)s could not be found.")


class InvalidKeypairNotFound(EC2NotFoundException):
    ec2_code = 'InvalidKeyPair.NotFound'
    msg_fmt = _("Keypair %(id)s is not found")


class InvalidAvailabilityZoneNotFound(EC2NotFoundException):
    ec2_code = 'InvalidAvailabilityZone.NotFound'
    msg_fmt = _("Availability zone %(id)s not found")


class InvalidGatewayIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidGatewayID.NotFound'
    msg_fmt = _("The gateway ID '%(id)s' does not exist")


class InvalidVpnGatewayIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidVpnGatewayID.NotFound'
    msg_fmt = _("The vpnGateway ID '%(id)s' does not exist")


class InvalidCustomerGatewayIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidCustomerGatewayID.NotFound'
    msg_fmt = _("The customerGateway ID '%(id)s' does not exist")


class InvalidVpnConnectionIDNotFound(EC2NotFoundException):
    ec2_code = 'InvalidVpnConnectionID.NotFound'
    msg_fmt = _("The vpnConnection ID '%(id)s' does not exist")


class InvalidVpnGatewayAttachmentNotFound(EC2NotFoundException):
    ec2_code = 'InvalidVpnGatewayAttachment.NotFound'
    msg_fmt = _("The attachment with vpn gateway ID '%(vgw_id)s' "
                "and vpc ID '%(vpc_id)s' does not exist")


class ResourceLimitExceeded(EC2OverlimitException):
    msg_fmt = _('You have reached the limit of %(resource)s')


class VpcLimitExceeded(EC2OverlimitException):
    msg_fmt = _('The maximum number of VPCs has been reached.')


class SubnetLimitExceeded(EC2OverlimitException):
    msg_fmt = _('You have reached the limit on the number of subnets that you '
                'can create')


class InsufficientFreeAddressesInSubnet(EC2OverlimitException):
    msg_fmt = _('The specified subnet does not have enough free addresses to '
                'satisfy the request.')


class AddressLimitExceeded(EC2OverlimitException):
    msg_fmt = _('The maximum number of addresses has been reached.')


class SecurityGroupLimitExceeded(EC2OverlimitException):
    msg_fmt = _('You have reached the limit of security groups')


class RulesPerSecurityGroupLimitExceeded(EC2OverlimitException):
    msg_fmt = _("You've reached the limit on the number of rules that "
                "you can add to a security group.")


class VpnGatewayAttachmentLimitExceeded(EC2OverlimitException):
    msg_fmt = _('The maximum number of virtual private gateway attachments '
                'has been reached.')


class InvalidGroupReserved(EC2InvalidException):
    ec2_code = 'InvalidGroup.Reserved'
    msg_fmt = _("The security group '%(group_name)' is reserved.")


class VPCIdNotSpecified(EC2InvalidException):
    msg_fmt = _("No default VPC for this user.")
