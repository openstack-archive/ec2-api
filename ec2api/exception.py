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

"""ec2api base exception handling.

Includes decorator for re-raising ec2api-type exceptions.

SHOULD include dedicated exception logging.

"""

import sys

from oslo.config import cfg

from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging

LOG = logging.getLogger(__name__)

exc_log_opts = [
    cfg.BoolOpt('fatal_exception_format_errors',
                default=False,
                help='Make exception message format errors fatal'),
]

CONF = cfg.CONF
CONF.register_opts(exc_log_opts)


class EC2ServerError(Exception):

    def __init__(self, response, content):
        self.response = response
        self.content = content


class EC2Exception(Exception):

    """Base EC2 Exception

    To correctly use this class, inherit from it and define
    a 'msg_fmt' property. That msg_fmt will get printf'd
    with the keyword arguments provided to the constructor.

    """
    msg_fmt = _("An unknown exception occurred.")
    code = 500
    headers = {}
    safe = False

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass

        if not message:
            try:
                message = self.msg_fmt % kwargs

            except Exception:
                exc_info = sys.exc_info()
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception(_('Exception in string format operation'))
                for name, value in kwargs.iteritems():
                    LOG.error("%s: %s" % (name, value))

                if CONF.fatal_exception_format_errors:
                    raise exc_info[0], exc_info[1], exc_info[2]
                else:
                    # at least get the core message out if something happened
                    message = self.msg_fmt

        super(EC2Exception, self).__init__(message)

    def format_message(self):
        # NOTE(mrodden): use the first argument to the python Exception object
        # which should be our full EC2Exception message, (see __init__)
        return self.args[0]


class Invalid(EC2Exception):
    msg_fmt = _("Unacceptable parameters.")
    code = 400


class InvalidRequest(Invalid):
    msg_fmt = _("The request is invalid.")


class InvalidEc2Id(Invalid):
    msg_fmt = _("Ec2 id %(ec2_id)s is unacceptable.")


class InvalidInput(Invalid):
    msg_fmt = _("Invalid input received: %(reason)s")


class ConfigNotFound(EC2Exception):
    msg_fmt = _("Could not find config at %(path)s")


class PasteAppNotFound(EC2Exception):
    msg_fmt = _("Could not load paste app '%(name)s' from %(path)s")


class MethodNotFound(EC2Exception):
    msg_fmt = _("Could not find method '%(name)s'")


class Forbidden(EC2Exception):
    ec2_code = 'AuthFailure'
    msg_fmt = _("Not authorized.")
    code = 403


class AuthFailure(Invalid):
    pass


class NotFound(EC2Exception):
    msg_fmt = _("Resource could not be found.")
    code = 404


class EC2NotFound(NotFound):
    code = 400


class InstanceNotFound(EC2NotFound):
    ec2_code = 'InvalidInstanceID.NotFound'
    msg_fmt = _("Instance %(instance_id)s could not be found.")


class InvalidVpcIDNotFound(EC2NotFound):
    ec2_code = 'InvalidVpcID.NotFound'
    msg_fmt = _("The vpc ID '%(vpc_id)s' does not exist")


class InvalidInternetGatewayIDNotFound(EC2NotFound):
    ec2_code = 'InvalidInternetGatewayID.NotFound'
    msg_fmt = _("The internetGateway ID '%(igw_id)s' does not exist")


class InvalidSubnetIDNotFound(EC2NotFound):
    ec2_code = 'InvalidSubnetID.NotFound'
    msg_fmt = _("The subnet ID '%(subnet_id)s' does not exist")


class InvalidNetworkInterfaceIDNotFound(EC2NotFound):
    ec2_code = 'InvalidNetworkInterfaceID.NotFound'
    msg_fmt = _("Network interface %(eni_id)s could not "
                "be found.")


class InvalidAttachmentIDNotFound(EC2NotFound):
    ec2_code = 'InvalidAttachmentID.NotFound'
    msg_fmt = _("Attachment %(eni-attach_id)s could not "
                "be found.")


class InvalidDhcpOptionsIDNotFound(EC2NotFound):
    ec2_code = 'InvalidDhcpOptionsID.NotFound'
    msg_fmt = _("The dhcp options ID '%(dopt_id)s' does not exist")


class InvalidAllocationIDNotFound(EC2NotFound):
    ec2_code = 'InvalidAllocationID.NotFound'
    msg_fmt = _("The allocation ID '%(eipalloc_id)s' does not exist")


class InvalidAssociationIDNotFound(EC2NotFound):
    ec2_code = 'InvalidAssociationID.NotFound'
    msg_fmt = _("The association ID '%(assoc_id)s' does not exist")


class InvalidRouteTableIDNotFound(EC2NotFound):
    ec2_code = 'InvalidRouteTableID.NotFound'
    msg_fmt = _("The routeTable ID '%(rtb_id)s' does not exist")


class InvalidRouteNotFound(EC2NotFound):
    ec2_code = 'InvalidRoute.NotFound'
    msg_fmt = _('No route with destination-cidr-block '
                '%(destination_cidr_block)s in route table %(route_table_id)s')


class InvalidGroupNotFound(EC2NotFound):
    ec2_code = 'InvalidGroup.NotFound'
    msg_fmg = _("The security group ID '%(sg_id)s' does not exist")


class InvalidPermissionNotFound(EC2NotFound):
    ec2_code = 'InvalidPermission.NotFound'
    msg_fmg = _("The specified permission does not exist")


class IncorrectState(EC2Exception):
    ec2_code = 'IncorrectState'
    code = 400
    msg_fmt = _("The resource is in incorrect state for the request - reason: "
                "'%(reason)s'")


class InvalidVpcRange(Invalid):
    ec2_code = 'InvalidVpc.Range'
    msg_fmt = _("The CIDR '%(cidr_block)s' is invalid.")


class InvalidSubnetRange(Invalid):
    ec2_code = 'InvalidSubnet.Range'
    msg_fmt = _("The CIDR '%(cidr_block)s' is invalid.")


class InvalidSubnetConflict(Invalid):
    ec2_code = 'InvalidSubnet.Conflict'
    msg_fmt = _("The CIDR '%(cidr_block)s' conflicts with another subnet")


class MissingParameter(Invalid):
    pass


class InvalidParameterValue(Invalid):
    msg_fmt = _("Value (%(value)s) for parameter %(parameter)s is invalid. "
                "%(reason)s")


class InvalidParameterCombination(Invalid):
    pass


class ResourceAlreadyAssociated(Invalid):
    ec2_code = 'Resource.AlreadyAssociated'


class GatewayNotAttached(Invalid):
    ec2_code = 'Gateway.NotAttached'
    msg_fmt = _("resource %(igw_id)s is not attached to network %(vpc_id)s")


class DependencyViolation(Invalid):
    ec2_code = 'DependencyViolation'
    msg_fmt = _('Object %(obj1_id)s has dependent resource %(obj2_id)s')


class InvalidNetworkInterfaceInUse(Invalid):
    ec2_code = 'InvalidNetworkInterface.InUse'
    msg_fmt = _('Interface: %(interface_ids)s in use.')


class InvalidInstanceId(Invalid):
    ec2_code = 'InvalidInstanceID'


class InvalidIPAddressInUse(Invalid):
    ec2_code = 'InvalidIPAddress.InUse'
    msg_fmt = _('Address %(ip_address)s is in use.')


class RouteAlreadyExists(Invalid):
    msg_fmt = _('The route identified by %(destination_cidr_block)s '
                'already exists.')
