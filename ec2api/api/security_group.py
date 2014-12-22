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


import copy
import re

try:
    from neutronclient.common import exceptions as neutron_exception
except ImportError:
    pass  # clients will log absense of neutronclient in this case
from novaclient import exceptions as nova_exception
from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


"""Security Groups related API implementation
"""

SECURITY_GROUP_MAP = {'domain-name-servers': 'dns-servers',
                      'domain-name': 'domain-name',
                      'ntp-servers': 'ntp-server',
                      'netbios-name-servers': 'netbios-ns',
                      'netbios-node-type': 'netbios-nodetype'}


def get_security_group_engine():
    if clients.neutronclient:
        return SecurityGroupEngineNeutron()
    else:
        return SecurityGroupEngineNova()


def create_security_group(context, group_name, group_description,
                          vpc_id=None):
    _validate_security_group_naming(group_name, group_description, vpc_id)
    nova = clients.nova(context)
    with utils.OnCrashCleaner() as cleaner:
        try:
            os_security_group = nova.security_groups.create(group_name,
                                                            group_description)
        except nova_exception.OverLimit:
            raise exception.ResourceLimitExceeded(resource='security groups')
        cleaner.addCleanup(nova.security_groups.delete,
                           os_security_group.id)
        if vpc_id:
            # NOTE(Alex) Check if such vpc exists
            ec2utils.get_db_item(context, 'vpc', vpc_id)
            security_group = db_api.add_item(context, 'sg',
                                             {'vpc_id': vpc_id,
                                              'os_id': os_security_group.id})
            return {'return': 'true',
                    'groupId': security_group['id']}
    return {'return': 'true'}


def _validate_security_group_naming(group_name, group_description, vpc_id):
    if group_name is None:
        raise exception.MissingParameter(param='group name')
    if group_description is None:
        raise exception.MissingParameter(param='group description')
    # NOTE(Alex) Amazon accepts any ASCII for EC2 classic;
    # for EC2-VPC: a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
    if vpc_id:
        allowed = '^[a-zA-Z0-9\._\-:/\(\)#,@\[\]\+=&;\{\}!\$\*\ ]+$'
    else:
        allowed = r'^[\x20-\x7E]+$'
    _validate_property(group_name, 'name', allowed)
    _validate_property(group_description, 'description', allowed)


def _validate_property(value, property, allowed):
    msg = ''
    try:
        val = value.strip()
    except AttributeError:
        msg = _("Security group %s is not a string or unicode") % property
    if not val:
        msg = _("Security group %s cannot be empty.") % property
    elif allowed and not re.match(allowed, val):
        # Some validation to ensure that values match API spec.
        # - Alphanumeric characters, spaces, dashes, and underscores.
        # TODO(Daviey): LP: #813685 extend beyond group_name checking, and
        #  probably create a param validator that can be used elsewhere.
        msg = (_("Specified value for parameter Group%(property)s is "
                 "invalid. Content limited to '%(allowed)s'.") %
               {'allowed': 'allowed',
                'property': property})
    elif len(val) > 255:
        msg = _("Security group %s should not be greater "
                        "than 255 characters.") % property
    if msg:
        raise exception.ValidationError(reason=msg)


def _create_default_security_group(context, vpc):
    return create_security_group(context, 'Default',
                                 'Default VPC security group', vpc['id'])


def delete_security_group(context, group_name=None, group_id=None):
    if group_name is None and group_id is None:
        raise exception.MissingParameter(param='group id or name')
    security_group_engine.delete_group(context, group_name, group_id)
    return True


class SecurityGroupDescriber(common.TaggableItemsDescriber):

    KIND = 'sg'
    FILTER_MAP = {'vpc-id': 'vpcId',
                  'group-name': 'groupName',
                  'group-id': 'groupId'}

    def __init__(self):
        self.all_db_items = None

    def format(self, item=None, os_item=None):
        if self.all_db_items is None:
            self.all_db_items = ec2utils.get_db_items(self.context, 'sg', None)
        return _format_security_group(item, os_item,
                                      self.all_db_items, self.os_items)

    def get_os_items(self):
        return security_group_engine.get_os_groups(self.context)


def describe_security_groups(context, group_name=None, group_id=None,
                             filter=None):
    formatted_security_groups = SecurityGroupDescriber().describe(
        context, group_id, group_name, filter)
    return {'securityGroupInfo': formatted_security_groups}


def authorize_security_group_ingress(context, group_id,
                                     group_name, ip_permissions):
    return _authorize_security_group(context, group_id, group_name,
                                     ip_permissions, 'ingress')


def authorize_security_group_egress(context, group_id, ip_permissions):
    return _authorize_security_group(context, group_id, None,
                                     ip_permissions, 'egress')


def _authorize_security_group(context, group_id, group_name,
                              ip_permissions, direction):
    rules_bodies = _build_rules(context, group_id, group_name,
                                ip_permissions, direction)
    for rule_body in rules_bodies:
        security_group_engine.authorize_security_group(context, rule_body)
    return True


def _validate_parameters(protocol, from_port, to_port):
    if (not isinstance(protocol, int) and
            protocol not in ['tcp', 'udp', 'icmp']):
        raise exception.InvalidParameterValue(
            _('Invalid value for IP protocol. Unknown protocol.'))
    if (not isinstance(from_port, int) or
            not isinstance(to_port, int)):
        raise exception.InvalidParameterValue(
            _('Integer values should be specified for ports'))
    if protocol in ['tcp', 'udp', 6, 17]:
        if from_port == -1 or to_port == -1:
            raise exception.InvalidParameterValue(
                _('Must specify both from and to ports with TCP/UDP.'))
        if from_port > to_port:
            raise exception.InvalidParameterValue(
                _('Invalid TCP/UDP port range.'))
        if from_port < 0 or from_port > 65535:
            raise exception.InvalidParameterValue(
                _('TCP/UDP from port is out of range.'))
        if to_port < 0 or to_port > 65535:
            raise exception.InvalidParameterValue(
                _('TCP/UDP to port is out of range.'))
    elif protocol in ['icmp', 1]:
        if from_port < -1 or from_port > 255:
            raise exception.InvalidParameterValue(
                _('ICMP type is out of range.'))
        if to_port < -1 or to_port > 255:
            raise exception.InvalidParameterValue(
                _('ICMP code is out of range.'))


def _build_rules(context, group_id, group_name, ip_permissions, direction):
    if group_name is None and group_id is None:
        raise exception.MissingParameter(param='group id or name')
    if ip_permissions is None:
        raise exception.MissingParameter(param='source group or cidr')
    os_security_group_id = security_group_engine.get_group_os_id(context,
                                                                 group_id,
                                                                 group_name)
    os_security_group_rule_bodies = []
    if ip_permissions is None:
        ip_permissions = []
    for rule in ip_permissions:
        os_security_group_rule_body = (
            {'security_group_id': os_security_group_id,
             'direction': direction,
             'ethertype': 'IPv4'})
        protocol = rule.get('ip_protocol', -1)
        from_port = rule.get('from_port', -1)
        to_port = rule.get('to_port', -1)
        _validate_parameters(protocol, from_port, to_port)
        if protocol != -1:
            os_security_group_rule_body['protocol'] = rule['ip_protocol']
        if from_port != -1:
            os_security_group_rule_body['port_range_min'] = rule['from_port']
        if to_port != -1:
            os_security_group_rule_body['port_range_max'] = rule['to_port']

        # TODO(Alex) AWS protocol claims support of multiple groups and cidrs,
        # however, neutron doesn't support it at the moment.
        # It's possible in the future to convert list values incoming from
        # REST API into several neutron rules and squeeze them back into one
        # for describing.
        # For now only 1 value is supported for either.
        if rule.get('groups'):
            os_security_group_rule_body['remote_group_id'] = (
                security_group_engine.get_group_os_id(
                    context,
                    rule['groups'][0].get('group_id'),
                    rule['groups'][0].get('group_name')))
        elif rule.get('ip_ranges'):
            os_security_group_rule_body['remote_ip_prefix'] = (
                rule['ip_ranges'][0]['cidr_ip'])
            ec2utils.validate_cidr_with_ipv6(
                os_security_group_rule_body['remote_ip_prefix'], 'cidr_ip')
        else:
            raise exception.MissingParameter(param='source group or cidr')
        os_security_group_rule_bodies.append(os_security_group_rule_body)
    return os_security_group_rule_bodies


def revoke_security_group_ingress(context, group_id,
                                  group_name, ip_permissions):
    return _revoke_security_group(context, group_id, group_name,
                                  ip_permissions, 'ingress')


def revoke_security_group_egress(context, group_id, ip_permissions):
    return _revoke_security_group(context, group_id, None,
                                  ip_permissions, 'egress')


def _are_identical_rules(rule1, rule2):

    def significant_values(rule):
        dict = {}
        for key, value in rule.items():
            if (value is not None and value != -1 and
                    value != '0.0.0.0/0' and
                    key not in ['id', 'tenant_id', 'security_group_id']):
                dict[key] = str(value)
        return dict

    r1 = significant_values(rule1)
    r2 = significant_values(rule2)
    return r1 == r2


def _revoke_security_group(context, group_id, group_name, ip_permissions,
                           direction):
    rules_bodies = _build_rules(context, group_id, group_name,
                                ip_permissions, direction)
    if not rules_bodies:
        return True
    os_rules = security_group_engine.get_os_group_rules(
        context, rules_bodies[0]['security_group_id'])

    os_rules_to_delete = []
    for rule_body in rules_bodies:
        for os_rule in os_rules:
            if _are_identical_rules(rule_body, os_rule):
                os_rules_to_delete.append(os_rule['id'])

    if len(os_rules_to_delete) != len(rules_bodies):
        raise exception.InvalidPermissionNotFound()
    for os_rule_id in os_rules_to_delete:
        security_group_engine.delete_os_group_rule(context, os_rule_id)
    return True


def _format_security_groups_ids_names(context):
    neutron = clients.neutron(context)
    os_security_groups = neutron.list_security_groups()['security_groups']
    security_groups = db_api.get_items(context, 'sg')
    ec2_security_groups = {}
    for os_security_group in os_security_groups:
        security_group = next((g for g in security_groups
                               if g['os_id'] == os_security_group['id']), None)
        if security_group is None:
            continue
        ec2_security_groups[os_security_group['id']] = (
            {'groupId': security_group['id'],
             'groupName': os_security_group['name']})
    return ec2_security_groups


def _format_security_group(security_group, os_security_group,
                           security_groups, os_security_groups):
    ec2_security_group = {}
    if security_group is not None:
        ec2_security_group['groupId'] = security_group['id']
        ec2_security_group['vpcId'] = security_group['vpc_id']
    ec2_security_group['ownerId'] = os_security_group['tenant_id']
    ec2_security_group['groupName'] = os_security_group['name']
    ec2_security_group['groupDescription'] = os_security_group['description']
    ingress_permissions = []
    egress_permissions = []
    for os_rule in os_security_group.get('security_group_rules', []):
        # NOTE(Alex) We're skipping IPv6 rules because AWS doesn't support
        # them.
        if os_rule.get('ethertype', 'IPv4') == 'IPv6':
            continue
        ec2_rule = {'ipProtocol': -1 if os_rule['protocol'] is None
                    else os_rule['protocol'],
                    'fromPort': -1 if os_rule['port_range_min'] is None
                    else os_rule['port_range_min'],
                    'toPort': -1 if os_rule['port_range_max'] is None
                    else os_rule['port_range_max']}
        remote_group_id = os_rule['remote_group_id']
        if remote_group_id is not None:
            ec2_remote_group = {}
            db_remote_group = next((g for g in security_groups
                                    if g['os_id'] == remote_group_id), None)
            if db_remote_group is not None:
                ec2_remote_group['groupId'] = db_remote_group['id']
            else:
                # TODO(Alex) Log absence of remote_group
                pass
            os_remote_group = next((g for g in os_security_groups
                                    if g['id'] == remote_group_id), None)
            if os_remote_group is not None:
                ec2_remote_group['groupName'] = os_remote_group['name']
                ec2_remote_group['userId'] = os_remote_group['tenant_id']
            else:
                # TODO(Alex) Log absence of remote_group
                pass
            ec2_rule['groups'] = [ec2_remote_group]
        elif os_rule['remote_ip_prefix'] is not None:
            ec2_rule['ipRanges'] = [{'cidrIp': os_rule['remote_ip_prefix']}]
        if os_rule.get('direction') == 'egress':
            egress_permissions.append(ec2_rule)
        else:
            if security_group is None and os_rule['protocol'] is None:
                for protocol, min_port, max_port in (('icmp', -1, -1),
                                                     ('tcp', 1, 65535),
                                                     ('udp', 1, 65535)):
                    ec2_rule['ipProtocol'] = protocol
                    ec2_rule['fromPort'] = min_port
                    ec2_rule['toPort'] = max_port
                    ingress_permissions.append(copy.deepcopy(ec2_rule))
            else:
                ingress_permissions.append(ec2_rule)

    ec2_security_group['ipPermissions'] = ingress_permissions
    if security_group is not None:
        ec2_security_group['ipPermissionsEgress'] = egress_permissions
    return ec2_security_group


class SecurityGroupEngineNeutron(object):

    def delete_group(self, context, group_name=None, group_id=None):
        neutron = clients.neutron(context)
        if group_id is None or not group_id.startswith('sg-'):
            return SecurityGroupEngineNova().delete_group(context,
                                                          group_name,
                                                          group_id)
        security_group = ec2utils.get_db_item(context, 'sg', group_id)
        try:
            neutron.delete_security_group(security_group['os_id'])
        except neutron_exception.Conflict as ex:
            # TODO(Alex): Instance ID is unknown here, report exception message
            # in its place - looks readable.
            raise exception.DependencyViolation(
                        obj1_id=group_id,
                        obj2_id=ex.message)
        except neutron_exception.NeutronClientException as ex:
            # TODO(Alex): do log error
            # TODO(Alex): adjust caught exception classes to catch:
            # the port doesn't exist
            pass
        db_api.delete_item(context, group_id)

    def get_os_groups(self, context):
        neutron = clients.neutron(context)
        return neutron.list_security_groups()['security_groups']

    def authorize_security_group(self, context, rule_body):
        neutron = clients.neutron(context)
        try:
            os_security_group_rule = neutron.create_security_group_rule(
                {'security_group_rule': rule_body})['security_group_rule']
        except neutron_exception.OverQuotaClient:
            raise exception.RulesPerSecurityGroupLimitExceeded()
        except neutron_exception.Conflict as ex:
            raise exception.InvalidPermissionDuplicate()

    def get_os_group_rules(self, context, os_id):
        neutron = clients.neutron(context)
        os_security_group = (
            neutron.show_security_group(os_id)['security_group'])
        return os_security_group.get('security_group_rules')

    def delete_os_group_rule(self, context, os_id):
        neutron = clients.neutron(context)
        neutron.delete_security_group_rule(os_id)

    def get_group_os_id(self, context, group_id, group_name):
        if group_name:
            return SecurityGroupEngineNova().get_group_os_id(context,
                                                             group_id,
                                                             group_name)
        return ec2utils.get_db_item(context, 'sg', group_id)['os_id']


class SecurityGroupEngineNova(object):

    def delete_group(self, context, group_name=None, group_id=None):
        nova = clients.nova(context)
        os_id = self.get_group_os_id(context, group_id, group_name)
        try:
            nova.security_groups.delete(os_id)
        except Exception as ex:
            # TODO(Alex): do log error
            # nova doesn't differentiate Conflict exception like neutron does
            pass

    def get_os_groups(self, context):
        nova = clients.nova(context)
        return self.convert_groups_to_neutron_format(
                        context,
                        nova.security_groups.list())

    def authorize_security_group(self, context, rule_body):
        nova = clients.nova(context)
        try:
            os_security_group_rule = nova.security_group_rules.create(
                rule_body['security_group_id'],
                rule_body.get('protocol'),
                rule_body.get('port_range_min', -1),
                rule_body.get('port_range_max', -1),
                rule_body.get('remote_ip_prefix'),
                rule_body.get('remote_group_id'))
        except nova_exception.Conflict:
            raise exception.InvalidPermissionDuplicate()
        except nova_exception.OverLimit:
            raise exception.RulesPerSecurityGroupLimitExceeded()

    def get_os_group_rules(self, context, os_id):
        nova = clients.nova(context)
        os_security_group = nova.security_groups.get(os_id)
        os_rules = os_security_group.rules
        neutron_rules = []
        for os_rule in os_rules:
            neutron_rules.append(
                self.convert_rule_to_neutron(context,
                                             os_rule,
                                             nova.security_groups.list()))
        return neutron_rules

    def delete_os_group_rule(self, context, os_id):
        nova = clients.nova(context)
        nova.security_group_rules.delete(os_id)

    def convert_groups_to_neutron_format(self, context, nova_security_groups):
        neutron_security_groups = []
        for nova_group in nova_security_groups:
            neutron_group = {'id': nova_group.id,
                             'name': nova_group.name,
                             'description': nova_group.description,
                             'tenant_id': nova_group.tenant_id}
            neutron_rules = []
            for rule in nova_group.rules:
                neutron_rules.append(
                    self.convert_rule_to_neutron(context,
                                                 rule, nova_security_groups))
            if neutron_rules:
                neutron_group['security_group_rules'] = neutron_rules
            neutron_security_groups.append(neutron_group)
        return neutron_security_groups

    def convert_rule_to_neutron(self, context, nova_rule,
                                 nova_security_groups=None):
        neutron_rule = {'id': nova_rule['id'],
                        'protocol': nova_rule['ip_protocol'],
                        'port_range_min': nova_rule['from_port'],
                        'port_range_max': nova_rule['to_port'],
                        'remote_ip_prefix': (
                            nova_rule.get('ip_range') or {}).get('cidr'),
                        'remote_group_id': None,
                        'direction': 'ingress',
                        'ethertype': 'IPv4',
                        'security_group_id': nova_rule['parent_group_id']}
        if (nova_rule.get('group') or {}).get('name'):
            neutron_rule['remote_group_id'] = (
                self.get_group_os_id(context, None,
                                     nova_rule['group']['name'],
                                     nova_security_groups))
        return neutron_rule

    def get_group_os_id(self, context, group_id, group_name,
                         nova_security_groups=None):
        if group_id:
            return group_id
        nova_group = self.get_nova_group_by_name(context, group_name,
                                                 nova_security_groups)
        return nova_group.id

    def get_nova_group_by_name(self, context, group_name,
                                nova_security_groups=None):
        if nova_security_groups is None:
            nova = clients.nova(context)
            nova_security_groups = nova.security_groups.list()
        nova_group = next((g for g in nova_security_groups
                           if g.name == group_name), None)
        if nova_group is None:
            raise exception.InvalidGroupNotFound(sg_id=group_name)
        return nova_group


security_group_engine = get_security_group_engine()
