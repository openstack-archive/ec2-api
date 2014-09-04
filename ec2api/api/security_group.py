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


from neutronclient.common import exceptions as neutron_exception
from oslo.config import cfg

from ec2api.api import clients
from ec2api.api import ec2client
from ec2api.api import ec2utils
from ec2api.api import utils
from ec2api.db import api as db_api
from ec2api import exception
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


FILTER_MAP = {'vpc-id': 'vpcId',
              'group-name': 'groupName',
              'group-id': 'groupId'}


def create_security_group(context, group_name, group_description,
                          vpc_id=None):
    if vpc_id is None:
        ec2 = ec2client.ec2client(context)
        return ec2.create_security_groups(group_name=group_name,
                                          group_description=group_description)
    vpc = ec2utils.get_db_item(context, 'vpc', vpc_id)
    neutron = clients.neutron(context)
    with utils.OnCrashCleaner() as cleaner:
        os_security_group = neutron.create_security_group(
            {'security_group':
             {'name': group_name,
              'description': group_description}})['security_group']
        cleaner.addCleanup(neutron.delete_security_group,
                           os_security_group['id'])
        security_group = db_api.add_item(context, 'sg',
                                         {'vpc_id': vpc['id'],
                                          'os_id': os_security_group['id']})
    return {'return': 'true',
            'groupId': ec2utils.get_ec2_id(security_group['id'], 'sg')}


def _create_default_security_group(context, vpc):
    neutron = clients.neutron(context)
    os_security_group = neutron.create_security_group(
        {'security_group':
         {'name': 'Default',
          'description': 'Default VPC security group'}})['security_group']
    security_group = db_api.add_item(context, 'sg',
                                     {'vpc_id': vpc['id'],
                                      'os_id': os_security_group['id']})


def delete_security_group(context, group_name=None, group_id=None):
    if group_id is None or not group_id.startswith('sg-'):
        ec2 = ec2client.ec2client(context)
        return ec2.delete_security_groups(group_name=group_name,
                                          group_id=group_id)
    security_group = ec2utils.get_db_item(context, 'sg', group_id)
    # TODO(Alex) Check dependencies - instances and other security groups
    neutron = clients.neutron(context)
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
    db_api.delete_item(context, security_group['id'])
    return True


def describe_security_groups(context, group_name=None, group_id=None,
                             filter=None):
    # TODO(Alex): implement filters
    neutron = clients.neutron(context)
    os_security_groups = neutron.list_security_groups()['security_groups']
    security_groups = ec2utils.get_db_items(context, 'sg', group_id)
    formatted_security_groups = []
    for os_security_group in os_security_groups:
        security_group = next((g for g in security_groups
                               if g['os_id'] == os_security_group['id']), None)
        if group_id is not None and security_group is None:
            continue
        formatted_security_group = _format_security_group(
            context, security_group,
            os_security_group, os_security_groups,
            security_groups)
        if not utils.filtered_out(formatted_security_group, filter,
                                  FILTER_MAP):
            formatted_security_groups.append(formatted_security_group)
    return {'securityGroupInfo': formatted_security_groups}


def authorize_security_group_ingress(context, group_id,
                                     group_name, ip_permissions):
    if group_id is None or not group_id.startswith('sg-'):
        ec2 = ec2client.ec2client(context)
        return ec2.authorize_security_groups_ingress(
            group_name=group_name,
            group_id=group_id,
            ip_permissions=ip_permissions)
    return _authorize_security_group(context, group_id, ip_permissions,
                                     'ingress')


def authorize_security_group_egress(context, group_id, ip_permissions):
    return _authorize_security_group(context, group_id, ip_permissions,
                                     'egress')


def _authorize_security_group(context, group_id, ip_permissions, direction):
    rule_body = _build_rule(context, group_id, ip_permissions, direction)
    neutron = clients.neutron(context)
    try:
        os_security_group_rule = neutron.create_security_group_rule(
            {'security_group_rule': rule_body})['security_group_rule']
    except neutron_exception.Conflict as ex:
        raise exception.RuleAlreadyExists()
    return True


def _build_rule(context, group_id, ip_permissions, direction):
    security_group = ec2utils.get_db_item(context, 'sg', group_id)
    os_security_group_rule_body = (
        {'security_group_id': security_group['os_id'],
         'direction': direction,
         'ethertype': 'IPv4'})
    if ip_permissions is None:
        ip_permissions = []
    for rule in ip_permissions:
        if rule.get('ip_protocol'):
            os_security_group_rule_body['protocol'] = rule['ip_protocol']
        if rule.get('from_port', -1) != -1:
            os_security_group_rule_body['port_range_min'] = rule['from_port']
        if rule.get('to_port', -1) != -1:
            os_security_group_rule_body['port_range_max'] = rule['to_port']
        # TODO(Alex) AWS protocol claims support of multiple groups and cidrs,
        # however, neither aws cli, nor neutron support it at the moment.
        # It's possible in the future to convert list values incoming from
        # REST API into several neutron rules and squeeze them back into one
        # for describing.
        # For now only 1 value is supported for either.
        if rule.get('groups'):
            os_security_group_rule_body['remote_group_id'] = (
                ec2utils.get_db_item(context, 'sg',
                                     rule['groups']['1']['group_id'])['os_id'])
        elif rule.get('ip_ranges'):
            os_security_group_rule_body['remote_ip_prefix'] = (
                rule['ip_ranges']['1']['cidr_ip'])
    return os_security_group_rule_body


def revoke_security_group_ingress(context, group_id,
                                  group_name, ip_permissions):
    if group_id is None or not group_id.startswith('sg-'):
        ec2 = ec2client.ec2client(context)
        return ec2.revoke_security_groups_ingress(
            group_name=group_name,
            group_id=group_id,
            ip_permissions=ip_permissions)
    return _revoke_security_group(context, group_id, ip_permissions,
                                  'ingress')


def revoke_security_group_egress(context, group_id, ip_permissions):
    return _revoke_security_group(context, group_id, ip_permissions, 'egress')


def _are_identical_rules(rule1, rule2):

    def significant_values(rule):
        dict = {}
        for key, value in rule.items():
            if (value is not None and value != -1 and
                    key not in ['id', 'tenant_id']):
                dict[key] = str(value)
        return dict

    r1 = significant_values(rule1)
    r2 = significant_values(rule2)
    return r1 == r2


def _revoke_security_group(context, group_id, ip_permissions, direction):
    rule_body = _build_rule(context, group_id, ip_permissions, direction)
    neutron = clients.neutron(context)
    os_security_group = neutron.show_security_group(
        rule_body['security_group_id'])['security_group']
    if not os_security_group.get('security_group_rules'):
        return True
    for os_rule in os_security_group['security_group_rules']:
        if _are_identical_rules(os_rule, rule_body):
            neutron.delete_security_group_rule(
                os_rule['id'])
            return True
    raise exception.InvalidPermissionNotFound()


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
            {'groupId': ec2utils.get_ec2_id(security_group['id'],
                                            'sg'),
             'groupName': os_security_group['name']})
    return ec2_security_groups


def _format_security_group(context, security_group, os_security_group,
                           os_security_groups, security_groups):
    ec2_security_group = {}
    if security_group is not None:
        ec2_security_group['groupId'] = (
            ec2utils.get_ec2_id(security_group['id'], 'sg'))
        ec2_security_group['vpcId'] = (
            ec2utils.get_ec2_id(security_group['vpc_id'], 'vpc'))
    ec2_security_group['ownerId'] = os_security_group['tenant_id']
    ec2_security_group['groupName'] = os_security_group['name']
    ec2_security_group['groupDescription'] = os_security_group['description']
    ingress_permissions = []
    egress_permissions = []
    for os_rule in os_security_group['security_group_rules']:
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
                ec2_remote_group['groupId'] = ec2utils.get_ec2_id(
                    db_remote_group['id'], 'sg')
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
        if os_rule['direction'] == 'egress':
            egress_permissions.append(ec2_rule)
        elif os_rule['direction'] == 'ingress':
            ingress_permissions.append(ec2_rule)

    ec2_security_group['ipPermissions'] = ingress_permissions
    ec2_security_group['ipPermissionsEgress'] = egress_permissions
    return ec2_security_group
