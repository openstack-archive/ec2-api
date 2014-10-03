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


import copy
import random
import uuid

from ec2api.api import ec2utils
from ec2api.openstack.common import timeutils
from ec2api.tests import tools


# Helper functions section

# mock helpers
def get_db_api_add_item(item_id_dict):
    def db_api_add_item(context, kind, data):
        if isinstance(item_id_dict, dict):
            item_id = item_id_dict[kind]
        else:
            item_id = item_id_dict
        data = tools.update_dict(data, {'id': item_id})
        data.setdefault('os_id')
        data.setdefault('vpc_id')
        return data
    return db_api_add_item


def get_db_api_get_items(results_dict_by_kind):
    def db_api_get_items(context, kind):
        return results_dict_by_kind.get(kind)
    return db_api_get_items


def get_db_api_get_item_by_id(results_dict_by_id):
    def db_api_get_item_by_id(context, kind, item_id):
        item = results_dict_by_id.get(item_id)
        if item is not None:
            item = copy.deepcopy(item)
        return item
    return db_api_get_item_by_id


def get_neutron_create(kind, os_id, addon={}):
    def neutron_create(body):
        body = copy.deepcopy(body)
        body[kind].update(addon)
        body[kind]['id'] = os_id
        return body
    return neutron_create


# random identifier generators
def random_os_id():
    return str(uuid.uuid4())


def random_db_id():
    return random.randint(0, 0xffff)


# Plain constants section
# Constant name notation:
# [<type>[<subtype>]]<object_name>
# where
#    type - type of object the constant represents
#        ID - for identifiers, CIDR for cidrs, etc
#    subtype - type of object storage, is used for IDs only
#        DB - object is stored in EC2 API database
#        EC2 - object representation to end user
#        OS - object is stored in OpenStack
#        EC2OS - object is returned from original nova's EC2 layer
#    object_name - identifies the object

# common constants
ID_OS_USER = random_os_id()
ID_OS_PROJECT = random_os_id()
TIME_ATTACH_NETWORK_INTERFACE = timeutils.isotime(None, True)


# vpc constants
ID_DB_VPC_1 = random_db_id()
ID_DB_VPC_2 = random_db_id()
ID_EC2_VPC_1 = ec2utils.get_ec2_id(ID_DB_VPC_1, 'vpc')
ID_EC2_VPC_2 = ec2utils.get_ec2_id(ID_DB_VPC_2, 'vpc')
ID_OS_ROUTER_1 = random_os_id()
ID_OS_ROUTER_2 = random_os_id()

CIDR_VPC_1 = '10.10.0.0/16'
CIDR_VPC_2 = '10.20.0.0/16'
ID_OS_PUBLIC_NETWORK = random_os_id()
NAME_OS_PUBLIC_NETWORK = 'public_external'


# internet gateway constants
ID_DB_IGW_1 = random_db_id()
ID_DB_IGW_2 = random_db_id()
ID_EC2_IGW_1 = ec2utils.get_ec2_id(ID_DB_IGW_1, 'igw')
ID_EC2_IGW_2 = ec2utils.get_ec2_id(ID_DB_IGW_2, 'igw')


# subnet constants
ID_DB_SUBNET_1 = random_db_id()
ID_DB_SUBNET_2 = random_db_id()
ID_EC2_SUBNET_1 = ec2utils.get_ec2_id(ID_DB_SUBNET_1, 'subnet')
ID_EC2_SUBNET_2 = ec2utils.get_ec2_id(ID_DB_SUBNET_2, 'subnet')
ID_OS_SUBNET_1 = random_os_id()
ID_OS_SUBNET_2 = random_os_id()
ID_OS_NETWORK_1 = random_os_id()
ID_OS_NETWORK_2 = random_os_id()

CIDR_SUBNET_1 = '10.10.1.0/24'
IP_FIRST_SUBNET_1 = '10.10.1.4'
IP_LAST_SUBNET_1 = '10.10.1.254'
IP_GATEWAY_SUBNET_1 = '10.10.1.1'
CIDR_SUBNET_2 = '10.10.2.0/24'
IP_FIRST_SUBNET_2 = '10.10.2.4'
IP_LAST_SUBNET_2 = '10.10.2.254'


# network interface constants
ID_DB_NETWORK_INTERFACE_1 = random_db_id()
ID_DB_NETWORK_INTERFACE_2 = random_db_id()
ID_EC2_NETWORK_INTERFACE_1 = ec2utils.get_ec2_id(ID_DB_NETWORK_INTERFACE_1,
                                                 'eni')
ID_EC2_NETWORK_INTERFACE_2 = ec2utils.get_ec2_id(ID_DB_NETWORK_INTERFACE_2,
                                                 'eni')
ID_EC2_NETWORK_INTERFACE_2_ATTACH = (
    ID_EC2_NETWORK_INTERFACE_2.replace('eni', 'eni-attach'))
ID_OS_PORT_1 = random_os_id()
ID_OS_PORT_2 = random_os_id()

IP_NETWORK_INTERFACE_1 = '10.10.1.4'
IP_NETWORK_INTERFACE_2 = '10.10.2.254'
IP_NETWORK_INTERFACE_2_EXT_1 = '10.10.2.4'
IP_NETWORK_INTERFACE_2_EXT_2 = '10.10.2.5'
IPS_NETWORK_INTERFACE_2 = (IP_NETWORK_INTERFACE_2,
                           IP_NETWORK_INTERFACE_2_EXT_1,
                           IP_NETWORK_INTERFACE_2_EXT_2)
DESCRIPTION_NETWORK_INTERFACE_1 = 'description1'
DESCRIPTION_NETWORK_INTERFACE_2 = 'description2'


# instance constants
ID_DB_INSTANCE_1 = random_db_id()
ID_DB_INSTANCE_2 = random_db_id()
ID_EC2_INSTANCE_1 = ec2utils.get_ec2_id(ID_DB_INSTANCE_1, 'i')
ID_EC2_INSTANCE_2 = ec2utils.get_ec2_id(ID_DB_INSTANCE_2, 'i')
ID_OS_INSTANCE_1 = random_os_id()
ID_OS_INSTANCE_2 = random_os_id()
ID_EC2_RESERVATION_1 = 'r-%s' % random_db_id()
ID_EC2_RESERVATION_2 = 'r-%s' % random_db_id()

# DHCP options constants
ID_DB_DHCP_OPTIONS_1 = random_db_id()
ID_DB_DHCP_OPTIONS_2 = random_db_id()
ID_EC2_DHCP_OPTIONS_1 = ec2utils.get_ec2_id(ID_DB_DHCP_OPTIONS_1, 'dopt')
ID_EC2_DHCP_OPTIONS_2 = ec2utils.get_ec2_id(ID_DB_DHCP_OPTIONS_2, 'dopt')


# address constants
ID_DB_ADDRESS_1 = random_db_id()
ID_DB_ADDRESS_2 = random_db_id()
ID_EC2_ADDRESS_1 = ec2utils.get_ec2_id(ID_DB_ADDRESS_1, 'eipalloc')
ID_EC2_ADDRESS_2 = ec2utils.get_ec2_id(ID_DB_ADDRESS_2, 'eipalloc')
ID_EC2_ASSOCIATION_1 = ID_EC2_ADDRESS_1.replace('eipalloc', 'eipassoc')
ID_EC2_ASSOCIATION_2 = ID_EC2_ADDRESS_2.replace('eipalloc', 'eipassoc')
ID_OS_FLOATING_IP_1 = random_os_id()
ID_OS_FLOATING_IP_2 = random_os_id()

IP_ADDRESS_1 = '192.168.1.100'
IP_ADDRESS_2 = '192.168.1.200'


# security group constants
ID_DB_SECURITY_GROUP_1 = random_db_id()
ID_DB_SECURITY_GROUP_2 = random_db_id()
ID_EC2_SECURITY_GROUP_1 = ec2utils.get_ec2_id(ID_DB_SECURITY_GROUP_1, 'sg')
ID_EC2_SECURITY_GROUP_2 = ec2utils.get_ec2_id(ID_DB_SECURITY_GROUP_2, 'sg')
ID_OS_SECURITY_GROUP_1 = random_os_id()
ID_OS_SECURITY_GROUP_2 = random_os_id()


# route table constants
ID_DB_ROUTE_TABLE_1 = random_db_id()
ID_DB_ROUTE_TABLE_2 = random_db_id()
ID_EC2_ROUTE_TABLE_1 = ec2utils.get_ec2_id(ID_DB_ROUTE_TABLE_1, 'rtb')
ID_EC2_ROUTE_TABLE_2 = ec2utils.get_ec2_id(ID_DB_ROUTE_TABLE_2, 'rtb')
ID_EC2_ROUTE_TABLE_ASSOCIATION_1 = ID_EC2_VPC_1.replace('vpc', 'rtbassoc')
ID_EC2_ROUTE_TABLE_ASSOCIATION_2 = ID_EC2_SUBNET_2.replace('subnet',
                                                           'rtbassoc')

CIDR_EXTERNAL_NETWORK = '192.168.50.0/24'


# Object constants section
# Constant name notation:
# [<subtype>]<object_name>
# where
#    subtype - type of object storage, is not used for DB objects
#        EC2 - object representation to end user
#        EC2 - object received from Nova EC2 API
#        OS - object is stored in OpenStack
#    object_name - identifies the object

# vpc objects
# 2 vpcs in normal state
DB_VPC_1 = {'id': ID_DB_VPC_1,
            'os_id': ID_OS_ROUTER_1,
            'vpc_id': None,
            'cidr_block': CIDR_VPC_1,
            'route_table_id': ID_DB_ROUTE_TABLE_1}
DB_VPC_2 = {'id': ID_DB_VPC_2,
            'os_id': ID_OS_ROUTER_2,
            'vpc_id': None,
            'cidr_block': CIDR_VPC_2}

EC2_VPC_1 = {'vpcId': ID_EC2_VPC_1,
             'cidrBlock': CIDR_VPC_1,
             'isDefault': False,
             'state': 'available',
             'dhcpOptionsId': 'default'}
EC2_VPC_2 = {'vpcId': ID_EC2_VPC_2,
             'cidrBlock': CIDR_VPC_2,
             'isDefault': False,
             'state': 'available',
             'dhcpOptionsId': 'default'}

OS_ROUTER_1 = {'id': ID_OS_ROUTER_1,
               'name': ID_EC2_VPC_1}
OS_ROUTER_2 = {'id': ID_OS_ROUTER_2,
               'name': ID_EC2_VPC_2}


# internet gateway objects
# 2 internate gateway, the first is attached to the first vpc
DB_IGW_1 = {'id': ID_DB_IGW_1,
            'os_id': None,
            'vpc_id': ID_DB_VPC_1}
DB_IGW_2 = {'id': ID_DB_IGW_2,
            'os_id': None,
            'vpc_id': None}

EC2_IGW_1 = {'internetGatewayId': ID_EC2_IGW_1,
             'attachmentSet': [{'vpcId': ID_EC2_VPC_1,
                                'state': 'available'}]}
EC2_IGW_2 = {'internetGatewayId': ID_EC2_IGW_2,
             'attachmentSet': []}


# subnet objects
# 2 subnets in the first vpc
DB_SUBNET_1 = {'id': ID_DB_SUBNET_1,
               'os_id': ID_OS_SUBNET_1,
               'vpc_id': ID_DB_VPC_1}
DB_SUBNET_2 = {'id': ID_DB_SUBNET_2,
               'os_id': ID_OS_SUBNET_2,
               'vpc_id': ID_DB_VPC_1}

EC2_SUBNET_1 = {'subnetId': ID_EC2_SUBNET_1,
                'state': 'available',
                'vpcId': ID_EC2_VPC_1,
                'cidrBlock': CIDR_SUBNET_1,
                'defaultForAz': False,
                'availableIpAddressCount': 253,
                'mapPublicIpOnLaunch': False}
EC2_SUBNET_2 = {'subnetId': ID_EC2_SUBNET_2,
                'state': 'available',
                'vpcId': ID_EC2_VPC_1,
                'cidrBlock': CIDR_SUBNET_2,
                'defaultForAz': False,
                'availableIpAddressCount': 253,
                'mapPublicIpOnLaunch': False}

OS_SUBNET_1 = {'id': ID_OS_SUBNET_1,
               'network_id': ID_OS_NETWORK_1,
               'name': ID_EC2_SUBNET_1,
               'ip_version': '4',
               'cidr': CIDR_SUBNET_1,
               'host_routes': [{'nexthop': IP_GATEWAY_SUBNET_1,
                                'destination': '10.10.0.0/16'},
                               {'nexthop': '127.0.0.1',
                                'destination': '0.0.0.0/0'}]}
OS_SUBNET_2 = {'id': ID_OS_SUBNET_2,
               'network_id': ID_OS_NETWORK_2,
               'name': ID_EC2_SUBNET_2,
               'ip_version': '4',
               'cidr': CIDR_SUBNET_2}
OS_NETWORK_1 = {'id': ID_OS_NETWORK_1,
                'name': ID_EC2_SUBNET_1,
                'status': 'available'}
OS_NETWORK_2 = {'id': ID_OS_NETWORK_2,
                'name': ID_EC2_SUBNET_2,
                'status': 'available'}


# network interface objects
# 2 ports in both subnets, the second is attached to the first instance
DB_NETWORK_INTERFACE_1 = {'id': ID_DB_NETWORK_INTERFACE_1,
                          'os_id': ID_OS_PORT_1,
                          'vpc_id': ID_DB_VPC_1,
                          'subnet_id': ID_DB_SUBNET_1,
                          'description': DESCRIPTION_NETWORK_INTERFACE_1,
                          'private_ip_address': IP_NETWORK_INTERFACE_1}
DB_NETWORK_INTERFACE_2 = {'id': ID_DB_NETWORK_INTERFACE_2,
                          'os_id': ID_OS_PORT_2,
                          'vpc_id': ID_DB_VPC_1,
                          'subnet_id': ID_DB_SUBNET_2,
                          'description': DESCRIPTION_NETWORK_INTERFACE_2,
                          'private_ip_address': IP_NETWORK_INTERFACE_2,
                          'instance_id': ID_DB_INSTANCE_1,
                          'delete_on_termination': False,
                          'attach_time': TIME_ATTACH_NETWORK_INTERFACE}

EC2_NETWORK_INTERFACE_1 = {
    'networkInterfaceId': ID_EC2_NETWORK_INTERFACE_1,
    'status': 'available',
    'vpcId': ID_EC2_VPC_1,
    'subnetId': ID_EC2_SUBNET_1,
    'description': DESCRIPTION_NETWORK_INTERFACE_1,
    'macAddress': 'fb:10:2e:b2:ba:b7',
    'privateIpAddress': IP_NETWORK_INTERFACE_1,
    'privateIpAddressesSet': [{'privateIpAddress': IP_NETWORK_INTERFACE_1,
                               'primary': True}],
    'sourceDestCheck': True,
    'ownerId': ID_OS_PROJECT,
    'requesterManaged': False,
    'groupSet': [],
}
EC2_NETWORK_INTERFACE_2 = {
    'networkInterfaceId': ID_EC2_NETWORK_INTERFACE_2,
    'status': 'in-use',
    'vpcId': ID_EC2_VPC_1,
    'subnetId': ID_EC2_SUBNET_2,
    'description': DESCRIPTION_NETWORK_INTERFACE_2,
    'macAddress': 'fb:10:2e:b2:ba:b7',
    'privateIpAddress': IP_NETWORK_INTERFACE_2,
    'association': {
        'associationId': ID_EC2_ASSOCIATION_2,
        'ipOwnerId': ID_OS_PROJECT,
        'publicDnsName': None,
        'publicIp': IP_ADDRESS_2,
    },
    'privateIpAddressesSet': [
        {'privateIpAddress': IP_NETWORK_INTERFACE_2,
         'primary': True,
         'association': {
             'associationId': ID_EC2_ASSOCIATION_2,
             'ipOwnerId': ID_OS_PROJECT,
             'publicDnsName': None,
             'publicIp': IP_ADDRESS_2,
         }},
        {'privateIpAddress': IP_NETWORK_INTERFACE_2_EXT_1,
         'primary': False},
        {'privateIpAddress': IP_NETWORK_INTERFACE_2_EXT_2,
         'primary': False},
    ],
    'sourceDestCheck': True,
    'ownerId': ID_OS_PROJECT,
    'requesterManaged': False,
    'attachment': {
        'status': 'attached',
        'attachTime': TIME_ATTACH_NETWORK_INTERFACE,
        'deleteOnTermination': False,
        'attachmentId': ID_EC2_NETWORK_INTERFACE_2_ATTACH,
        'instanceId': ID_EC2_INSTANCE_1,
        'instanceOwnerId': ID_OS_PROJECT,
    },
    'groupSet': [],
}

OS_PORT_1 = {'id': ID_OS_PORT_1,
             'network_id': ID_OS_SUBNET_1,
             'name': ID_EC2_NETWORK_INTERFACE_1,
             'status': 'DOWN',
             'mac_address': 'fb:10:2e:b2:ba:b7',
             'fixed_ips': [{'ip_address': IP_NETWORK_INTERFACE_1,
                            'subnet_id': ID_OS_SUBNET_1}],
             'device_id': None,
             'device_owner': '',
             'security_groups': []}
OS_PORT_2 = {'id': ID_OS_PORT_2,
             'network_id': ID_OS_SUBNET_2,
             'name': ID_EC2_NETWORK_INTERFACE_2,
             'status': 'ACTIVE',
             'mac_address': 'fb:10:2e:b2:ba:b7',
             'fixed_ips': [{'ip_address': IP_NETWORK_INTERFACE_2,
                            'subnet_id': ID_OS_SUBNET_2},
                           {'ip_address': IP_NETWORK_INTERFACE_2_EXT_1,
                            'subnet_id': ID_OS_SUBNET_2},
                           {'ip_address': IP_NETWORK_INTERFACE_2_EXT_2,
                            'subnet_id': ID_OS_SUBNET_2}],
             'device_id': ID_OS_INSTANCE_1,
             'device_owner': '',
             'security_groups': []}


# instance objects
EC2OS_INSTANCE_1 = {
    'instanceId': ID_EC2_INSTANCE_1,
    'privateIpAddress': IP_NETWORK_INTERFACE_2,
    'fakeKey': 'fakeValue',
}
EC2OS_INSTANCE_2 = {
    'instanceId': ID_EC2_INSTANCE_2,
    'privateIpAddress': None,
    'fakeKey': 'fakeValue',
}
EC2OS_RESERVATION_1 = {
    'instancesSet': [EC2OS_INSTANCE_1],
    'fakeKey': 'fakeValue',
}
EC2OS_RESERVATION_2 = {
    'instancesSet': [EC2OS_INSTANCE_2],
    'fakeKey': 'fakeValue',
}
EC2_INSTANCE_1 = {
    'instanceId': ID_EC2_INSTANCE_1,
    'privateIpAddress': IP_NETWORK_INTERFACE_2,
    'fakeKey': 'fakeValue',
    'vpcId': ID_EC2_VPC_1,
    'subnetId': ID_EC2_SUBNET_2,
    'networkInterfaceSet': [
        {'networkInterfaceId': ID_EC2_NETWORK_INTERFACE_2,
         'status': 'in-use',
         'vpcId': ID_EC2_VPC_1,
         'subnetId': ID_EC2_SUBNET_2,
         'description': DESCRIPTION_NETWORK_INTERFACE_2,
         'macAddress': 'fb:10:2e:b2:ba:b7',
         'privateIpAddress': IP_NETWORK_INTERFACE_2,
         'association': {
             'associationId': ID_EC2_ASSOCIATION_2,
             'ipOwnerId': ID_OS_PROJECT,
             'publicDnsName': None,
             'publicIp': IP_ADDRESS_2,
         },
         'privateIpAddressesSet': [
             {'privateIpAddress': IP_NETWORK_INTERFACE_2,
              'primary': True,
              'association': {
                  'associationId': ID_EC2_ASSOCIATION_2,
                  'ipOwnerId': ID_OS_PROJECT,
                  'publicDnsName': None,
                  'publicIp': IP_ADDRESS_2}},
             {'privateIpAddress': IP_NETWORK_INTERFACE_2_EXT_1,
              'primary': False},
             {'privateIpAddress': IP_NETWORK_INTERFACE_2_EXT_2,
              'primary': False},
         ],
         'attachment': {
             'status': 'attached',
             'attachTime': TIME_ATTACH_NETWORK_INTERFACE,
             'deleteOnTermination': False,
             'attachmentId': ID_EC2_NETWORK_INTERFACE_2_ATTACH,
         },
         'sourceDestCheck': True,
         'ownerId': ID_OS_PROJECT,
         'requesterManaged': False,
         'groupSet': []},
    ],
}
EC2_INSTANCE_2 = EC2OS_INSTANCE_2
EC2_RESERVATION_1 = {
    'instancesSet': [EC2_INSTANCE_1],
    'fakeKey': 'fakeValue',
}
EC2_RESERVATION_2 = {
    'instancesSet': [EC2_INSTANCE_2],
    'fakeKey': 'fakeValue',
}


# DHCP options objects
DB_DHCP_OPTIONS_1 = {'id': ID_DB_DHCP_OPTIONS_1,
                     'dhcp_configuration':
                     {'domain-name': ['my.domain.com'],
                      'domain-name-servers': ['8.8.8.8', '127.0.0.1']}}

DB_DHCP_OPTIONS_2 = {'id': ID_DB_DHCP_OPTIONS_2,
                     'dhcp_configuration':
                     {'domain-name': ['my.domain.com'],
                      'domain-name-servers': ['8.8.8.8', '127.0.0.1'],
                      'netbios-name-servers': ['127.0.0.1'],
                      'netbios-node-type': [1],
                      'ntp-servers': ['127.0.0.1']}}

EC2_DHCP_OPTIONS_1 = {
    'dhcpOptionsId': ID_EC2_DHCP_OPTIONS_1,
    'dhcpConfigurationSet': [
        {'valueSet': [{'value': 'my.domain.com'}],
         'key': 'domain-name'},
        {'valueSet': [{'value': '8.8.8.8'}, {'value': '127.0.0.1'}],
         'key': 'domain-name-servers'}]}

EC2_DHCP_OPTIONS_2 = {
    'dhcpOptionsId': ID_EC2_DHCP_OPTIONS_2,
    'dhcpConfigurationSet': [
        {'valueSet': [{'value': 'my.domain.com'}],
         'key': 'domain-name'},
        {'valueSet': [{'value': '8.8.8.8'}, {'value': '127.0.0.1'}],
         'key': 'domain-name-servers'},
        {'valueSet': [{'value': 1}],
         'key': 'netbios-node-type'},
        {'valueSet': [{'value': '127.0.0.1'}],
         'key': 'ntp-servers'},
        {'valueSet': [{'value': '127.0.0.1'}],
         'key': 'netbios-name-servers'}]
}

OS_DHCP_OPTIONS_1 = {'extra_dhcp_opts': [{'opt_name': 'domain-name',
                                          'opt_value': 'my.domain.com'},
                                         {'opt_name': 'dns-servers',
                                          'opt_value': '8.8.8.8,127.0.0.1'}]}


# address objects
DB_ADDRESS_1 = {
    'id': ID_DB_ADDRESS_1,
    'os_id': ID_OS_FLOATING_IP_1,
    'vpc_id': None,
    'public_ip': IP_ADDRESS_1,
}
DB_ADDRESS_2 = {
    'id': ID_DB_ADDRESS_2,
    'os_id': ID_OS_FLOATING_IP_2,
    'vpc_id': None,
    'public_ip': IP_ADDRESS_2,
    'network_interface_id': ID_DB_NETWORK_INTERFACE_2,
    'private_ip_address': IP_NETWORK_INTERFACE_2,
}

EC2OS_ADDRESS_1 = {
    'publicIp': IP_ADDRESS_1,
}
EC2OS_ADDRESS_2 = {
    'publicIp': IP_ADDRESS_2,
    'instanceId': ID_EC2_INSTANCE_1,
}
EC2_ADDRESS_1 = {
    'allocationId': ID_EC2_ADDRESS_1,
    'publicIp': IP_ADDRESS_1,
    'domain': 'vpc',
}
EC2_ADDRESS_2 = {
    'allocationId': ID_EC2_ADDRESS_2,
    'publicIp': IP_ADDRESS_2,
    'domain': 'vpc',
    'instanceId': ID_EC2_INSTANCE_1,
    'associationId': ID_EC2_ASSOCIATION_2,
    'networkInterfaceId': ID_EC2_NETWORK_INTERFACE_2,
    'privateIpAddress': IP_NETWORK_INTERFACE_2,
    'networkInterfaceOwnerId': ID_OS_PROJECT,
}

OS_FLOATING_IP_1 = {
    'id': ID_OS_FLOATING_IP_1,
    'floating_ip_address': IP_ADDRESS_1,
    'port_id': None,
    'fixed_ip_address': None,
}
OS_FLOATING_IP_2 = {
    'id': ID_OS_FLOATING_IP_2,
    'floating_ip_address': IP_ADDRESS_2,
    'port_id': ID_OS_PORT_2,
    'fixed_ip_address': IP_NETWORK_INTERFACE_2,
}


# security group objects
DB_SECURITY_GROUP_1 = {
    'id': ID_DB_SECURITY_GROUP_1,
    'os_id': ID_OS_SECURITY_GROUP_1,
    'vpc_id': ID_DB_VPC_1,
}
DB_SECURITY_GROUP_2 = {
    'id': ID_DB_SECURITY_GROUP_2,
    'os_id': ID_OS_SECURITY_GROUP_2,
    'vpc_id': ID_DB_VPC_1,
}
OS_SECURITY_GROUP_RULE_1 = {
    'direction': 'ingress',
    'ethertype': 'IPv4',
    'id': random_os_id(),
    'port_range_min': 10,
    'port_range_max': 10,
    'protocol': 'tcp',
    'remote_group_id': None,
    'remote_ip_prefix': '192.168.1.0/24',
    'security_group_id': ID_OS_SECURITY_GROUP_2
}
OS_SECURITY_GROUP_RULE_2 = {
    'direction': 'egress',
    'ethertype': 'IPv4',
    'id': random_os_id(),
    'port_range_min': 10,
    'port_range_max': None,
    'protocol': 100,
    'remote_group_id': ID_OS_SECURITY_GROUP_1,
    'remote_ip_prefix': None,
    'security_group_id': ID_OS_SECURITY_GROUP_2
}
OS_SECURITY_GROUP_1 = {
    'id': ID_OS_SECURITY_GROUP_1,
    'name': 'groupname',
    'security_group_rules':
    [{'remote_group_id': None,
      'direction': 'egress',
      'remote_ip_prefix': None,
      'protocol': None,
      'port_range_max': None,
      'security_group_id': ID_OS_SECURITY_GROUP_1,
      'port_range_min': None,
      'ethertype': 'IPv4',
      'id': random_os_id()},
     {'remote_group_id': None,
      'direction': 'egress',
      'remote_ip_prefix': None,
      'protocol': None,
      'port_range_max': None,
      'security_group_id': ID_OS_SECURITY_GROUP_1,
      'port_range_min': None,
      'ethertype': 'IPv6',
      'id': random_os_id()}],
    'description': 'Group description',
    'tenant_id': ID_OS_PROJECT
}
OS_SECURITY_GROUP_2 = {
    'id': ID_OS_SECURITY_GROUP_2,
    'name': 'groupname',
    'security_group_rules': [
        OS_SECURITY_GROUP_RULE_1,
        OS_SECURITY_GROUP_RULE_2
    ],
    'description': 'Group description',
    'tenant_id': ID_OS_PROJECT
}
EC2_SECURITY_GROUP_1 = {
    'vpcId': ID_EC2_VPC_1,
    'groupDescription': 'Group description',
    'ipPermissions': None,
    'groupName': 'groupname',
    'ipPermissionsEgress':
    [{'toPort': -1,
      'ipProtocol': -1,
      'fromPort': -1}],
    'ownerId': ID_OS_PROJECT,
    'groupId': ID_EC2_SECURITY_GROUP_1
}
EC2_SECURITY_GROUP_2 = {
    'vpcId': ID_EC2_VPC_1,
    'groupDescription': 'Group description',
    'ipPermissions':
    [{'toPort': 10,
      'ipProtocol': 'tcp',
      'fromPort': 10,
      'ipRanges':
      [{'cidrIp': '192.168.1.0/24'}]
      }],
    'groupName': 'groupname',
    'ipPermissionsEgress':
    [{'toPort': -1,
      'ipProtocol': 100,
      'fromPort': 10,
      'groups':
      [{'groupId': ID_EC2_SECURITY_GROUP_1,
        'groupName': 'groupname',
        'userId': ID_OS_PROJECT}]
      }],
    'ownerId': ID_OS_PROJECT,
    'groupId': ID_EC2_SECURITY_GROUP_2
}


# route table objects
DB_ROUTE_TABLE_1 = {
    'id': ID_DB_ROUTE_TABLE_1,
    'vpc_id': ID_DB_VPC_1,
    'routes': [{'destination_cidr_block': CIDR_VPC_1,
                'gateway_id': None}],
}
DB_ROUTE_TABLE_2 = {
    'id': ID_DB_ROUTE_TABLE_2,
    'vpc_id': ID_DB_VPC_1,
    'routes': [{'destination_cidr_block': CIDR_VPC_1,
                'gateway_id': None},
               {'destination_cidr_block': CIDR_EXTERNAL_NETWORK,
                'network_interface_id': ID_DB_NETWORK_INTERFACE_2},
               {'destination_cidr_block': '0.0.0.0/0',
                'gateway_id': ID_DB_IGW_1}],
}
EC2_ROUTE_TABLE_1 = {
    'routeTableId': ID_EC2_ROUTE_TABLE_1,
    'vpcId': ID_EC2_VPC_1,
    'routeSet': [
        {'destinationCidrBlock': CIDR_VPC_1,
         'gatewayId': 'local',
         'state': 'active',
         'origin': 'CreateRouteTable'}],
    'associationSet': [
        {'routeTableAssociationId': ID_EC2_ROUTE_TABLE_ASSOCIATION_1,
         'routeTableId': ID_EC2_ROUTE_TABLE_1,
         'main': True}],
}
EC2_ROUTE_TABLE_2 = {
    'routeTableId': ID_EC2_ROUTE_TABLE_2,
    'vpcId': ID_EC2_VPC_1,
    'routeSet': [
        {'destinationCidrBlock': CIDR_VPC_1,
         'gatewayId': 'local',
         'state': 'active',
         'origin': 'CreateRouteTable'},
        {'destinationCidrBlock': CIDR_EXTERNAL_NETWORK,
         'instanceId': ID_EC2_INSTANCE_1,
         'instanceOwnerId': ID_OS_PROJECT,
         'networkInterfaceId': ID_EC2_NETWORK_INTERFACE_2,
         'state': 'active',
         'origin': 'CreateRoute'},
        {'destinationCidrBlock': '0.0.0.0/0',
         'gatewayId': ID_EC2_IGW_1,
         'state': 'active',
         'origin': 'CreateRoute'}]
}


# Object generator functions section

# internet gateway generator functions
def gen_db_igw(db_id, db_vpc_id=None):
    return {'id': db_id,
            'os_id': None,
            'vpc_id': db_vpc_id}


# network interface generator functions
def gen_db_network_interface(db_id, os_id, vpc_db_id, subnet_db_id,
                             private_ip_address, description=None,
                             instance_id=None, delete_on_termination=False):
    eni = {'id': db_id,
           'os_id': os_id,
           'vpc_id': vpc_db_id,
           'subnet_id': subnet_db_id,
           'description': description,
           'private_ip_address': private_ip_address}
    if instance_id:
        eni['instance_id'] = instance_id
        eni['delete_on_termination'] = delete_on_termination
        eni['attach_time'] = TIME_ATTACH_NETWORK_INTERFACE
    return eni


def gen_ec2_network_interface(ec2_network_interface_id, ec2_subnet, ips,
                              description=None, ec2_instance_id=None,
                              delete_on_termination=False,
                              for_instance_output=False,
                              ec2_subnet_id=None,
                              ec2_vpc_id=None):
    """Generate EC2 Network Interface dictionary.

    Set privateIpAddres from the first element of ips.
    If ec2_subnet_id and ec2_vpc_id are used if passed instead of getting
    appropriate values from ec2_subnet
    """
    ec2_network_interface = {
        'networkInterfaceId': ec2_network_interface_id,
        'vpcId': ec2_vpc_id if ec2_vpc_id else ec2_subnet['vpcId'],
        'subnetId': ec2_subnet_id if ec2_subnet_id else ec2_subnet['subnetId'],
        'description': description,
        'macAddress': 'fb:10:2e:b2:ba:b7',
        'privateIpAddress': ips[0],
        'privateIpAddressesSet': [{'privateIpAddress': ip,
                                   'primary': ip == ips[0]}
                                  for ip in ips],
        'sourceDestCheck': True,
        'ownerId': ID_OS_PROJECT,
        'requesterManaged': False,
        'groupSet': [],
    }
    if not ec2_instance_id:
        ec2_network_interface['status'] = 'available'
    else:
        attachment_id = ec2_network_interface_id.replace('eni', 'eni-attach')
        attachment = {'status': 'attached',
                      'attachTime': TIME_ATTACH_NETWORK_INTERFACE,
                      'deleteOnTermination': delete_on_termination,
                      'attachmentId': attachment_id}
        if not for_instance_output:
            attachment.update({
                'instanceId': ec2_instance_id,
                'instanceOwnerId': ID_OS_PROJECT})
        ec2_network_interface['status'] = 'in-use'
        ec2_network_interface['attachment'] = attachment
    return ec2_network_interface


def gen_os_port(os_id, ec2_network_interface, os_subnet_id, fixed_ips,
                os_instance_id=None):
    return {'id': os_id,
            'network_id': os_subnet_id,
            'name': ec2_network_interface['networkInterfaceId'],
            'status': 'ACTIVE' if os_instance_id else 'DOWN',
            'mac_address': 'fb:10:2e:b2:ba:b7',
            'fixed_ips': [{'ip_address': ip, 'subnet_id': os_subnet_id}
                          for ip in fixed_ips],
            'device_id': os_instance_id,
            'security_groups': []}


# instance generator functions
def gen_ec2_instance(ec2_instance_id, private_ip_address='',
                     ec2_network_interfaces=None, is_private_ip_in_vpc=True):
    """Generate EC2 Instance dictionary.

    private_ip_address must be specified as IP value or None
    Set vpcId from the first ec2_network_interfaces
    If private_ip_address is not None, set subnetId from the first
    ec2_network_interfaces
    """
    ec2_instance = {'instanceId': ec2_instance_id,
                    'privateIpAddress': private_ip_address,
                    'fakeKey': 'fakeValue'}
    if ec2_network_interfaces is not None:
        ec2_instance['networkInterfaceSet'] = (
            [ni for ni in ec2_network_interfaces])
        ec2_instance['vpcId'] = ec2_network_interfaces[0]['vpcId']
        if private_ip_address and is_private_ip_in_vpc:
            ec2_instance['subnetId'] = ec2_network_interfaces[0]['subnetId']
    return ec2_instance


def gen_ec2_reservation(ec2_reservation_id, ec2_instances):
    """Generate EC2 Reservation dictionary."""
    return {'reservationId': ec2_reservation_id,
            'ownerId': ID_OS_PROJECT,
            'instancesSet': [inst for inst in ec2_instances],
            'groupSet': []}
