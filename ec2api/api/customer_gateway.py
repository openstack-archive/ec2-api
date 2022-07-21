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

from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


"""Customer gateways related API implementation
"""


Validator = common.Validator


DEFAULT_BGP_ASN = 65000


def create_customer_gateway(context, type, bgp_asn=None,
                        ip_address=None, public_ip=None):
    if ip_address:
        ip_addr = ip_address
    elif (ip_address == None) and public_ip:
        ip_addr = public_ip
    elif (ip_address == None) and (public_ip == None):
        raise exception.Unsupported("GW without ip not supported")
    if bgp_asn and bgp_asn != DEFAULT_BGP_ASN:
        raise exception.Unsupported("BGP dynamic routing is unsupported")
        # testing output to get ec2 failures
    customer_gateway = next((cgw for cgw in db_api.get_items(context, 'cgw')
                             if cgw['ip_address'] == ip_addr), None)
    if not customer_gateway:
        customer_gateway = db_api.add_item(context, 'cgw',
                                           {'ip_address': ip_addr})
    return {'customerGateway': _format_customer_gateway(customer_gateway)}


def delete_customer_gateway(context, customer_gateway_id):
    customer_gateway = ec2utils.get_db_item(context, customer_gateway_id)
    vpn_connections = db_api.get_items(context, 'vpn')
    if any(vpn['customer_gateway_id'] == customer_gateway['id']
           for vpn in vpn_connections):
        raise exception.IncorrectState(
            reason=_('The customer gateway is in use.'))
    db_api.delete_item(context, customer_gateway['id'])
    return True


def describe_customer_gateways(context, customer_gateway_id=None,
                               filter=None):
    formatted_cgws = CustomerGatewayDescriber().describe(
        context, ids=customer_gateway_id, filter=filter)
    return {'customerGatewaySet': formatted_cgws}


class CustomerGatewayDescriber(common.TaggableItemsDescriber,
                               common.NonOpenstackItemsDescriber):

    KIND = 'cgw'
    FILTER_MAP = {'bgp-asn': 'bgpAsn',
                  'customer-gateway-id': 'customerGatewayId',
                  'ip-address': 'ipAddress',
                  'state': 'state',
                  'type': 'type'}

    def format(self, customer_gateway):
        return _format_customer_gateway(customer_gateway)


def _format_customer_gateway(customer_gateway):
    return {'customerGatewayId': customer_gateway['id'],
            'ipAddress': customer_gateway['ip_address'],
            'state': 'available',
            'type': 'ipsec.1',
            'bgpAsn': DEFAULT_BGP_ASN}
