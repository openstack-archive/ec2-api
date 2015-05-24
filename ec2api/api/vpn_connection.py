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

import random
import string

from neutronclient.common import exceptions as neutron_exception
from oslo_log import log as logging

from ec2api.api import clients
from ec2api.api import common
from ec2api.api import ec2utils
from ec2api.db import api as db_api
from ec2api import exception
from ec2api.i18n import _


LOG = logging.getLogger(__name__)


Validator = common.Validator


SHARED_KEY_CHARS = string.ascii_letters + '_.' + string.digits


def create_vpn_connection(context, customer_gateway_id, vpn_gateway_id,
                          type, options=None):
    if not options or options.get('static_routes_only') is not True:
        raise exception.Unsupported('BGP dynamic routing is unsupported')
    customer_gateway = ec2utils.get_db_item(context, customer_gateway_id)
    vpn_gateway = ec2utils.get_db_item(context, vpn_gateway_id)
    vpn_connection = next(
        (vpn for vpn in db_api.get_items(context, 'vpn')
         if vpn['customer_gateway_id'] == customer_gateway_id),
        None)
    if vpn_connection:
        if vpn_connection['vpn_gateway_id'] == vpn_gateway_id:
            return {'vpnConnection': _format_vpn_connection(vpn_connection)}
        else:
            raise exception.InvalidCustomerGatewayDuplicateIpAddress()
    neutron = clients.neutron(context)
    with common.OnCrashCleaner() as cleaner:
        os_ikepolicy = {'ike_version': 'v1',
                        'auth_algorithm': 'sha1',
                        'encryption_algorithm': 'aes-128',
                        'pfs': 'group2',
                        'phase1_negotiation_mode': 'main',
                        'lifetime': {'units': 'seconds',
                                     'value': 28800}}
        os_ikepolicy = neutron.create_ikepolicy(
            {'ikepolicy': os_ikepolicy})['ikepolicy']
        cleaner.addCleanup(neutron.delete_ikepolicy, os_ikepolicy['id'])

        os_ipsecpolicy = {'transform_protocol': 'esp',
                          'auth_algorithm': 'sha1',
                          'encryption_algorithm': 'aes-128',
                          'pfs': 'group2',
                          'encapsulation_mode': 'tunnel',
                          'lifetime': {'units': 'seconds',
                                       'value': 3600}}
        os_ipsecpolicy = neutron.create_ipsecpolicy(
            {'ipsecpolicy': os_ipsecpolicy})['ipsecpolicy']
        cleaner.addCleanup(neutron.delete_ipsecpolicy, os_ipsecpolicy['id'])

        psk = ''.join(random.choice(SHARED_KEY_CHARS) for _x in xrange(32))
        vpn_connection = db_api.add_item(
             context, 'vpn',
             {'customer_gateway_id': customer_gateway['id'],
              'vpn_gateway_id': vpn_gateway['id'],
              'pre_shared_key': psk,
              'os_ikepolicy_id': os_ikepolicy['id'],
              'os_ipsecpolicy_id': os_ipsecpolicy['id'],
              })
        cleaner.addCleanup(db_api.delete_item, context, vpn_connection['id'])

        neutron.update_ikepolicy(
            os_ikepolicy['id'], {'ikepolicy': {'name': vpn_connection['id']}})
        neutron.update_ipsecpolicy(
            os_ipsecpolicy['id'],
            {'ipsecpolicy': {'name': vpn_connection['id']}})

    return {'vpnConnection': _format_vpn_connection(vpn_connection)}


def delete_vpn_connection(context, vpn_connection_id):
    vpn_connection = ec2utils.get_db_item(context, vpn_connection_id)
    with common.OnCrashCleaner() as cleaner:
        db_api.delete_item(context, vpn_connection['id'])
        cleaner.addCleanup(db_api.restore_item, context, 'vpn', vpn_connection)
        neutron = clients.neutron(context)
        try:
            neutron.delete_ipsecpolicy(vpn_connection['os_ipsecpolicy_id'])
        except neutron_exception.Conflict as ex:
            LOG.warning(
                _('Failed to delete ipsecoplicy %(os_id)s during deleting '
                  'VPN connection %(id)s. Reason: %(reason)s'),
                {'id': vpn_connection['id'],
                 'os_id': vpn_connection['os_ipsecpolicy_id'],
                 'reason': ex.message})
        except neutron_exception.NotFound:
            pass
        try:
            neutron.delete_ikepolicy(vpn_connection['os_ikepolicy_id'])
        except neutron_exception.Conflict as ex:
            LOG.warning(
                _('Failed to delete ikepolicy %(os_id)s during deleting '
                  'VPN connection %(id)s. Reason: %(reason)s'),
                {'id': vpn_connection['id'],
                 'os_id': vpn_connection['os_ikepolicy_id'],
                 'reason': ex.message})
        except neutron_exception.NotFound:
            pass
    return True


def describe_vpn_connections(context, vpn_connection_id=None, filter=None):
    formatted_vpn_connections = VpnConnectionDescriber().describe(
        context, ids=vpn_connection_id, filter=filter)
    return {'vpnConnectionSet': formatted_vpn_connections}


class VpnConnectionDescriber(common.TaggableItemsDescriber,
                             common.NonOpenstackItemsDescriber):

    KIND = 'vpn'
    FILTER_MAP = {'customer-gateway-id': 'customerGatewayId',
                  'state': 'state',
                  'option.static-routes-only': ('options', 'staticRoutesOnly'),
                  'type': 'type',
                  'vpn-connection-id': 'vpnConnectionId',
                  'vpn-gateway-id': 'vpnGatewayId'}

    def format(self, vpn_connection):
        return _format_vpn_connection(vpn_connection)


def _format_vpn_connection(vpn_connection):
    return {'vpnConnectionId': vpn_connection['id'],
            'vpnGatewayId': vpn_connection['vpn_gateway_id'],
            'customerGatewayId': vpn_connection['customer_gateway_id'],
            'state': 'available',
            'type': 'ipsec.1',
            'vgwTelemetry': [],
            'options': {'staticRoutesOnly': True}}
