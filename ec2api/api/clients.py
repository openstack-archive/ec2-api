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


from keystoneclient.v2_0 import client as kc
from novaclient import client as novaclient
from novaclient import exceptions as nova_exception
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging

from ec2api import context as ec2_context
from ec2api.i18n import _, _LW

logger = logging.getLogger(__name__)

CONF = cfg.CONF


try:
    from neutronclient.v2_0 import client as neutronclient
except ImportError:
    neutronclient = None
    logger.info(_('neutronclient not available'))
try:
    from cinderclient import client as cinderclient
except ImportError:
    cinderclient = None
    logger.info(_('cinderclient not available'))
try:
    from glanceclient import client as glanceclient
except ImportError:
    glanceclient = None
    logger.info(_('glanceclient not available'))


# Nova API's 2.3 microversion provides additional EC2 compliant instance
# properties
_novaclient_vertion = '2.3'
_nova_service_type = 'computev21'


def nova(context):
    args = {
        'auth_url': CONF.keystone_url,
        'auth_token': context.auth_token,
        # NOTE(ft): These parameters are not used for authentification,
        # but are required by novaclient < v2.18 which may be installed in
        # Icehouse deployment
        'username': None,
        'api_key': None,
        'project_id': None,
    }
    global _novaclient_vertion, _nova_service_type
    bypass_url = _url_for(context, service_type=_nova_service_type)
    if not bypass_url and _nova_service_type == 'computev21':
        # NOTE(ft): partial compatibility with pre Kilo OS releases:
        # if computev21 isn't provided by Nova, use compute instead
        logger.warning(_LW("Nova server doesn't support v2.1, use v2 instead. "
                           "A lot of useful EC2 compliant instance properties "
                           "will be unavailable."))
        _nova_service_type = 'compute'
        return nova(context)
    try:
        return novaclient.Client(_novaclient_vertion, bypass_url=bypass_url,
                                 **args)
    except nova_exception.UnsupportedVersion:
        if _novaclient_vertion == '2':
            raise
        # NOTE(ft): partial compatibility with Nova client w/o microversion
        # support
        logger.warning(_LW("Nova client doesn't support v2.3, use v2 instead. "
                           "A lot of useful EC2 compliant instance properties "
                           "will be unavailable."))
        _novaclient_vertion = '2'
        return nova(context)


def neutron(context):
    if neutronclient is None:
        return None

    args = {
        'auth_url': CONF.keystone_url,
        'service_type': 'network',
        'token': context.auth_token,
        'endpoint_url': _url_for(context, service_type='network'),
    }

    return neutronclient.Client(**args)


def glance(context):
    if glanceclient is None:
        return None

    args = {
        'auth_url': CONF.keystone_url,
        'service_type': 'image',
        'token': context.auth_token,
    }

    return glanceclient.Client(
        "1", endpoint=_url_for(context, service_type='image'), **args)


def cinder(context):
    if cinderclient is None:
        return nova(context, 'volume')

    args = {
        'service_type': 'volume',
        'auth_url': CONF.keystone_url,
        'username': None,
        'api_key': None,
    }

    _cinder = cinderclient.Client('1', **args)
    management_url = _url_for(context, service_type='volume')
    _cinder.client.auth_token = context.auth_token
    _cinder.client.management_url = management_url

    return _cinder


def keystone(context):
    _keystone = kc.Client(
        token=context.auth_token,
        tenant_id=context.project_id,
        auth_url=CONF.keystone_url)

    return _keystone


def nova_cert(context):
    _cert_api = _rpcapi_CertAPI(context)
    return _cert_api


def _url_for(context, **kwargs):
    service_catalog = context.service_catalog
    if not service_catalog:
        catalog = keystone(context).service_catalog.catalog
        service_catalog = catalog['serviceCatalog']
        context.service_catalog = service_catalog

    service_type = kwargs['service_type']
    for service in service_catalog:
        if service['type'] != service_type:
            continue
        for endpoint in service['endpoints']:
            if 'publicURL' in endpoint:
                return endpoint['publicURL']
        else:
            return None

    return None


class _rpcapi_CertAPI(object):
    '''Client side of the cert rpc API.'''

    def __init__(self, context):
        super(_rpcapi_CertAPI, self).__init__()
        target = messaging.Target(topic=CONF.cert_topic, version='2.0')
        self.client = _rpc_get_client(target)
        self.context = context

    def decrypt_text(self, text):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'decrypt_text',
                          project_id=self.context.project_id,
                          text=text)


_rpc_TRANSPORT = None


def _rpc_init(conf):
    global _rpc_TRANSPORT
    # NOTE(ft): set control_exchange parameter to use Nova cert topic
    messaging.set_transport_defaults('nova')
    _rpc_TRANSPORT = messaging.get_transport(conf)


def _rpc_get_client(target):
    if not _rpc_TRANSPORT:
        _rpc_init(CONF)
    assert _rpc_TRANSPORT is not None
    serializer = _rpc_RequestContextSerializer()
    return messaging.RPCClient(_rpc_TRANSPORT,
                               target,
                               serializer=serializer)


class _rpc_RequestContextSerializer(messaging.NoOpSerializer):

    def serialize_context(self, context):
        return context.to_dict()

    def deserialize_context(self, context):
        return ec2_context.RequestContext.from_dict(context)
