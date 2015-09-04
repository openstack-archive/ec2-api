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

from novaclient import client as novaclient
from novaclient import exceptions as nova_exception
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging

from ec2api import context as ec2_context
from ec2api.i18n import _, _LI, _LW

logger = logging.getLogger(__name__)

ec2_opts = [
    cfg.StrOpt('nova_service_type',
               default='compute',
               help='Service type of Compute API, registered in Keystone '
                    'catalog. Should be v2.1 with microversion support. '
                    'If it is obsolete v2, a lot of useful EC2 compliant '
                    'instance properties will be unavailable.')
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)


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
try:
    # api_versions module is introduced since v2.27 novaclient
    from novaclient import api_versions as nova_api_versions
except ImportError:
    nova_api_versions = None


# Nova API version with microversions support
REQUIRED_NOVA_API_VERSION = '2.1'
REQUIRED_NOVA_API_VERSION_ID = 'v%s' % REQUIRED_NOVA_API_VERSION
LEGACY_NOVA_API_VERSION = '2'
# Nova API's 2.3 microversion provides additional EC2 compliant instance
# properties
REQUIRED_NOVA_API_MICROVERSION = '2.3'
_nova_api_version = None


def nova(context):
    args = {
        'auth_url': CONF.keystone_url,
        'auth_token': context.auth_token,
        'bypass_url': _url_for(context, service_type=CONF.nova_service_type),
        'http_log_debug': CONF.debug,
    }
    global _nova_api_version
    if not _nova_api_version:
        _nova_api_version = _get_nova_api_version(context)
    return novaclient.Client(_nova_api_version, **args)


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

    _cinder = cinderclient.Client('1', http_log_debug=CONF.debug, **args)
    management_url = _url_for(context, service_type='volume')
    _cinder.client.auth_token = context.auth_token
    _cinder.client.management_url = management_url

    return _cinder


def keystone(context):
    keystone_client_class = ec2_context.get_keystone_client_class()
    return keystone_client_class(
        token=context.auth_token,
        project_id=context.project_id,
        tenant_id=context.project_id,
        auth_url=CONF.keystone_url)


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
            elif endpoint.get('interface') == 'public':
                # NOTE(andrey-mp): keystone v3
                return endpoint['url']
        else:
            return None

    return None


def _get_nova_api_version(context):
    url = _url_for(context, service_type=CONF.nova_service_type)
    try:
        client = novaclient.Client(REQUIRED_NOVA_API_VERSION, bypass_url=url,
                                   http_log_debug=CONF.debug)
    except nova_exception.UnsupportedVersion:
        logger.warning(
            _LW('Nova client does not support v2.1 Nova API, use v2 instead. '
                'A lot of useful EC2 compliant instance properties '
                'will be unavailable.'))
        return LEGACY_NOVA_API_VERSION

    # NOTE(ft): this is a somewhat paranoid check, because api_versions
    # had been introduced to novaclient together with v2.1 support. Probaly
    # it should be removed after at least a couple of novaclinet has been
    # released with no change of APIVersion class location.
    if not nova_api_versions:
        logger.warning(_LW('Nova client suports v2.1, but does unexpectedly '
                           'not have api_versions module. Nova API version '
                           'check is skipped. Use v%s Nova API.'),
                       REQUIRED_NOVA_API_MICROVERSION)
        return REQUIRED_NOVA_API_MICROVERSION

    required = nova_api_versions.APIVersion(REQUIRED_NOVA_API_MICROVERSION)
    current = client.versions.get_current()
    if not current:
        logger.warning(
            _LW('Could not check Nova API version because no version '
                'was found in Nova version list for url %(url)s of service '
                'type "%(service_type)s". '
                'Use v%(required_api_version)s Nova API.'),
            {'url': url, 'service_type': CONF.nova_service_type,
             'required_api_version': REQUIRED_NOVA_API_MICROVERSION})
        return REQUIRED_NOVA_API_MICROVERSION
    if current.id != REQUIRED_NOVA_API_VERSION_ID:
        logger.warning(
            _LW('Specified "%s" Nova service type does not support v2.1 API. '
                'A lot of useful EC2 compliant instance properties '
                'will be unavailable.'),
            CONF.nova_service_type)
        return LEGACY_NOVA_API_VERSION
    if (nova_api_versions.APIVersion(current.version) < required):
        logger.warning(
            _LW('Nova support v%(nova_api_version)s, '
                'but v%(required_api_version)s is required. '
                'A lot of useful EC2 compliant instance properties '
                'will be unavailable.'),
            {'nova_api_version': current.version,
             'required_api_version': REQUIRED_NOVA_API_MICROVERSION})
        return current.version
    logger.info(_LI('Provided Nova API version is  v%(nova_api_version)s, '
                    'used one is v%(required_api_version)s'),
                {'nova_api_version': current.version,
                 'required_api_version': (
                        REQUIRED_NOVA_API_MICROVERSION)})
    return REQUIRED_NOVA_API_MICROVERSION


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
