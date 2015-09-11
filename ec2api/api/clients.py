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

from cinderclient import client as cinderclient
from glanceclient import client as glanceclient
from neutronclient.v2_0 import client as neutronclient
from novaclient import api_versions as nova_api_versions
from novaclient import client as novaclient
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging

from ec2api import context as ec2_context
from ec2api.i18n import _LI, _LW

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


# Nova API version with microversions support
REQUIRED_NOVA_API_VERSION = '2.1'
REQUIRED_NOVA_API_VERSION_ID = 'v%s' % REQUIRED_NOVA_API_VERSION
LEGACY_NOVA_API_VERSION = '2'
# Nova API's 2.3 microversion provides additional EC2 compliant instance
# properties
REQUIRED_NOVA_API_MICROVERSION = '2.3'
_nova_api_version = None


def nova(context):
    global _nova_api_version
    if not _nova_api_version:
        _nova_api_version = _get_nova_api_version(context)
    clnt = novaclient.Client(_nova_api_version,
                             session=context.session,
                             service_type=CONF.nova_service_type)
    # NOTE(ft): workaround for LP #1494116 bug
    if not hasattr(clnt.client, 'last_request_id'):
        setattr(clnt.client, 'last_request_id', None)
    return clnt


def neutron(context):
    if neutronclient is None:
        return None

    return neutronclient.Client(session=context.session,
                                service_type='network')


def glance(context):
    if glanceclient is None:
        return None

    return glanceclient.Client('1', service_type='image',
                               session=context.session)


def cinder(context):
    if cinderclient is None:
        return nova(context, 'volume')

    return cinderclient.Client('1', session=context.session,
                               service_type='volume')


def keystone(context):
    keystone_client_class = ec2_context.get_keystone_client_class()
    return keystone_client_class(session=context.session)


def nova_cert(context):
    _cert_api = _rpcapi_CertAPI(context)
    return _cert_api


def _get_nova_api_version(context):
    client = novaclient.Client(REQUIRED_NOVA_API_VERSION,
                               session=context.session,
                               service_type=CONF.nova_service_type)

    required = nova_api_versions.APIVersion(REQUIRED_NOVA_API_MICROVERSION)
    current = client.versions.get_current()
    if not current:
        logger.warning(
            _LW('Could not check Nova API version because no version '
                'was found in Nova version list for url %(url)s of service '
                'type "%(service_type)s". '
                'Use v%(required_api_version)s Nova API.'),
            {'url': client.client.get_endpoint(),
             'service_type': CONF.nova_service_type,
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
