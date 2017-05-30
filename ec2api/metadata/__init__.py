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

import hashlib
import hmac
import posixpath

import httplib2
from oslo_cache import core as cache_core
from oslo_config import cfg
from oslo_log import log as logging
import six
import six.moves.urllib.parse as urlparse
import webob

from ec2api import context as ec2_context
from ec2api import exception
from ec2api.i18n import _
from ec2api.metadata import api
from ec2api import utils
from ec2api import wsgi

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
CONF.import_opt('use_forwarded_for', 'ec2api.api.auth')

metadata_opts = [
    cfg.StrOpt('nova_metadata_ip',
               default='127.0.0.1',
               help=_("IP address used by Nova metadata server.")),
    cfg.IntOpt('nova_metadata_port',
               default=8775,
               help=_("TCP Port used by Nova metadata server.")),
    cfg.StrOpt('nova_metadata_protocol',
               default='http',
               choices=['http', 'https'],
               help=_("Protocol to access nova metadata, http or https")),
    cfg.BoolOpt('nova_metadata_insecure',
                default=False,
                help=_("Allow to perform insecure SSL (https) requests to "
                       "nova metadata")),
    cfg.StrOpt('auth_ca_cert',
               help=_("Certificate Authority public key (CA cert) "
                      "file for ssl")),
    cfg.StrOpt('nova_client_cert',
               default='',
               help=_("Client certificate for nova metadata api server.")),
    cfg.StrOpt('nova_client_priv_key',
               default='',
               help=_("Private key of client certificate.")),
    cfg.StrOpt('metadata_proxy_shared_secret',
               default='',
               help=_('Shared secret to sign instance-id request'),
               secret=True),
    cfg.IntOpt("cache_expiration",
        default=15,
        min=0,
        help=_('This option is the time (in seconds) to cache metadata. '
               'Increasing this setting should improve response times of the '
               'metadata API when under heavy load. Higher values may '
               'increase memory usage, and result in longer times for host '
               'metadata changes to take effect.'))
]

CONF.register_opts(metadata_opts, group='metadata')
cache_core.configure(CONF)


class MetadataRequestHandler(wsgi.Application):
    """Serve metadata."""

    def __init__(self):
        if not CONF.cache.enabled:
            LOG.warning("Metadata doesn't use cache. "
                        "Configure cache options to use cache.")
        self.cache_region = cache_core.create_region()
        cache_core.configure_cache_region(CONF, self.cache_region)

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        LOG.debug('Request: %s', req)

        path = req.path_info
        if path == '' or path[0] != '/':
            path = '/' + path
        path = posixpath.normpath(path)
        path_tokens = path.split('/')[1:]
        if path_tokens[0] == 'ec2':
            path_tokens = path_tokens[1:]

        if path_tokens == ['']:
            resp = api.get_version_list()
            return self._add_response_data(req.response, resp)

        try:
            requester = self._get_requester(req)
            if path_tokens[0] == 'openstack':
                return self._proxy_request(req, requester)

            resp = self._get_metadata(path_tokens, requester)
            return self._add_response_data(req.response, resp)

        except exception.EC2MetadataNotFound:
            return webob.exc.HTTPNotFound()
        except Exception:
            LOG.exception("Unexpected error.")
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            return webob.exc.HTTPInternalServerError(
                explanation=six.text_type(msg))

    def _proxy_request(self, req, requester):
        headers = self._build_proxy_request_headers(requester)
        nova_ip_port = '%s:%s' % (CONF.metadata.nova_metadata_ip,
                                  CONF.metadata.nova_metadata_port)
        url = urlparse.urlunsplit((
            CONF.metadata.nova_metadata_protocol,
            nova_ip_port,
            req.path_info,
            req.query_string,
            ''))

        h = httplib2.Http(
            ca_certs=CONF.metadata.auth_ca_cert,
            disable_ssl_certificate_validation=(
                    CONF.metadata.nova_metadata_insecure)
        )
        if (CONF.metadata.nova_client_cert and
                CONF.metadata.nova_client_priv_key):
            h.add_certificate(CONF.metadata.nova_client_priv_key,
                              CONF.metadata.nova_client_cert,
                              nova_ip_port)
        resp, content = h.request(url, method=req.method, headers=headers,
                                  body=req.body)

        if resp.status == 200:
            LOG.debug(str(resp))
            req.response.content_type = resp['content-type']
            req.response.body = content
            return req.response
        elif resp.status == 403:
            LOG.warning(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            return webob.exc.HTTPForbidden()
        elif resp.status == 400:
            return webob.exc.HTTPBadRequest()
        elif resp.status == 404:
            return webob.exc.HTTPNotFound()
        elif resp.status == 409:
            return webob.exc.HTTPConflict()
        elif resp.status == 500:
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.warning(msg)
            return webob.exc.HTTPInternalServerError(
                explanation=six.text_type(msg))
        else:
            raise Exception(_('Unexpected response code: %s') % resp.status)

    def _build_proxy_request_headers(self, requester):
        signature = self._sign_instance_id(requester['os_instance_id'])
        return {
            'X-Forwarded-For': requester['private_ip'],
            'X-Instance-ID': requester['os_instance_id'],
            'X-Tenant-ID': requester['project_id'],
            'X-Instance-ID-Signature': signature,
        }

    def _sign_instance_id(self, instance_id):
        return hmac.new(
            CONF.metadata.metadata_proxy_shared_secret.encode("utf-8"),
            instance_id.encode(),
            hashlib.sha256).hexdigest()

    def _get_requester(self, req):
        if req.headers.get('X-Metadata-Provider'):
            provider_id, remote_ip = self._unpack_nsx_request(req)
            context = ec2_context.get_os_admin_context()
            os_instance_id, project_id = (
                api.get_os_instance_and_project_id_by_provider_id(
                    context, provider_id, remote_ip))
        else:
            os_instance_id, project_id, remote_ip = (
                self._unpack_neutron_request(req))
        return {'os_instance_id': os_instance_id,
                'project_id': project_id,
                'private_ip': remote_ip}

    def _unpack_neutron_request(self, req):
        os_instance_id = req.headers.get('X-Instance-ID')
        project_id = req.headers.get('X-Tenant-ID')
        signature = req.headers.get('X-Instance-ID-Signature')
        remote_ip = req.headers.get('X-Forwarded-For')

        if not remote_ip:
            raise exception.EC2MetadataInvalidAddress()

        if os_instance_id is None:
            msg = _('X-Instance-ID header is missing from request.')
        elif project_id is None:
            msg = _('X-Tenant-ID header is missing from request.')
        elif not isinstance(os_instance_id, six.string_types):
            msg = _('Multiple X-Instance-ID headers found within request.')
        elif not isinstance(project_id, six.string_types):
            msg = _('Multiple X-Tenant-ID headers found within request.')
        else:
            msg = None

        if msg:
            raise webob.exc.HTTPBadRequest(explanation=msg)

        self._validate_signature(signature, os_instance_id, remote_ip)
        return os_instance_id, project_id, remote_ip

    def _unpack_nsx_request(self, req):
        remote_address = req.headers.get('X-Forwarded-For')
        if remote_address is None:
            msg = _('X-Forwarded-For is missing from request.')
            raise webob.exc.HTTPBadRequest(explanation=msg)
        provider_id = req.headers.get('X-Metadata-Provider')
        if provider_id is None:
            msg = _('X-Metadata-Provider is missing from request.')
            raise webob.exc.HTTPBadRequest(explanation=msg)
        remote_ip = remote_address.split(',')[0]

        if CONF.metadata.metadata_proxy_shared_secret:
            signature = req.headers.get('X-Metadata-Provider-Signature')
            self._validate_signature(signature, provider_id, remote_ip)

        return provider_id, remote_ip

    def _validate_signature(self, signature, requester_id, requester_ip):
        expected_signature = hmac.new(
            CONF.metadata.metadata_proxy_shared_secret.encode("utf-8"),
            requester_id.encode(),
            hashlib.sha256).hexdigest()

        if not (signature and
                utils.constant_time_compare(expected_signature, signature)):
            LOG.warning('X-Instance-ID-Signature: %(signature)s does '
                        'not match the expected value: '
                        '%(expected_signature)s for id: '
                        '%(requester_id)s. Request From: '
                        '%(requester_ip)s',
                        {'signature': signature,
                         'expected_signature': expected_signature,
                         'requester_id': requester_id,
                         'requester_ip': requester_ip})

            msg = _('Invalid proxy request signature.')
            raise webob.exc.HTTPForbidden(explanation=msg)

    def _get_metadata(self, path_tokens, requester):
        context = ec2_context.get_os_admin_context()
        # NOTE(ft): substitute project_id for context to instance's one.
        # It's needed for correct describe and auto update DB operations.
        # It doesn't affect operations via OpenStack's clients because
        # these clients use auth_token field only
        context.project_id = requester['project_id']
        return api.get_metadata_item(context, path_tokens,
                                     requester['os_instance_id'],
                                     requester['private_ip'],
                                     self.cache_region)

    def _add_response_data(self, response, data):
        if isinstance(data, six.text_type):
            response.text = data
        else:
            response.body = data
        response.content_type = 'text/plain'
        return response
