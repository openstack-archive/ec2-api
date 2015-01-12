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
import urlparse

import httplib2
from keystoneclient.v2_0 import client as keystone_client
from oslo.config import cfg
import webob

from ec2api import context as ec2context
from ec2api.metadata import api
from ec2api.openstack.common import gettextutils as textutils
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging
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
    cfg.StrOpt('admin_user',
               help=_("Admin user")),
    cfg.StrOpt('admin_password',
               help=_("Admin password"),
               secret=True),
    cfg.StrOpt('admin_tenant_name',
               help=_("Admin tenant name")),
    cfg.StrOpt('metadata_proxy_shared_secret',
               default='',
               help=_('Shared secret to sign instance-id request'),
               secret=True),
]

CONF.register_opts(metadata_opts, group='metadata')


class MetadataRequestHandler(wsgi.Application):
    """Serve metadata."""

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        try:
            LOG.debug("Request: %s", req)

            return self._proxy_request(req)
        except Exception:
            LOG.exception(textutils._LE("Unexpected error."))
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            return webob.exc.HTTPInternalServerError(explanation=unicode(msg))

    def _proxy_request(self, req):
        headers = self._build_proxy_request_headers(req)
        if not headers:
            return webob.exc.HTTPNotFound()
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
            LOG.warn(textutils._LW(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            ))
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
            LOG.warn(msg)
            return webob.exc.HTTPInternalServerError(explanation=unicode(msg))
        else:
            raise Exception(_('Unexpected response code: %s') % resp.status)

    def _build_proxy_request_headers(self, req):
        if req.headers.get('X-Instance-ID'):
            return req.headers

        instance_ip = self._get_instance_ip(req)
        context = self._get_context()
        instance_id, project_id = api.get_instance_and_project_id(context,
                                                                  instance_ip)
        if not instance_id:
            return None

        return {
            'X-Forwarded-For': instance_ip,
            'X-Instance-ID': instance_id,
            'X-Tenant-ID': project_id,
            'X-Instance-ID-Signature': self._sign_instance_id(instance_id),
        }

    def _get_instance_ip(self, req):
        instance_ip = req.remote_addr
        if CONF.use_forwarded_for:
            instance_ip = req.headers.get('X-Forwarded-For', instance_ip)
        return instance_ip

    def _get_context(self):
        # TODO(ft): make authentification token reusable
        keystone = keystone_client.Client(
            username=CONF.metadata.admin_user,
            password=CONF.metadata.admin_password,
            tenant_name=CONF.metadata.admin_tenant_name,
            auth_url=CONF.keystone_url,
        )
        service_catalog = keystone.service_catalog.get_data()
        return ec2context.RequestContext(
                keystone.auth_user_id,
                keystone.auth_tenant_id,
                None, None,
                auth_token=keystone.auth_token,
                service_catalog=service_catalog)

    def _sign_instance_id(self, instance_id):
        return hmac.new(CONF.metadata.metadata_proxy_shared_secret,
                        instance_id,
                        hashlib.sha256).hexdigest()
