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

"""
Starting point for routing EC2 requests.
"""
import functools
import hashlib
import sys

from oslo.config import cfg
import requests
import six
import webob
import webob.dec
import webob.exc

from ec2api.api import apirequest
from ec2api.api import ec2utils
from ec2api.api import faults
from ec2api import context
from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import jsonutils
from ec2api.openstack.common import log as logging
from ec2api.openstack.common import timeutils
from ec2api import wsgi


LOG = logging.getLogger(__name__)

ec2_opts = [
    cfg.StrOpt('keystone_url',
               default='http://localhost:5000/v2.0',
               help='URL to get token from ec2 request.'),
    cfg.IntOpt('ec2_timestamp_expiry',
               default=300,
               help='Time in seconds before ec2 timestamp expires'),
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)
CONF.import_opt('use_forwarded_for', 'ec2api.api.auth')


EMPTY_SHA256_HASH = (
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
# This is the buffer size used when calculating sha256 checksums.
# Experimenting with various buffer sizes showed that this value generally
# gave the best result (in terms of performance).
PAYLOAD_BUFFER = 1024 * 1024


# Fault Wrapper around all EC2 requests #
class FaultWrapper(wsgi.Middleware):

    """Calls the middleware stack, captures any exceptions into faults."""

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        try:
            return req.get_response(self.application)
        except Exception as ex:
            LOG.exception(_("FaultWrapper: %s"), unicode(ex))
            return faults.Fault(webob.exc.HTTPInternalServerError())


class RequestLogging(wsgi.Middleware):

    """Access-Log akin logging for all EC2 API requests."""

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        start = timeutils.utcnow()
        rv = req.get_response(self.application)
        self.log_request_completion(rv, req, start)
        return rv

    def log_request_completion(self, response, request, start):
        apireq = request.environ.get('ec2.request', None)
        if apireq:
            action = apireq.action
        else:
            action = None
        ctxt = request.environ.get('ec2api.context', None)
        delta = timeutils.utcnow() - start
        seconds = delta.seconds
        microseconds = delta.microseconds
        LOG.info(
            "%s.%ss %s %s %s %s %s [%s] %s %s",
            seconds,
            microseconds,
            request.remote_addr,
            request.method,
            "%s%s" % (request.script_name, request.path_info),
            action,
            response.status_int,
            request.user_agent,
            request.content_type,
            response.content_type,
            context=ctxt)


class EC2KeystoneAuth(wsgi.Middleware):

    """Authenticate an EC2 request with keystone and convert to context."""

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        request_id = context.generate_request_id()

        if 'Signature' in req.params:
            cred_dict = self._get_creds(req, request_id)
        else:
            cred_dict = self._get_creds_v4(req, request_id)
        access = cred_dict['access']
        token_url = CONF.keystone_url + "/ec2tokens"
        if "ec2" in token_url:
            creds = {'ec2Credentials': cred_dict}
        else:
            creds = {'auth': {'OS-KSEC2:ec2Credentials': cred_dict}}
        creds_json = jsonutils.dumps(creds)
        headers = {'Content-Type': 'application/json'}

        response = requests.request('POST', token_url,
                                    data=creds_json, headers=headers)
        status_code = response.status_code
        if status_code != 200:
            if status_code == 401:
                msg = response.reason
            else:
                msg = _("Failure communicating with keystone")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=status_code)
        result = response.json()

        try:
            token_id = result['access']['token']['id']
            user_id = result['access']['user']['id']
            project_id = result['access']['token']['tenant']['id']
            user_name = result['access']['user'].get('name')
            project_name = result['access']['token']['tenant'].get('name')
            roles = [role['name'] for role
                     in result['access']['user']['roles']]
        except (AttributeError, KeyError) as e:
            LOG.exception(_("Keystone failure: %s") % e)
            msg = _("Failure communicating with keystone")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)

        remote_address = req.remote_addr
        if CONF.use_forwarded_for:
            remote_address = req.headers.get('X-Forwarded-For',
                                             remote_address)

        headers["X-Auth-Token"] = token_id
        url = CONF.keystone_url + ("/users/%s/credentials/OS-EC2/%s"
            % (user_id, access))
        response = requests.request('GET', url, headers=headers)
        status_code = response.status_code
        if status_code != 200:
            if status_code == 401:
                msg = response.reason
            else:
                msg = _("Failure communicating with keystone")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=status_code)
        ec2_creds = response.json()

        catalog = result['access']['serviceCatalog']
        ctxt = context.RequestContext(user_id,
                                      project_id,
                                      ec2_creds["credential"]["access"],
                                      ec2_creds["credential"]["secret"],
                                      user_name=user_name,
                                      project_name=project_name,
                                      roles=roles,
                                      auth_token=token_id,
                                      remote_address=remote_address,
                                      service_catalog=catalog,
                                      api_version=req.params.get('Version'))

        req.environ['ec2api.context'] = ctxt

        return self.application

    def _get_creds(self, req, request_id):
        signature = req.params.get('Signature')
        if not signature:
            msg = _("Signature not provided")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)
        access = req.params.get('AWSAccessKeyId')
        if not access:
            msg = _("Access key not provided")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)

        # Make a copy of args for authentication and signature verification.
        auth_params = dict(req.params)
        # Not part of authentication args
        auth_params.pop('Signature')

        cred_dict = {
            'access': access,
            'signature': signature,
            'host': req.host,
            'verb': req.method,
            'path': req.path,
            'params': auth_params,
        }
        return cred_dict

    def _get_creds_v4(self, req, request_id):
        auth = req.environ['HTTP_AUTHORIZATION'].split(',')
        auth = [a.strip() for a in auth]
        if not auth[0].startswith('AWS4-HMAC-SHA256'):
            msg = _("Invalid authorization parameters")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)
        access = auth[0].split('=')[1].split('/')[0]
        if not access:
            msg = _("Access key not provided")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)

        for item in auth:
            if item.startswith('Signature'):
                signature = item.split('=')[1]
        if not signature:
            msg = _("Signature could not be found in request")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)

        headers = dict()
        for key in req.headers:
            headers[key] = req.headers.get(key)

        if 'X-Amz-Content-SHA256' in req.headers:
            body_hash = req.headers['X-Amz-Content-SHA256']
        else:
            body_hash = self._payload(req)

        cred_dict = {
            'access': access,
            'signature': signature,
            'host': req.host,
            'verb': req.method,
            'path': req.path,
            # most clients do not use req.params(that stores body for now)
            'params': dict(),
            'headers': headers,
            'body_hash': body_hash
        }
        return cred_dict

    def _payload(self, request):
        if request.body and hasattr(request.body, 'seek'):
            position = request.body.tell()
            read_chunksize = functools.partial(request.body.read,
                                               PAYLOAD_BUFFER)
            checksum = hashlib.sha256()
            for chunk in iter(read_chunksize, b''):
                checksum.update(chunk)
            hex_checksum = checksum.hexdigest()
            request.body.seek(position)
            return hex_checksum
        elif request.body:
            return hashlib.sha256(request.body.encode('utf-8')).hexdigest()
        else:
            return EMPTY_SHA256_HASH


class Requestify(wsgi.Middleware):

    def __init__(self, app):
        super(Requestify, self).__init__(app)

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        non_args = ['Action', 'Signature', 'AWSAccessKeyId', 'SignatureMethod',
                    'SignatureVersion', 'Version', 'Timestamp']
        args = dict(req.params)
        try:
            expired = ec2utils.is_ec2_timestamp_expired(
                req.params,
                expires=CONF.ec2_timestamp_expiry)
            if expired:
                msg = _("Timestamp failed validation.")
                LOG.exception(msg)
                raise webob.exc.HTTPForbidden(explanation=msg)

            # Raise KeyError if omitted
            action = req.params['Action']
            # Fix bug lp:720157 for older (version 1) clients
            version = req.params.get('SignatureVersion')
            if version and int(version) == 1:
                non_args.remove('SignatureMethod')
                if 'SignatureMethod' in args:
                    args.pop('SignatureMethod')
            for non_arg in non_args:
                args.pop(non_arg, None)
        except KeyError:
            raise webob.exc.HTTPBadRequest()
        except exception.InvalidRequest as err:
            raise webob.exc.HTTPBadRequest(explanation=unicode(err))

        LOG.debug('action: %s', action)
        for key, value in args.items():
            LOG.debug('arg: %(key)s\t\tval: %(value)s',
                      {'key': key, 'value': value})

        # Success!
        api_request = apirequest.APIRequest(
            action, req.params['Version'], args)
        req.environ['ec2.request'] = api_request
        return self.application


def exception_to_ec2code(ex):
    """Helper to extract EC2 error code from exception.

    For other than EC2 exceptions (those without ec2_code attribute),
    use exception name.
    """
    if hasattr(ex, 'ec2_code'):
        code = ex.ec2_code
    else:
        code = type(ex).__name__
    return code


def ec2_error_ex(ex, req, code=None, message=None, unexpected=False):
    """Return an EC2 error response.

    Return an EC2 error response based on passed exception and log
    the exception on an appropriate log level:

        * DEBUG: expected errors
        * ERROR: unexpected errors

    All expected errors are treated as client errors and 4xx HTTP
    status codes are always returned for them.

    Unexpected 5xx errors may contain sensitive information,
    suppress their messages for security.
    """
    if not code:
        code = exception_to_ec2code(ex)
    status = getattr(ex, 'code', None)
    if not status:
        status = 500

    if unexpected:
        log_fun = LOG.error
        log_msg = _("Unexpected %(ex_name)s raised: %(ex_str)s")
        exc_info = sys.exc_info()
    else:
        log_fun = LOG.debug
        log_msg = _("%(ex_name)s raised: %(ex_str)s")
        # NOTE(jruzicka): For compatibility with EC2 API, treat expected
        # exceptions as client (4xx) errors. The exception error code is 500
        # by default and most exceptions inherit this from EC2Exception even
        # though they are actually client errors in most cases.
        if status >= 500:
            status = 400
        exc_info = None

    context = req.environ['ec2api.context']
    request_id = context.request_id
    log_msg_args = {
        'ex_name': type(ex).__name__,
        'ex_str': unicode(ex)
    }
    log_fun(log_msg % log_msg_args, context=context, exc_info=exc_info)

    if ex.args and not message and (not unexpected or status < 500):
        message = unicode(ex.args[0])
    if unexpected:
        # Log filtered environment for unexpected errors.
        env = req.environ.copy()
        for k in env.keys():
            if not isinstance(env[k], six.string_types):
                env.pop(k)
        log_fun(_('Environment: %s') % jsonutils.dumps(env))
    if not message:
        message = _('Unknown error occurred.')
    return faults.ec2_error_response(request_id, code, message, status=status)


class Executor(wsgi.Application):

    """Execute an EC2 API request.

    Executes 'ec2.action', passing 'ec2api.context' and
    'ec2.action_args' (all variables in WSGI environ.)  Returns an XML
    response, or a 400 upon failure.
    """

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        context = req.environ['ec2api.context']
        api_request = req.environ['ec2.request']
        try:
            result = api_request.invoke(context)
        except Exception as ex:
            return ec2_error_ex(
                ex, req, unexpected=not isinstance(ex, exception.EC2Exception))
        else:
            resp = webob.Response()
            resp.status = 200
            resp.headers['Content-Type'] = 'text/xml'
            resp.body = str(result)

            return resp
