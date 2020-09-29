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
import hashlib
import sys

import botocore
from keystoneauth1 import session as keystone_session
from keystoneclient import access as keystone_access
from keystoneclient.auth.identity import access as keystone_identity_access
from oslo_config import cfg
from oslo_context import context as common_context
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import requests
import webob
import webob.dec
import webob.exc

from ec2api.api import apirequest
from ec2api.api import ec2utils
from ec2api.api import faults
from ec2api import clients
from ec2api import context
from ec2api import exception
from ec2api.i18n import _
from ec2api import wsgi


LOG = logging.getLogger(__name__)

ec2_opts = [
    cfg.StrOpt('keystone_ec2_tokens_url',
               default='http://localhost:5000/v3/ec2tokens',
               help='URL to authenticate token from ec2 request.'),
    cfg.IntOpt('ec2_timestamp_expiry',
               default=300,
               help='Time in seconds before ec2 timestamp expires'),
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)
CONF.import_opt('use_forwarded_for', 'ec2api.api.auth')


# Fault Wrapper around all EC2 requests #
class FaultWrapper(wsgi.Middleware):

    """Calls the middleware stack, captures any exceptions into faults."""

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        try:
            return req.get_response(self.application)
        except Exception:
            LOG.exception("FaultWrapper catches error")
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

    def _get_signature(self, req):
        """Extract the signature from the request.

        This can be a get/post variable or for version 4 also in a header
        called 'Authorization'.
        - params['Signature'] == version 0,1,2,3
        - params['X-Amz-Signature'] == version 4
        - header 'Authorization' == version 4
        """
        sig = req.params.get('Signature') or req.params.get('X-Amz-Signature')
        if sig is not None:
            return sig

        if 'Authorization' not in req.headers:
            return None

        auth_str = req.headers['Authorization']
        if not auth_str.startswith('AWS4-HMAC-SHA256'):
            return None

        return auth_str.partition("Signature=")[2].split(',')[0]

    def _get_access(self, req):
        """Extract the access key identifier.

        For version 0/1/2/3 this is passed as the AccessKeyId parameter, for
        version 4 it is either an X-Amz-Credential parameter or a Credential=
        field in the 'Authorization' header string.
        """
        access = req.params.get('AWSAccessKeyId')
        if access is not None:
            return access

        cred_param = req.params.get('X-Amz-Credential')
        if cred_param:
            access = cred_param.split("/")[0]
            if access is not None:
                return access

        if 'Authorization' not in req.headers:
            return None
        auth_str = req.headers['Authorization']
        if not auth_str.startswith('AWS4-HMAC-SHA256'):
            return None
        cred_str = auth_str.partition("Credential=")[2].split(',')[0]
        return cred_str.split("/")[0]

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        request_id = common_context.generate_request_id()

        # NOTE(alevine) We need to calculate the hash here because
        # subsequent access to request modifies the req.body so the hash
        # calculation will yield invalid results.
        body_hash = hashlib.sha256(req.body).hexdigest()

        signature = self._get_signature(req)
        if not signature:
            msg = _("Signature not provided")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)
        access = self._get_access(req)
        if not access:
            msg = _("Access key not provided")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)

        if 'X-Amz-Signature' in req.params or 'Authorization' in req.headers:
            params = {}
        else:
            # Make a copy of args for authentication and signature verification
            params = dict(req.params)
            # Not part of authentication args
            params.pop('Signature', None)

        cred_dict = {
            'access': access,
            'signature': signature,
            'host': req.host,
            'verb': req.method,
            'path': req.path,
            'params': params,
            # python3 takes only keys for json from headers object
            'headers': {k: req.headers[k] for k in req.headers},
            'body_hash': body_hash
        }

        token_url = CONF.keystone_ec2_tokens_url
        if "ec2" in token_url:
            creds = {'ec2Credentials': cred_dict}
        else:
            creds = {'auth': {'OS-KSEC2:ec2Credentials': cred_dict}}
        creds_json = jsonutils.dumps(creds)
        headers = {'Content-Type': 'application/json'}
        params = {'data': creds_json, 'headers': headers}
        clients.update_request_params_with_ssl(params)
        response = requests.request('POST', token_url, **params)
        status_code = response.status_code
        if status_code != 200:
            msg = response.reason
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=status_code)

        try:
            auth_ref = keystone_access.AccessInfo.factory(resp=response,
                                                          body=response.json())
        except (NotImplementedError, KeyError):
            LOG.exception("Keystone failure")
            msg = _("Failure communicating with keystone")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=400)
        auth = keystone_identity_access.AccessInfoPlugin(auth_ref)
        params = {'auth': auth}
        clients.update_request_params_with_ssl(params)
        session = keystone_session.Session(**params)
        remote_address = req.remote_addr
        if CONF.use_forwarded_for:
            remote_address = req.headers.get('X-Forwarded-For',
                                             remote_address)

        ctxt = context.RequestContext(auth_ref.user_id, auth_ref.project_id,
                                      request_id=request_id,
                                      user_name=auth_ref.username,
                                      project_name=auth_ref.project_name,
                                      remote_address=remote_address,
                                      session=session,
                                      api_version=req.params.get('Version'))

        req.environ['ec2api.context'] = ctxt

        return self.application


class Requestify(wsgi.Middleware):

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
            raise webob.exc.HTTPBadRequest(explanation=err.format_message())

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


def ec2_error_ex(ex, req, unexpected=False):
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
    code = exception_to_ec2code(ex)
    for status_name in ('code', 'status', 'status_code', 'http_status'):
        status = getattr(ex, status_name, None)
        if isinstance(status, int):
            break
    else:
        status = 500

    if unexpected:
        log_fun = LOG.error
        log_msg = _("Unexpected %(ex_name)s raised: %(ex_str)s")
        exc_info = sys.exc_info()
    else:
        log_fun = LOG.debug
        log_msg = _("%(ex_name)s raised: %(ex_str)s")
        exc_info = None

    context = req.environ['ec2api.context']
    request_id = context.request_id
    log_msg_args = {
        'ex_name': type(ex).__name__,
        'ex_str': ex
    }
    log_fun(log_msg % log_msg_args, context=context, exc_info=exc_info)

    if unexpected and status >= 500:
        message = _('Unknown error occurred.')
    elif getattr(ex, 'message', None):
        message = str(ex.message)
    elif ex.args and any(arg for arg in ex.args):
        message = " ".join(map(str, ex.args))
    else:
        message = str(ex)
    if unexpected:
        # Log filtered environment for unexpected errors.
        env = req.environ.copy()
        for k in list(env.keys()):
            if not isinstance(env[k], str):
                env.pop(k)
        log_fun(_('Environment: %s') % jsonutils.dumps(env))
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
        except botocore.exceptions.ClientError as ex:
            error = ex.response.get('Error', {})
            code = ex.response.get('Code', error.get('Code'))
            message = ex.response.get('Message', error.get('Message'))
            # the early versions of botocore didn't provide HTTPStatusCode
            # for 400 errors
            status = ex.response.get('ResponseMetadata', {}).get(
                'HTTPStatusCode', 400)
            if status < 400 or status > 499:
                LOG.exception("Exception from remote server")
            return faults.ec2_error_response(
                context.request_id, code, message, status=status)
        except Exception as ex:
            return ec2_error_ex(
                ex, req, unexpected=not isinstance(ex, exception.EC2Exception))
        else:
            resp = webob.Response()
            resp.status = 200
            resp.headers['Content-Type'] = 'text/xml'
            resp.body = bytes(result)

            return resp
