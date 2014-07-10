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

"""
Starting point for routing EC2 requests.
"""

from eventlet.green import httplib
import netaddr
from oslo.config import cfg
import six
import six.moves.urllib.parse as urlparse
import webob
import webob.dec
import webob.exc

from ec2api.api import apirequest
from ec2api.api import ec2utils
from ec2api.api import faults
from ec2api.api import validator
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
        token_url = CONF.keystone_url + "/ec2tokens"
        if "ec2" in token_url:
            creds = {'ec2Credentials': cred_dict}
        else:
            creds = {'auth': {'OS-KSEC2:ec2Credentials': cred_dict}}
        creds_json = jsonutils.dumps(creds)
        headers = {'Content-Type': 'application/json'}

        o = urlparse.urlparse(token_url)
        if o.scheme == "http":
            conn = httplib.HTTPConnection(o.netloc)
        else:
            conn = httplib.HTTPSConnection(o.netloc)
        conn.request('POST', o.path, body=creds_json, headers=headers)
        response = conn.getresponse()
        data = response.read()
        if response.status != 200:
            if response.status == 401:
                msg = response.reason
            else:
                msg = _("Failure communicating with keystone")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=response.status)
        result = jsonutils.loads(data)
        conn.close()

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
        o = urlparse.urlparse(CONF.keystone_url
            + ("/users/%s/credentials/OS-EC2/%s" % (user_id, access)))
        if o.scheme == "http":
            conn = httplib.HTTPConnection(o.netloc)
        else:
            conn = httplib.HTTPSConnection(o.netloc)
        conn.request('GET', o.path, headers=headers)
        response = conn.getresponse()
        data = response.read()
        if response.status != 200:
            if response.status == 401:
                msg = response.reason
            else:
                msg = _("Failure communicating with keystone")
            return faults.ec2_error_response(request_id, "AuthFailure", msg,
                                             status=response.status)
        ec2_creds = jsonutils.loads(data)
        conn.close()

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


class Requestify(wsgi.Middleware):

    def __init__(self, app):
        super(Requestify, self).__init__(app)

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        non_args = ['Action', 'Signature', 'AWSAccessKeyId', 'SignatureMethod',
                    'SignatureVersion', 'Version', 'Timestamp']
        args = dict(req.params)
        try:
            expired = ec2utils.is_ec2_timestamp_expired(req.params,
                            expires=CONF.ec2_timestamp_expiry)
            if expired:
                msg = _("Timestamp failed validation.")
                LOG.exception(msg)
                raise webob.exc.HTTPForbidden(explanation=msg)

            # Raise KeyError if omitted
            action = req.params['Action']
            # Fix bug lp:720157 for older (version 1) clients
            version = req.params['SignatureVersion']
            if int(version) == 1:
                non_args.remove('SignatureMethod')
                if 'SignatureMethod' in args:
                    args.pop('SignatureMethod')
            for non_arg in non_args:
                # Remove, but raise KeyError if omitted
                args.pop(non_arg)
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


def validate_ec2_id(val):
    if not validator.validate_str()(val):
        return False
    try:
        ec2utils.ec2_id_to_id(val)
    except exception.InvalidEc2Id:
        return False
    return True


def is_valid_ipv4(address):
    """Verify that address represents a valid IPv4 address."""
    try:
        return netaddr.valid_ipv4(address)
    except Exception:
        return False


class Validator(wsgi.Middleware):

    validator.validate_ec2_id = validate_ec2_id

    validator.DEFAULT_VALIDATOR = {
        'instance_id': validate_ec2_id,
        'volume_id': validate_ec2_id,
        'image_id': validate_ec2_id,
        'attribute': validator.validate_str(),
        'image_location': validator.validate_image_path,
        'public_ip': is_valid_ipv4,
        'region_name': validator.validate_str(),
        'group_name': validator.validate_str(max_length=255),
        'group_description': validator.validate_str(max_length=255),
        'size': validator.validate_int(),
        'user_data': validator.validate_user_data
    }

    def __init__(self, application):
        super(Validator, self).__init__(application)

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        if validator.validate(req.environ['ec2.request'].args,
                              validator.DEFAULT_VALIDATOR):
            return self.application
        else:
            raise webob.exc.HTTPBadRequest()


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


def ec2_error_ex(ex, req, code=None, message=None):
    """Return an EC2 error response based on passed exception and log it."""
    if not code:
        code = exception_to_ec2code(ex)
    status = getattr(ex, 'code', None)
    if not status:
        status = 500

    log_fun = LOG.error
    log_msg = _("Unexpected %(ex_name)s raised: %(ex_str)s")

    context = req.environ['ec2api.context']
    request_id = context.request_id
    log_msg_args = {
        'ex_name': type(ex).__name__,
        'ex_str': unicode(ex)
    }
    log_fun(log_msg % log_msg_args, context=context)

    if ex.args and not message and status < 500:
        message = unicode(ex.args[0])
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
        except exception.InstanceNotFound as ex:
            ec2_id = ec2utils.id_to_ec2_inst_id(ex.kwargs['instance_id'])
            message = ex.msg_fmt % {'instance_id': ec2_id}
            return ec2_error_ex(ex, req, message=message)
        except exception.MethodNotFound:
            try:
                http, response = api_request.proxy(req)
                resp = webob.Response()
                resp.status = http["status"]
                resp.headers["content-type"] = http["content-type"]
                resp.body = str(response)
                return resp
            except Exception as ex:
                return ec2_error_ex(ex, req)
        except exception.EC2ServerError as ex:
            resp = webob.Response()
            resp.status = ex.response['status']
            resp.headers['Content-Type'] = ex.response['content-type']
            resp.body = ex.content
            return resp
        except Exception as ex:
            return ec2_error_ex(ex, req)
        else:
            resp = webob.Response()
            resp.status = 200
            resp.headers['Content-Type'] = 'text/xml'
            resp.body = str(result)

            return resp
