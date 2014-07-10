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

import base64
import hashlib
import hmac
import re
import time
import types
import urllib
import urlparse

import httplib2
from lxml import etree
from oslo.config import cfg

from ec2api.api import ec2utils
from ec2api import exception
from ec2api.openstack.common import log as logging


ec2_opts = [
    cfg.StrOpt('base_ec2_host',
               default="localhost",
               help='The IP address of the EC2 API server'),
    cfg.IntOpt('base_ec2_port',
               default=8773,
               help='The port of the EC2 API server'),
    cfg.StrOpt('base_ec2_scheme',
               default='http',
               help='The protocol to use when connecting to the EC2 API '
                    'server (http, https)'),
    cfg.StrOpt('base_ec2_path',
               default='/services/Cloud',
               help='The path prefix used to call the ec2 API server'),
]

CONF = cfg.CONF
CONF.register_opts(ec2_opts)
LOG = logging.getLogger(__name__)

ISO8601 = '%Y-%m-%dT%H:%M:%SZ'


def ec2client(context):
    return EC2Client(context)


class EC2Requester(object):

    def __init__(self, version, http_method):
        self.http_obj = httplib2.Http(
            disable_ssl_certificate_validation=True)
        self.version = version
        self.method = http_method

    def request(self, context, action, args):
        headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'connection': 'close',
        }
        params = args
        params['Action'] = action
        params['Version'] = self.version
        self._add_auth(context, params)
        params = self._get_query_string(params)

        if self.method == 'POST':
            url = self._ec2_url
            body = params
        else:
            url = '?'.join((self._ec2_url, params,))
            body = None

        response, content = self.http_obj.request(url, self.method,
                                                  body=body, headers=headers)
        return response, content

    _ec2_url = '%s://%s:%s%s' % (CONF.base_ec2_scheme,
                                 CONF.base_ec2_host,
                                 CONF.base_ec2_port,
                                 CONF.base_ec2_path)

    @staticmethod
    def _get_query_string(params):
        pairs = []
        for key in sorted(params):
            value = params[key]
            pairs.append(urllib.quote(key.encode('utf-8'), safe='') + '=' +
                         urllib.quote(value.encode('utf-8'), safe='-_~'))
        return '&'.join(pairs)

    def _calc_signature(self, context, params):
        LOG.debug('Calculating signature using v2 auth.')
        split = urlparse.urlsplit(self._ec2_url)
        path = split.path
        if len(path) == 0:
            path = '/'
        string_to_sign = '%s\n%s\n%s\n' % (self.method,
                                           split.netloc,
                                           path)
        secret = context.secret_key
        lhmac = hmac.new(secret.encode('utf-8'), digestmod=hashlib.sha256)
        string_to_sign += self._get_query_string(params)
        LOG.debug('String to sign: %s', string_to_sign)
        lhmac.update(string_to_sign.encode('utf-8'))
        b64 = base64.b64encode(lhmac.digest()).strip().decode('utf-8')
        return b64

    def _add_auth(self, context, params):
        params['AWSAccessKeyId'] = context.access_key
        params['SignatureVersion'] = '2'
        params['SignatureMethod'] = 'HmacSHA256'
        params['Timestamp'] = time.strftime(ISO8601, time.gmtime())
        signature = self._calc_signature(context, params)
        params['Signature'] = signature


class EC2Client(object):

    def __init__(self, context):
        self.context = context
        self.requester = EC2Requester(context.api_version, 'POST')

    def __getattr__(self, name):
        ec2_name = self._underscore_to_camelcase(name)

        def func(self, **kwargs):
            params = self._build_params(**kwargs)
            response, content = self.requester.request(self.context, ec2_name,
                                                       params)
            return self._process_response(response, content)

        func.__name__ = name
        setattr(self, name, types.MethodType(func, self, self.__class__))
        setattr(self.__class__, name,
                types.MethodType(func, None, self.__class__))
        return getattr(self, name)

    @staticmethod
    def _process_response(response, content):
        if response.status > 200:
            raise exception.EC2ServerError(response, content)

        res = EC2Client._parse_xml(content)

        res = next(res.itervalues())
        if 'return' in res:
            return res['return']
        else:
            res.pop('requestId')
            return res

    @staticmethod
    def _build_params(**kwargs):
        def add_list_param(params, items, label):
            for i in range(1, len(items) + 1):
                item = items[i - 1]
                item_label = '%s.%d' % (label, i)
                if isinstance(item, dict):
                    add_dict_param(params, item, item_label)
                else:
                    params[item_label] = str(item)

        def add_dict_param(params, items, label=None):
            for key, value in items.iteritems():
                ec2_key = EC2Client._underscore_to_camelcase(key)
                item_label = '%s.%s' % (label, ec2_key) if label else ec2_key
                if isinstance(value, dict):
                    add_dict_param(params, value, item_label)
                elif isinstance(value, list):
                    add_list_param(params, value, item_label)
                else:
                    params[item_label] = str(value)

        params = {}
        add_dict_param(params, kwargs)
        return params

    _xml_scheme = re.compile('\sxmlns=".*"')

    @staticmethod
    # NOTE(ft): this function is used in unit tests until it be moved to one
    # of utils module
    def _parse_xml(xml_string):
        xml_string = EC2Client._xml_scheme.sub('', xml_string)
        xml = etree.fromstring(xml_string)

        def convert_node(node):
            children = list(node)
            if len(children):
                if children[0].tag == 'item':
                    val = list(convert_node(child)[1] for child in children)
                else:
                    val = dict(convert_node(child) for child in children)
            elif node.tag.endswith('Set'):
                val = []
            else:
                # TODO(ft): do not use private function
                val = (ec2utils._try_convert(node.text)
                       if node.text
                       else node.text)
            return node.tag, val

        return dict([convert_node(xml)])

    @staticmethod
    # NOTE(ft): this function is copied from apirequest to avoid circular
    # module reference. It should be moved to one of utils module
    def _underscore_to_camelcase(st):
        return ''.join([x[:1].upper() + x[1:] for x in st.split('_')])
