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
APIRequest class
"""

import datetime
# TODO(termie): replace minidom with etree
from xml.dom import minidom

from lxml import etree
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils
import six

from ec2api.api import cloud
from ec2api.api import ec2utils
from ec2api import exception
from ec2api.i18n import _

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _underscore_to_camelcase(st):
    return ''.join([x[:1].upper() + x[1:] for x in st.split('_')])


def _underscore_to_xmlcase(st):
    res = _underscore_to_camelcase(st)
    return res[:1].lower() + res[1:]


def _database_to_isoformat(datetimeobj):
    """Return a xs:dateTime parsable string from datatime."""
    return datetimeobj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'


class APIRequest(object):

    def __init__(self, action, version, args):
        self.action = action
        self.version = version
        self.args = args
        if CONF.full_vpc_support:
            self.controller = cloud.VpcCloudController()
        else:
            self.controller = cloud.CloudController()

    def invoke(self, context):
        try:
            method = getattr(self.controller,
                             ec2utils.camelcase_to_underscore(self.action))
        except AttributeError:
            LOG.exception(_('Unsupported API request: action = %(action)s'),
                          {'action': self.action})
            raise exception.InvalidRequest()

        args = ec2utils.dict_from_dotted_str(self.args.items())

        def convert_dicts_to_lists(args):
            if not isinstance(args, dict):
                return args
            for key in args.keys():
                # NOTE(vish): Turn numeric dict keys into lists
                # NOTE(Alex): Turn "value"-only dict keys into values
                if isinstance(args[key], dict):
                    if args[key] == {}:
                        continue
                    if args[key].keys()[0].isdigit():
                        s = args[key].items()
                        s.sort()
                        args[key] = [convert_dicts_to_lists(v) for k, v in s]
                    elif (args[key].keys()[0] == 'value' and
                            len(args[key]) == 1):
                        args[key] = args[key]['value']
            return args

        args = convert_dicts_to_lists(args)
        result = method(context, **args)
        return self._render_response(result, context.request_id)

    def _render_response(self, response_data, request_id):
        xml = minidom.Document()

        response_el = xml.createElement(self.action + 'Response')
        response_el.setAttribute('xmlns',
                                 'http://ec2.amazonaws.com/doc/%s/'
                                 % self.version)
        request_id_el = xml.createElement('requestId')
        request_id_el.appendChild(xml.createTextNode(request_id))
        response_el.appendChild(request_id_el)
        if response_data is True:
            self._render_dict(xml, response_el, {'return': 'true'})
        else:
            self._render_dict(xml, response_el, response_data)

        xml.appendChild(response_el)

        response = xml.toxml()
        root = etree.fromstring(response)
        response = etree.tostring(root, pretty_print=True)

        xml.unlink()

        # Don't write private key to log
        if self.action != "CreateKeyPair":
            LOG.debug(response)
        else:
            LOG.debug("CreateKeyPair: Return Private Key")

        return response

    def _render_dict(self, xml, el, data):
        try:
            for key in data.keys():
                val = data[key]
                el.appendChild(self._render_data(xml, key, val))
        except Exception:
            LOG.debug(data)
            raise

    def _render_data(self, xml, el_name, data):
        el_name = _underscore_to_xmlcase(el_name)
        data_el = xml.createElement(el_name)

        if isinstance(data, list):
            for item in data:
                data_el.appendChild(self._render_data(xml, 'item', item))
        elif isinstance(data, dict):
            self._render_dict(xml, data_el, data)
        elif hasattr(data, '__dict__'):
            self._render_dict(xml, data_el, data.__dict__)
        elif isinstance(data, bool):
            data_el.appendChild(xml.createTextNode(str(data).lower()))
        elif isinstance(data, datetime.datetime):
            data_el.appendChild(
                xml.createTextNode(_database_to_isoformat(data)))
        elif data is not None:
            data_el.appendChild(xml.createTextNode(
                encodeutils.safe_encode(six.text_type(data))))

        return data_el
