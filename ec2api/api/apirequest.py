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

from lxml import etree
from oslo_config import cfg
from oslo_log import log as logging
import six

from ec2api.api import cloud
from ec2api.api import ec2utils
from ec2api import exception


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _underscore_to_camelcase(st):
    return ''.join([x[:1].upper() + x[1:] for x in st.split('_')])


def _database_to_isoformat(datetimeobj):
    """Return a xs:dateTime parsable string from datatime."""
    return datetimeobj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'


class APIRequest(object):

    def __init__(self, action, version, args):
        self.action = action
        self.version = version
        self.args = args
        self.controller = cloud.VpcCloudController()

    def invoke(self, context):
        try:
            method = getattr(self.controller,
                             ec2utils.camelcase_to_underscore(self.action))
        except AttributeError:
            LOG.exception('Unsupported API request: action = %(action)s',
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
                    first_subkey = next(six.iterkeys(args[key]))
                    if first_subkey.isdigit():
                        s = args[key]
                        args[key] = [convert_dicts_to_lists(s[k])
                                     for k in sorted(s)]
                    elif (first_subkey == 'value' and
                            len(args[key]) == 1):
                        args[key] = args[key]['value']
            return args

        args = convert_dicts_to_lists(args)
        result = method(context, **args)
        return self._render_response(result, context.request_id)

    def _render_response(self, response_data, request_id):
        response_el = ec2utils.dict_to_xml(
            {'return': 'true'} if response_data is True else response_data,
            self.action + 'Response')
        response_el.attrib['xmlns'] = ('http://ec2.amazonaws.com/doc/%s/'
                                       % self.version)
        request_id_el = etree.Element('requestId')
        request_id_el.text = request_id
        response_el.insert(0, request_id_el)

        response = etree.tostring(response_el, pretty_print=True)

        # Don't write private key to log
        if self.action != "CreateKeyPair":
            LOG.debug(response)
        else:
            LOG.debug("CreateKeyPair: Return Private Key")

        return response
