# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import itertools
import operator

from keystoneauth1 import loading as ks_loading
from oslo_config import cfg

import ec2api.clients
import ec2api.db.api
import ec2api.exception
import ec2api.paths
import ec2api.service
import ec2api.utils
import ec2api.wsgi


CONF = cfg.CONF


def list_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             ec2api.clients.ec2_opts,
             ec2api.db.api.tpool_opts,
             ec2api.exception.exc_log_opts,
             ec2api.paths.path_opts,
             ec2api.service.service_opts,
             ec2api.utils.utils_opts,
             ec2api.wsgi.wsgi_opts,
         )),
    ]


GROUP_AUTHTOKEN = 'keystone_authtoken'


def list_auth_opts():
    opt_list = ks_loading.register_session_conf_options(CONF, GROUP_AUTHTOKEN)
    opt_list.insert(0, ks_loading.get_auth_common_conf_options()[0])
    # NOTE(mhickey): There are a lot of auth plugins, we just generate
    # the config options for a few common ones
    plugins = ['password', 'v2password', 'v3password']
    for name in plugins:
        for plugin_option in ks_loading.get_auth_plugin_conf_options(name):
            if all(option.name != plugin_option.name for option in opt_list):
                opt_list.append(plugin_option)
    opt_list.sort(key=operator.attrgetter('name'))
    return [(GROUP_AUTHTOKEN, opt_list)]
