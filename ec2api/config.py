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

from oslo_config import cfg
from oslo_db import options
from oslo_log import log

from ec2api import paths
from ec2api import version


CONF = cfg.CONF

_DEFAULT_SQL_CONNECTION = 'sqlite:///' + paths.state_path_def('ec2api.sqlite')

_DEFAULT_LOG_LEVELS = ['amqp=WARN', 'amqplib=WARN', 'boto=WARN',
                       'sqlalchemy=WARN', 'suds=INFO',
                       'iso8601=WARN',
                       'requests.packages.urllib3.connectionpool=WARN',
                       'urllib3.connectionpool=WARN', 'websocket=WARN',
                       'keystonemiddleware=WARN', 'routes.middleware=WARN',
                       'stevedore=WARN', 'keystoneclient.auth=WARN']


def parse_args(argv, default_config_files=None):
    log.set_defaults(default_log_levels=_DEFAULT_LOG_LEVELS)
    log.register_options(CONF)
    options.set_defaults(CONF, connection=_DEFAULT_SQL_CONNECTION)

    cfg.CONF(argv[1:],
             project='ec2api',
             version=version.version_info.version_string(),
             default_config_files=default_config_files)
