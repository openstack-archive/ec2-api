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

from oslo.config import cfg

from ec2api.openstack.common.db import options
from ec2api import paths
from ec2api import version

_DEFAULT_SQL_CONNECTION = 'sqlite:///' + paths.state_path_def('nova.sqlite')


def parse_args(argv, default_config_files=None):
    options.set_defaults(sql_connection=_DEFAULT_SQL_CONNECTION,
                         sqlite_db='nova.sqlite')
    cfg.CONF(argv[1:],
             project='ec2api',
             version=version.version_info.version_string(),
             default_config_files=default_config_files)
