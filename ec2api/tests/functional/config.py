# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
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

import logging as std_logging
import os

from oslo_config import cfg
from oslo_log import log as logging

from ec2api.tests.functional import config_opts


LOG = logging.getLogger('ec2api')


# this should never be called outside of this class
class ConfigPrivate(object):
    """Provides OpenStack configuration information."""

    DEFAULT_CONFIG_FILE = "functional_tests.conf"

    def __init__(self):
        """Initialize a configuration from a conf directory and conf file."""
        super(ConfigPrivate, self).__init__()

        # if this was run from tempest runner then config already parsed
        if config_opts.aws_group.name in cfg.CONF:
            self.aws = cfg.CONF.aws
            self.service_available = cfg.CONF.service_available
            return

        # Environment variables override defaults...
        conf_file = os.environ.get('TEST_CONFIG', self.DEFAULT_CONFIG_FILE)
        conf_dirs = list()
        if os.environ.get('TEST_CONFIG_DIR'):
            conf_dirs.append(os.environ.get('TEST_CONFIG_DIR'))
        conf_dirs.append('.')
        conf_dirs.append(os.path.dirname(os.path.dirname(
                            os.path.dirname(os.path.dirname(__file__)))))
        for _dir in conf_dirs:
            path = os.path.join(_dir, conf_file)
            if os.path.isfile(path):
                break
        else:
            raise Exception('Config could not be found')

        LOG.info("Using ec2api config file %s" % path)
        conf = cfg.CONF
        conf([], project='ec2api', default_config_files=[path])

        conf.register_group(config_opts.aws_group)
        group_name = config_opts.aws_group.name
        for opt in config_opts.AWSGroup:
            conf.register_opt(opt, group=group_name)
        self.aws = cfg.CONF.aws

        conf.register_group(config_opts.service_available_group)
        group_name = config_opts.service_available_group.name
        for opt in config_opts.ServiceAvailableGroup:
            conf.register_opt(opt, group=group_name)
        self.service_available = cfg.CONF.service_available

        conf.log_opt_values(LOG, std_logging.DEBUG)


class ConfigProxy(object):
    _config = None

    def __getattr__(self, attr):
        if not self._config:
            self._config = ConfigPrivate()

        return getattr(self._config, attr)


CONF = ConfigProxy()
