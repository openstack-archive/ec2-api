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

from __future__ import print_function

import logging as std_logging
import os

from oslo_config import cfg
from oslo_log import log as logging


def register_opt_group(conf, opt_group, options):
    conf.register_group(opt_group)
    for opt in options:
        conf.register_opt(opt, group=opt_group.name)


aws_group = cfg.OptGroup(name='aws',
                         title='AWS options')
AWSGroup = [
    cfg.StrOpt('ec2_url',
               default="http://localhost:8788/",
               help="EC2 URL"),
    cfg.StrOpt('aws_secret',
               default=None,
               help="AWS Secret Key",
               secret=True),
    cfg.StrOpt('aws_access',
               default=None,
               help="AWS Access Key"),
    cfg.StrOpt('aws_region',
               default="RegionOne",
               help="AWS region for EC2 tests"),
    cfg.StrOpt('aws_zone',
               default='nova',
               help="AWS zone inside region for EC2 tests"),
    cfg.IntOpt('build_timeout',
               default=120,
               help="Status Change Timeout"),
    cfg.IntOpt('build_interval',
               default=1,
               help="Status Change Test Interval"),
    cfg.StrOpt('instance_type',
               default="m1.tiny",
               help="Instance type"),
    cfg.StrOpt('image_id',
               default=None,
               help="Image ID for instance running"),
    cfg.StrOpt('ebs_image_id',
               default=None,
               help="EBS Image ID for testing snapshots, volumes, instances"),
    cfg.StrOpt('image_user',
               default='cirros',
               help="User for sshing into instance based on configured image"),
    cfg.BoolOpt('run_incompatible_tests',
                default=False,
                help='Will run all tests plus incompatible with Amazon.'),
]


def register_opts():
    register_opt_group(cfg.CONF, aws_group, AWSGroup)


# this should never be called outside of this class
class ConfigPrivate(object):
    """Provides OpenStack configuration information."""

    DEFAULT_CONFIG_DIR = os.path.join(
        os.path.abspath(os.path.dirname(os.path.dirname(__file__))),
        "etc")

    DEFAULT_CONFIG_FILE = "functional_tests.conf"

    def __init__(self, parse_conf=True):
        """Initialize a configuration from a conf directory and conf file."""
        super(ConfigPrivate, self).__init__()
        config_files = []

        # Environment variables override defaults...
        conf_dir = os.environ.get('TEST_CONFIG_DIR', '.')
        conf_file = os.environ.get('TEST_CONFIG', self.DEFAULT_CONFIG_FILE)
        path = os.path.join(conf_dir, conf_file)

        # only parse the config file if we expect one to exist. This is needed
        # to remove an issue with the config file up to date checker.
        if parse_conf:
            config_files.append(path)

        cfg.CONF([], project='ec2api', default_config_files=config_files)
        LOG = logging.getLogger('ec2api')
        LOG.info("Using ec2api config file %s" % path)
        register_opts()
        self.aws = cfg.CONF.aws
        if parse_conf:
            cfg.CONF.log_opt_values(LOG, std_logging.DEBUG)


class ConfigProxy(object):
    _config = None

    def __getattr__(self, attr):
        if not self._config:
            self._config = ConfigPrivate()

        return getattr(self._config, attr)


CONF = ConfigProxy()
