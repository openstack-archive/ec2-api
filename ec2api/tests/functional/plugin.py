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

import os

from tempest import config
from tempest.test_discover import plugins

from ec2api.tests.functional import config_opts as aws_config


class AWSTempestPlugin(plugins.TempestPlugin):
    def load_tests(self):
        base_path = os.path.split(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))))[0]
        test_dir = "ec2api/tests/functional"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        group_name = aws_config.service_available_group.name
        if group_name not in conf:
            config.register_opt_group(
                conf, aws_config.service_available_group,
                aws_config.ServiceAvailableGroup)
        else:
            for opt in aws_config.ServiceAvailableGroup:
                conf.register_opt(opt, group=group_name)

        if aws_config.aws_group.name not in conf:
            config.register_opt_group(conf, aws_config.aws_group,
                                      aws_config.AWSGroup)

    def get_opt_lists(self):
        return [
            (aws_config.service_available_group.name,
             aws_config.ServiceAvailableGroup),
            (aws_config.aws_group.name,
             aws_config.AWSGroup)
        ]
