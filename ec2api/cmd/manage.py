#    Copyright 2013 Cloudscaling Group, Inc
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
  CLI interface for EC2 API management.
"""

import sys

from oslo_config import cfg
from oslo_log import log

from ec2api import config
from ec2api.db import migration


CONF = cfg.CONF


def do_db_version():
    """Print database's current migration level."""
    print(migration.db_version())


def do_db_sync():
    """Place a database under migration control and upgrade,

    creating if necessary.
    """
    migration.db_sync(CONF.command.version)


def add_command_parsers(subparsers):
    """
    Add command line arguments for the given subcommand.

    Args:
        subparsers: (todo): write your description
    """
    parser = subparsers.add_parser('db_version')
    parser.set_defaults(func=do_db_version)

    parser = subparsers.add_parser('db_sync')
    parser.set_defaults(func=do_db_sync)
    parser.add_argument('version', nargs='?')
    parser.add_argument('current_version', nargs='?')


command_opt = cfg.SubCommandOpt('command',
                                title='Commands',
                                help='Available commands',
                                handler=add_command_parsers)


def main():
    """
    Main entry point.

    Args:
    """
    CONF.register_cli_opt(command_opt)
    config.parse_args(sys.argv)
    log.setup(CONF, "ec2api")

    try:
        CONF.command.func()
    except Exception as e:
        sys.exit("ERROR: %s" % e)
