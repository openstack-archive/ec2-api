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

from oslo_config import cfg

service_available_group = cfg.OptGroup(name="service_available",
                                       title="Available OpenStack Services")

ServiceAvailableGroup = [
    cfg.BoolOpt("ec2api",
                default=True,
                help="Whether or not ec2-api is expected to be available"),
]


aws_group = cfg.OptGroup(name='aws',
                         title='AWS options')
AWSGroup = [
    cfg.StrOpt('ec2_url',
               default="http://localhost:8788/",
               help="EC2 URL"),
    cfg.StrOpt('s3_url',
               default="http://localhost:3334/",
               help="S3 URL"),
    cfg.StrOpt('ca_bundle',
               default=None,
               help="The CA certificate bundle to use when verifying "
                    "SSL certificates. Or True/False to pass to botocore."),
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
    cfg.StrOpt('instance_type_alt',
               default=None,
               help="Instance type"),
    cfg.StrOpt('image_id',
               default=None,
               help="Image ID for instance running(can be cirros). "
                    "It must be any instance with instance-store "
                    "root device type."),
    cfg.StrOpt('ebs_image_id',
               default=None,
               help="EBS Image ID for testing snapshots, volumes, instances."),
    cfg.StrOpt('image_user',
               default='cirros',
               help="User for sshing into instance based on configured image"),
    cfg.StrOpt('image_id_ubuntu',
               default=None,
               help="Fully functional image ID for instance running. "
                    "For some tests it must be ubuntu-trusty-i386."),
    cfg.StrOpt('image_user_ubuntu',
               default='ubuntu',
               help="User for sshing into instance based on configured image"),
    cfg.BoolOpt('run_incompatible_tests',
                default=False,
                help='Will run all tests plus incompatible with Amazon.'),
    cfg.BoolOpt('run_long_tests',
                default=False,
                help='Will run all long tests also.'),
    cfg.StrOpt('ami_image_location',
               default=None,
               help="S3 URL with manifest of AMI Machine Image."),
    cfg.BoolOpt('run_ssh',
                default=True,
                help='Can block all tests that wants to ssh into instance.'),
]
