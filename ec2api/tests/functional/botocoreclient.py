# Copyright 2015 OpenStack Foundation
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

import botocore.session
from oslo_config import types


def _get_client(client_name, url, region, access, secret, ca_bundle):
    connection_data = {
        'config_file': (None, 'AWS_CONFIG_FILE', None, None),
        'region': ('region', 'AWS_DEFAULT_REGION', region, None),
    }
    session = botocore.session.get_session(connection_data)
    kwargs = {
        'region_name': region,
        'endpoint_url': url,
        'aws_access_key_id': access,
        'aws_secret_access_key': secret
    }
    if ca_bundle:
        try:
            kwargs['verify'] = types.Boolean()(ca_bundle)
        except Exception:
            kwargs['verify'] = ca_bundle
    return session.create_client(client_name, **kwargs)


def get_ec2_client(url, region, access, secret, ca_bundle=None):
    return _get_client('ec2', url, region, access, secret, ca_bundle)


def get_s3_client(url, region, access, secret, ca_bundle=None):
    return _get_client('s3', url, region, access, secret, ca_bundle)
