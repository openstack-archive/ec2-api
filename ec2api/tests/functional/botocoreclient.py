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


def _get_ec2_client(url, region, access, secret):
    connection_data = {
        'config_file': (None, 'AWS_CONFIG_FILE', None),
        'region': ('region', 'BOTO_DEFAULT_REGION', region),
    }
    session = botocore.session.get_session(connection_data)
    return session.create_client(
        'ec2', region_name=region, endpoint_url=url,
        aws_access_key_id=access, aws_secret_access_key=secret)
