# Copyright 2014 OpenStack Foundation
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

import types

from botocore import session
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class BotocoreClientBase(object):

    def __init__(self, region, access, secret):
        self.region = region
        self.connection_data = {
            'config_file': (None, 'AWS_CONFIG_FILE', None),
            'region': ('region', 'BOTO_DEFAULT_REGION', self.region),
        }

        if not access or not secret:
            raise Exception('Auth params did not provided')

        self.session = session.get_session(self.connection_data)
        self.session.set_credentials(access, secret)

    def __getattr__(self, name):
        """Automatically creates methods for the allowed methods set."""
        op = self.service.get_operation(name)
        if not op:
            raise AttributeError(name)

        def func(self, *args, **kwargs):
            return op.call(self.endpoint, *args, **kwargs)

        func.__name__ = name
        setattr(self, name, types.MethodType(func, self, self.__class__))
        return getattr(self, name)


class APIClientEC2(BotocoreClientBase):

    url = None

    def __init__(self, url, region, access, secret, *args, **kwargs):
        super(APIClientEC2, self).__init__(region, access, secret,
                                           *args, **kwargs)
        self.url = url
        self.service = self.session.get_service('ec2')
        self.endpoint = self.service.get_endpoint(
            region_name=self.region,
            endpoint_url=url)

    def get_url(self):
        return self.url
