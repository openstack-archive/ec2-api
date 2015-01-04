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

import mock
from novaclient import exceptions as nova_exception

from ec2api.metadata import api
from ec2api.tests import base
from ec2api.tests import fakes


class MetadataApiTestCase(base.ApiTestCase):
    # TODO(ft): 'execute' feature isn't used here, but some mocks and
    # fake context are. ApiTestCase should be split to some classes to use
    # its feature optimally

    def test_get_instance_and_project_id(self):
        fake_context = self._create_context()

        def check_none_result():
            self.assertEqual((None, None),
                             api.get_instance_and_project_id(
                                    fake_context,
                                    fakes.IP_NETWORK_INTERFACE_2))

        self.nova_fixed_ips.get.return_value = mock.Mock(hostname=None)
        check_none_result()

        self.nova_servers.list.return_value = [fakes.OS_INSTANCE_2]
        check_none_result()

        self.nova_servers.list.return_value = [fakes.OS_INSTANCE_1,
                                               fakes.OS_INSTANCE_2]
        self.nova_fixed_ips.get.return_value = mock.Mock(hostname='fake_name')
        self.assertEqual((fakes.ID_OS_INSTANCE_1, fakes.ID_OS_PROJECT),
                         api.get_instance_and_project_id(
                                fake_context, fakes.IP_NETWORK_INTERFACE_2))
        self.nova_fixed_ips.get.assert_called_with(
                fakes.IP_NETWORK_INTERFACE_2)
        self.nova_servers.list.assert_called_with(
                search_opts={'hostname': 'fake_name',
                             'all_tenants': True})

        self.nova_fixed_ips.get.side_effect = nova_exception.NotFound('fake')
        check_none_result()
