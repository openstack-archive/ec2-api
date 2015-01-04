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

import itertools

from novaclient import exceptions as nova_exception

from ec2api.api import clients


def get_instance_and_project_id(context, fixed_ip):
    nova = clients.nova(context)
    try:
        os_address = nova.fixed_ips.get(fixed_ip)
    except nova_exception.NotFound:
        return None, None
    if not os_address.hostname:
        return None, None

    os_instances = nova.servers.list(
            search_opts={'hostname': os_address.hostname,
                         'all_tenants': True})
    for os_instance in os_instances:
        if any(addr['addr'] == fixed_ip and addr['OS-EXT-IPS:type'] == 'fixed'
               for addr in itertools.chain(
                        *os_instance.addresses.itervalues())):
            return os_instance.id, os_instance.tenant_id

    return None, None
