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

from rally.common import logging
from rally import osclients
from rally.plugins.openstack import scenario
from rally.task import atomic

from ec2api.tests.functional import botocoreclient

LOG = logging.getLogger(__name__)

_resources = dict()


class EC2APIPlugin(scenario.OpenStackScenario):

    def __init__(self, *args, **kwargs):
        super(EC2APIPlugin, self).__init__(*args, **kwargs)

        if 'instance_id' in _resources:
            self.instance_id = _resources['instance_id']
        else:
            client = self.get_ec2_client()
            data = client.describe_instances()
            instances = (data['Reservations'][0]['Instances']
                if data.get('Reservations') else None)
            if instances:
                index = len(instances) / 3
                self.instance_id = instances[index]['InstanceId']
                LOG.info("found instance = %s for ec2" % (self.instance_id))
                _resources['instance_id'] = self.instance_id
            else:
                _resources['instance_id'] = None

        if 'nova_server_id' in _resources:
            self.nova_server_id = _resources['nova_server_id']
        else:
            client = osclients.Clients(
                self.context['user']['credential']).nova()
            project_id = self.context["tenant"]["id"]
            servers = client.servers.list(
                search_opts={'project_id': project_id})
            if servers:
                index = len(servers) / 3
                self.nova_server_id = servers[index].id
                LOG.info("found server = %s for nova" % (self.nova_server_id))
                _resources['nova_server_id'] = self.nova_server_id
            else:
                _resources['nova_server_id'] = None

    def get_ec2_client(self):
        args = self.context['user']['ec2args']
        client = botocoreclient.get_ec2_client(
            args['url'], args['region'], args['access'], args['secret'])
        return client

    @scenario.configure()
    def describe_images(self):
        self.describe_images_ec2api()
        self.describe_images_nova()

    def describe_images_ec2api(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_images_ec2api'):
            data = client.describe_images()

    def describe_images_nova(self):
        client = osclients.Clients(
            self.context['user']['credential']).nova().images
        with atomic.ActionTimer(self, 'describe_images_nova'):
            client.list()

    @scenario.configure()
    def describe_regions(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_regions_ec2api'):
            data = client.describe_regions()

    @scenario.configure()
    def describe_all_in_one(self):
        self.describe_addresses_ec2api()
        self.describe_floatingips_neutron()
        self.describe_instances_ec2api()
        self.describe_one_instance_ec2api()
        self.describe_instances_nova()
        self.describe_one_instance_nova()
        self.describe_vpcs_ec2api()
        self.describe_subnets_ec2api()
        self.describe_network_interfaces_ec2api()
        self.describe_route_tables_ec2api()
        self.describe_security_groups_ec2api()
        self.describe_networks_neutron()
        self.describe_subnets_neutron()
        self.describe_ports_neutron()
        self.describe_security_groups_neutron()

    @scenario.configure()
    def describe_networks(self):
        self.describe_vpcs_ec2api()
        self.describe_subnets_ec2api()
        self.describe_network_interfaces_ec2api()
        self.describe_route_tables_ec2api()
        self.describe_security_groups_ec2api()
        self.describe_networks_neutron()
        self.describe_subnets_neutron()
        self.describe_ports_neutron()
        self.describe_security_groups_neutron()

    def describe_addresses_ec2api(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_addresses_ec2api'):
            data = client.describe_addresses()

    def describe_instances_ec2api(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_instances_ec2api'):
            data = client.describe_instances()

    def describe_one_instance_ec2api(self):
        if not self.instance_id:
            return
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_one_instance_ec2api'):
            data = client.describe_instances(InstanceIds=[self.instance_id])

    def describe_instances_nova(self):
        nova = osclients.Clients(
            self.context['user']['credential']).nova()
        project_id = self.context["tenant"]["id"]
        with atomic.ActionTimer(self, 'describe_instances_nova'):
            nova.servers.list(search_opts={'project_id': project_id})

    def describe_one_instance_nova(self):
        if not self.nova_server_id:
            return
        nova = osclients.Clients(
            self.context['user']['credential']).nova()
        with atomic.ActionTimer(self, 'describe_one_instance_nova'):
            nova.servers.get(self.nova_server_id)

    def describe_vpcs_ec2api(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_vpcs_ec2api'):
            data = client.describe_vpcs()

    def describe_subnets_ec2api(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_subnets_ec2api'):
            data = client.describe_subnets()

    def describe_network_interfaces_ec2api(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_network_interfaces_ec2api'):
            data = client.describe_network_interfaces()

    def describe_route_tables_ec2api(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_route_tables_ec2api'):
            data = client.describe_route_tables()

    def describe_security_groups_ec2api(self):
        client = self.get_ec2_client()
        with atomic.ActionTimer(self, 'describe_security_groups_ec2api'):
            data = client.describe_security_groups()

    def describe_floatingips_neutron(self):
        neutron = osclients.Clients(
            self.context['user']['credential']).neutron()
        project_id = self.context["tenant"]["id"]
        with atomic.ActionTimer(self, 'describe_addesses_neutron'):
            neutron.list_floatingips(tenant_id=project_id)

    def describe_networks_neutron(self):
        neutron = osclients.Clients(
            self.context['user']['credential']).neutron()
        project_id = self.context["tenant"]["id"]
        with atomic.ActionTimer(self, 'describe_networks_neutron'):
            neutron.list_networks(tenant_id=project_id)

    def describe_subnets_neutron(self):
        neutron = osclients.Clients(
            self.context['user']['credential']).neutron()
        project_id = self.context["tenant"]["id"]
        with atomic.ActionTimer(self, 'describe_subnets_neutron'):
            neutron.list_subnets(tenant_id=project_id)

    def describe_ports_neutron(self):
        neutron = osclients.Clients(
            self.context['user']['credential']).neutron()
        project_id = self.context["tenant"]["id"]
        with atomic.ActionTimer(self, 'describe_ports_neutron'):
            neutron.list_ports(tenant_id=project_id)

    def describe_security_groups_neutron(self):
        neutron = osclients.Clients(
            self.context['user']['credential']).neutron()
        project_id = self.context["tenant"]["id"]
        with atomic.ActionTimer(self, 'describe_security_groups_neutron'):
            neutron.list_security_groups(tenant_id=project_id)
