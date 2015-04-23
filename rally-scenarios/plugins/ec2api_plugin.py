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

import functools

from rally.benchmark.scenarios import base
from rally.common import log as logging

from ec2api.tests.functional import botocoreclient

LOG = logging.getLogger(__name__)


class AtomicActionWithoutFirst(base.AtomicAction):

    def __init__(self, scenario_instance, name):
        super(AtomicActionWithoutFirst, self).__init__(scenario_instance, name)
        self.scenario_instance = scenario_instance
        self.name = name

    def __exit__(self, type, value, tb):
        args = self.scenario_instance.context['user']['ec2args']
        if self.name in args:
            super(AtomicActionWithoutFirst, self).__exit__(type, value, tb)
        else:
            args[self.name] = True


class EC2APIPlugin(base.Scenario):

    def _get_client(self, is_nova):
        args = self.context['user']['ec2args']
        url = args['nova_url'] if is_nova else args['url']
        client = botocoreclient._get_ec2_client(
            url, args['region'], args['access'], args['secret'])
        return client

    def _run_both(self, base_name, func):
        client = self._get_client(True)
        with AtomicActionWithoutFirst(self, base_name + '_nova'):
            func(self, client)
        client = self._get_client(False)
        with AtomicActionWithoutFirst(self, base_name + '_ec2api'):
            func(self, client)

    def _run_ec2(self, base_name, func):
        client = self._get_client(False)
        with AtomicActionWithoutFirst(self, base_name + '_ec2api'):
            func(self, client)

    def _runner(run_func):
        def wrap(func):
            @functools.wraps(func)
            def runner(self, *args, **kwargs):
                run_func(self, func.__name__, func)
            return runner
        return wrap

    @base.scenario()
    @_runner(_run_both)
    def describe_instances(self, client):
        data = client.describe_instances()

    @base.scenario()
    @_runner(_run_both)
    def describe_addresses(self, client):
        data = client.describe_addresses()

    @base.scenario()
    @_runner(_run_both)
    def describe_security_groups(self, client):
        data = client.describe_security_groups()

    @base.scenario()
    @_runner(_run_both)
    def describe_regions(self, client):
        data = client.describe_regions()

    @base.scenario()
    @_runner(_run_both)
    def describe_images(self, client):
        data = client.describe_images()

    @base.scenario()
    @_runner(_run_ec2)
    def describe_vpcs(self, client):
        data = client.describe_vpcs()

    @base.scenario()
    @_runner(_run_ec2)
    def describe_subnets(self, client):
        data = client.describe_subnets()

    @base.scenario()
    @_runner(_run_ec2)
    def describe_network_interfaces(self, client):
        data = client.describe_network_interfaces()

    @base.scenario()
    @_runner(_run_ec2)
    def describe_route_tables(self, client):
        data = client.describe_route_tables()

    _instance_id_by_client = dict()

    @base.scenario()
    @_runner(_run_both)
    def describe_one_instance(self, client):
        client_id = client._endpoint
        instance_id = self._instance_id_by_client.get(client_id)
        if not instance_id:
            data = client.describe_instances()
            instances = data['Reservations'][0]['Instances']
            index = len(instances) / 3
            instance_id = instances[index]['InstanceId']
            self._instance_id_by_client[client_id] = instance_id
            LOG.info("found instance = %s for client %s"
                     % (instance_id, client_id))

        data = client.describe_instances(InstanceIds=[instance_id])

    @base.scenario()
    def describe_all_in_one(self):
        self.describe_addresses()
        self.describe_instances()
        self.describe_security_groups()
        self.describe_one_instance()
        self.describe_vpcs()
        self.describe_subnets()
        self.describe_network_interfaces()
        self.describe_route_tables()

    @base.scenario()
    def describe_networks(self):
        self.describe_vpcs()
        self.describe_subnets()
        self.describe_network_interfaces()
        self.describe_route_tables()
