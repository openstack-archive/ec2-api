# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import time

from rally.common.i18n import _
from rally.common import logging
from rally.common import utils as rutils
from rally import consts
from rally.task import context

from ec2api.tests import botocoreclient


LOG = logging.getLogger(__name__)


class EC2Objects(context.Context):

    CIDR = "10.0.0.0/16"
    AWS_ZONE = "nova"

    def run_instances(self, tenant_id, client, image_id):
        flavor = self.config["flavor"]
        servers_per_tenant = self.config["servers_per_tenant"]
        LOG.info("Calling run_instance with image_id=%s "
                 "flavor=%s servers_per_tenant=%s"
                 % (image_id, flavor, servers_per_tenant))

        servers_per_run = self.config["servers_per_run"]
        while servers_per_tenant > 0:
            if servers_per_tenant < servers_per_run:
                servers_per_run = servers_per_tenant
            kwargs = {"ImageId": image_id, "InstanceType": flavor,
                "MinCount": servers_per_run, "MaxCount": servers_per_run}
            if self.config.get("run_in_vpc", False):
                subnet_id = self.prepare_network(tenant_id, client)
                kwargs["SubnetId"] = subnet_id
            data = client.run_instances(*[], **kwargs)
            ids = [s['InstanceId'] for s in data['Instances']]
            self.context["tenants"][tenant_id]["servers"] += ids
            servers_per_tenant -= servers_per_run

    def wait_for_instances(self, tenant_id, client):
        LOG.info("waiting for running state")
        ids = self.context["tenants"][tenant_id]["servers"]
        start_time = time.time()
        while True:
            data = client.describe_instances(InstanceIds=ids)
            for instance in data['Reservations'][0]['Instances']:
                assert 'error' != instance['State']['Name']
                if instance['State']['Name'] != 'running':
                    break
            else:
                break
            time.sleep(5)
            dtime = time.time() - start_time
            assert dtime <= self.config["build_timeout"]
        LOG.info("end of waiting")

    def prepare_network(self, tenant_id, client, ni_count=0):
        result = dict()
        self.context["tenants"][tenant_id]["networks"].append(result)

        data = client.create_vpc(CidrBlock=self.CIDR)
        vpc_id = data['Vpc']['VpcId']
        result["vpc_id"] = vpc_id
        data = client.create_subnet(VpcId=vpc_id,
            CidrBlock=self.CIDR, AvailabilityZone=self.AWS_ZONE)
        subnet_id = data['Subnet']['SubnetId']
        result["subnet_id"] = subnet_id

        result["ni_ids"] = list()
        for dummy in xrange(0, ni_count):
            data = client.create_network_interface(SubnetId=subnet_id)
            ni_id = data['NetworkInterface']['NetworkInterfaceId']
            result["ni_ids"].append(ni_id)
            time.sleep(1)

        if self.config.get('assign_floating_ip', False):
            data = client.create_internet_gateway()
            gw_id = data['InternetGateway']['InternetGatewayId']
            result["gw_id"] = gw_id
            data = client.attach_internet_gateway(VpcId=vpc_id,
                                                  InternetGatewayId=gw_id)

            data = client.describe_route_tables(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            # len(data['RouteTables']) should be 1
            route_table_id = data['RouteTables'][0]['RouteTableId']
            kwargs = {
                'DestinationCidrBlock': '0.0.0.0/0',
                'RouteTableId': route_table_id,
                'GatewayId': gw_id
            }
            client.create_route(*[], **kwargs)

        return subnet_id

    def assign_floating_ips(self, tenant_id, client):
        self.context["tenants"][tenant_id]["addresses"] = list()
        if not self.config.get('assign_floating_ip', False):
            return
        LOG.info("assign floating ips")
        ids = self.context["tenants"][tenant_id]["servers"]
        for instance_id in ids:
            self.assign_floating_ip(tenant_id, client, instance_id)

    def assign_floating_ip(self, tenant_id, client, instance_id):
        is_vpc = self.config.get("run_in_vpc", False)

        kwargs = dict()
        if is_vpc:
            kwargs['Domain'] = 'vpc'
        data = client.allocate_address(*[], **kwargs)
        alloc_id = data.get('AllocationId')
        public_ip = data['PublicIp']

        kwargs = {'InstanceId': instance_id}
        if is_vpc:
            kwargs['AllocationId'] = alloc_id
        else:
            kwargs['PublicIp'] = public_ip
        try:
            data = client.associate_address(*[], **kwargs)
            kwargs.pop('InstanceId')
            self.context["tenants"][tenant_id]["addresses"].append(kwargs)
        except Exception:
            LOG.exception('')
            kwargs.pop('InstanceId')
            data = client.release_address(*[], **kwargs)

    def terminate_instances_and_wait(self, tenant_id, client):
        ids = self.context["tenants"][tenant_id].get("servers", [])
        servers_per_run = self.config["servers_per_run"]
        mod = len(ids) / servers_per_run
        for i in xrange(0, mod):
            part_ids = ids[i * servers_per_run:(i + 1) * servers_per_run]
            data = client.terminate_instances(InstanceIds=part_ids)
        part_ids = ids[mod * servers_per_run:]
        if part_ids:
            data = client.terminate_instances(InstanceIds=part_ids)

        start_time = time.time()
        while True:
            try:
                data = client.describe_instances(InstanceIds=ids)
            except Exception:
                break
            if (len(data['Reservations']) == 0
                    or len(data['Reservations'][0]['Instances']) == 0):
                break
            for instance in data['Reservations'][0]['Instances']:
                assert 'error' != instance['State']['Name']
                if instance['State']['Name'] != 'terminated':
                    break
            else:
                break
            time.sleep(5)
            dtime = time.time() - start_time
            assert dtime <= self.config["build_timeout"]

    def release_addresses(self, tenant_id, client):
        LOG.info("Cleanup addresses")
        kwargss = self.context["tenants"][tenant_id].get("addresses", [])
        for kwargs in kwargss:
            try:
                data = client.release_address(*[], **kwargs)
            except Exception:
                LOG.exception('')

    def cleanup_networks(self, tenant_id, client):
        LOG.info("Cleanup networks")
        networks = self.context["tenants"][tenant_id].get("networks", [])
        for network in networks:
            vpc_id = network.get("vpc_id")
            gw_id = network.get("gw_id")
            if gw_id:
                try:
                    data = client.detach_internet_gateway(
                        VpcId=vpc_id, InternetGatewayId=gw_id)
                except Exception:
                    LOG.exception('')
                time.sleep(1)
                try:
                    data = client.delete_internet_gateway(
                        InternetGatewayId=gw_id)
                except Exception:
                    LOG.exception('')
                time.sleep(1)
            ni_ids = network.get("ni_ids")
            if ni_ids:
                for ni_id in ni_ids:
                    try:
                        data = client.delete_network_interface(
                            NetworkInterfaceId=ni_id)
                    except Exception:
                        LOG.exception('')
                time.sleep(1)
            subnet_id = network.get("subnet_id")
            if subnet_id:
                try:
                    data = client.delete_subnet(SubnetId=subnet_id)
                except Exception:
                    LOG.exception('')
                time.sleep(1)
            if vpc_id:
                try:
                    data = client.delete_vpc(VpcId=vpc_id)
                except Exception:
                    LOG.exception('')


@context.configure(name="ec2api_networks", platform="openstack", order=451)
class FakeNetworkGenerator(EC2Objects):
    """Context class for adding temporary networks for benchmarks.

        Networks are added for each tenant.
    """

    CONFIG_SCHEMA = {
        "type": "object",
        "$schema": consts.JSON_SCHEMA,
        "properties": {
            "subnets_per_tenant": {
                "type": "integer",
                "minimum": 1
            },
            "nis_per_subnet": {
                "type": "integer",
                "minimum": 1
            },
        },
        "additionalProperties": False
    }

    DEFAULT_CONFIG = {
        "subnets_per_tenant": 5,
        "nis_per_subnet": 5,
    }

    @logging.log_task_wrapper(LOG.info, _("Enter context: `EC2 Networks`"))
    def setup(self):
        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            LOG.info("Creating networks for user tenant %s "
                     % (user["tenant_id"]))

            args = user['ec2args']
            client = botocoreclient.get_ec2_client(
                args['url'], args['region'], args['access'], args['secret'])

            self.context["tenants"][tenant_id]["networks"] = list()
            subnets_count = self.config["subnets_per_tenant"]
            nis_count = self.config["nis_per_subnet"]
            for dummy in xrange(0, subnets_count):
                self.prepare_network(tenant_id, client, nis_count)

    @logging.log_task_wrapper(LOG.info, _("Exit context: `EC2 Networks`"))
    def cleanup(self):
        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            args = user['ec2args']
            client = botocoreclient.get_ec2_client(
                args['url'], args['region'], args['access'], args['secret'])
            self.cleanup_networks(tenant_id, client)


@context.configure(name="ec2api_servers", platform="openstack", order=450)
class FakeServerGenerator(EC2Objects):
    """Context class for adding temporary servers for benchmarks.

        Servers are added for each tenant.
    """

    CONFIG_SCHEMA = {
        "type": "object",
        "$schema": consts.JSON_SCHEMA,
        "properties": {
            "image": {
                "type": "string",
            },
            "flavor": {
                "type": "string"
            },
            "servers_per_tenant": {
                "type": "integer",
                "minimum": 1
            },
            "run_in_vpc": {
                "type": "boolean"
            },
            "assign_floating_ip": {
                "type": "boolean"
            },
            "build_timeout": {
                "type": "integer",
                "minimum": 30
            },
            "servers_per_run": {
                "type": "integer",
                "minimum": 1
            }
        },
        "required": ["image", "flavor"],
        "additionalProperties": False
    }

    DEFAULT_CONFIG = {
        "servers_per_tenant": 5,
        "build_timeout": 30,
        "servers_per_run": 10
    }

    @logging.log_task_wrapper(LOG.info, _("Enter context: `EC2 Servers`"))
    def setup(self):
        image = self.config["image"]
        image_id = None

        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            LOG.info("Booting servers for user tenant %s "
                     % (user["tenant_id"]))

            args = user['ec2args']
            client = botocoreclient.get_ec2_client(
                args['url'], args['region'], args['access'], args['secret'])

            if image_id is None:
                data = client.describe_images(
                    Filters=[{'Name': 'name', 'Values': [image]},
                             {'Name': 'image-type', 'Values': ['machine']}])
                image_id = data['Images'][0]['ImageId']

            self.context["tenants"][tenant_id]["servers"] = list()
            self.context["tenants"][tenant_id]["networks"] = list()
            self.run_instances(tenant_id, client, image_id)
            self.wait_for_instances(tenant_id, client)
            self.assign_floating_ips(tenant_id, client)

    @logging.log_task_wrapper(LOG.info, _("Exit context: `EC2 Servers`"))
    def cleanup(self):
        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            args = user['ec2args']
            client = botocoreclient.get_ec2_client(
                args['url'], args['region'], args['access'], args['secret'])

            self.terminate_instances_and_wait(tenant_id, client)
            self.release_addresses(tenant_id, client)
            self.cleanup_networks(tenant_id, client)
