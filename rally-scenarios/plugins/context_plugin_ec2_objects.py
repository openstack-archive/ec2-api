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

from rally.benchmark.context import base
from rally.common.i18n import _
from rally.common import log as logging
from rally.common import utils as rutils
from rally import consts

from ec2api.tests.functional import base as ec2_tests_base
from ec2api.tests.functional import botocoreclient


LOG = logging.getLogger(__name__)


class EC2Objects(base.Context):

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
            resp, data = client.RunInstances(*[], **kwargs)
            if resp.status_code != 200:
                LOG.error(ec2_tests_base.EC2ErrorConverter(data))
                assert 200 == resp.status_code
            ids = [s['InstanceId'] for s in data['Instances']]
            self.context["tenants"][tenant_id]["servers"] += ids
            servers_per_tenant -= servers_per_run

    def wait_for_instances(self, tenant_id, client):
        LOG.info("waiting for running state")
        ids = self.context["tenants"][tenant_id]["servers"]
        start_time = time.time()
        while True:
            resp, data = client.DescribeInstances(InstanceIds=ids)
            if resp.status_code != 200:
                LOG.error(ec2_tests_base.EC2ErrorConverter(data))
                assert 200 == resp.status_code
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

        resp, data = client.CreateVpc(CidrBlock=self.CIDR)
        if resp.status_code != 200:
            LOG.error(ec2_tests_base.EC2ErrorConverter(data))
            assert 200 == resp.status_code
        vpc_id = data['Vpc']['VpcId']
        result["vpc_id"] = vpc_id
        resp, data = client.CreateSubnet(VpcId=vpc_id,
            CidrBlock=self.CIDR, AvailabilityZone=self.AWS_ZONE)
        if resp.status_code != 200:
            LOG.error(ec2_tests_base.EC2ErrorConverter(data))
            assert 200 == resp.status_code
        subnet_id = data['Subnet']['SubnetId']
        result["subnet_id"] = subnet_id

        result["ni_ids"] = list()
        for dummy in xrange(0, ni_count):
            resp, data = client.CreateNetworkInterface(SubnetId=subnet_id)
            if resp.status_code != 200:
                LOG.error(ec2_tests_base.EC2ErrorConverter(data))
                assert 200 == resp.status_code
            ni_id = data['NetworkInterface']['NetworkInterfaceId']
            result["ni_ids"].append(ni_id)
            time.sleep(1)

        if self.config.get('assign_floating_ip', False):
            resp, data = client.CreateInternetGateway()
            if resp.status_code != 200:
                LOG.error(ec2_tests_base.EC2ErrorConverter(data))
                assert 200 == resp.status_code
            gw_id = data['InternetGateway']['InternetGatewayId']
            result["gw_id"] = gw_id
            resp, data = client.AttachInternetGateway(VpcId=vpc_id,
                                                      InternetGatewayId=gw_id)
            if resp.status_code != 200:
                LOG.error(ec2_tests_base.EC2ErrorConverter(data))
                assert 200 == resp.status_code

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
        resp, data = client.AllocateAddress(*[], **kwargs)
        if resp.status_code != 200:
            LOG.warning(ec2_tests_base.EC2ErrorConverter(data))
            return
        alloc_id = data.get('AllocationId')
        public_ip = data['PublicIp']
        if is_vpc:
            self.context["tenants"][tenant_id]["addresses"].append(
                {'AllocationId': alloc_id})
        else:
            self.context["tenants"][tenant_id]["addresses"].append(
                {'PublicIp': public_ip})

        kwargs = {'InstanceId': instance_id}
        if is_vpc:
            kwargs['AllocationId'] = alloc_id
        else:
            kwargs['PublicIp'] = public_ip
        resp, data = client.AssociateAddress(*[], **kwargs)
        if resp.status_code != 200:
            LOG.error(ec2_tests_base.EC2ErrorConverter(data))
            if is_vpc:
                resp, data = client.ReleaseAddress(AllocationId=alloc_id)
            else:
                resp, data = client.ReleaseAddress(PublicIp=public_ip)
            if resp.status_code != 200:
                LOG.error(ec2_tests_base.EC2ErrorConverter(data))

    def terminate_instances_and_wait(self, tenant_id, client):
        ids = self.context["tenants"][tenant_id].get("servers", [])
        servers_per_run = self.config["servers_per_run"]
        mod = len(ids) / servers_per_run
        for i in xrange(0, mod):
            part_ids = ids[i * servers_per_run:(i + 1) * servers_per_run]
            resp, data = client.TerminateInstances(InstanceIds=part_ids)
            if resp.status_code != 200:
                LOG.warning(ec2_tests_base.EC2ErrorConverter(data))
        part_ids = ids[mod * servers_per_run:]
        if part_ids:
            resp, data = client.TerminateInstances(InstanceIds=part_ids)
            if resp.status_code != 200:
                LOG.warning(ec2_tests_base.EC2ErrorConverter(data))

        start_time = time.time()
        while True:
            resp, data = client.DescribeInstances(InstanceIds=ids)
            if (resp.status_code == 400
                    or len(data['Reservations']) == 0
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
            resp, data = client.ReleaseAddress(*[], **kwargs)
            if resp.status_code != 200:
                LOG.warning(ec2_tests_base.EC2ErrorConverter(data))

    def cleanup_networks(self, tenant_id, client):
        LOG.info("Cleanup networks")
        networks = self.context["tenants"][tenant_id].get("networks", [])
        for network in networks:
            vpc_id = network.get("vpc_id")
            gw_id = network.get("gw_id")
            if gw_id:
                resp, data = client.DetachInternetGateway(
                    VpcId=vpc_id, InternetGatewayId=gw_id)
                if resp.status_code != 200:
                    LOG.warning(ec2_tests_base.EC2ErrorConverter(data))
                time.sleep(1)
                resp, data = client.DeleteInternetGateway(
                    InternetGatewayId=gw_id)
                if resp.status_code != 200:
                    LOG.warning(ec2_tests_base.EC2ErrorConverter(data))
                time.sleep(1)
            ni_ids = network.get("ni_ids")
            if ni_ids:
                for ni_id in ni_ids:
                    resp, data = client.DeleteNetworkInterface(
                        NetworkInterfaceId=ni_id)
                    if resp.status_code != 200:
                        LOG.warning(ec2_tests_base.EC2ErrorConverter(data))
                time.sleep(1)
            subnet_id = network.get("subnet_id")
            if subnet_id:
                resp, data = client.DeleteSubnet(SubnetId=subnet_id)
                if resp.status_code != 200:
                    LOG.warning(ec2_tests_base.EC2ErrorConverter(data))
                time.sleep(1)
            if vpc_id:
                resp, data = client.DeleteVpc(VpcId=vpc_id)
                if resp.status_code != 200:
                    LOG.warning(ec2_tests_base.EC2ErrorConverter(data))


@base.context(name="ec2_networks", order=451)
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

    @rutils.log_task_wrapper(LOG.info, _("Enter context: `EC2 Networks`"))
    def setup(self):
        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            LOG.info("Creating networks for user tenant %s "
                     % (user["tenant_id"]))

            args = user['ec2args']
            client = botocoreclient.APIClientEC2(
                args['url'], args['region'], args['access'], args['secret'])

            self.context["tenants"][tenant_id]["networks"] = list()
            subnets_count = self.config["subnets_per_tenant"]
            nis_count = self.config["nis_per_subnet"]
            for dummy in xrange(0, subnets_count):
                self.prepare_network(tenant_id, client, nis_count)

    @rutils.log_task_wrapper(LOG.info, _("Exit context: `EC2 Networks`"))
    def cleanup(self):
        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            args = user['ec2args']
            client = botocoreclient.APIClientEC2(
                args['url'], args['region'], args['access'], args['secret'])
            ids = self.context["tenants"][tenant_id].get("servers", [])

            self.cleanup_networks(tenant_id, client)


@base.context(name="ec2_servers", order=450)
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

    @rutils.log_task_wrapper(LOG.info, _("Enter context: `EC2 Servers`"))
    def setup(self):
        image = self.config["image"]
        image_id = None

        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            LOG.info("Booting servers for user tenant %s "
                     % (user["tenant_id"]))

            args = user['ec2args']
            client = botocoreclient.APIClientEC2(
                args['url'], args['region'], args['access'], args['secret'])

            if image_id is None:
                resp, data = client.DescribeImages(
                    Filters=[{'Name': 'name', 'Values': [image]},
                             {'Name': 'image-type', 'Values': ['machine']}])
                if resp.status_code != 200:
                    LOG.error(ec2_tests_base.EC2ErrorConverter(data))
                    assert 200 == resp.status_code
                image_id = data['Images'][0]['ImageId']

            self.context["tenants"][tenant_id]["servers"] = list()
            self.context["tenants"][tenant_id]["networks"] = list()
            self.run_instances(tenant_id, client, image_id)
            self.wait_for_instances(tenant_id, client)
            self.assign_floating_ips(tenant_id, client)

    @rutils.log_task_wrapper(LOG.info, _("Exit context: `EC2 Servers`"))
    def cleanup(self):
        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            args = user['ec2args']
            client = botocoreclient.APIClientEC2(
                args['url'], args['region'], args['access'], args['secret'])
            ids = self.context["tenants"][tenant_id].get("servers", [])

            self.terminate_instances_and_wait(tenant_id, client)
            self.release_addresses(tenant_id, client)
            self.cleanup_networks(tenant_id, client)
