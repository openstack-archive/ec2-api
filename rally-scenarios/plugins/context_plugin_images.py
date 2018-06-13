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

from rally.common.i18n import _
from rally.common import logging
from rally.common import utils as rutils
from rally.task import context
from rally_openstack import consts
from rally_openstack import osclients

from ec2api.tests import botocoreclient


LOG = logging.getLogger(__name__)


@context.configure(name="fake_images", platform="openstack", order=411)
class FakeImageGenerator(context.Context):
    """Context class for adding images to each user for benchmarks."""

    CONFIG_SCHEMA = {
        "type": "object",
        "$schema": consts.JSON_SCHEMA,
        "properties": {
            "disk_format": {
                "enum": ["qcow2", "raw", "vhd", "vmdk", "vdi", "iso", "aki",
                         "ari", "ami"],
            },
            "container_format": {
                "type": "string",
            },
            "images_per_tenant": {
                "type": "integer",
                "minimum": 1
            },
        },
        "required": ["disk_format", "container_format", "images_per_tenant"],
        "additionalProperties": False
    }

    @logging.log_task_wrapper(LOG.info, _("Enter context: `Images`"))
    def setup(self):
        disk_format = self.config["disk_format"]
        container_format = self.config["container_format"]
        images_per_tenant = self.config["images_per_tenant"]

        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            glance = osclients.Clients(user["credential"]).glance().images
            current_images = []
            for i in range(images_per_tenant):
                kw = {
                    "name": "image-" + tenant_id[0:8] + "-" + str(i),
                    "container_format": container_format,
                    "disk_format": disk_format,
                }
                image = glance.create(**kw)
                glance.upload(image.id, '', image_size=1000000)
                current_images.append(image.id)

            self.context["tenants"][tenant_id]["images"] = current_images

            # NOTE(andrey-mp): call ec2 api to initialize it
            args = user['ec2args']
            client = botocoreclient.get_ec2_client(
                args['url'], args['region'], args['access'], args['secret'])
            data = client.describe_images()

    @logging.log_task_wrapper(LOG.info, _("Exit context: `Images`"))
    def cleanup(self):
        for user, tenant_id in rutils.iterate_per_tenants(
                self.context["users"]):
            glance = osclients.Clients(user["credential"]).glance().images
            for image in self.context["tenants"][tenant_id].get("images", []):
                with logging.ExceptionLogger(
                        LOG,
                        _("Failed to delete network for tenant %s")
                        % tenant_id):
                    glance.delete(image)
