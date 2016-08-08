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

import base64
import os

from oslo_log import log
import six
from tempest.lib.common import ssh
from tempest.lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config
from ec2api.tests.functional.scenario import base as scenario_base

CONF = config.CONF
LOG = log.getLogger(__name__)

PRIVATE_KEY_MATERIAL = (
    '-----BEGIN RSA PRIVATE KEY-----\n'
    'MIIEpAIBAAKCAQEAxkaf7L0BoNmyzlWPh29WPsaUP2+kV2vuoCQrO2FWliV8OOUP\n'
    '+OIPvqRF+XtcCWc5LIQrSzKnitazJmoUO1m/J7fwxv2Qf2kbKVLrLqP7AUh1pAgG\n'
    'DUqnBS8F5+2kPsMRKAE+xz1uJDpnP5ktIzpn1hWDVCoG80/jP7d7YSi0KlIYMHVx\n'
    'E3WegrQ5IWw/BI62LR1KOe2YBSrv1n9SDc2w69QbfrnsZOpNKAnv/+G7LIqeHKP1\n'
    'G5YMh2iWtEzdDgHqWa+HvtifhS3AzdtG7zgpmpwq8JYheYXLC+S/qxdZSGFx3p5s\n'
    'JKr7kiAcxWqTsYEEtJdbYKDYfmu1e+k5hP901wIDAQABAoIBAFJkDJaSX7fYXq3Q\n'
    '7giIYl1JpVbK7I6LQih3fyN4qkNQJlN6E+4G+iXtG0q1USRzKVXvQhJIZUiTOPSQ\n'
    'hgG3pHA7xijaOw5GvcupMiM6btY0pvXXg7RIPikwRhL/NA4Efv+RrOWcCEWzoy3R\n'
    'V+lYnsdePyldIXA/1R2n//P6twsSP+055XCabN/HVEJMtYmeVnZsoffRgos5cDlT\n'
    'afpq29W93kI7kXTDIlNxdQXzOa1rKqmUK/nBf0caMwaGy9Di9s3OP8M+Xs4Y/L0b\n'
    '+QOuILwBNjMMj3yqdDyDT698kQoO0oX458L70MUk660PItdaqyPT1KAaCIz7xTFJ\n'
    '7OQM10kCgYEA+ES8irwqkkSocZ0QQzCR5qxIp3cVrnw1kaaqWuZOgojMPvRpzFJO\n'
    'x4IB6VbvcpPPqHBhCGuJYIDYXuM1Ke0YR4TllNec9ZvSPvUYFNNQLeXmAyaWKtIE\n'
    '91BoONyEMsbpWr/hsG60y4cFoqNZVqILHTNS48TMVtB4Lv8IgOv3OVsCgYEAzHNV\n'
    'YZzUMdBN5rEuNwJ5NtModung7H08g9jOiGHMo0ZQvhKhFYgieQmJRGXOhMpbNPL4\n'
    '9RLQjAVr4mrFdk+sDqVmscqu07q2/jjT1U1x2rprBpzckOvmmw7TKveiGfgcwqZ+\n'
    'Qs3tWoiLc8m74loJyT/7c0tpyZxjbPJL7jVQzzUCgYEAqnNuywWDaObwiwhduPOo\n'
    'yCmyvB87aI9oq/Y0cbI7Zs2LBRIDbT95TOqKa2y/evfWk3uMcx55tCLh6sutnXpl\n'
    't/ybLwSVg98Wixj1Dp9CJjD4KWOdqAqHVFEFLTzhGoeMgTzKM7reL/okuVPTK3KX\n'
    'lNW+7BgafuQkD4gTi4f2NY8CgYEAiUNlr4N7c3ZG1vtd69DdUNGz+SJMwHnUhzCo\n'
    'eSgwG+65huM7AxnDC0A7yJARd1Xkpkf6nY9kNJ3vMLQ+npAfFDY4HGXXuo9BDK1a\n'
    'i3rTVeaStH3cF/BJgxEQ9WgMjSLnLEhbvL5E/ONvvO1UF0QcDeHHEEExZQp6Nkr2\n'
    'b5ecCYECgYBtL4kr0qttoowbfj+pXjwiJjbwb6GBaMBVNQTtJBKdl5AeyDm9qh2o\n'
    'vF60vnm+wWFfUs8nlvPMT/FNHwjHtFOBLPhw6tUcyrzh1ba4v/FE40FW4NxgqSK/\n'
    'VS0+XhPxet+E9kXjMMrVUaDrHHR2+zM5OyOLG0a/JIcsFuf7qZgAMQ==\n'
    '-----END RSA PRIVATE KEY-----'
)
PUBLIC_KEY_MATERIAL = (
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGRp/svQGg2bLOVY+Hb1Y+xpQ/'
    'b6RXa+6gJCs7YVaWJXw45Q/44g++pEX5e1wJZzkshCtLMqeK1rMmahQ7Wb8nt/DG'
    '/ZB/aRspUusuo/sBSHWkCAYNSqcFLwXn7aQ+wxEoAT7HPW4kOmc/mS0jOmfWFYNU'
    'KgbzT+M/t3thKLQqUhgwdXETdZ6CtDkhbD8EjrYtHUo57ZgFKu/Wf1INzbDr1Bt+'
    'uexk6k0oCe//4bssip4co/UblgyHaJa0TN0OAepZr4e+2J+FLcDN20bvOCmanCrw'
    'liF5hcsL5L+rF1lIYXHenmwkqvuSIBzFapOxgQS0l1tgoNh+a7V76TmE/3TX '
    'ubuntu@test.com'
)


class InstancesTest(scenario_base.BaseScenarioTest):

    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_metadata(self):
        key_name = data_utils.rand_name('testkey')
        self.client.import_key_pair(KeyName=key_name,
                                    PublicKeyMaterial=PUBLIC_KEY_MATERIAL)
        self.addResourceCleanUp(self.client.delete_key_pair, KeyName=key_name)

        sec_group_name = self.create_standard_security_group()
        user_data = six.text_type(data_utils.rand_uuid()) + six.unichr(1071)
        instance_id = self.run_instance(KeyName=key_name, UserData=user_data,
                                        SecurityGroups=[sec_group_name])

        data = self.client.describe_instance_attribute(
            InstanceId=instance_id, Attribute='userData')
        self.assertEqual(
            data['UserData']['Value'],
            base64.b64encode(user_data.encode("utf-8")).decode("utf-8"))

        ip_address = self.get_instance_ip(instance_id)

        ssh_client = ssh.Client(ip_address, CONF.aws.image_user,
                                pkey=PRIVATE_KEY_MATERIAL)

        url = 'http://169.254.169.254'
        data = ssh_client.exec_command('curl %s/latest/user-data' % url)
        if isinstance(data, six.binary_type):
            data = data.decode("utf-8")
        self.assertEqual(user_data, data)

        data = ssh_client.exec_command('curl %s/latest/meta-data/ami-id' % url)
        self.assertEqual(CONF.aws.image_id, data)

        data = ssh_client.exec_command(
            'curl %s/latest/meta-data/public-keys/0/openssh-key' % url)
        # compare only keys. without 'sha-rsa' and owner
        self.assertEqual(PUBLIC_KEY_MATERIAL.split()[1], data.split()[1])

    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.image_id, "image id is not defined")
    def test_compare_console_output(self):
        key_name = data_utils.rand_name('testkey')
        pkey = self.create_key_pair(key_name)
        sec_group_name = self.create_standard_security_group()
        instance_id = self.run_instance(KeyName=key_name,
                                        SecurityGroups=[sec_group_name])

        data_to_check = data_utils.rand_uuid()
        ip_address = self.get_instance_ip(instance_id)
        ssh_client = ssh.Client(ip_address, CONF.aws.image_user, pkey=pkey)
        cmd = 'sudo sh -c "echo \\"%s\\" >/dev/console"' % data_to_check
        ssh_client.exec_command(cmd)

        waiter = base.EC2Waiter(self.client.get_console_output)
        waiter.wait_no_exception(InstanceId=instance_id)

        def _compare_console_output():
            data = self.client.get_console_output(InstanceId=instance_id)
            self.assertEqual(instance_id, data['InstanceId'])
            self.assertIsNotNone(data['Timestamp'])
            self.assertIn('Output', data)
            self.assertIn(data_to_check, data['Output'])

        waiter = base.EC2Waiter(_compare_console_output)
        waiter.wait_no_exception()

    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.ami_image_location, "Image is absent in S3")
    def test_run_and_ping_registered_image(self):
        image_name = data_utils.rand_name("ami-name")
        data = self.client.register_image(
            Name=image_name, ImageLocation=CONF.aws.ami_image_location)
        image_id = data['ImageId']
        self.addResourceCleanUp(self.client.deregister_image, ImageId=image_id)
        self.get_image_waiter().wait_available(image_id)

        # launch this image
        sec_group_name = self.create_standard_security_group()
        instance_id = self.run_instance(ImageId=image_id,
                                        SecurityGroups=[sec_group_name])

        waiter = base.EC2Waiter(self.client.get_console_output)
        waiter.wait_no_exception(InstanceId=instance_id)

        def _compare_console_output():
            data = self.client.get_console_output(InstanceId=instance_id)
            self.assertEqual(instance_id, data['InstanceId'])
            self.assertIsNotNone(data['Timestamp'])
            self.assertIn('Output', data)
            self.assertNotEqual('', data['Output'])

        waiter = base.EC2Waiter(_compare_console_output)
        waiter.wait_no_exception()

        # check ping
        ip_address = self.get_instance_ip(instance_id)

        def _ping():
            response = os.system("ping -c 1 " + ip_address + " > /dev/null")
            self.assertEqual(0, response)

        waiter = base.EC2Waiter(_ping)
        waiter.wait_no_exception()
