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

import json
import os
import six
import tempfile

from cinderclient import exceptions as cinder_exception
import eventlet
import mock
from oslo_concurrency import processutils

from ec2api.api import image as image_api
from ec2api import exception
from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


AMI_MANIFEST_XML = """<?xml version="1.0" ?>
<manifest>
        <version>2011-06-17</version>
        <bundler>
                <name>test-s3</name>
                <version>0</version>
                <release>0</release>
        </bundler>
        <machine_configuration>
                <architecture>x86_64</architecture>
                <block_device_mapping>
                        <mapping>
                                <virtual>ami</virtual>
                                <device>sda1</device>
                        </mapping>
                        <mapping>
                                <virtual>root</virtual>
                                <device>/dev/sda1</device>
                        </mapping>
                        <mapping>
                                <virtual>ephemeral0</virtual>
                                <device>sda2</device>
                        </mapping>
                        <mapping>
                                <virtual>swap</virtual>
                                <device>sda3</device>
                        </mapping>
                </block_device_mapping>
                <kernel_id>%(aki-id)s</kernel_id>
                <ramdisk_id>%(ari-id)s</ramdisk_id>
        </machine_configuration>
        <image>
                <ec2_encrypted_key>foo</ec2_encrypted_key>
                <user_encrypted_key>foo</user_encrypted_key>
                <ec2_encrypted_iv>foo</ec2_encrypted_iv>
                <parts count="1">
                        <part index="0">
                               <filename>foo</filename>
                        </part>
                </parts>
        </image>
</manifest>
""" % {'aki-id': fakes.ID_EC2_IMAGE_AKI_1,
       'ari-id': fakes.ID_EC2_IMAGE_ARI_1}

FILE_MANIFEST_XML = """<?xml version="1.0" ?>
<manifest>
        <image>
                <ec2_encrypted_key>foo</ec2_encrypted_key>
                <user_encrypted_key>foo</user_encrypted_key>
                <ec2_encrypted_iv>foo</ec2_encrypted_iv>
                <parts count="1">
                        <part index="0">
                               <filename>foo</filename>
                        </part>
                </parts>
        </image>
</manifest>
"""


class ImageTestCase(base.ApiTestCase):

    @mock.patch('ec2api.api.instance._is_ebs_instance')
    def _test_create_image(self, instance_status, no_reboot, is_ebs_instance):
        self.set_mock_db_items(fakes.DB_INSTANCE_2)
        os_instance = mock.MagicMock()
        os_instance.configure_mock(id=fakes.ID_OS_INSTANCE_2,
                                   status=instance_status)
        stop_called = iter([False, True])
        os_instance.stop.side_effect = lambda: next(stop_called)
        os_instance.get.side_effect = lambda: (setattr(os_instance, 'status',
                                                       'SHUTOFF')
                                               if next(stop_called) else None)
        image_id = fakes.random_ec2_id('ami')
        os_image_id = fakes.random_os_id()
        os_instance.create_image.return_value = os_image_id
        self.glance.images.get.return_value = fakes.OSImage(
            {'id': os_image_id},
            from_get=True)
        self.nova.servers.get.return_value = os_instance
        is_ebs_instance.return_value = True
        self.db_api.add_item.side_effect = tools.get_db_api_add_item(image_id)

        resp = self.execute('CreateImage',
                            {'InstanceId': fakes.ID_EC2_INSTANCE_2,
                             'Name': 'fake_name',
                             'Description': 'fake desc',
                             'NoReboot': str(no_reboot)})
        self.assertEqual({'imageId': image_id},
                         resp)
        self.db_api.get_item_by_id.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_INSTANCE_2)
        self.nova.servers.get.assert_called_once_with(fakes.ID_OS_INSTANCE_2)
        is_ebs_instance.assert_called_once_with(mock.ANY, os_instance.id)
        expected_image = {'is_public': False,
                          'description': 'fake desc'}
        if no_reboot:
            expected_image['os_id'] = os_image_id
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'ami', expected_image)
        if not no_reboot:
            eventlet.sleep()
        if not no_reboot:
            os_instance.stop.assert_called_once_with()
            os_instance.get.assert_called_once_with()
            os_instance.start.assert_called_once_with()
        if no_reboot:
            os_instance.create_image.assert_called_once_with('fake_name')
        else:
            os_instance.create_image.assert_called_once_with(
                'fake_name', metadata={'ec2_id': image_id})
            self.db_api.update_item.assert_called_once_with(
                mock.ANY, {'id': image_id,
                           'is_public': False,
                           'description': 'fake desc',
                           'os_id': os_image_id,
                           'vpc_id': None})

        self.db_api.reset_mock()
        self.nova.servers.reset_mock()

    def test_create_image(self):
        self._test_create_image('ACTIVE', False)
        self._test_create_image('SHUTOFF', True)

    @mock.patch('ec2api.api.instance._is_ebs_instance')
    def test_create_image_invalid_parameters(self, is_ebs_instance):
        self.set_mock_db_items(fakes.DB_INSTANCE_1)
        is_ebs_instance.return_value = False

        self.assert_execution_error('InvalidParameterValue', 'CreateImage',
                                    {'InstanceId': fakes.ID_EC2_INSTANCE_1,
                                     'Name': 'fake_name'})

    @mock.patch('ec2api.api.image._s3_create')
    def test_register_image_by_s3(self, s3_create):
        s3_create.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_IMAGE_1))

        resp = self.execute(
            'RegisterImage',
            {'ImageLocation': fakes.LOCATION_IMAGE_1})
        self.assertThat(resp, matchers.DictMatches(
            {'imageId': fakes.ID_EC2_IMAGE_1}))

        s3_create.assert_called_once_with(
            mock.ANY,
            {'name': fakes.LOCATION_IMAGE_1,
             'image_location': fakes.LOCATION_IMAGE_1})
        s3_create.reset_mock()

        resp = self.execute(
            'RegisterImage',
            {'ImageLocation': fakes.LOCATION_IMAGE_1,
             'Name': 'an image name'})
        self.assertThat(resp, matchers.DictMatches(
            {'imageId': fakes.ID_EC2_IMAGE_1}))

        s3_create.assert_called_once_with(
            mock.ANY,
            {'name': 'an image name',
             'image_location': fakes.LOCATION_IMAGE_1})

    @mock.patch('ec2api.api.ec2utils.get_os_image')
    def test_register_image_by_bdm(self, get_os_image):
        self.glance.images.create.return_value = (
            fakes.OSImage(fakes.OS_IMAGE_2))
        self.glance.images.upload.return_value = (
            fakes.OSImage(fakes.OS_IMAGE_2))
        self.cinder.volume_snapshots.get.side_effect = (
            tools.get_by_1st_arg_getter(
                {fakes.ID_OS_SNAPSHOT_1: (
                    fakes.OSSnapshot(fakes.OS_SNAPSHOT_1))},
                notfound_exception=cinder_exception.NotFound(404)))
        self.db_api.add_item.side_effect = (
            tools.get_db_api_add_item(fakes.ID_EC2_IMAGE_2))
        self.set_mock_db_items(fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2,
                               fakes.DB_IMAGE_AKI_1, fakes.DB_IMAGE_ARI_1)
        get_os_image.side_effect = [fakes.OSImage(fakes.OS_IMAGE_AKI_1),
                                    fakes.OSImage(fakes.OS_IMAGE_ARI_1)]

        resp = self.execute(
            'RegisterImage',
            {'RootDeviceName': fakes.ROOT_DEVICE_NAME_IMAGE_2,
             'Name': 'fake_name',
             'KernelId': fakes.ID_EC2_IMAGE_AKI_1,
             'RamdiskId': fakes.ID_EC2_IMAGE_ARI_1,
             'BlockDeviceMapping.1.DeviceName': fakes.ROOT_DEVICE_NAME_IMAGE_2,
             'BlockDeviceMapping.1.Ebs.SnapshotId': fakes.ID_EC2_SNAPSHOT_1,
             'BlockDeviceMapping.2.DeviceName': '/dev/vdf',
             'BlockDeviceMapping.2.Ebs.VolumeSize': '100',
             'BlockDeviceMapping.2.Ebs.DeleteOnTermination': 'False',
             'BlockDeviceMapping.3.DeviceName': '/dev/vdg',
             'BlockDeviceMapping.3.Ebs.SnapshotId': fakes.ID_EC2_SNAPSHOT_1,
             'BlockDeviceMapping.3.Ebs.VolumeSize': '55',
             'BlockDeviceMapping.3.Ebs.DeleteOnTermination': 'True',
             'BlockDeviceMapping.4.DeviceName': '/dev/vdh',
             'BlockDeviceMapping.4.Ebs.SnapshotId': fakes.ID_EC2_SNAPSHOT_2})
        self.assertThat(resp, matchers.DictMatches(
            {'imageId': fakes.ID_EC2_IMAGE_2}))
        self.db_api.add_item.assert_called_once_with(
            mock.ANY, 'ami', {'os_id': fakes.ID_OS_IMAGE_2,
                              'is_public': False,
                              'description': None})
        self.assertEqual(1, self.glance.images.create.call_count)
        self.assertEqual((), self.glance.images.create.call_args[0])
        self.assertIsInstance(
            self.glance.images.create.call_args[1], dict)
        bdm = self.glance.images.create.call_args[1].pop(
            'block_device_mapping', 'null')
        self.assertEqual(
            {'visibility': 'private',
             'name': 'fake_name',
             'kernel_id': fakes.ID_OS_IMAGE_AKI_1,
             'ramdisk_id': fakes.ID_OS_IMAGE_ARI_1,
             'root_device_name': fakes.ROOT_DEVICE_NAME_IMAGE_2,
             'container_format': 'bare',
             'disk_format': 'raw',
             'bdm_v2': 'True'},
            self.glance.images.create.call_args[1])
        self.assertEqual([{'boot_index': 0,
                           'delete_on_termination': True,
                           'destination_type': 'volume',
                           'device_name': fakes.ROOT_DEVICE_NAME_IMAGE_2,
                           'source_type': 'snapshot',
                           'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
                           'volume_size': 1},
                          {'boot_index': -1,
                           'delete_on_termination': False,
                           'destination_type': 'volume',
                           'device_name': '/dev/vdf',
                           'source_type': 'blank',
                           'volume_size': 100},
                          {'boot_index': -1,
                           'delete_on_termination': True,
                           'destination_type': 'volume',
                           'device_name': '/dev/vdg',
                           'source_type': 'snapshot',
                           'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
                           'volume_size': 55},
                          {'boot_index': -1,
                           'delete_on_termination': True,
                           'destination_type': 'volume',
                           'device_name': '/dev/vdh',
                           'source_type': 'snapshot',
                           'snapshot_id': fakes.ID_OS_SNAPSHOT_2}],
                         json.loads(bdm))
        get_os_image.assert_has_calls(
            [mock.call(mock.ANY, fakes.ID_EC2_IMAGE_AKI_1),
             mock.call(mock.ANY, fakes.ID_EC2_IMAGE_ARI_1)])
        self.cinder.volume_snapshots.get.assert_any_call(
            fakes.ID_OS_SNAPSHOT_1)

    def test_register_image_invalid_parameters(self):
        self.assert_execution_error(
            'InvalidParameterCombination', 'RegisterImage', {})

    def test_deregister_image(self):
        self._setup_model()

        # normal flow
        resp = self.execute('DeregisterImage',
                            {'ImageId': fakes.ID_EC2_IMAGE_1})
        self.assertThat(resp, matchers.DictMatches({'return': True}))
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_IMAGE_1)
        self.glance.images.delete.assert_called_once_with(
            fakes.ID_OS_IMAGE_1)

        # deregister image which failed on asynchronously creation
        self.glance.reset_mock()
        image_id = fakes.random_ec2_id('ami')
        self.add_mock_db_items({'id': image_id,
                                'os_id': None,
                                'state': 'failed'})
        resp = self.execute('DeregisterImage',
                            {'ImageId': image_id})
        self.assertThat(resp, matchers.DictMatches({'return': True}))
        self.db_api.delete_item.assert_called_with(mock.ANY, image_id)
        self.assertFalse(self.glance.images.delete.called)

    def test_deregister_image_invalid_parameters(self):
        self._setup_model()

        self.assert_execution_error('InvalidAMIID.NotFound', 'DeregisterImage',
                                    {'ImageId': fakes.random_ec2_id('ami')})

        # deregister asynchronously creating image
        image_id = fakes.random_ec2_id('ami')
        self.add_mock_db_items({'id': image_id,
                                'os_id': None})
        self.assert_execution_error('IncorrectState',
                                    'DeregisterImage',
                                    {'ImageId': image_id})

    def test_describe_images(self):
        self._setup_model()

        resp = self.execute('DescribeImages', {})
        self.assertThat(
            resp,
            matchers.DictMatches(
                {'imagesSet': [fakes.EC2_IMAGE_1, fakes.EC2_IMAGE_2]},
                orderless_lists=True),
            verbose=True)

        self.db_api.get_items.assert_any_call(mock.ANY, 'ami')
        self.db_api.get_items.assert_any_call(mock.ANY, 'aki')
        self.db_api.get_items.assert_any_call(mock.ANY, 'ari')

        self.db_api.get_items_by_ids = tools.CopyingMock(
            side_effect=self.db_api.get_items_by_ids.side_effect)

        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.ID_EC2_IMAGE_1})
        self.assertThat(resp,
                        matchers.DictMatches(
                            {'imagesSet': [fakes.EC2_IMAGE_1]},
                            orderless_lists=True))
        self.db_api.get_items_by_ids.assert_any_call(
            mock.ANY, set([fakes.ID_EC2_IMAGE_1]))

        self.check_filtering(
            'DescribeImages', 'imagesSet',
            [('architecture', 'x86_64'),
             ('block-device-mapping.device-name', '/dev/sdb2'),
             ('block-device-mapping.snapshot-id', fakes.ID_EC2_SNAPSHOT_1),
             ('block-device-mapping.volume-size', 22),
             ('description', 'fake desc'),
             ('image-id', fakes.ID_EC2_IMAGE_1),
             ('image-type', 'machine'),
             ('is-public', True),
             ('kernel_id', fakes.ID_EC2_IMAGE_AKI_1,),
             ('name', 'fake_name'),
             ('owner-id', fakes.ID_OS_PROJECT),
             ('ramdisk-id', fakes.ID_EC2_IMAGE_ARI_1),
             ('root-device-name', fakes.ROOT_DEVICE_NAME_IMAGE_1),
             ('root-device-type', 'instance-store'),
             ('state', 'available')])
        self.check_tag_support(
            'DescribeImages', 'imagesSet',
            fakes.ID_EC2_IMAGE_1, 'imageId',
            ('ami', 'ari', 'aki'))

    def test_describe_images_invalid_parameters(self):
        self._setup_model()

        self.assert_execution_error('InvalidAMIID.NotFound', 'DescribeImages',
                                    {'ImageId.1': fakes.random_ec2_id('ami')})

        self.glance.images.list.side_effect = lambda: []

        self.assert_execution_error('InvalidAMIID.NotFound', 'DescribeImages',
                                    {'ImageId.1': fakes.ID_EC2_IMAGE_1})

    def test_describe_image_attributes(self):
        self._setup_model()

        def do_check(attr, ec2_image_id, response):
            resp = self.execute('DescribeImageAttribute',
                                {'ImageId': ec2_image_id,
                                 'Attribute': attr})
            response['imageId'] = ec2_image_id
            self.assertThat(resp,
                            matchers.DictMatches(response,
                                                 orderless_lists=True),
                            verbose=True)

        do_check('launchPermission',
                 fakes.ID_EC2_IMAGE_2,
                 {'launchPermission': [{'group': 'all'}]})

        do_check('kernel',
                 fakes.ID_EC2_IMAGE_1,
                 {'kernel': {'value': fakes.ID_EC2_IMAGE_AKI_1}})

        do_check('ramdisk',
                 fakes.ID_EC2_IMAGE_1,
                 {'ramdisk': {'value': fakes.ID_EC2_IMAGE_ARI_1}})

        do_check('rootDeviceName',
                 fakes.ID_EC2_IMAGE_1,
                 {'rootDeviceName': fakes.ROOT_DEVICE_NAME_IMAGE_1})

        do_check('rootDeviceName',
                 fakes.ID_EC2_IMAGE_2,
                 {'rootDeviceName': fakes.ROOT_DEVICE_NAME_IMAGE_2})

        do_check('blockDeviceMapping',
                 fakes.ID_EC2_IMAGE_1,
                 {'blockDeviceMapping': (
                        fakes.EC2_IMAGE_1['blockDeviceMapping'])})

        do_check('blockDeviceMapping',
                 fakes.ID_EC2_IMAGE_2,
                 {'blockDeviceMapping': (
                        fakes.EC2_IMAGE_2['blockDeviceMapping'])})

    def test_describe_image_attributes_invalid_parameters(self):
        image_id = fakes.random_ec2_id('ami')
        self.set_mock_db_items({'id': image_id,
                                'os_id': None})
        self.assert_execution_error('IncorrectState',
                                    'DescribeImageAttribute',
                                    {'ImageId': image_id,
                                     'Attribute': 'kernel'})

    def test_modify_image_attributes(self):
        self._setup_model()

        resp = self.execute('ModifyImageAttribute',
                            {'imageId': fakes.ID_EC2_IMAGE_1,
                             'attribute': 'launchPermission',
                             'operationType': 'add',
                             'userGroup.1': 'all'})
        self.assertThat(resp, matchers.DictMatches({'return': True}))
        self.glance.images.update.assert_called_once_with(
                fakes.ID_OS_IMAGE_1, visibility='public')

    def test_modify_image_attributes_invalid_parameters(self):
        image_id = fakes.random_ec2_id('ami')
        self.set_mock_db_items({'id': image_id,
                                'os_id': None})
        self.assert_execution_error('IncorrectState',
                                    'ModifyImageAttribute',
                                    {'ImageId': image_id,
                                     'Attribute': 'kernel'})

    def _setup_model(self):
        self.set_mock_db_items(fakes.DB_IMAGE_1, fakes.DB_IMAGE_2,
                               fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2,
                               fakes.DB_IMAGE_AKI_1, fakes.DB_IMAGE_ARI_1,
                               fakes.DB_VOLUME_1, fakes. DB_VOLUME_2)
        self.db_api.get_public_items.return_value = []

        # NOTE(ft): glance.image.list returns an iterator, not just a list
        self.glance.images.list.side_effect = (
            lambda: (fakes.OSImage(i)
                     for i in (fakes.OS_IMAGE_1, fakes.OS_IMAGE_2)))
        self.glance.images.get.side_effect = (
            lambda os_id: (fakes.OSImage(fakes.OS_IMAGE_1, from_get=True)
                           if os_id == fakes.ID_OS_IMAGE_1 else
                           fakes.OSImage(fakes.OS_IMAGE_2, from_get=True)
                           if os_id == fakes.ID_OS_IMAGE_2 else
                           None))


class ImagePrivateTestCase(base.BaseTestCase):

    def test_format_image(self):
        image_ids = {fakes.ID_OS_IMAGE_1: fakes.ID_EC2_IMAGE_1,
                     fakes.ID_OS_IMAGE_AKI_1: fakes.ID_EC2_IMAGE_AKI_1,
                     fakes.ID_OS_IMAGE_ARI_1: fakes.ID_EC2_IMAGE_ARI_1}
        os_image = {'id': fakes.ID_OS_IMAGE_1,
                    'owner': fakes.ID_OS_PROJECT,
                    'created_at': fakes.TIME_CREATE_IMAGE,
                    'visibility': 'private',
                    'status': 'active',
                    'container_format': 'ami',
                    'name': 'fake_name'}

        # check name and location attributes for an unnamed image
        os_image['image_location'] = 'location'
        os_image['name'] = None

        image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, fakes.OSImage(os_image),
                None, image_ids)

        self.assertEqual('location', image['imageLocation'])
        self.assertEqual('location', image['name'])

        # check name and location attributes for complete image
        os_image['image_location'] = None
        os_image['name'] = 'fake_name'

        image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, fakes.OSImage(os_image),
                None, image_ids)

        self.assertEqual('None (fake_name)', image['imageLocation'])
        self.assertEqual('fake_name', image['name'])

        # check ebs image type for bdm_v2 mapping type
        os_image['bdm_v2'] = True
        os_image['root_device_name'] = '/dev/vda'
        os_image['block_device_mapping'] = [
            {'boot_index': 0,
             'snapshot_id': fakes.ID_OS_SNAPSHOT_2,
             'source_type': 'snapshot',
             'destination_type': 'volume'}]

        image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, fakes.OSImage(os_image),
                None, image_ids,
                snapshot_ids={fakes.ID_OS_SNAPSHOT_2: fakes.ID_EC2_SNAPSHOT_2})

        self.assertEqual('ebs', image['rootDeviceType'])

        # check instance-store image attributes with no any device mappings
        os_image['bdm_v2'] = False
        os_image['root_device_name'] = '/dev/vda'
        os_image['block_device_mapping'] = []
        image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, fakes.OSImage(os_image),
                None, None)

        self.assertEqual('instance-store', image['rootDeviceType'])
        self.assertNotIn('blockDeviceMapping', image)

        # check Glance status translation
        os_image = fakes.OSImage({'id': fakes.ID_OS_IMAGE_1})

        def check_status_translation(status, expected):
            os_image.status = status
            image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, os_image, None, None)
            self.assertEqual(expected, image['imageState'],
                             "Wrong '%s' Glance status translation" % status)
        check_status_translation('queued', 'pending')
        check_status_translation('saving', 'pending')
        check_status_translation('active', 'available')
        check_status_translation('killed', 'deregistered')
        check_status_translation('pending_delete', 'deregistered')
        check_status_translation('deleted', 'deregistered')
        check_status_translation('deactivated', 'invalid')
        check_status_translation('unknown-status', 'error')

        # check internal state translation
        os_image.status = 'queued'

        def check_state_translation(state, expected):
            os_image.image_state = state
            image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, os_image, None, None)
            self.assertEqual(expected, image['imageState'],
                             "Wrong '%s' internal state translation" % state)

        for state in ('downloading', 'decrypting', 'untarring', 'uploading'):
            check_state_translation(state, 'pending')
        for state in ('failed_download', 'failed_decrypt', 'failed_untar',
                      'failed_upload'):
            check_state_translation(state, 'failed')
        os_image.status = 'active'
        check_state_translation('available', 'available')
        check_state_translation('unknown-state', 'available')

    def test_format_mappings(self):
        db_api = self.mock_db()
        # check virtual mapping formatting
        properties = {
            'mappings': [
                {'virtual': 'ami', 'device': '/dev/sda'},
                {'virtual': 'root', 'device': 'sda'},
                {'virtual': 'ephemeral0', 'device': 'sdb'},
                {'virtual': 'swap', 'device': 'sdc'},
                {'virtual': 'ephemeral1', 'device': 'sdd'},
                {'virtual': 'ephemeral2', 'device': 'sde'},
                {'virtual': 'ephemeral', 'device': 'sdf'},
                {'virtual': '/dev/sdf1', 'device': 'root'}],
        }
        expected = [
            {'virtualName': 'ephemeral0', 'deviceName': '/dev/sdb'},
            {'virtualName': 'swap', 'deviceName': '/dev/sdc'},
            {'virtualName': 'ephemeral1', 'deviceName': '/dev/sdd'},
            {'virtualName': 'ephemeral2', 'deviceName': '/dev/sde'},
        ]

        result = image_api._format_mappings('fake_context', properties)
        self.assertEqual(expected, result)

        # check bdm v2 formatting
        db_api.set_mock_items(fakes.DB_IMAGE_2, fakes.DB_VOLUME_3)
        properties = {
            'bdm_v2': True,
            'block_device_mapping': [
                {'boot_index': 0,
                 'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
                 'source_type': 'snapshot',
                 'destination_type': 'volume'},
                {'boot_index': None,
                 'snapshot_id': fakes.ID_OS_SNAPSHOT_2,
                 'source_type': 'snapshot',
                 'destination_type': 'volume'},
                {'device_name': 'vdi',
                 'boot_index': -1,
                 'image_id': fakes.ID_OS_IMAGE_2,
                 'source_type': 'image',
                 'destination_type': 'volume',
                 'volume_size': 20},
                {'device_name': 'vdv',
                 'boot_index': -1,
                 'volume_id': fakes.ID_OS_VOLUME_3,
                 'source_type': 'volume',
                 'destination_type': 'volume'},
                {'device_name': 'vdb',
                 'boot_index': -1,
                 'source_type': 'blank',
                 'destination_type': 'volume',
                 'volume_size': 100,
                 'delete_on_termination': True},
            ],
        }
        expected = [
            {'deviceName': 'vdx',
             'ebs': {'snapshotId': fakes.ID_EC2_SNAPSHOT_1,
                     'deleteOnTermination': False}},
            {'ebs': {'snapshotId': fakes.ID_EC2_SNAPSHOT_2,
                     'deleteOnTermination': False}},
            {'deviceName': 'vdi',
             'ebs': {'snapshotId': fakes.ID_EC2_IMAGE_2,
                     'volumeSize': 20,
                     'deleteOnTermination': False}},
            {'deviceName': 'vdv',
             'ebs': {'snapshotId': fakes.ID_EC2_VOLUME_3,
                     'deleteOnTermination': False}},
            {'deviceName': 'vdb',
             'ebs': {'volumeSize': 100,
                     'deleteOnTermination': True}},
        ]
        result = image_api._format_mappings(
            'fake_context', properties, root_device_name='vdx',
            snapshot_ids={fakes.ID_OS_SNAPSHOT_1: fakes.ID_EC2_SNAPSHOT_1,
                          fakes.ID_OS_SNAPSHOT_2: fakes.ID_EC2_SNAPSHOT_2})
        self.assertEqual(expected, result)

        # check inheritance and generation of virtual name
        properties = {
            'mappings': [
                {'device': 'vdd', 'virtual': 'ephemeral1'},
            ],
            'bdm_v2': True,
            'block_device_mapping': [
                {'device_name': '/dev/vdb',
                 'source_type': 'blank',
                 'destination_type': 'local',
                 'guest_format': 'swap'},
                {'device_name': 'vdc',
                 'source_type': 'blank',
                 'destination_type': 'local',
                 'volume_size': 5},
                {'device_name': 'vde',
                 'source_type': 'blank',
                 'destination_type': 'local'},
            ],
        }
        expected = [
            {'deviceName': '/dev/vdd', 'virtualName': 'ephemeral1'},
            {'deviceName': '/dev/vdb', 'virtualName': 'swap'},
            {'deviceName': 'vdc', 'virtualName': 'ephemeral0'},
            {'deviceName': 'vde', 'virtualName': 'ephemeral2'},
        ]
        result = image_api._format_mappings('fake_context', properties)
        self.assertEqual(expected, result)

    def test_get_db_items(self):
        describer = image_api.ImageDescriber()
        describer.context = base.create_context()

        # NOTE(ft): the first requested image appears is user owend and public,
        # the second is absent
        db_api = self.mock_db()
        db_api.set_mock_items(fakes.DB_IMAGE_1)

        describer.ids = set([fakes.ID_EC2_IMAGE_1, fakes.ID_EC2_IMAGE_2])
        self.assertRaises(exception.InvalidAMIIDNotFound,
                          describer.get_db_items)

    def test_describe_images_being_created(self):
        db_api = self.mock_db()
        glance = self.mock_glance()
        context = base.create_context()
        image_id = fakes.random_ec2_id('ami')
        image = {'id': image_id,
                 'os_id': None,
                 'is_public': False,
                 'description': 'fake desc'}
        db_api.set_mock_items(image)
        db_api.get_public_items.return_value = []

        # describe cases when no glance image exists
        glance.images.list.return_value = []
        expected = {'imagesSet': [{'imageId': image_id,
                                   'description': 'fake desc',
                                   'imageOwnerId': fakes.ID_OS_PROJECT,
                                   'imageState': 'pending',
                                   'imageType': 'machine',
                                   'isPublic': False}]}

        # describe all images
        result = image_api.describe_images(context)
        self.assertEqual(expected, result)

        # describe the image
        result = image_api.describe_images(context, image_id=[image_id])
        self.assertEqual(expected, result)

        # describe with filter
        result = image_api.describe_images(
            context, filter=[{'name': 'name', 'value': 'noname'}])
        self.assertEqual({'imagesSet': []}, result)

        # describe failed image
        image['state'] = 'failed'
        expected['imagesSet'][0]['imageState'] = 'failed'
        result = image_api.describe_images(base.create_context())
        self.assertEqual(expected, result)

        # describe cases when glance image exists, db item is yet not updated
        del image['state']
        os_image_id = fakes.random_os_id()
        os_image = {'id': os_image_id,
                    'owner': fakes.ID_OS_PROJECT,
                    'status': 'active',
                    'visibility': 'private',
                    'ec2_id': image_id}
        glance.images.list.return_value = [fakes.OSImage(os_image)]
        expected['imagesSet'] = [{
            'architecture': None,
            'creationDate': None,
            'description': 'fake desc',
            'imageId': image_id,
            'imageLocation': 'None (None)',
            'imageOwnerId': fakes.ID_OS_PROJECT,
            'imageState': 'available',
            'imageType': 'machine',
            'isPublic': False,
            'name': None,
            'rootDeviceType': 'instance-store'}]

        # describe all images
        result = image_api.describe_images(context)
        self.assertEqual(expected, result)
        db_api.update_item.assert_called_once_with(
            context, tools.update_dict(image, {'os_id': os_image_id}))

        # describe the image
        db_api.reset_mock()
        result = image_api.describe_images(context, image_id=[image_id])
        self.assertEqual(expected, result)
        db_api.update_item.assert_called_once_with(
            context, tools.update_dict(image, {'os_id': os_image_id}))


class S3TestCase(base.BaseTestCase):

    def test_s3_parse_manifest(self):
        db_api = self.mock_db()
        glance = self.mock_glance()
        db_api.set_mock_items(fakes.DB_IMAGE_AKI_1, fakes.DB_IMAGE_ARI_1)
        glance.images.get.side_effect = (
            tools.get_by_1st_arg_getter({
                fakes.ID_OS_IMAGE_AKI_1: fakes.OSImage(fakes.OS_IMAGE_AKI_1),
                fakes.ID_OS_IMAGE_ARI_1: fakes.OSImage(fakes.OS_IMAGE_ARI_1)}))

        metadata, image_parts, key, iv = image_api._s3_parse_manifest(
            base.create_context(), AMI_MANIFEST_XML)

        expected_metadata = {
            'disk_format': 'ami',
            'container_format': 'ami',
            'architecture': 'x86_64',
            'kernel_id': fakes.ID_OS_IMAGE_AKI_1,
            'ramdisk_id': fakes.ID_OS_IMAGE_ARI_1,
            'mappings': [
                {"device": "sda1", "virtual": "ami"},
                {"device": "/dev/sda1", "virtual": "root"},
                {"device": "sda2", "virtual": "ephemeral0"},
                {"device": "sda3", "virtual": "swap"}]}
        self.assertThat(metadata,
                        matchers.DictMatches(expected_metadata,
                                             orderless_lists=True))
        self.assertThat(image_parts,
                        matchers.ListMatches(['foo']))
        self.assertEqual('foo', key)
        self.assertEqual('foo', iv)
        db_api.get_items_ids.assert_any_call(
            mock.ANY, 'aki', item_ids=(fakes.ID_EC2_IMAGE_AKI_1,),
            item_os_ids=None)
        db_api.get_items_ids.assert_any_call(
            mock.ANY, 'ari', item_ids=(fakes.ID_EC2_IMAGE_ARI_1,),
            item_os_ids=None)

    def test_s3_create_image_locations(self):
        self.configure(image_decryption_dir=None)
        glance = self.mock_glance()
        _handle, tempf = tempfile.mkstemp()
        fake_context = base.create_context()

        @mock.patch('ec2api.api.image._s3_untarzip_image')
        @mock.patch('ec2api.api.image._s3_decrypt_image')
        @mock.patch('ec2api.api.image._s3_download_file')
        @mock.patch('ec2api.api.image._s3_conn')
        def do_test(s3_conn, s3_download_file, s3_decrypt_image,
                    s3_untarzip_image):
            (s3_conn.return_value.
             get_object.return_value) = {'Body': FILE_MANIFEST_XML}
            s3_download_file.return_value = tempf
            s3_untarzip_image.return_value = tempf
            os_image_id = fakes.random_os_id()
            (glance.images.create.return_value) = (
                fakes.OSImage({'id': os_image_id,
                               'status': 'queued'}))

            data = [
                ({'image_location': 'testbucket_1/test.img.manifest.xml'},
                 'testbucket_1', 'test.img.manifest.xml'),
                ({'image_location': '/testbucket_2/test.img.manifest.xml'},
                 'testbucket_2', 'test.img.manifest.xml')]
            for mdata, bucket, manifest in data:
                image = image_api._s3_create(fake_context, mdata)
                eventlet.sleep()
                self.glance.images.update.assert_called_with(
                    os_image_id, image_state='available')
                self.glance.images.upload.assert_any_call(
                    os_image_id, mock.ANY)
                s3_conn.return_value.get_object.assert_called_with(
                    Bucket=bucket, Key=manifest)
                s3_download_file.assert_called_with(
                    mock.ANY, bucket, 'foo', mock.ANY)
                s3_decrypt_image.assert_called_with(
                    fake_context, mock.ANY, 'foo', 'foo', mock.ANY)
                s3_untarzip_image.assert_called_with(mock.ANY, mock.ANY)

            do_test()

    @mock.patch('ec2api.api.image.eventlet.spawn_n')
    def test_s3_create_bdm(self, spawn_n):
        glance = self.mock_glance()
        metadata = {'image_location': 'fake_bucket/fake_manifest',
                    'root_device_name': '/dev/sda1',
                    'block_device_mapping': [
                        {'device_name': '/dev/sda1',
                         'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
                         'delete_on_termination': True},
                        {'device_name': '/dev/sda2',
                         'virtual_name': 'ephemeral0'},
                        {'device_name': '/dev/sdb0',
                         'no_device': True}]}
        fake_context = base.create_context()
        with mock.patch('ec2api.api.image._s3_conn') as s3_conn:

            (s3_conn.return_value.
             get_object.return_value) = {'Body': FILE_MANIFEST_XML}

            image_api._s3_create(fake_context, metadata)

            glance.images.create.assert_called_once_with(
                disk_format='ami', container_format='ami',
                visibility='private', architecture='x86_64',
                image_state='pending', root_device_name='/dev/sda1',
                block_device_mapping=[{'device_name': '/dev/sda1',
                                       'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
                                       'delete_on_termination': True},
                                      {'device_name': '/dev/sda2',
                                       'virtual_name': 'ephemeral0'},
                                      {'device_name': '/dev/sdb0',
                                       'no_device': True}],
                image_location='fake_bucket/fake_manifest')

    def test_s3_malicious_tarballs(self):
        self.assertRaises(
            exception.EC2InvalidException,
            image_api._s3_test_for_malicious_tarball,
            "/unused", os.path.join(os.path.dirname(__file__), 'abs.tar.gz'))
        self.assertRaises(
            exception.EC2InvalidException,
            image_api._s3_test_for_malicious_tarball,
            "/unused", os.path.join(os.path.dirname(__file__), 'rel.tar.gz'))

    def test_decrypt_text(self):
        public_key = os.path.join(os.path.dirname(__file__), 'test_cert.pem')
        private_key = os.path.join(os.path.dirname(__file__),
                                   'test_private_key.pem')
        subject = "/C=RU/ST=Moscow/L=Moscow/O=Progmatic/CN=RootCA"
        certificate_file = processutils.execute('openssl',
                                                'req', '-x509', '-new',
                                                '-key', private_key,
                                                '-days', '365',
                                                '-out', public_key,
                                                '-subj', subject)
        text = "some @#!%^* test text"
        process_input = text.encode("ascii") if six.PY3 else text
        enc, _err = processutils.execute('openssl',
                                         'rsautl',
                                         '-certin',
                                         '-encrypt',
                                         '-inkey', public_key,
                                         process_input=process_input,
                                         binary=True)
        self.assertRaises(exception.EC2Exception, image_api._decrypt_text, enc)
        self.configure(x509_root_private_key=private_key)
        dec = image_api._decrypt_text(enc)
        self.assertIsInstance(dec, bytes)
        if six.PY3:
            dec = dec.decode('ascii')
        self.assertEqual(text, dec)
