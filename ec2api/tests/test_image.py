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

import copy
import os
import tempfile

import eventlet
import mock
from oslo.config import cfg
from oslotest import base as test_base

from ec2api.api import image as image_api
from ec2api import exception
from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


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

    @mock.patch('ec2api.api.image._s3_create')
    def test_register_image(self, s3_create):
        s3_create.return_value = fakes.OSImage(fakes.OS_IMAGE_1)
        self.db_api.add_item.side_effect = (
            fakes.get_db_api_add_item(fakes.ID_EC2_IMAGE_1))

        resp = self.execute(
            'RegisterImage',
            {'ImageLocation': fakes.LOCATION_IMAGE_1})
        self.assertThat(resp, matchers.DictMatches(
            {'status': 200,
            'imageId': fakes.ID_EC2_IMAGE_1}))

        s3_create.assert_called_once_with(
            mock.ANY,
            {'name': fakes.LOCATION_IMAGE_1,
             'properties': {'image_location': fakes.LOCATION_IMAGE_1}})
        s3_create.reset_mock()

        resp = self.execute(
            'RegisterImage',
            {'ImageLocation': fakes.LOCATION_IMAGE_1,
             'Name': 'an image name'})
        self.assertThat(resp, matchers.DictMatches(
            {'status': 200,
            'imageId': fakes.ID_EC2_IMAGE_1}))

        s3_create.assert_called_once_with(
            mock.ANY,
            {'name': 'an image name',
             'properties': {'image_location': fakes.LOCATION_IMAGE_1}})

    def test_register_image_invalid_parameters(self):
        resp = self.execute('RegisterImage', {})
        self.assertEqual(400, resp['status'])
        self.assertEqual('MissingParameter', resp['Error']['Code'])

    def test_deregister_image(self):
        self._setup_model()

        resp = self.execute('DeregisterImage',
                            {'ImageId': fakes.ID_EC2_IMAGE_1})
        self.assertThat(resp, matchers.DictMatches({'status': 200,
                                                    'return': True}))
        self.db_api.delete_item.assert_called_once_with(
            mock.ANY, fakes.ID_EC2_IMAGE_1)
        self.glance.images.delete.assert_called_once_with(
            fakes.ID_OS_IMAGE_1)

    def test_deregister_image_invalid_parameters(self):
        self._setup_model()

        resp = self.execute('DeregisterImage',
                            {'ImageId': fakes.random_ec2_id('ami')})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidAMIID.NotFound', resp['Error']['Code'])

    def test_describe_images(self):
        self._setup_model()

        resp = self.execute('DescribeImages', {})
        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.assertThat(resp, matchers.DictMatches(
            {'imagesSet': [fakes.EC2_IMAGE_1, fakes.EC2_IMAGE_2]},
            orderless_lists=True))

        self.db_api.get_items_by_ids.assert_any_call(mock.ANY, 'ami', set([]))

        self.db_api.get_items_by_ids = tools.CopyingMock(
            side_effect=self.db_api.get_items_by_ids.side_effect)

        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.ID_EC2_IMAGE_1})
        self.assertEqual(200, resp['status'])
        resp.pop('status')
        self.assertThat(resp, matchers.DictMatches(
            {'imagesSet': [fakes.EC2_IMAGE_1]},
            orderless_lists=True))

        self.db_api.get_items_by_ids.assert_any_call(
            mock.ANY, 'ami', set([fakes.ID_EC2_IMAGE_1]))

    def test_describe_images_invalid_parameters(self):
        self._setup_model()

        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.random_ec2_id('ami')})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidAMIID.NotFound', resp['Error']['Code'])

        self.glance.images.list.side_effect = lambda: []

        resp = self.execute('DescribeImages',
                            {'ImageId.1': fakes.ID_EC2_IMAGE_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidAMIID.NotFound', resp['Error']['Code'])

    def test_describe_image_attributes(self):
        self._setup_model()

        def do_check(attr, ec2_image_id, response):
            self.db_api.reset_mock()
            self.glance.reset_mock()
            resp = self.execute('DescribeImageAttribute',
                                {'ImageId': ec2_image_id,
                                 'Attribute': attr})
            response['status'] = 200
            response['imageId'] = ec2_image_id
            self.assertThat(resp, matchers.DictMatches(response,
                                                       orderless_lists=True))

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
                 {'blockDeviceMapping':
                        fakes.EC2_IMAGE_1['blockDeviceMapping']})

        do_check('blockDeviceMapping',
                 fakes.ID_EC2_IMAGE_2,
                 {'blockDeviceMapping':
                        fakes.EC2_IMAGE_2['blockDeviceMapping']})

    @mock.patch.object(fakes.OSImage, 'update', autospec=True)
    def test_modify_image_attributes(self, osimage_update):
        self._setup_model()

        resp = self.execute('ModifyImageAttribute',
                            {'imageId': fakes.ID_EC2_IMAGE_1,
                             'attribute': 'launchPermission',
                             'operationType': 'add',
                             'userGroup.1': 'all'})
        self.assertThat(resp, matchers.DictMatches({'status': 200,
                                                    'return': True}))
        osimage_update.assert_called_once_with(
                mock.ANY, is_public=True)
        self.assertEqual(fakes.ID_OS_IMAGE_1,
                         osimage_update.call_args[0][0].id)

    def _setup_model(self):
        self.db_api.get_item_by_id.side_effect = (
            fakes.get_db_api_get_item_by_id({
                fakes.ID_EC2_IMAGE_1: fakes.DB_IMAGE_1,
                fakes.ID_EC2_IMAGE_2: fakes.DB_IMAGE_2}))
        self.db_api.get_items_by_ids.side_effect = (
            fakes.get_db_api_get_items({
                'ami': [fakes.DB_IMAGE_1, fakes.DB_IMAGE_2],
                'ari': [],
                'aki': []}))
        self.db_api.get_items.side_effect = (
            fakes.get_db_api_get_items({
                'snap': [fakes.DB_SNAPSHOT_1, fakes.DB_SNAPSHOT_2]}))
        self.db_api.get_public_items.return_value = []

        self.db_api.get_item_ids.side_effect = (
            fakes.get_db_api_get_item_by_id({
                (fakes.ID_OS_IMAGE_ARI_1,): [(fakes.ID_EC2_IMAGE_ARI_1,
                                              fakes.ID_OS_IMAGE_ARI_1)],
                (fakes.ID_OS_IMAGE_AKI_1,): [(fakes.ID_EC2_IMAGE_AKI_1,
                                              fakes.ID_OS_IMAGE_AKI_1)],
                (fakes.ID_OS_SNAPSHOT_1,): [(fakes.ID_EC2_SNAPSHOT_1,
                                             fakes.ID_OS_SNAPSHOT_1)],
                (fakes.ID_OS_SNAPSHOT_2,): [(fakes.ID_EC2_SNAPSHOT_2,
                                             fakes.ID_OS_SNAPSHOT_2)],
                (fakes.ID_OS_VOLUME_1,): [(fakes.ID_EC2_VOLUME_1,
                                           fakes.ID_OS_VOLUME_1)],
                (fakes.ID_OS_VOLUME_2,): [(fakes.ID_EC2_VOLUME_2,
                                           fakes.ID_OS_VOLUME_2)]}))

        self.glance.images.list.side_effect = (
            lambda: [fakes.OSImage(fakes.OS_IMAGE_1),
                     fakes.OSImage(fakes.OS_IMAGE_2)])
        self.glance.images.get.side_effect = (
            lambda os_id: (fakes.OSImage(fakes.OS_IMAGE_1)
                           if os_id == fakes.ID_OS_IMAGE_1 else
                           fakes.OSImage(fakes.OS_IMAGE_2)
                           if os_id == fakes.ID_OS_IMAGE_2 else
                           None))


class ImagePrivateTestCase(test_base.BaseTestCase):

    def test_format_image(self):
        image_ids = {fakes.ID_OS_IMAGE_1: fakes.ID_EC2_IMAGE_1,
                     fakes.ID_OS_IMAGE_AKI_1: fakes.ID_EC2_IMAGE_AKI_1,
                     fakes.ID_OS_IMAGE_ARI_1: fakes.ID_EC2_IMAGE_ARI_1}

        os_image = copy.deepcopy(fakes.OS_IMAGE_1)
        os_image['properties'] = {'image_location': 'location'}
        os_image['name'] = None

        image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, fakes.OSImage(os_image),
                None, image_ids)

        self.assertEqual('location', image['imageLocation'])
        self.assertEqual('location', image['name'])

        os_image['properties'] = {}
        os_image['name'] = 'fake_name'

        image = image_api._format_image(
                'fake_context', fakes.DB_IMAGE_1, fakes.OSImage(os_image),
                None, image_ids)

        self.assertEqual('None (fake_name)', image['imageLocation'])
        self.assertEqual('fake_name', image['name'])

    def test_cloud_format_mappings(self):
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
        expected = {
            'blockDeviceMapping': [
                {'virtualName': 'ephemeral0', 'deviceName': '/dev/sdb'},
                {'virtualName': 'swap', 'deviceName': '/dev/sdc'},
                {'virtualName': 'ephemeral1', 'deviceName': '/dev/sdd'},
                {'virtualName': 'ephemeral2', 'deviceName': '/dev/sde'},
            ]
        }

        result = {}
        image_api._cloud_format_mappings('fake_context', properties, result)

        self.assertThat(result,
                        matchers.DictMatches(expected, orderless_lists=True))

    def test_block_device_properties_root_device_name(self):
        root_device0 = '/dev/sda'
        root_device1 = '/dev/sdb'
        mappings = [{'virtual': 'root',
                     'device': root_device0}]

        properties0 = {'mappings': mappings}
        properties1 = {'mappings': mappings,
                       'root_device_name': root_device1}

        self.assertIsNone(
            image_api._block_device_properties_root_device_name({}))
        self.assertEqual(
            image_api._block_device_properties_root_device_name(properties0),
            root_device0)
        self.assertEqual(
            image_api._block_device_properties_root_device_name(properties1),
            root_device1)


class S3TestCase(base.ApiTestCase):
    # TODO(ft): 'execute' feature isn't used here, but some mocks and
    # fake context are. ApiTestCase should be split to some classes to use
    # its feature optimally

    def test_s3_parse_manifest(self):
        self.db_api.get_public_items.side_effect = (
            fakes.get_db_api_get_items({
                'aki': ({'id': fakes.ID_EC2_IMAGE_AKI_1,
                         'os_id': fakes.ID_OS_IMAGE_AKI_1},),
                'ari': ({'id': fakes.ID_EC2_IMAGE_ARI_1,
                         'os_id': fakes.ID_OS_IMAGE_ARI_1},)}))
        self.db_api.get_item_by_id.return_value = None

        fake_context = self._create_context()
        metadata, image_parts, key, iv = image_api._s3_parse_manifest(
            fake_context, AMI_MANIFEST_XML)

        expected_metadata = {
            'disk_format': 'ami',
            'container_format': 'ami',
            'properties': {'architecture': 'x86_64',
                           'kernel_id': fakes.ID_OS_IMAGE_AKI_1,
                           'ramdisk_id': fakes.ID_OS_IMAGE_ARI_1,
                           'mappings': [
                                {"device": "sda1", "virtual": "ami"},
                                {"device": "/dev/sda1", "virtual": "root"},
                                {"device": "sda2", "virtual": "ephemeral0"},
                                {"device": "sda3", "virtual": "swap"}]}}
        self.assertThat(metadata,
                        matchers.DictMatches(expected_metadata,
                                             orderless_lists=True))
        self.assertThat(image_parts,
                        matchers.ListMatches(['foo']))
        self.assertEqual('foo', key)
        self.assertEqual('foo', iv)
        self.db_api.get_public_items.assert_any_call(
            mock.ANY, 'aki', (fakes.ID_EC2_IMAGE_AKI_1,))
        self.db_api.get_public_items.assert_any_call(
            mock.ANY, 'ari', (fakes.ID_EC2_IMAGE_ARI_1,))

    @mock.patch.object(fakes.OSImage, 'update', autospec=True)
    def test_s3_create_image_locations(self, osimage_update):
        conf = cfg.CONF
        conf.set_override('image_decryption_dir', None)
        self.addCleanup(conf.reset)
        _handle, tempf = tempfile.mkstemp()
        fake_context = self._create_context()
        with mock.patch(
                'ec2api.api.image._s3_conn') as s3_conn, mock.patch(
                'ec2api.api.image._s3_download_file'
                    ) as s3_download_file, mock.patch(
                'ec2api.api.image._s3_decrypt_image'
                    ) as s3_decrypt_image, mock.patch(
                'ec2api.api.image._s3_untarzip_image'
                    ) as s3_untarzip_image:

            (s3_conn.return_value.
             get_bucket.return_value.
             get_key.return_value.
             get_contents_as_string.return_value) = FILE_MANIFEST_XML
            s3_download_file.return_value = tempf
            s3_untarzip_image.return_value = tempf
            (self.glance.images.create.return_value) = (
                fakes.OSImage({'id': fakes.random_os_id(),
                               'owner': fakes.ID_OS_PROJECT,
                               'is_public': False,
                               'status': 'queued',
                               'container_format': 'ami',
                               'name': 'fake_name',
                               'properties': {}}))

            data = [
                ({'properties': {
                    'image_location': 'testbucket_1/test.img.manifest.xml'}},
                 'testbucket_1', 'test.img.manifest.xml'),
                ({'properties': {
                    'image_location': '/testbucket_2/test.img.manifest.xml'}},
                 'testbucket_2', 'test.img.manifest.xml')]
            for mdata, bucket, manifest in data:
                image = image_api._s3_create(fake_context, mdata)
                eventlet.sleep()
                osimage_update.assert_called_with(
                    image, properties={'image_state': 'available'})
                osimage_update.assert_any_call(
                    image, data=mock.ANY)
                s3_conn.return_value.get_bucket.assert_called_with(bucket)
                (s3_conn.return_value.get_bucket.return_value.
                 get_key.assert_called_with(manifest))
                (s3_conn.return_value.get_bucket.return_value.
                 get_key.return_value.
                 get_contents_as_string.assert_called_with())
                s3_download_file.assert_called_with(
                    s3_conn.return_value.get_bucket.return_value,
                    'foo', mock.ANY)
                s3_decrypt_image.assert_called_with(
                    fake_context, mock.ANY, 'foo', 'foo', mock.ANY)
                s3_untarzip_image.assert_called_with(mock.ANY, mock.ANY)

    @mock.patch('ec2api.api.image.eventlet.spawn_n')
    def test_s3_create_bdm(self, spawn_n):
        metadata = {'properties': {
                        'image_location': 'fake_bucket/fake_manifest',
                        'root_device_name': '/dev/sda1',
                        'block_device_mapping': [
                            {'device_name': '/dev/sda1',
                             'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
                             'delete_on_termination': True},
                            {'device_name': '/dev/sda2',
                             'virtual_name': 'ephemeral0'},
                            {'device_name': '/dev/sdb0',
                             'no_device': True}]}}
        fake_context = self._create_context()
        with mock.patch(
                'ec2api.api.image._s3_conn') as s3_conn:

            (s3_conn.return_value.
             get_bucket.return_value.
             get_key.return_value.
             get_contents_as_string.return_value) = FILE_MANIFEST_XML

            image_api._s3_create(fake_context, metadata)

            self.glance.images.create.assert_called_once_with(
                disk_format='ami', container_format='ami', is_public=False,
                properties={'architecture': 'x86_64',
                            'image_state': 'pending',
                            'root_device_name': '/dev/sda1',
                            'block_device_mapping': [
                                {'device_name': '/dev/sda1',
                                 'snapshot_id': fakes.ID_OS_SNAPSHOT_1,
                                 'delete_on_termination': True},
                                {'device_name': '/dev/sda2',
                                 'virtual_name': 'ephemeral0'},
                                {'device_name': '/dev/sdb0',
                                 'no_device': True}],
                            'image_location': 'fake_bucket/fake_manifest'})

    def test_s3_malicious_tarballs(self):
        self.assertRaises(exception.Invalid,
            image_api._s3_test_for_malicious_tarball,
            "/unused", os.path.join(os.path.dirname(__file__), 'abs.tar.gz'))
        self.assertRaises(exception.Invalid,
            image_api._s3_test_for_malicious_tarball,
            "/unused", os.path.join(os.path.dirname(__file__), 'rel.tar.gz'))
