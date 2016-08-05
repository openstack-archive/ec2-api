# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
"""
Unittets for S3 objectstore clone.
"""
from botocore import exceptions as botocore_exception
import botocore.session
import fixtures
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslotest import base as test_base

from ec2api.s3 import s3server

CONF = cfg.CONF


class S3APITestCase(test_base.BaseTestCase):
    """Test objectstore through S3 API."""

    def setUp(self):
        """Setup users, projects, and start a test server."""
        super(S3APITestCase, self).setUp()
        tempdir = self.useFixture(fixtures.TempDir())
        conf = self.useFixture(config_fixture.Config())
        conf.config(buckets_path=tempdir.path,
                    s3_listen='127.0.0.1',
                    s3_listen_port=0)

        self.server = s3server.get_wsgi_server()
        # NOTE(ft): this requires eventlet.monkey_patch, which is called in
        # tests/unit/__init__.py. Remove it out from there if you get these
        # tests rid of server run
        self.server.start()
        self.addCleanup(self.server.stop)

        s3_url = 'http://' + CONF.s3_listen + ':' + str(self.server.port)
        region = 'FakeRegion'
        connection_data = {
            'config_file': (None, 'AWS_CONFIG_FILE', None, None),
            'region': ('region', 'BOTO_DEFAULT_REGION', region, None),
        }
        session = botocore.session.get_session(connection_data)
        conn = session.create_client(
            's3', region_name=region, endpoint_url=s3_url,
            aws_access_key_id='fake', aws_secret_access_key='fake')
        self.conn = conn

        def get_http_connection(*args):
            """Get a new S3 connection, don't attempt to reuse connections."""
            return self.conn.new_http_connection(*args)

        self.conn.get_http_connection = get_http_connection

    def _ensure_no_buckets(self, buckets):
        self.assertEqual(len(buckets['Buckets']), 0,
                         "Bucket list was not empty")
        return True

    def _ensure_one_bucket(self, buckets, name):
        self.assertEqual(len(buckets['Buckets']), 1,
                         "Bucket list didn't have exactly one element in it")
        self.assertEqual(buckets['Buckets'][0]['Name'], name, "Wrong name")
        return True

    def test_list_buckets(self):
        # Make sure we started with no buckets.
        self._ensure_no_buckets(self.conn.list_buckets())

    def test_create_and_delete_bucket(self):
        # Test bucket creation and deletion.
        bucket_name = 'testbucket'

        self.conn.create_bucket(Bucket=bucket_name)
        self._ensure_one_bucket(self.conn.list_buckets(), bucket_name)
        self.conn.delete_bucket(Bucket=bucket_name)
        self._ensure_no_buckets(self.conn.list_buckets())

    def test_create_bucket_and_key_and_delete_key(self):
        # Test key operations on buckets.
        bucket_name = 'testbucket'
        key_name = 'somekey'
        key_contents = b'somekey'

        self.conn.create_bucket(Bucket=bucket_name)
        self.conn.put_object(Bucket=bucket_name, Key=key_name,
                             Body=key_contents)

        # make sure the contents are correct
        key = self.conn.get_object(Bucket=bucket_name, Key=key_name)
        self.assertEqual(key['Body'].read(), key_contents,
                         "Bad contents")

        # delete the key
        self.conn.delete_object(Bucket=bucket_name, Key=key_name)

        self.assertRaises(botocore_exception.ClientError, self.conn.get_object,
                          Bucket=bucket_name, Key=key_name)

    def test_unknown_bucket(self):
        bucket_name = 'falalala'
        self.assertRaises(botocore_exception.ClientError,
                          self.conn.head_bucket,
                          Bucket=bucket_name)
        self.assertRaises(botocore_exception.ClientError,
                          self.conn.list_objects,
                          Bucket=bucket_name, MaxKeys=0)
