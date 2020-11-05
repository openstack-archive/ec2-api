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

import base64

from novaclient import exceptions as nova_exception

from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class KeyPairCase(base.ApiTestCase):

    def test_create_key_pair(self):
        """
        Create a new key pair.

        Args:
            self: (todo): write your description
        """
        self.nova.keypairs.create.return_value = (
            fakes.NovaKeyPair(fakes.OS_KEY_PAIR))
        resp = self.execute('CreateKeyPair', {'KeyName': fakes.NAME_KEY_PAIR})
        self.assertThat(fakes.EC2_KEY_PAIR, matchers.DictMatches(resp))
        self.nova.keypairs.create.assert_called_once_with(fakes.NAME_KEY_PAIR)

    def test_create_key_pair_invalid(self):
        """
        Create a new key pair in the key pair.

        Args:
            self: (todo): write your description
        """
        self.nova.keypairs.create.side_effect = (
            nova_exception.Conflict(409))
        self.assert_execution_error(
            'InvalidKeyPair.Duplicate', 'CreateKeyPair',
            {'KeyName': fakes.NAME_KEY_PAIR})
        self.assert_execution_error(
            'ValidationError', 'CreateKeyPair', {'KeyName': 'k' * 256})
        self.nova.keypairs.create.side_effect = (
            nova_exception.OverLimit(413))
        self.assert_execution_error(
            'ResourceLimitExceeded', 'CreateKeyPair',
            {'KeyName': fakes.NAME_KEY_PAIR})

    def test_import_key_pair(self):
        """
        Purpose a key pair.

        Args:
            self: (todo): write your description
        """
        self.nova.keypairs.create.return_value = (
            fakes.NovaKeyPair(fakes.OS_KEY_PAIR))
        resp = self.execute('ImportKeyPair',
                            {'KeyName': fakes.NAME_KEY_PAIR,
                             'PublicKeyMaterial': base64.b64encode(
                                 fakes.PUBLIC_KEY_KEY_PAIR.encode("ascii")
                             ).decode("ascii")})
        self.assertThat(
            tools.purge_dict(fakes.EC2_KEY_PAIR, {'keyMaterial'}),
            matchers.DictMatches(resp))
        self.nova.keypairs.create.assert_called_once_with(
            fakes.NAME_KEY_PAIR, fakes.PUBLIC_KEY_KEY_PAIR)

    def test_import_key_pair_invalid(self):
        """
        Test if the pair of the pair is valid.

        Args:
            self: (todo): write your description
        """
        self.nova.keypairs.create.side_effect = (
            nova_exception.OverLimit(413))
        self.assert_execution_error(
            'ResourceLimitExceeded', 'ImportKeyPair',
            {'KeyName': fakes.NAME_KEY_PAIR,
             'PublicKeyMaterial': base64.b64encode(
                 fakes.PUBLIC_KEY_KEY_PAIR.encode("ascii")
             ).decode("ascii")})

    def test_delete_key_pair(self):
        """
        Removes a key pair.

        Args:
            self: (todo): write your description
        """
        self.nova.keypairs.delete.return_value = True
        self.execute('DeleteKeyPair', {'KeyName': fakes.NAME_KEY_PAIR})
        self.nova.keypairs.delete.assert_called_once_with(fakes.NAME_KEY_PAIR)
        self.nova.keypairs.delete.side_effect = nova_exception.NotFound(404)
        self.execute('DeleteKeyPair', {'KeyName': 'keyname1'})
        self.nova.keypairs.delete.assert_any_call('keyname1')

    def test_describe_key_pairs(self):
        """
        Lists key pairs.

        Args:
            self: (todo): write your description
        """
        self.nova.keypairs.list.return_value = [fakes.NovaKeyPair(
                                                    fakes.OS_KEY_PAIR)]
        resp = self.execute('DescribeKeyPairs', {})
        self.assertThat(resp['keySet'],
                        matchers.ListMatches([
                            tools.purge_dict(fakes.EC2_KEY_PAIR,
                                             {'keyMaterial'})]))
        self.nova.keypairs.list.assert_called_once_with()

        self.check_filtering(
            'DescribeKeyPairs', 'keySet',
            [('fingerprint', fakes.FINGERPRINT_KEY_PAIR),
             ('key-name', fakes.NAME_KEY_PAIR)])

    def test_describe_key_pairs_invalid(self):
        """
        A list of keypairs.

        Args:
            self: (todo): write your description
        """
        self.nova.keypairs.list.return_value = [fakes.NovaKeyPair(
                                                    fakes.OS_KEY_PAIR)]
        self.assert_execution_error(
            'InvalidKeyPair.NotFound', 'DescribeKeyPairs',
            {'KeyName.1': 'badname'})
        self.nova.keypairs.list.assert_called_once_with()
