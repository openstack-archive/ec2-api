# Copyright 2014 OpenStack Foundation
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

from tempest.lib import decorators
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class KeyPairTest(base.EC2TestCase):

    @decorators.idempotent_id('15cfd866-d6bb-473a-9b8a-6420900a5ca3')
    def test_create_delete_key_pair(self):
        keyName = 'Test key'
        data = self.client.create_key_pair(KeyName=keyName)
        res_clean = self.addResourceCleanUp(self.client.delete_key_pair,
                                            KeyName=keyName)

        self.assertEqual(keyName, data['KeyName'])
        self.assertIsNotNone(data.get('KeyFingerprint'))
        self.assertGreater(len(data['KeyFingerprint']), 0)
        self.assertGreater(len(data.get('KeyMaterial')), 0)

        data = self.client.delete_key_pair(KeyName=keyName)
        self.cancelResourceCleanUp(res_clean)

    @decorators.idempotent_id('05478a51-1505-42a8-8c7d-4fd7e32c467e')
    def test_create_duplicate_key_pair(self):
        keyName = 'Test key'
        self.client.create_key_pair(KeyName=keyName)
        res_clean = self.addResourceCleanUp(self.client.delete_key_pair,
                                            KeyName=keyName)

        self.assertRaises('InvalidKeyPair.Duplicate',
                          self.client.create_key_pair,
                          KeyName=keyName)

        self.client.delete_key_pair(KeyName=keyName)
        self.cancelResourceCleanUp(res_clean)

    @decorators.idempotent_id('43d87b6e-6667-4d19-8c0b-e73901105bb7')
    def test_describe_key_pairs(self):
        keyName = 'Test key'
        data = self.client.create_key_pair(KeyName=keyName)
        res_clean = self.addResourceCleanUp(self.client.delete_key_pair,
                                            KeyName=keyName)
        self.assertIsNotNone(data.get('KeyFingerprint'))
        self.assertGreater(len(data['KeyFingerprint']), 0)
        fingerprint = data.get('KeyFingerprint')

        data = self.client.describe_key_pairs(KeyNames=[keyName])
        self.assertEqual(1, len(data.get('KeyPairs')))
        data = data['KeyPairs'][0]
        self.assertEqual(keyName, data['KeyName'])
        self.assertIsNotNone(data.get('KeyFingerprint'))
        self.assertGreater(len(data['KeyFingerprint']), 0)
        self.assertIsNone(data.get('KeyMaterial'))

        data = self.client.describe_key_pairs(
            Filters=[{'Name': 'key-name', 'Values': [keyName]}])
        self.assertEqual(1, len(data.get('KeyPairs')))
        self.assertEqual(keyName, data['KeyPairs'][0]['KeyName'])

        data = self.client.describe_key_pairs(
            Filters=[{'Name': 'fingerprint', 'Values': [fingerprint]}])
        self.assertEqual(1, len(data.get('KeyPairs')))
        self.assertEqual(keyName, data['KeyPairs'][0]['KeyName'])

        self.assertRaises('InvalidKeyPair.NotFound',
                          self.client.describe_key_pairs,
                          KeyNames=['fake key'])

        data = self.client.delete_key_pair(KeyName=keyName)
        self.cancelResourceCleanUp(res_clean)

        self.assertRaises('InvalidKeyPair.NotFound',
                          self.client.describe_key_pairs,
                          KeyNames=[keyName])

        # NOTE(andrey-mp): Amazon allows to delete absent key and returns 200
        self.client.delete_key_pair(KeyName=keyName)

    @decorators.idempotent_id('0e51eec5-3f61-4d8a-89c9-8d098f381682')
    def test_import_empty_key_pair(self):
        keyName = 'Test key'
        publicKey = ''

        def _rollback(fn_data):
            self.client.delete_key_pair(KeyName=keyName)

        self.assertRaises('MissingParameter',
                          self.client.import_key_pair,
                          rollback_fn=_rollback,
                          KeyName=keyName, PublicKeyMaterial=publicKey)

    @decorators.idempotent_id('478c17e6-b7ca-4115-bee2-be279bdd0f65')
    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Different error code")
    def test_import_invalid_key_pair(self):
        keyName = 'Test key'
        publicKey = 'ssh-rsa JUNK test@ubuntu'

        def _rollback():
            self.client.delete_key_pair(KeyName=keyName)

        self.assertRaises('InvalidKey.Format',
                          self.client.import_key_pair,
                          rollback_fn=_rollback,
                          KeyName=keyName, PublicKeyMaterial=publicKey)

    @decorators.idempotent_id('eda525d6-144b-4840-b6ba-e18d93e3589f')
    def test_import_key_pair(self):
        keyName = 'Test key'
        publicKey = ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCs"
                     "Ne3/1ILNCqFyfYWDeTKLD6jEXC2OQHLmietMWW+/vd"
                     "aZq7KZEwO0jhglaFjU1mpqq4Gz5RX156sCTNM9vRbw"
                     "KAxfsdF9laBYVsex3m3Wmui3uYrKyumsoJn2g9GNnG1P"
                     "I1mrVjZ61i0GY3khna+wzlTpCCmy5HNlrmbj3XLqBUpip"
                     "TOXmsnr4sChzC53KCd8LXuwc1i/CZPvF+3XipvAgFSE53pCt"
                     "LOeB1kYMOBaiUPLQTWXR3JpckqFIQwhIH0zoHlJvZE8hh90"
                     "XcPojYN56tI0OlrGqojbediJYD0rUsJu4weZpbn8vilb3JuDY+jws"
                     "snSA8wzBx3A/8y9Pp1B test@ubuntu")
        data = self.client.import_key_pair(KeyName=keyName,
                                           PublicKeyMaterial=publicKey)
        res_clean = self.addResourceCleanUp(self.client.delete_key_pair,
                                            KeyName=keyName)

        self.assertEqual(keyName, data['KeyName'])
        self.assertIsNotNone(data.get('KeyFingerprint'))
        self.assertGreater(len(data['KeyFingerprint']), 0)
        self.assertIsNone(data.get('KeyMaterial'))

        self.client.delete_key_pair(KeyName=keyName)
        self.cancelResourceCleanUp(res_clean)
