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

import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config

CONF = config.CONF


class KeyPairTest(base.EC2TestCase):

    def test_create_delete_key_pair(self):
        keyName = 'Test key'
        resp, data = self.client.CreateKeyPair(KeyName=keyName)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        res_clean = self.addResourceCleanUp(self.client.DeleteKeyPair,
                                            KeyName=keyName)

        self.assertEqual(keyName, data['KeyName'])
        self.assertIsNotNone(data.get('KeyFingerprint'))
        self.assertGreater(len(data['KeyFingerprint']), 0)
        self.assertGreater(len(data.get('KeyMaterial')), 0)

        resp, data = self.client.DeleteKeyPair(KeyName=keyName)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_create_duplicate_key_pair(self):
        keyName = 'Test key'
        resp, data = self.client.CreateKeyPair(KeyName=keyName)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        res_clean = self.addResourceCleanUp(self.client.DeleteKeyPair,
                                            KeyName=keyName)

        resp, data = self.client.CreateKeyPair(KeyName=keyName)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidKeyPair.Duplicate', data['Error']['Code'])

        resp, data = self.client.DeleteKeyPair(KeyName=keyName)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

    def test_describe_key_pairs(self):
        keyName = 'Test key'
        resp, data = self.client.CreateKeyPair(KeyName=keyName)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        res_clean = self.addResourceCleanUp(self.client.DeleteKeyPair,
                                            KeyName=keyName)
        self.assertIsNotNone(data.get('KeyFingerprint'))
        self.assertGreater(len(data['KeyFingerprint']), 0)
        fingerprint = data.get('KeyFingerprint')

        resp, data = self.client.DescribeKeyPairs(KeyNames=[keyName])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data.get('KeyPairs')))
        data = data['KeyPairs'][0]
        self.assertEqual(keyName, data['KeyName'])
        self.assertIsNotNone(data.get('KeyFingerprint'))
        self.assertGreater(len(data['KeyFingerprint']), 0)
        self.assertIsNone(data.get('KeyMaterial'))

        resp, data = self.client.DescribeKeyPairs(
            Filters=[{'Name': 'key-name', 'Values': [keyName]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data.get('KeyPairs')))
        self.assertEqual(keyName, data['KeyPairs'][0]['KeyName'])

        resp, data = self.client.DescribeKeyPairs(
            Filters=[{'Name': 'fingerprint', 'Values': [fingerprint]}])
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual(1, len(data.get('KeyPairs')))
        self.assertEqual(keyName, data['KeyPairs'][0]['KeyName'])

        resp, data = self.client.DescribeKeyPairs(KeyNames=['fake key'])
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidKeyPair.NotFound', data['Error']['Code'])

        resp, data = self.client.DeleteKeyPair(KeyName=keyName)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)

        resp, data = self.client.DescribeKeyPairs(KeyNames=[keyName])
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidKeyPair.NotFound', data['Error']['Code'])

        # NOTE(andrey-mp): Amazon allows to delete absent key and returns 200
        resp, data = self.client.DeleteKeyPair(KeyName=keyName)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))

    def test_import_empty_key_pair(self):
        keyName = 'Test key'
        publicKey = ''
        resp, data = self.client.ImportKeyPair(KeyName=keyName,
                                               PublicKeyMaterial=publicKey)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteKeyPair, KeyName=keyName)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('MissingParameter', data['Error']['Code'])

    @testtools.skipUnless(CONF.aws.run_incompatible_tests,
                          "Different error code")
    def test_import_invalid_key_pair(self):
        keyName = 'Test key'
        publicKey = 'ssh-rsa JUNK test@ubuntu'
        resp, data = self.client.ImportKeyPair(KeyName=keyName,
                                               PublicKeyMaterial=publicKey)
        if resp.status_code == 200:
            self.addResourceCleanUp(self.client.DeleteKeyPair, KeyName=keyName)
        self.assertEqual(400, resp.status_code, base.EC2ErrorConverter(data))
        self.assertEqual('InvalidKey.Format', data['Error']['Code'])

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
        resp, data = self.client.ImportKeyPair(KeyName=keyName,
                                               PublicKeyMaterial=publicKey)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        res_clean = self.addResourceCleanUp(self.client.DeleteKeyPair,
                                            KeyName=keyName)

        self.assertEqual(keyName, data['KeyName'])
        self.assertIsNotNone(data.get('KeyFingerprint'))
        self.assertGreater(len(data['KeyFingerprint']), 0)
        self.assertIsNone(data.get('KeyMaterial'))

        resp, data = self.client.DeleteKeyPair(KeyName=keyName)
        self.assertEqual(200, resp.status_code, base.EC2ErrorConverter(data))
        self.cancelResourceCleanUp(res_clean)
