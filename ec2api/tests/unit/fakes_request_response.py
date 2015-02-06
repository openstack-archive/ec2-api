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


from ec2api.tests.unit import tools

XML_RESULT_TEMPLATE = '''
<%(action)sResponse
    xmlns="http://ec2.amazonaws.com/doc/%(api_version)s/">
  <requestId>%(request_id)s</requestId>
  %(data)s
</%(action)sResponse>'''
XML_ERROR_TEMPLATE = '''
<Response>
    <Errors><Error>
        <Code>%(code)s</Code><Message>%(message)s</Message>
    </Error></Errors>
    <RequestID>%(request_id)s</RequestID>
</Response>'''

XML_FAKE_RESULT = '''<FakeActionResponse
xmlns="http://ec2.amazonaws.com/doc/2010-08-31/">
  <fakeInfo>
    <fakeNone/>
    <fakeTrue>true</fakeTrue>
    <fakeFalse>false</fakeFalse>
    <fakeInt>1234</fakeInt>
    <fakeStr>fake</fakeStr>
    <fakeSet>
      <item>
        <fakeData>fake</fakeData>
      </item>
      <item>
        <fakeData>fake</fakeData>
      </item>
    </fakeSet>
  </fakeInfo>
  <fakeEmptySet/>
  <fakeComplexSet>
    <item>
      <fakeSubSet>
        <item>
          <fakeData>fake</fakeData>
        </item>
        <item>
          <fakeData/>
        </item>
      </fakeSubSet>
    </item>
    <item>
      <fakeSubSet>
        <item>
          <fakeData>fake</fakeData>
        </item>
        <item>
          <fakeData>fake</fakeData>
        </item>
      </fakeSubSet>
    </item>
  </fakeComplexSet>
  <requestId/>
</FakeActionResponse>
'''
DICT_FAKE_RESULT_DATA = {
    'fakeInfo': {
        'fakeNone': None,
        'fakeTrue': True,
        'fakeFalse': False,
        'fakeInt': 1234,
        'fakeStr': 'fake',
        'fakeSet': [{'fakeData': 'fake'},
                    {'fakeData': 'fake'}],
    },
    'fakeEmptySet': [],
    'fakeComplexSet': [
        {'fakeSubSet': [{'fakeData': 'fake'},
                        {'fakeData': None}]},
        {'fakeSubSet': [{'fakeData': 'fake'},
                        {'fakeData': 'fake'}]},
    ],
}
DICT_FAKE_RESULT = {
    'FakeActionResponse': tools.update_dict(
        DICT_FAKE_RESULT_DATA,
        {'requestId': None})
}

XML_SINGLE_RESULT = '''
<CreateSnapshotResponse xmlns="http://ec2.amazonaws.com/doc/2009-11-30/">
  <requestId>req-8a80bb71-1e1d-49be-819f-fba429b0ddf1</requestId>
  <status>pending</status>
  <description/>
  <volumeId>vol-00000001</volumeId>
  <volumeSize>1</volumeSize>
  <progress/>
  <startTime>2014-06-04T19:55:55.448117</startTime>
  <ownerId/>
  <snapshotId>snap-00000001</snapshotId>
</CreateSnapshotResponse>
'''
DICT_SINGLE_RESULT = {
    'CreateSnapshotResponse': {
        'status': 'pending',
        'description': None,
        'volumeId': 'vol-00000001',
        'volumeSize': 1,
        'progress': None,
        'startTime': '2014-06-04T19:55:55.448117',
        'ownerId': None,
        'snapshotId': 'snap-00000001',
        'requestId': 'req-8a80bb71-1e1d-49be-819f-fba429b0ddf1',
    }
}

XML_RESULT_SET = '''
<DescribeImagesResponse xmlns="http://ec2.amazonaws.com/doc/2010-08-31/">
  <requestId>req-1fc541a8-477d-4928-a90e-4448ea57ba51</requestId>
  <imagesSet>
    <item>
      <description/>
      <imageOwnerId>77dcabaee8ea4a8fbae697ddc09afdaf</imageOwnerId>
      <isPublic>true</isPublic>
      <imageId>aki-00000001</imageId>
      <imageState>available</imageState>
      <architecture/>
      <imageLocation>None (cirros-0.3.2-x86_64-uec-kernel)</imageLocation>
      <rootDeviceType>instance-store</rootDeviceType>
      <rootDeviceName>/dev/sda1</rootDeviceName>
      <imageType>kernel</imageType>
      <name>cirros-0.3.2-x86_64-uec-kernel</name>
    </item>
    <item>
      <description/>
      <imageOwnerId>77dcabaee8ea4a8fbae697ddc09afdaf</imageOwnerId>
      <isPublic>true</isPublic>
      <imageId>ari-00000002</imageId>
      <imageState>available</imageState>
      <architecture/>
      <imageLocation>None (cirros-0.3.2-x86_64-uec-ramdisk)</imageLocation>
      <rootDeviceType>instance-store</rootDeviceType>
      <rootDeviceName>/dev/sda1</rootDeviceName>
      <imageType>ramdisk</imageType>
      <name>cirros-0.3.2-x86_64-uec-ramdisk</name>
    </item>
    <item>
      <name>cirros-0.3.2-x86_64-uec</name>
      <imageOwnerId>77dcabaee8ea4a8fbae697ddc09afdaf</imageOwnerId>
      <isPublic>true</isPublic>
      <imageId>ami-00000003</imageId>
      <imageState>available</imageState>
      <rootDeviceType>instance-store</rootDeviceType>
      <architecture/>
      <imageLocation>None (cirros-0.3.2-x86_64-uec)</imageLocation>
      <kernelId>aki-00000001</kernelId>
      <ramdiskId>ari-00000002</ramdiskId>
      <rootDeviceName>/dev/sda1</rootDeviceName>
      <imageType>machine</imageType>
      <description/>
    </item>
    <item>
      <description/>
      <imageOwnerId>77dcabaee8ea4a8fbae697ddc09afdaf</imageOwnerId>
      <isPublic>true</isPublic>
      <imageId>ami-00000004</imageId>
      <imageState>available</imageState>
      <architecture/>
      <imageLocation>None (Fedora-x86_64-20-20131211.1-sda)</imageLocation>
      <rootDeviceType>instance-store</rootDeviceType>
      <rootDeviceName>/dev/sda1</rootDeviceName>
      <imageType>machine</imageType>
      <name>Fedora-x86_64-20-20131211.1-sda</name>
    </item>
  </imagesSet>
</DescribeImagesResponse>
'''
DICT_RESULT_SET = {
    'DescribeImagesResponse': {
        'imagesSet': [{
            'description': None,
            'imageOwnerId': '77dcabaee8ea4a8fbae697ddc09afdaf',
            'isPublic': True,
            'imageId': 'aki-00000001',
            'imageState': 'available',
            'architecture': None,
            'imageLocation': 'None (cirros-0.3.2-x86_64-uec-kernel)',
            'rootDeviceType': 'instance-store',
            'rootDeviceName': '/dev/sda1',
            'imageType': 'kernel',
            'name': 'cirros-0.3.2-x86_64-uec-kernel',
        },
            {
            'description': None,
            'imageOwnerId': '77dcabaee8ea4a8fbae697ddc09afdaf',
            'isPublic': True,
            'imageId': 'ari-00000002',
            'imageState': 'available',
            'architecture': None,
            'imageLocation': 'None (cirros-0.3.2-x86_64-uec-ramdisk)',
            'rootDeviceType': 'instance-store',
            'rootDeviceName': '/dev/sda1',
            'imageType': 'ramdisk',
            'name': 'cirros-0.3.2-x86_64-uec-ramdisk',
        },
            {
            'name': 'cirros-0.3.2-x86_64-uec',
            'imageOwnerId': '77dcabaee8ea4a8fbae697ddc09afdaf',
            'isPublic': True,
            'imageId': 'ami-00000003',
            'imageState': 'available',
            'rootDeviceType': 'instance-store',
            'architecture': None,
            'imageLocation': 'None (cirros-0.3.2-x86_64-uec)',
            'kernelId': 'aki-00000001',
            'ramdiskId': 'ari-00000002',
            'rootDeviceName': '/dev/sda1',
            'imageType': 'machine',
            'description': None,
        },
            {
            'description': None,
            'imageOwnerId': '77dcabaee8ea4a8fbae697ddc09afdaf',
            'isPublic': True,
            'imageId': 'ami-00000004',
            'imageState': 'available',
            'architecture': None,
            'imageLocation': 'None (Fedora-x86_64-20-20131211.1-sda)',
            'rootDeviceType': 'instance-store',
            'rootDeviceName': '/dev/sda1',
            'imageType': 'machine',
            'name': 'Fedora-x86_64-20-20131211.1-sda',
        }],
        'requestId': 'req-1fc541a8-477d-4928-a90e-4448ea57ba51',
    }
}

XML_EMPTY_RESULT_SET = '''<?xml version="1.0" encoding="UTF-8"?>
<DescribeVolumesResponse xmlns="http://ec2.amazonaws.com/doc/2014-05-01/">
    <requestId>a25fa489-f97f-428a-9d30-9fcb1e9b9b65</requestId>
    <volumeSet/>
</DescribeVolumesResponse>
'''
DICT_EMPTY_RESULT_SET = {
    'DescribeVolumesResponse': {
        'requestId': 'a25fa489-f97f-428a-9d30-9fcb1e9b9b65',
        'volumeSet': [],
    }
}

XML_ERROR = '''<?xml version="1.0"?>
<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code>
<Message>Instance i-00000001 could not be found.</Message></Error></Errors>
<RequestID>req-89eb083f-3c44-46e7-bc37-2c050ed7a9ce</RequestID></Response>
'''
DICT_ERROR = {
    'Response': {
        'RequestID': 'req-89eb083f-3c44-46e7-bc37-2c050ed7a9ce',
        'Errors': {
            'Error': {
                'Code': 'InvalidInstanceID.NotFound',
                'Message': 'Instance i-00000001 could not be found.',
            }
        }
    }
}

XML_SILENT_OPERATIN_RESULT = '''
<DeleteVpcResponse xmlns="http://ec2.amazonaws.com/doc/2009-11-30/">
  <requestId>req-8a80bb71-1e1d-49be-819f-fba429b0ddf1</requestId>
  <return>true</return>
</DeleteVpcResponse>
'''

DOTTED_FAKE_PARAMS = {
    'FakeStr': 'fake',
    'FakeInt': '1234',
    'FakeBool': 'False',
    'FakeDict.FakeKey': 'fake',
    'FakeList.1.FakeElemKey': 'fake',
    'FakeList.2.FakeElemKey': 'fake',
    'FakeComplexList.1.FakeElemKey.1.FakeSubElemKey': 'fake',
    'FakeComplexList.1.FakeElemKey.2.FakeSubElemKey': 'fake',
    'FakeComplexList.1.FakeElemKeyOther': 'fake',
    'FakeComplexList.2.FakeElemKey.1.FakeSubElemKey': 'fake',
    'FakeComplexList.2.FakeElemKey.2.FakeSubElemKey': 'fake',
    'FakeComplexList.2.FakeElemKeyOther': 'fake',
}
DICT_FAKE_PARAMS = {
    'fake_str': 'fake',
    'fake_int': 1234,
    'fake_bool': False,
    'fake_dict': {'fake_key': 'fake'},
    'fake_list': [{'fake_elem_key': 'fake'},
                  {'fake_elem_key': 'fake'}],
    'fake_complex_list': [
        {'fake_elem_key': [{'fake_sub_elem_key': 'fake'},
                           {'fake_sub_elem_key': 'fake'}],
         'fake_elem_key_other': 'fake'},
        {'fake_elem_key': [{'fake_sub_elem_key': 'fake'},
                           {'fake_sub_elem_key': 'fake'}],
         'fake_elem_key_other': 'fake'}],
}
