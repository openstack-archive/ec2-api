#!/bin/bash -x
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This script is executed inside post_test_hook function in devstack gate.

# Sleep some time until all services are started
sleep 5

export TEST_CONFIG_DIR=$(readlink -f .)
export TEST_CONFIG="functional_tests.conf"

if [[ ! -f $TEST_CONFIG_DIR/$TEST_CONFIG ]]; then

IMAGE_ID=$(euca-describe-images | grep "cirros" | grep "ami-" | head -n 1 | awk '{print $2}')

  sudo bash -c "cat > $TEST_CONFIG_DIR/$TEST_CONFIG <<EOF
[aws]
ec2_url = $EC2_URL
aws_access = $EC2_ACCESS_KEY
aws_secret = $EC2_SECRET_KEY
image_id = $IMAGE_ID
EOF"
fi

sudo pip install -r test-requirements.txt
# botocore not in openstack requirements now, so install it manually
sudo pip install botocore==0.85
sudo OS_STDOUT_CAPTURE=-1 OS_STDERR_CAPTURE=-1 OS_TEST_TIMEOUT=500 OS_TEST_LOCK_PATH=${TMPDIR:-'/tmp'} \
  python -m subunit.run discover -t ./ ./ec2api/tests/functional | subunit-2to1 | tools/colorizer.py
RETVAL=$?

# Here can be some commands for log archiving, etc...

exit $RETVAL
