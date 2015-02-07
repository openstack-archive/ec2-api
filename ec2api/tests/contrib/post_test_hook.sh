#!/bin/bash
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

CONFIG_DIR="."
export TEST_CONFIG_DIR=$(readlink -f $CONFIG_DIR)
export TEST_CONFIG="functional_tests.conf"

if [[ ! -f $CONFIG_DIR/$TEST_CONFIG ]]; then

IMAGE_ID=$(euca-describe-images | grep "ami-" | head -n 1 | awk '{print $2}')

  cat > $CONFIG_DIR/$TEST_CONFIG <<EOF
[aws]
ec2_url = $EC2_URL
aws_access = $EC2_ACCESS_KEY
aws_secret = $EC2_SECRET_KEY
image_id = $IMAGE_ID
EOF
fi

python -m testtools.run discover -v -t ./ ec2api/tests/functional
RETVAL=$?

# Here can be some commands for log archiving, etc...

exit $RETVAL
