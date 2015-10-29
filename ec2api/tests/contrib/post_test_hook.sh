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

# Sleep some time until all services are starting
sleep 5

sudo apt-get install euca2ools -fy

export TEST_CONFIG_DIR=$(readlink -f .)
export TEST_CONFIG="functional_tests.conf"

# save original creds(admin) for later usage
OLD_OS_PROJECT_NAME=$OS_PROJECT_NAME
OLD_OS_USERNAME=$OS_USERNAME
OLD_OS_PASSWORD=$OS_PASSWORD

# bug somewhere
unset OS_AUTH_TYPE

if [[ ! -f $TEST_CONFIG_DIR/$TEST_CONFIG ]]; then

  openstack endpoint list --os-identity-api-version=3
  openstack service list --long
  if [[ "$?" -ne "0" ]]; then
    echo "Looks like credentials are absent."
    exit 1
  fi

  # prepare flavors
  nova flavor-create --is-public True m1.ec2api 16 512 0 1
  nova flavor-create --is-public True m1.ec2api-alt 17 256 0 1

  # prepare ubuntu image
  if [[ $RUN_LONG_TESTS == "1" ]]; then
    REGULAR_IMAGE_URL="https://cloud-images.ubuntu.com/precise/current/precise-server-cloudimg-i386-disk1.img"
    REGULAR_IMAGE_FNAME="precise-server-cloudimg-i386-disk1.img"
    REGULAR_IMAGE_NAME="precise"
    sudo rm /tmp/$REGULAR_IMAGE_FNAME
    wget -nv -P /tmp $REGULAR_IMAGE_URL
    if [[ "$?" -ne "0" ]]; then
      echo "Downloading of precise image failed."
      exit 1
    fi
    openstack image create --disk-format raw --container-format bare --public --file /tmp/$REGULAR_IMAGE_FNAME $REGULAR_IMAGE_NAME
    if [[ "$?" -ne "0" ]]; then
      echo "Creation of precise image failed."
      exit 1
    fi
    # find this image
    image_id_ubuntu=$(euca-describe-images --show-empty-fields | grep "$REGULAR_IMAGE_NAME" | grep "ami-" | head -n 1 | awk '{print $2}')
  fi

  # create separate user/project
  project_name="project-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)"
  eval $(openstack project create -f shell -c id $project_name)
  project_id=$id
  [[ -n "$project_id" ]] || { echo "Can't create project"; exit 1; }
  user_name="user-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)"
  eval $(openstack user create "$user_name" --project "$project_id" --password "password" --email "$user_name@example.com" -f shell -c id)
  user_id=$id
  [[ -n "$user_id" ]] || { echo "Can't create user"; exit 1; }
  # add 'Member' role for swift access
  role_id=$(openstack role show  Member -c id -f value)
  openstack role add --project $project_id --user $user_id $role_id
  # create network
  if [[ -n $(openstack service list | grep neutron) ]]; then
    net_id=$(neutron net-create --tenant-id $project_id "private" | grep ' id ' | awk '{print $4}')
    [[ -n "$net_id" ]] || { echo "net-create failed"; exit 1; }
    subnet_id=$(neutron subnet-create --tenant-id $project_id --ip_version 4 --gateway 10.0.0.1 --name "private_subnet" $net_id 10.0.0.0/24 | grep ' id ' | awk '{print $4}')
    [[ -n "$subnet_id" ]] || { echo "subnet-create failed"; exit 1; }
    router_id=$(neutron router-create --tenant-id $project_id "private_router" | grep ' id ' | awk '{print $4}')
    [[ -n "$router_id" ]] || { echo "router-create failed"; exit 1; }
    neutron router-interface-add $router_id $subnet_id
    [[ "$?" -eq 0 ]] || { echo "router-interface-add failed"; exit 1; }
    public_net_id=$(neutron net-list | grep public | awk '{print $2}')
    [[ -n "$public_net_id" ]] || { echo "can't find public network"; exit 1; }
    neutron router-gateway-set $router_id $public_net_id
    [[ "$?" -eq 0 ]] || { echo "router-gateway-set failed"; exit 1; }
  fi
  # populate credentials
  openstack ec2 credentials create --user $user_id --project $project_id 1>&2
  line=`openstack ec2 credentials list --user $user_id | grep " $project_id "`
  read EC2_ACCESS_KEY EC2_SECRET_KEY <<<  `echo $line | awk '{print $2 " " $4 }'`
  export EC2_ACCESS_KEY
  export EC2_SECRET_KEY
  export OS_PROJECT_NAME=$project_name
  export OS_TENANT_NAME=$project_name
  export OS_USERNAME=$user_name
  export OS_PASSWORD="password"

  # prepare cirros image for register_image test. uploading it to S3.
  CIRROS_IMAGE_URL="http://download.cirros-cloud.net/0.3.4/cirros-0.3.4-x86_64-disk.img"
  CIRROS_IMAGE_FNAME="cirros-0.3.4-x86_64-disk.img"
  sudo rm /tmp/$CIRROS_IMAGE_FNAME
  wget -nv -P /tmp $CIRROS_IMAGE_URL
  if [[ "$?" -eq "0" ]]; then
    mkdir -p /tmp/cirros
    # do it under sudo because admin-pk is not accessible under user
    sudo euca-bundle-image -i /tmp/$CIRROS_IMAGE_FNAME -d /tmp/cirrosimage -r x86_64 -c $EC2_CERT -k $EC2_PRIVATE_KEY --ec2cert $EUCALYPTUS_CERT --user $EC2_USER_ID
    if [[ "$?" -eq "0" ]]; then
      sudo chmod a+r /tmp/cirrosimage/*
      euca-upload-bundle -b cirrosimage -m /tmp/cirrosimage/$CIRROS_IMAGE_FNAME.manifest.xml --acl public-read -I $EC2_ACCESS_KEY -S $EC2_SECRET_KEY --debug
      if [[ "$?" -eq "0" ]]; then
        CIRROS_IMAGE_MANIFEST="cirrosimage/$CIRROS_IMAGE_FNAME.manifest.xml"
      else
        echo "Uploading of image $CIRROS_IMAGE_URL to S3 failed."
      fi
    else
      echo "Bundling of image $CIRROS_IMAGE_URL failed."
    fi
  else
    echo "Downloading of image $CIRROS_IMAGE_URL failed."
  fi

  # find simple image
  image_id=$(euca-describe-images --show-empty-fields | grep "cirros" | grep "ami-" | head -n 1 | awk '{print $2}')

  # create EBS image
  MAX_FAIL=20
  FLAVOR_NAME="m1.ec2api"
  volume_status() { cinder show $1|awk '/ status / {print $4}'; }
  instance_status() { nova show $1|awk '/ status / {print $4}'; }

  openstack_image_id=$(openstack image list --long | grep "cirros" | grep " ami " | head -1 | awk '{print $2}')
  if [[ -n "$openstack_image_id" ]]; then
    volume_id=$(cinder create --image-id $openstack_image_id 1 | awk '/ id / {print $4}')
    [[ -n "$volume_id" ]] || { echo "can't create volume for EBS image creation"; exit 1; }
    fail=0
    while [[ true ]] ; do
      if ((fail >= MAX_FAIL)); then
        echo "Volume creation fails (timeout)"
        exit 1
      fi
      echo "attempt "$fail" of "$MAX_FAIL
      status=$(volume_status $volume_id)
      if [[ $status == "available" ]]; then
        break
      fi
      if [[ $status == "error" || -z "$status" ]]; then
        cinder show $volume_id
        exit 1
      fi
      sleep 10
      ((++fail))
    done

    instance_name="i-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)"
    instance_id=$(nova boot \
      --flavor "$FLAVOR_NAME" \
      --block-device "device=/dev/vda,id=$volume_id,shutdown=remove,source=volume,dest=volume,bootindex=0" \
      "$instance_name" | awk '/ id / {print $4}')
    [[ -n "$instance_id" ]] || { echo "can't boot EBS instance"; exit 1; }
    fail=0
    while [[ true ]] ; do
      if ((fail >= MAX_FAIL)); then
        echo "Instance active status wait timeout occured"
        exit 1
      fi
      echo "attempt "$fail" of "$MAX_FAIL
      status=$(instance_status $instance_id)
      if [[ "$status" == "ACTIVE" ]]; then
        break
      fi
      if [[ "$status" == "ERROR" || -z "$status" ]]; then
        nova show $instance_id
        exit 1
      fi
      sleep 10
      ((++fail))
    done

    image_name="image-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 8)"
    nova image-create $instance_name $image_name
    if [[ "$?" -ne "0" ]]; then
      echo "Image creation from instance fails"
      exit 1
    fi
    ebs_image_id=$(euca-describe-images --show-empty-fields | grep $image_name | awk '{print $2}')
    nova delete $instance_id
  fi

  timeout="180"
  run_long_tests="False"
  if [[ $RUN_LONG_TESTS == "1" ]]; then
    timeout="600"
    run_long_tests="True"
  else
    timeout="180"
    run_long_tests="False"
  fi

  sudo bash -c "cat > $TEST_CONFIG_DIR/$TEST_CONFIG <<EOF
[aws]
ec2_url = $EC2_URL
s3_url = $S3_URL
aws_access = $EC2_ACCESS_KEY
aws_secret = $EC2_SECRET_KEY
image_id = $image_id
image_id_ubuntu = $image_id_ubuntu
ebs_image_id = $ebs_image_id
build_timeout = $timeout
run_long_tests = $run_long_tests
instance_type = m1.ec2api
instance_type_alt = m1.ec2api-alt
ami_image_location=$CIRROS_IMAGE_MANIFEST
EOF"
fi

sudo pip install -r test-requirements.txt
sudo OS_STDOUT_CAPTURE=-1 OS_STDERR_CAPTURE=-1 OS_TEST_TIMEOUT=500 OS_TEST_LOCK_PATH=${TMPDIR:-'/tmp'} \
  python -m subunit.run discover -t ./ ./ec2api/tests/functional | subunit-2to1 | tools/colorizer.py
RETVAL=$?

# Here can be some commands for log archiving, etc...

# list resources to check what left after tests
euca-describe-instances
euca-describe-images
euca-describe-volumes
euca-describe-snapshots
export OS_PROJECT_NAME=$OLD_OS_PROJECT_NAME
export OS_TENANT_NAME=$OLD_OS_PROJECT_NAME
export OS_USERNAME=$OLD_OS_USERNAME
export OS_PASSWORD=$OLD_OS_PASSWORD
openstack server list --all-projects
openstack image list
openstack volume list --all-projects
cinder snapshot-list --all-tenants

exit $RETVAL
