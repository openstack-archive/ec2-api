======================
 Enabling in Devstack
======================

1. Download DevStack

    git clone https://git.openstack.org/openstack-dev/devstack
    cd devstack

2. Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     enable_plugin ec2-api https://git.openstack.org/openstack/ec2-api

3. run ``stack.sh``
