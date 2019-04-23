======================
 Enabling in Devstack
======================

1. Download DevStack

    git clone https://opendev.org/openstack/devstack
    cd devstack

2. Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     enable_plugin ec2-api https://opendev.org/openstack/ec2-api

3. run ``stack.sh``
