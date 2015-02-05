======================
 Enabling in Devstack
======================

1. Download DevStack

2. Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     enable_plugin ec2-api https://github.com/stackforge/ec2-api

3. run ``stack.sh``
