1. Follow Devstack documentation to setup a host for Devstack. Then clone
   Devstack source code.

2. Copy ec2-api integration scripts to Devstack::

      $ cp lib/ec2-api ${DEVSTACK_DIR}/lib
      $ cp extras.d/70-ec2-api.sh ${DEVSTACK_DIR}/extras.d

3. Create a ``localrc`` file as input to devstack.

4. The ec2-api services are not enabled by default, so they must be
   enabled in ``localrc`` before running ``stack.sh``. This example ``localrc``
   file shows all of the settings required for ec2-api::

      # Enable ec2-api
      enable_service ec2-api

5. Deploy your OpenStack Cloud with ec2-api::

   $ ./stack.sh
