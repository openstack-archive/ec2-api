.. _credentials-creation:

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

#. To create the service credentials, complete these steps:

   * Create the ``ec2api`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt ec2api

   * Add the ``admin`` role to the ``ec2api`` user:

     .. code-block:: console

        $ openstack role add --project service --user ec2api admin

   * Create the ec2api service entities:

     .. code-block:: console

        $ openstack service create --name ec2-api --description "ec2api" ec2api
