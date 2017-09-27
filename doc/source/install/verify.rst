.. _verify:

Verify operation
~~~~~~~~~~~~~~~~

Verify operation of the ec2-api service.

.. note::

   Perform these commands on the controller node.

#. Source the ``admin`` project credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . openrc admin admin

#. List service components to verify successful launch and registration
   of each process:

   .. code-block:: console

      $ openstack service list


#. Install aws cli.

   .. code-block:: console

      # pip install awscli --upgrade --user

#. Create configuration file for aws cli in your home directory
   ``~/.aws/config`` or by "**aws configure**" command:

   .. code-block:: console

      [default]
      aws_access_key_id = 1b013f18d5ed47ae8ed0fbb8debc036b
      aws_secret_access_key = 9bbc6f270ffd4dfdbe0e896947f41df3
      region = RegionOne

   Change the aws_access_key_id and aws_secret_acces_key above to the values
   appropriate for your cloud (can be obtained by
   "**openstack ec2 credentials list**" command).

#. Run aws cli commands using new EC2 API endpoint URL (can be obtained from
   keystone with the new port 8788) like this:

   .. code-block:: console

      aws --endpoint-url http://10.0.2.15:8788 ec2 describe-images
