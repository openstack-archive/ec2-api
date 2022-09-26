.. _configuration:

To configure OpenStack for EC2 API service add to ``/etc/ec2api/ec2api.conf``:

.. code-block:: ini

     [DEFAULT]
     external_network = public
     ec2_port = 8788
     ec2api_listen_port = 8788
     keystone_ec2_tokens_url = http://192.168.56.101/identity/v3/ec2tokens
     api_paste_config = /etc/ec2api/api-paste.ini
     disable_ec2_classic = True

.. [*] - ``external_network`` option specifies the name of the external network,
         which is used to Internet and to allocate Elastic IPs. It must be
         specified to get access into VMs from outside of the cloud.

       - ``disable_ec2_classic`` option is not mandatory, but we strongly
         recommend it to be specified. It turns off EC2 Classic mode and forces
         objects to be created inside VPCs.

         With ``disable_ec2_classic`` = True, any user of the cloud must have
         the only network (created with neutron directly and attached to a router
         to provide outside access for that VMS), which is used for launch
         ec2-classic instances.

         Keep in mind that an operator is not able to change
         ``disable_ec2_classic`` setting seamlessly.

In the *[keystone_authtoken]* section, configure Identity service access.

.. code-block:: ini

     [keystone_authtoken]
     project_domain_name = Default
     project_name = service
     user_domain_name = Default
     password = password
     username = ec2api
     auth_type = password

Also you need to configure database connection:

.. code-block:: ini

     [database]
     connection = mysql+pymysql://root:password@127.0.0.1/ec2api?charset=utf8

and you need to configure oslo_concurrency lock_path:

.. code-block:: ini

     [oslo_concurrency]
     lock_path = /path/to/oslo_concurrency_lock_dir

and cache if you want to use it.

.. code-block:: ini

     [cache]
     enabled = True

You can look for other configuration options in the `Configuration Reference`_

.. _`Configuration Reference`: ../configuration/api.html