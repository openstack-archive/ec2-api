.. _install-manual:

Manual Installation
~~~~~~~~~~~~~~~~~~~

Install and configure components
--------------------------------

1. Install the packages in any way you prefer
   (**github+setup.py** / **pip** / **packages**)

2. Create the service credentials

   .. include:: credentials-creation.rst

3. Create database

   .. include:: database-creation.rst

   There is a script creating 'ec2api' database that is accessible
   only on localhost by user 'ec2api' with password 'ec2api'.
   https://github.com/openstack/ec2-api/blob/master/tools/db/ec2api-db-setup

4. Create endpoints:

   .. include:: endpoints-creation.rst

5. Create configuration files ``/etc/ec2api/api-paste.ini``
   (can be copied from
   https://github.com/openstack/ec2-api/blob/master/etc/ec2api/api-paste.ini)

   and ``/etc/ec2api/ec2api.conf``

   .. include:: configuration.rst

6. Configure metadata:

   .. include:: metadata-configuration.rst

7. Start the services as binaries

   .. code-block:: console

       $ /usr/local/bin/ec2-api
       $ /usr/local/bin/ec2-api-metadata

   or set up as Linux services.
