.. _install-sh:

Installation by install.sh
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install and configure components
--------------------------------

Install the packages:

.. code-block:: console

   # apt-get update
   # git clone https://github.com/openstack/ec2-api.git
   # cd ec2-api

Run install.sh

The EC2 API service gets installed on port 8788 by default. It can be changed
before the installation in ``/etc/ec2api/ec2api.conf`` configuration file.

:ref:`configuring`.

The services afterwards can be started as binaries:

.. code-block:: console

   $ /usr/local/bin/ec2-api
   $ /usr/local/bin/ec2-api-metadata

or set up as Linux services.

.. include:: endpoints-creation.rst

Configuring OpenStack for EC2 API metadata service
---------------------------------------------------

.. include:: metadata-configuration.rst
