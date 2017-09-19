.. _install-ubuntu:

Installation on existing OpenStack deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure the ec2-api
service for Ubuntu (LTS).

Install and configure components
--------------------------------

Install the packages:

.. code-block:: console

   # apt-get update
   # git clone https://github.com/openstack/ec2-api.git
   # cd ec2-api

Run install.sh

The EC2 API service gets installed on port 8788 by default. It can be changed
before the installation in install.sh script.

The services afterwards can be started as binaries:

::

   /usr/local/bin/ec2-api
   /usr/local/bin/ec2-api-metadata

or set up as Linux services.

.. include:: endpoints-creation.rst

Configuring OpenStack for EC2 API metadata service
--------------------------------------------------

To configure OpenStack for EC2 API metadata service:

for Nova-network add:

.. code-block:: console

    # [DEFAULT]
    # metadata_port = 8789
    # [neutron]
    # service_metadata_proxy = True

to ``/etc/nova.conf``

then restart nova-metadata (can be run as part of nova-api service) and
nova-network services.

for Neutron add:

.. code-block:: console

    # [DEFAULT]
    # nova_metadata_port = 8789

to ``/etc/neutron/metadata_agent.ini``

then restart neutron-metadata service.
