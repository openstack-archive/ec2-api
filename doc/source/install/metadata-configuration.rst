EC2 metadata is built in between the nova-metadata and the neutron-metadata,
so we need to configure Neutron so that it sends requests to ec2-api-metadata,
not to the nova.

To configure OpenStack for EC2 API metadata service for Neutron add:

.. code-block:: ini

    [DEFAULT]
    nova_metadata_port = 8789

to ``/etc/neutron/metadata_agent.ini``

then restart neutron-metadata service.
