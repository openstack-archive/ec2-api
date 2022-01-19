EC2 metadata is built in between the nova-metadata and the neutron-metadata,
so we need to configure Neutron so that it sends requests to ec2-api-metadata,
not to the nova.

To configure OpenStack for EC2 API metadata service for Neutron add:

.. code-block:: ini

    [DEFAULT]
    nova_metadata_port = 8789

to ``/etc/neutron/metadata_agent.ini`` for legacy neutron or
to ``neutron_ovn_metadata_agent.ini`` for OVN

then restart neutron-metadata service.

If you want to obtain metadata via SSL you need to configure neutron:

.. code-block:: ini

    [DEFAULT]
    nova_metadata_protocol = https
    # in case of self-signed certs you may need to specify CA
    auth_ca_cert = /path/to/root/cert/if/self/signed
    # or skip certs checking
    nova_metadata_insecure = True

And then you'll be able to get EC2-API/Nova metadata from neutron via SSL.
Anyway metadata URL inside the server still be http://169.254.169.254