Create the ec2api service API endpoints:

.. code-block:: console

   $ openstack endpoint create --region RegionOne \
     ec2api public http://controller:XXXX/vY/%\(tenant_id\)s
   $ openstack endpoint create --region RegionOne \
     ec2api internal http://controller:XXXX/vY/%\(tenant_id\)s
   $ openstack endpoint create --region RegionOne \
     ec2api admin http://controller:XXXX/vY/%\(tenant_id\)s
