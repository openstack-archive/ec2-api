Create the ec2api service API endpoints:

.. code-block:: console

   $ openstack endpoint create --region RegionOne ec2api \
     public http://controller:XXXX/
   $ openstack endpoint create --region RegionOne ec2api \
     admin http://controller:XXXX/
   $ openstack endpoint create --region RegionOne ec2api \
     internal http://controller:XXXX/

- where 'controller' is address your ec2api is installed on
- and 'XXXX' is port (8788 by default)
