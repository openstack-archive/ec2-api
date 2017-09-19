Create the ec2api service API endpoints:

.. code-block:: console

   $ openstack endpoint create --region RegionOne ec2api \
     public http://controller:XXXX/
   $ openstack endpoint create --region RegionOne ec2api \
     admin http://controller:XXXX/
   $ openstack endpoint create --region RegionOne ec2api \
     internal http://controller:XXXX/

- where 'controller' is address of controller,
- and 'XXXX' is port your ec2api is installed on (8788 by default)
