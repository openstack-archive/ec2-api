OpenStack EC2 API
=====================

Support of EC2 API for OpenStack.
This project provides a standalone EC2 API service which pursues two goals:

1. Implement VPC API which is now absent in nova's EC2 API

2. Create a standalone service for EC2 API support which accommodates
   not only the VPC API but the rest of the EC2 API currently present in nova as
   well.

It doesn't replace existing nova EC2 API service in deployment, it gets
installed to a different port (8788 by default).

The ec2-api service consists of the following components:

``ec2-api`` service
  Accepts and responds to end user EC2 and VPC API calls.

``ec2-api-metadata`` service
  Provides the OpenStack Metadata API to servers. The metadata is used to
  configure the running servers.


Installing EC2API
=================

.. toctree::
    :maxdepth: 1

    install/index

Configuring EC2API
==================

.. toctree::
    :maxdepth: 1

    configuration/index

EC2API Reference
==================

-  `EC2-API Reference`_

   .. _`EC2-API Reference`: https://docs.openstack.org/api-ref/ec2-api/


.. toctree::
   :maxdepth: 1

   hacking

For Contributors
================

* If you are a new contributor to ec2-api please refer: :doc:`contributor/contributing`

  .. toctree::
     :hidden:

     contributor/contributing

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
