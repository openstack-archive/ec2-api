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

Contents:

.. toctree::
   :maxdepth: 1

   hacking

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
