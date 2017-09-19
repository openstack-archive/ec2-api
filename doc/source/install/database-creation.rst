.. _database-creation:

Creating the database
~~~~~~~~~~~~~~~~~~~~~

The database is created automatically by the install.sh.

To create the database manually, complete these steps:

* Use the database access client to connect to the database
  server as the ``root`` user:

  .. code-block:: console

     $ mysql -u root -p

* Create the ``ec2api`` database:

  .. code-block:: mysql

     CREATE DATABASE ec2api;

* Grant proper access to the ``ec2api`` database:

  .. code-block:: console

     GRANT ALL PRIVILEGES ON ec2api.* TO 'ec2api'@'localhost' \
      IDENTIFIED BY 'EC2-API_DBPASS';
     GRANT ALL PRIVILEGES ON ec2api.* TO 'ec2api'@'%' \
      IDENTIFIED BY 'EC2-API_DBPASS';

  Replace ``EC2-API_DBPASS`` with a suitable password.

* Exit the database access client.

  .. code-block:: mysql

     exit;
