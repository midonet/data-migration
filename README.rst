======================
MidoNet Data Migration
======================

This is the MidoNet data migration tool.

Currently data migration assumes that the Neutron version is kilo.


How to Run
----------

Run the following command to insert Neutron objects to ``midonet_tasks`` table
(of Neutron DB) where they will be imported to midonet cluster::

     $ ./migrate.py

The script requires ``neutron.conf`` and ``midonet.ini`` files to run.  By
default, it assumes ``/etc/neutron/neutron.conf`` and
``/etc/neutron/plugins/midonet.ini``.

To override, run it with the following optional arguments::

     $ ./migrate.py -n ./my_neutron.conf -p ./my_plugin.conf

Run the following command to do a dry-run of the data migration::

     $ ./migrate.py --dryrun

This command outputs the list of tasks that would be performed in order for
data migration.  Currently only dry-run is supported.

To turn on debugging::

     $ ./migrate.py --debug

For more information about the command::

     $ ./migrate.py --help
