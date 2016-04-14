======================
MidoNet Data Migration
======================

This is the MidoNet data migration tool.

Currently data migration assumes that the Neutron version is kilo.


How to Run
----------

``migrate.py`` command is defined as follows::

     $ ./migrate_py [-h|--help] [-d|--debug] [-n|--dryrun]
                    [-c|--neutron_conf <neutron_conf_file>]
                    [-p|--plugin_conf <plugin_conf_file>]
                    <command>
Options::

     -h,--help
         Show usage of the command

     -d,--debug
         Turn on debug level logging.  Default is off.

     -n,--dryrun
         Run the command but only print out actions that would be taken
         normally, without actually committing the data.

     -c,--neutron_conf <conf_file>
         Use the specified Neutron configuration file instead of the default,
         '/etc/neutron/neutron.conf'.

     -p,--plugin_conf <conf_file>
         Use the specified MidoNet plugin configuration file instead of the
         default, '/etc/neutron/plugins/midonet/midonet.ini'.

Commands::

     neutron
         Export the Neutron data by inserting Neutron objects to
         `midonet_tasks' table of Neutron DB where they will be imported to
         midonet cluster.  With --dryrun, nothing gets inserted.

     prepare
         Prepare MidoNet data by printing the gathered data in a JSON format.

     import
         Read from stdin the JSON output generated from 'prepare' command, and
         import the data into MidoNet cluster.

