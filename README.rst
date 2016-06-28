======================
MidoNet Data Migration
======================

This is the MidoNet data migration tool.

Currently data migration assumes that the Neutron version is kilo.


How to Run
----------

``migrate.py`` command is defined as follows::

     $ ./migrate_py [-h|--help] [-d|--debug] [-n|--dryrun] [-t|--tenant]
                    [-c|--conf <conf_file>]
                    <command>
Options::

     -h,--help
         Show usage of the command

     -d,--debug
         Turn on debug level logging.  Default is off.

     -t, --tenant
         Tenant ID to use for the Provider Router to edge router conversion.

     -n,--dryrun
         Run the command but only print out actions that would be taken
         normally, without actually committing the data.

     -c,--conf <conf_file>
         Use the specified configuration file for data migration.  If not
         specified, it looks for './migration.conf'.

Commands::

     prepare
         Output in JSON the existing Neutron resource ID -> resource object
         mappings and MidoNet data required for migration.
     migrate
         Migrate both Neutron generated and MidoNet generated data to the
         midonet cluster.  The input to this command is the JSON output from
         the 'prepare' command.
     pr2er
         Convert provider router to edge router and uplink networks.
         -t (--tenant) must be set for this command.  The input to this command
         is the JSON output from the 'prepare' command.
     deler
         Delete edge router and uplink networks created from pr2er command.
     extraroutes
         Convert MidoNet routes to Neutron extra routes.  The input to this
         command is the JSON output from the 'prepare' command.
