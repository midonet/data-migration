#!/usr/bin/env python
# Copyright (C) 2016 Midokura SARL
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import print_function
import argparse
from data_migration import config
from data_migration import constants as const
from data_migration import midonet_data as md
from data_migration import neutron_data as nd
import json
import logging
import sys

LOG = logging.getLogger(name="data_migration")
logging.basicConfig(level=logging.INFO)


def main():
    # Parse args
    parser = argparse.ArgumentParser(
        description='MidoNet Data Migration Tool',
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('command', action='store',
                        help="Command to run:\n\n"
                             '\tneutron_prepare: prepare Neutron data\n'
                             '\tneutron_export: export Neutron data\n'
                             '\tprepare: prepare MidoNet data\n'
                             '\timport:  import MidoNet data from JSON\n'
                             '\t         output generated from prepare\n')
    parser.add_argument('-n', '--dryrun', action='store_true', default=False,
                        help='Perform a "dry run" and print out the examined\n'
                             'information and actions that would normally be\n'
                             'taken')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Turn on debug logging (off by default)')
    parser.add_argument('-c', '--neutron_conf', action='store',
                        default=const.NEUTRON_CONF_FILE,
                        help='Neutron configuration file')
    parser.add_argument('-p', '--plugin_conf', action='store',
                        default=const.MIDONET_PLUGIN_CONF_FILE,
                        help='MidoNet plugin configuration file')
    args = parser.parse_args()

    # Initialize configs
    config.register([args.neutron_conf, args.plugin_conf])
    dry_run = args.dryrun

    # For now, just allow DEBUG or INFO
    LOG.setLevel(level=logging.DEBUG if args.debug else logging.INFO)

    # Start the migration
    if args.command == "neutron_prepare":
        nm = nd.NeutronDataMigrator()
        print(json.dumps(nm.prepare()))
    elif args.command == "neutron_export":
        source = sys.stdin.readline()
        nm = nd.NeutronDataMigrator()
        nm.migrate(json.loads(source), dry_run=dry_run)
    elif args.command == "prepare":
        mm = md.MidonetDataMigrator()
        print(json.dumps(mm.prepare()))
    elif args.command == "import":
        source = sys.stdin.readline()
        mm = md.MidonetDataMigrator()
        mm.migrate(json.loads(source), dry_run=dry_run)
    else:
        print("Invalid command: " + args.command, file=sys.stderr)
        parser.print_help()
        sys.exit(-1)


if __name__ == "__main__":
    main()
