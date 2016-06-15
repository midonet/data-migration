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
from data_migration import midonet_data as md
from data_migration import neutron_data as nd
import json
import logging
from oslo_config import cfg
import sys

LOG = logging.getLogger(name="data_migration")
logging.basicConfig(level=logging.INFO)


def _exit_on_error(msg, parser):
    print(msg, file=sys.stderr)
    parser.print_help()
    sys.exit(-1)


def main():
    # Parse args
    parser = argparse.ArgumentParser(
        description='MidoNet Data Migration Tool',
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('command', action='store',
                        help="Command to run:\n\n"
                             '\tprepare: prepare intermediary data in JSON\n'
                             '\tmigrate: migrate data from JSON input\n'
                             '\tpr2er: convert provider router to edge router'
                             '\n'
                             '\textraroutes: convert midonet routes to Neutron'
                             'extra routes')
    parser.add_argument('-n', '--dryrun', action='store_true', default=False,
                        help='Perform a "dry run" and print out the examined\n'
                             'information and actions that would normally be\n'
                             'taken')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Turn on debug logging (off by default)')
    parser.add_argument('-c', '--conf', action='store',
                        default="./migration.conf",
                        help='Migration configuration file')
    parser.add_argument('-t', '--tenant', action='store', default=None,
                        help='Tenant name to use for the edge router')
    args = parser.parse_args()

    # Initialize configs
    cfg.CONF(args=[], project='neutron', default_config_files=[args.conf])
    dry_run = args.dryrun

    # For now, just allow DEBUG or INFO
    LOG.setLevel(level=logging.DEBUG if args.debug else logging.INFO)

    # Start the migration
    if args.command == "prepare":
        n_data = nd.prepare()
        mm = md.DataReader(n_data)
        output = {
            "neutron": n_data,
            "midonet": mm.prepare()
        }
        print(json.dumps(output))
    elif args.command == "migrate":
        source = sys.stdin.readline()
        json_source = json.loads(source)

        nm = nd.DataWriter(json_source, dry_run=dry_run)
        nm.migrate()

        mm = md.DataWriter(json_source, dry_run=dry_run)
        mm.migrate()
    elif args.command == "pr2er":
        if not args.tenant:
            _exit_on_error("tenant is required for this command", parser)

        source = sys.stdin.readline()
        json_source = json.loads(source)
        nm = nd.DataWriter(json_source, dry_run=dry_run)
        nm.provider_router_to_edge_router(args.tenant)
    elif args.command == "extraroutes":
        source = sys.stdin.readline()
        json_source = json.loads(source)
        nm = nd.DataWriter(json_source, dry_run=dry_run)
        nm.routes_to_extra_routes()
    else:
        _exit_on_error("Invalid command: " + args.command, parser)


if __name__ == "__main__":
    main()
