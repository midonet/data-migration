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
from data_migration import constants as const
from data_migration import data as dm_data
from data_migration import provider_router as pr
import json
import logging
from neutron.db import extraroute_db
from oslo_config import cfg
import sys

LOG = logging.getLogger(name="data_migration")


class RouteAdder(dm_data.CommonData, dm_data.DataCounterMixin,
                 pr.ProviderRouterMixin):

    def _external_nets_exist(self):
        # Find the external network with the given name
        net_names = [p[0] + const.EXT_NET_SUFFIX
                     for p in const.PROVIDER_ROUTER_TO_EXT_NET_MAP.values()]
        nets = self.mc.plugin.get_networks(
            self.mc.n_ctx, filters={"name": net_names})
        return len(nets) > 0

    def create(self, tenant):
        for _, ex_net in const.PROVIDER_ROUTER_TO_EXT_NET_MAP.items():
            net_name = ex_net[0] + const.EXT_NET_SUFFIX
            ext_net_obj = self.mc.plugin.get_networks(
                self.mc.n_ctx, filters={"name": [net_name]})

            if len(ext_net_obj) != 1:
                LOG.warning(
                    "Only one external network should have been found for "
                    "external net: " + net_name + ", but we found " +
                    str(len(ext_net_obj)) + ", skipping.")
                continue

            edge_router_list = self.mc.l3_plugin.get_routers(
                self.mc.n_ctx,
                filters={"name": [ex_net[0] + const.EDGE_ROUTER_SUFFIX]})
            if len(edge_router_list) != 1:
                LOG.warning(
                    "Only one edge router should have been found for "
                    "external net: " + net_name + ", but we found " +
                    str(len(edge_router_list)) + ", skipping.")
                continue

            edge_router = edge_router_list[0]
            ext_bridge = self.mc.mn_api.get_bridge(ext_net_obj[0]['id'])

            ext_router_new_routes = {}
            # Loop all other ports except GW port to get tenant router ports
            for port in [p for p in ext_bridge.get_ports()]:
                tr_port = self.mc.mn_api.get_port(port.get_peer_id())
                tr_port_ip = tr_port.get_port_address()
                # If this is actually the gateway port, skip it.
                if tr_port_ip == ex_net[2]:
                    LOG.info("Skipping gateway port: " +
                             tr_port.get_port_address())
                    continue

                tr_id = tr_port.get_device_id()
                tr = self.mc.mn_api.get_router(tr_id)
                tr_net_ports = [s for s in tr.get_ports()
                                if s.get_id() != tr_port.get_id()]
                for net_port in tr_net_ports:
                    tn_cidr = (net_port.get_network_address() + '/' +
                               str(net_port.get_network_length()))
                    tenant_router_next_hop = tr_port_ip
                    ext_router_new_routes[tn_cidr] = tenant_router_next_hop

            # Add all extra routes to this edge router
            LOG.info("For edge router: " + edge_router['name'])
            for dest, next_hop in ext_router_new_routes.items():
                LOG.info("Adding route: " + dest + " via " + next_hop)

            if not self.dry_run:
                router_obj = {'router': {
                    'routes': [
                        {'destination': dest,
                         'nexthop': next_hop}
                        for dest, next_hop in ext_router_new_routes.items()],
                    'tenant_id': tenant}}
                extraroute_db.cfg.CONF.max_routes = (
                    len(ext_router_new_routes) + 1)
                self.mc.l3_plugin.update_router(
                    self.mc.n_ctx, edge_router['id'], router_obj)


def _exit_on_error(msg, parser):
    print(msg, file=sys.stderr)
    parser.print_help()
    sys.exit(-1)


def add_routes(data, tenant, dry_run=False):
    LOG.info('Running route creation process')
    route_adder = RouteAdder(data, dry_run=dry_run)
    route_adder.create(tenant)


def main():
    # Parse args
    parser = argparse.ArgumentParser(
        description='MidoNet Route Migration Tool',
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Turn on debug logging (off by default)')
    parser.add_argument('-c', '--conf', action='store',
                        default="./migration.conf",
                        help='Migration configuration file')
    parser.add_argument('-n', '--dryrun', action='store_true', default=False,
                        help='Perform a "dry run" and print out the examined\n'
                             'information and actions that would normally be\n'
                             'taken')
    parser.add_argument('-t', '--tenant', action='store', default=None,
                        help='Tenant name to use for the edge router')
    args = parser.parse_args()

    dry_run = args.dryrun
    # Initialize configs
    cfg.CONF(args=[], project='neutron', default_config_files=[args.conf])

    # For now, just allow DEBUG or INFO
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level)

    source = sys.stdin.readline()
    sys.stdin = open('/dev/tty')

    json_source = json.loads(source)
    add_routes(json_source, args.tenant, dry_run=dry_run)

if __name__ == "__main__":
    main()
