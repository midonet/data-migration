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

from data_migration import constants as const
from data_migration import context as ctx
from data_migration import data as dm_data
import logging
import netaddr

LOG = logging.getLogger(name="data_migration")


def _make_extra_route(route):
    dst = route['dstNetworkAddr'] + "/" + str(route["dstNetworkLength"])
    return {"destination": dst, "nexthop": route["nextHopGateway"]}


def _is_extra_route_convertible(route, cidrs, ips):
    # Convert to extra route only if the following conditions are met
    next_hop = route['nextHopGateway']
    return (route['nextHopPort'] and
            not route['learned'] and
            route['dstNetworkAddr'] != const.METADATA_ROUTE_IP and
            route['srcNetworkAddr'] == "0.0.0.0" and
            route['srcNetworkLength'] == 0 and
            route['weight'] == 100 and
            next_hop and
            netaddr.all_matching_cidrs(next_hop, cidrs) and
            next_hop not in ips)


def is_default_route(route):
    return (route.get('nextHopPort') and
            not route['learned'] and
            route['srcNetworkAddr'] == "0.0.0.0" and
            route['srcNetworkLength'] == 0 and
            route['dstNetworkAddr'] == "0.0.0.0" and
            route['dstNetworkLength'] == 0)


class RouteMixin(object):

    def _find_nexthop_port_route(self, route, router_id, f):
        port_map = self._get_midonet_resources('ports')
        ports = port_map[router_id]
        return next((p for p in ports if f(p, route)), None)

    def is_network_route(self, route, router_id):
        def _is_network_route(p, r):
            return (r.get('nextHopPort') == p['id'] and
                    not r['learned'] and
                    r['srcNetworkAddr'] == "0.0.0.0" and
                    r['srcNetworkLength'] == 0 and
                    r['dstNetworkAddr'] == p['networkAddress'] and
                    r['dstNetworkLength'] == p['networkLength'])

        return self._find_nexthop_port_route(route, router_id,
                                             _is_network_route)

    def is_port_route(self, route, router_id):

        def _is_port_route(p, r):
            return (r.get('nextHopPort') == p['id'] and
                    not r['learned'] and
                    r['srcNetworkAddr'] == "0.0.0.0" and
                    r['srcNetworkLength'] == 0 and
                    r['dstNetworkAddr'] == p['portAddress'] and
                    r['dstNetworkLength'] == 32)

        return self._find_nexthop_port_route(route, router_id, _is_port_route)


class ExtraRoutesMixin(RouteMixin):

    def _get_extra_route_map(self, router_id, cidrs, ips):
        extra_routes = {}

        # Get all the "normal" routes, store and delete them
        m_route_map = self._get_midonet_resources("routes")
        m_routes = m_route_map[router_id]
        for m_r in m_routes:
            if _is_extra_route_convertible(m_r, cidrs, ips):
                er = _make_extra_route(m_r)
                extra_routes[m_r['id']] = er

        return extra_routes

    def routes_to_extra_routes(self, router_id, dest_router=None, delete=True,
                               cidrs=None):
        mc = ctx.get_write_context()

        if dest_router:
            dest_router_id = dest_router['id']
        else:
            dest_router_id = router_id

        # Get all the neutron ports on this router and save the CIDRs.
        filters = {'device_id': [dest_router_id]}
        ports = mc.plugin.get_ports(mc.n_ctx, filters)
        cidrs = []
        ips = []
        for port in ports:
            for ip in port['fixed_ips']:
                cidrs.append(mc.plugin.get_subnet(mc.n_ctx,
                                                  ip['subnet_id'])['cidr'])
                ips.append(ip['ip_address'])

        # Get all the "normal" routes, store and delete them
        extra_route_map = self._get_extra_route_map(router_id, cidrs, ips)
        for route_id in extra_route_map.keys():
            if delete:
                LOG.debug("Deleting midonet route " + str(route_id))
                if not self.dry_run:
                    mc.mn_api.delete_route(route_id)

        if extra_route_map:
            routes = extra_route_map.values()
            LOG.debug("Updating Neutron router with routes: " + str(routes))
            if not self.dry_run:
                n_router = mc.l3_plugin.get_router(mc.n_ctx, dest_router_id)
                n_router["routes"] = routes
                mc.l3_plugin.update_router(mc.n_ctx, dest_router_id,
                                           {"router": n_router})


class ExtraRoute(dm_data.CommonData, ExtraRoutesMixin):

    def migrate_routes(self):
        n_router_ids = self._neutron_ids("routers")

        # Process existing Neutron routers first
        for router_id in n_router_ids:
            self.routes_to_extra_routes(router_id)


def migrate(data, dry_run=False):
    LOG.info('Running extra routes migration process')
    er = ExtraRoute(data, dry_run=dry_run)
    er.migrate_routes()
