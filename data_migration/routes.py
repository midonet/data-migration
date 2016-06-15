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
import logging

LOG = logging.getLogger(name="data_migration")


def _make_extra_route(route):
    dst = route['dstNetworkAddr'] + "/" + str(route["dstNetworkLength"])
    return {"destination": dst, "nexthop": route["nextHopGateway"]}


def _is_extra_route_convertible(route):
    return (route['srcNetworkAddr'] == "0.0.0.0" and
            route['srcNetworkLength'] == 0 and
            route['nextHopGateway'] and
            route['weight'] == 100)


def is_learned_route(route):
    return route['learned']


def is_metadata_route(route):
    return route['dstNetworkAddr'] == const.METADATA_ROUTE_IP


class RouteMixin(object):

    def _is_port_route(self, route, router_id):
        port_map = self._get_midonet_resources('ports')
        ports = port_map[router_id]
        route_map = {}
        for port in ports:
            route_map[port['id']] = port['portAddress']

        next_hop_port = route['nextHopPort']
        return (route['srcNetworkAddr'] == "0.0.0.0" and
                route['srcNetworkLength'] == 0 and
                route['dstNetworkLength'] == 32 and
                next_hop_port and
                route['dstNetworkAddr'] == route_map.get(next_hop_port))

    def _is_normal_route(self, route, router_id):
        return not (is_learned_route(route) or
                    self._is_port_route(route, router_id) or
                    is_metadata_route(route))


class ExtraRoutesMixin(RouteMixin):

    def _get_extra_route_map(self, router_id):
        extra_routes = {}

        # Get all the "normal" routes, store and delete them
        m_route_map = self._get_midonet_resources("routes")
        m_routes = m_route_map[router_id]
        for m_r in m_routes:
            if (self._is_normal_route(m_r, router_id) and
                    _is_extra_route_convertible(m_r)):
                er = _make_extra_route(m_r)
                extra_routes[m_r['id']] = er

        return extra_routes

    def _update_extra_routes(self, router_id, routes):
        mc = ctx.get_write_context()
        n_router = mc.l3_plugin.get_router(mc.n_ctx, router_id)
        n_router["router"]["routes"] = routes
        LOG.debug("Updating Neutron router " + str(n_router))
        if not self.dry_run:
            mc.l3_plugin.update_router(mc.n_ctx, router_id, n_router)

    def routes_to_extra_routes(self):
        LOG.info('Running extra routes migration process')
        mc = ctx.get_write_context()
        n_router_ids = self._neutron_ids("routers")

        # Process existing Neutron routers first
        for router_id in n_router_ids:

            # Get all the "normal" routes, store and delete them
            extra_route_map = self._get_extra_route_map(router_id)
            for route_id in extra_route_map.keys():
                LOG.debug("Deleting midonet route " + str(route_id))
                if not self.dry_run:
                    mc.mn_api.delete_route(route_id)

            if extra_route_map:
                self._update_extra_routes(router_id, extra_route_map.values())
