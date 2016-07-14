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

    def _is_extra_route_convertible(self, route, cidrs, ips):
        # Convert to extra route only if the following conditions are met
        next_hop = route['nextHopGateway']
        if not next_hop:
            self.add_skip(route['id'], "Route does not have next hop gateway")
            return False

        if not route['nextHopPort']:
            self.add_skip(route['id'], "Route does not have next hop port")
            return False

        if route['learned']:
            self.add_skip(route['id'], "Route is learned")
            return False

        if (route['srcNetworkAddr'] != "0.0.0.0" or
                route['srcNetworkLength'] != 0):
            self.add_skip(route['id'], "Route has source field(s) set")
            return False

        if route['dstNetworkAddr'] == const.METADATA_ROUTE_IP:
            self.add_skip(route['id'], "Route has metadata IP destination")
            return False

        if route['weight'] != 100:
            self.add_skip(route['id'], "Route has non-default weight")
            return False

        if not netaddr.all_matching_cidrs(next_hop, cidrs):
            self.add_skip(route['id'],
                          "Route has next hop to IP not created by Neutron")
            return False

        if next_hop in ips:
            self.add_skip(route['id'],
                          "Route has next hop set to Neutron port IP")
            return False

        return True

    def _get_extra_route_map(self, router_id, cidrs, ips):
        # Get all the "normal" routes, store and delete them
        m_route_map = self._get_midonet_resources("routes")
        m_routes = m_route_map.get(router_id)
        if not m_routes:
            # It's possible that MN data was missing
            return {}

        extra_routes = {}
        for m_r in m_routes:
            if self._is_extra_route_convertible(m_r, cidrs, ips):
                er = _make_extra_route(m_r)
                extra_routes[m_r['id']] = er

        return extra_routes

    def routes_to_extra_routes(self, router_id, dest_router=None, delete=True):
        mc = ctx.get_write_context()

        if dest_router:
            dest_router_id = dest_router['id']
        else:
            dest_router_id = router_id

        # Get all the neutron ports on this router and save the CIDRs.
        n_ports = self._get_neutron_resources("ports")
        router_ports = [p for p in n_ports.values()
                        if p['device_id'] == dest_router_id]
        cidrs = []
        ips = []
        n_subnets = self._get_neutron_resources("subnets")
        for port in router_ports:
            for ip in port['fixed_ips']:
                subnet = n_subnets[ip['subnet_id']]
                cidrs.append(subnet['cidr'])
                ips.append(ip['ip_address'])

        # Get all the "normal" routes, store and delete them
        extra_route_map = self._get_extra_route_map(router_id, cidrs, ips)
        for route_id in extra_route_map.keys():
            if delete:
                LOG.debug("Deleting midonet route " + str(route_id))
                if not self.dry_run:
                    mc.mn_api.delete_route(route_id)
                    self.deleted.append(router_id)

        if extra_route_map:
            r = {"router": {
                    "id": dest_router_id,
                    "routes": extra_route_map.values()}}
            LOG.debug("Updating Neutron router write routes: " + str(r))
            if not self.dry_run:
                mc.l3_plugin.update_router(mc.n_ctx, dest_router_id, r)
                self.updated.append(r)


class ExtraRoute(dm_data.CommonData, dm_data.DataCounterMixin,
                 ExtraRoutesMixin):

    @property
    def key(self):
        return "extra_routes"

    def migrate(self):
        n_router_ids = self._neutron_ids("routers")

        # Process existing Neutron routers first
        for router_id in n_router_ids:
            self.routes_to_extra_routes(router_id)


def migrate(data, dry_run=False):
    LOG.info('Running extra routes migration process')
    er = ExtraRoute(data, dry_run=dry_run)
    er.migrate()
    er.print_summary()
