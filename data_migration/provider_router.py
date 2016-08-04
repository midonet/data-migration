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
from data_migration import routes as er
import logging

LOG = logging.getLogger(name="data_migration")


def _get_external_subnet_ids(nets):
    subnet_ids = []
    networks = [net for net in iter(nets.values())
                if net['router:external']]
    for net in networks:
        for sub in net['subnets']:
            subnet_ids.append(sub)

    return subnet_ids


class ProviderRouterMixin(object):

    def __init__(self):
        self._provider_routers = {}
        self._pr_port_map = {}
        self._pr_peer_port_map = {}
        super(ProviderRouterMixin, self).__init__()

    @property
    def provider_routers(self):
        if len(self._provider_routers) == 0:
            self._provider_routers = {}
            for r in self._get_midonet_resources('routers'):
                if r['name'] in self._provider_routers:
                    raise ValueError("More than one provider router with "
                                     "the name: " + r['name'] +
                                     " has been found.  This is not "
                                     "supported by this script.")
                self._provider_routers[r['name']] = r

        if len(self._provider_routers) == 0:
            raise ValueError("No Provider Router found")

        return self._provider_routers

    @property
    def provider_routers_ports(self):
        if not self._pr_port_map:
            port_map = self._get_midonet_resources('ports')
            for rtr_name, rtr in self.provider_routers.items():
                self._pr_port_map[rtr_name] = {
                    p['id']: p
                    for p in (port_map[rtr['id']]
                              if rtr['id'] in port_map
                              else [])}

        return self._pr_port_map

    def provider_router_port_ids(self, name):
        return (self.provider_routers_ports[name].keys()
                if name in self.provider_routers_ports
                else [])

    @property
    def provider_router_peer_port_map(self):
        if not self._pr_peer_port_map:
            port_map = self._get_midonet_resource_map(const.MN_PORTS)
            for rtr, pr_port_map in self.provider_routers_ports.items():
                # Skip any provider router not getting mapped to an
                # external network
                if rtr not in const.PROVIDER_ROUTER_TO_EXT_NET_MAP:
                    continue
                edge_name = const.PROVIDER_ROUTER_TO_EXT_NET_MAP[rtr][0]
                for port in filter(
                        lambda p: p.get('peerId') is not None,
                        pr_port_map.values()):
                    peer = port_map[port.get('peerId')]
                    if peer['type'] == const.RTR_PORT_TYPE:
                        self._pr_peer_port_map[peer['deviceId']] = edge_name
        return self._pr_peer_port_map


class ProviderRouter(dm_data.CommonData, dm_data.DataCounterMixin,
                     ProviderRouterMixin, er.ExtraRoutesMixin):

    def provider_routers_to_edge_routers(self, tenant):
        if self._edge_routers_exist():
            LOG.info("Edge routers already exist.  Delete before running "
                     "this command. " + str())
            return

        for pr, ex_net in const.PROVIDER_ROUTER_TO_EXT_NET_MAP.items():
            ext_subnet_name = ex_net[0] + '_sub'
            ext_subnet = self.mc.plugin.get_subnets(
                self.mc.n_ctx, filters={"name": [ext_subnet_name]})
            if len(ext_subnet) != 1:
                LOG.debug("Only one external subnet should have been found for"
                          " external net: " + ex_net[0] + ", but we found " +
                          str(len(ext_subnet)) + ", skipping.")
                continue

            er_name = ex_net[0] + '_edge_router'
            edge_router = self._create_edge_router(tenant, er_name)

            for port in self.provider_routers_ports[pr].values():
                if not (port.get('hostId') and
                    port.get('interfaceName')):
                    LOG.debug("Skipping unbound port: " + port['id'])
                    continue

                # We need to create new binding ports on the new router as well
                # as transfer over any BGP/route data
                self._create_midonet_uplink_port(edge_router['id'], port)

            self._link_external_subnets(edge_router, ext_subnet[0])

            # Migrate BGP
            self._migrate_bgp(self.provider_routers[pr],
                              edge_router)

            # Migrate extra routes
            self.routes_to_extra_routes(self.provider_routers[pr]['id'],
                                        dest_router=edge_router,
                                        delete=False)

    def _edge_routers_exist(self):
        # Find the edge router
        names = map(lambda s: s + '_edge_router',
                    [p[0]
                     for p in const.PROVIDER_ROUTER_TO_EXT_NET_MAP.values()])
        routers = self.mc.l3_plugin.get_routers(
            self.mc.n_ctx, filters={"name": names})
        return len(routers) > 0

    def _link_external_subnets(self, edge_router, ext_subnet):
        iface_obj = {'subnet_id': ext_subnet['id']}
        LOG.debug("Create Edge Router Port on Ext Network: " + str(iface_obj))
        self._create_neutron_data(self.mc.l3_plugin.add_router_interface,
                                  edge_router['id'], iface_obj)

    def _create_edge_router(self, tenant, name):
        router_obj = {
            'router': {
                'name': name,
                'tenant_id': tenant,
                'admin_state_up': True}}
        LOG.debug("Create Edge Router: " + str(router_obj))
        return self._create_neutron_data(self.mc.l3_plugin.create_router,
                                         router_obj)

    def _create_midonet_uplink_port(self, dest_router, old_port):
        host = self.mc.mn_api.get_host(old_port.get('hostId'))
        iface = old_port.get('interfaceName')

        mn_router = self.mc.mn_api.get_router(dest_router)
        rtr_port = (self.mc.mn_api.add_router_port(mn_router)
                    .admin_state_up(True)
                    .port_address(old_port['portAddress'])
                    .network_address(old_port['networkAddress'])
                    .network_length(old_port['networkLength'])
                    .port_mac(old_port['portMac'])
                    .create())
        self.mc.mn_api.add_host_interface_port(host, rtr_port.get_id(), iface)

    def _get_host_name_from_host_id(self, host_id):
        hosts = self._get_midonet_resources("hosts")
        return next((h["name"] for h in hosts if h["id"] == host_id), None)

    def _create_uplink_port(self, port, upl_net, upl_sub, tenant):
        net_id = upl_net['id'] if upl_net else None
        sub_id = upl_sub['id'] if upl_sub else None
        host_name = self._get_host_name_from_host_id(port['hostId'])
        port_obj = {'port': {'name': port['id'] + "_uplink_port",
                             'tenant_id': tenant,
                             'network_id': net_id,
                             'device_id': '',
                             'device_owner': '',
                             'mac_address': port['portMac'],
                             'fixed_ips': [
                                 {'subnet_id': sub_id,
                                  'ip_address': port['portAddress']}],
                             'binding:host_id': host_name,
                             'binding:profile': {
                                 'interface_name': port['interfaceName']},
                             'admin_state_up': port['adminStateUp']}}
        LOG.debug("Create Uplink Port: " + str(port_obj))
        return self._create_neutron_data(self.mc.plugin.create_port, port_obj)

    def _create_uplink_subnet(self, port, upl_net, tenant):
        cidr = port['networkAddress'] + "/" + str(port['networkLength'])
        net_id = upl_net['id'] if upl_net else None
        subnet_obj = {'subnet': {'name': port['id'] + "_uplink_subnet",
                                 'network_id': net_id,
                                 'ip_version': 4,
                                 'cidr': cidr,
                                 'dns_nameservers': [],
                                 'host_routes': [],
                                 'allocation_pools': None,
                                 'enable_dhcp': False,
                                 'tenant_id': tenant,
                                 'admin_state_up': True}}
        LOG.debug("Create Uplink Subnet: " + str(subnet_obj))
        return self._create_neutron_data(self.mc.plugin.create_subnet,
                                         subnet_obj)

    def _link_edge_router_to_uplink(self, port, edge_router):
        port_id = port['id'] if port else None
        edge_router_id = edge_router['id'] if edge_router else None
        iface_obj = {'port_id': port_id}
        LOG.debug("Create Uplink Router Intf: " + str(iface_obj))
        self._create_neutron_data(self.mc.l3_plugin.add_router_interface,
                                  edge_router_id, iface_obj)

    def _create_uplink_network(self, port, edge_router, tenant):
        net_obj = {'network': {'name': port['id'] + "_uplink_net",
                               'tenant_id': tenant,
                               'shared': False,
                               'provider:network_type': 'uplink',
                               'admin_state_up': True}}
        LOG.debug("Create Uplink Network: " + str(net_obj))
        upl_net = self._create_neutron_data(self.mc.plugin.create_network,
                                            net_obj)
        upl_sub = self._create_uplink_subnet(port, upl_net, tenant)
        upl_port = self._create_uplink_port(port, upl_net, upl_sub, tenant)
        self._link_edge_router_to_uplink(upl_port, edge_router)

    def _migrate_bgp(self, source_router, edge_router):
        bgp_objs = self._get_midonet_resources(const.MN_BGP)
        pr_bgp_objs = []

        for port_id in self.provider_router_port_ids(source_router['name']):
            bgp_list = bgp_objs.get(port_id)
            pr_bgp_objs.extend(bgp_list if bgp_list else [])

        LOG.debug("Create edge router BGP peers from BGP: " + str(pr_bgp_objs))

        pr_bgp_ids = [bgp['id'] for bgp in pr_bgp_objs]
        ad_routes = self._get_midonet_resources(const.MN_AD_ROUTES)
        pr_ad_routes = []
        for bgp_id, route_list in iter(ad_routes.items()):
            if bgp_id in pr_bgp_ids:
                pr_ad_routes.extend(route_list)
        LOG.debug("Create edge router BGP networks from Ad Route: " +
                  str(pr_ad_routes))

        if self.dry_run:
            return

        mido_router = self.mc.mn_api.get_router(edge_router['id'])
        for bgp in pr_bgp_objs:
            (mido_router.add_bgp_peer()
                .asn(bgp['peerAS'])
                .address(bgp['peerAddr']).create())
            mido_router.asn(bgp['localAS']).update()

        for ad_route in pr_ad_routes:
            (mido_router.add_bgp_network()
                .subnet_address(ad_route['nwPrefix'])
                .subnet_length(ad_route['prefixLength']).create())


def migrate(data, tenant, dry_run=False):
    LOG.info('Running Edge Router migration process')
    pr = ProviderRouter(data, dry_run=dry_run)
    pr.provider_routers_to_edge_routers(tenant)


def delete_edge_routers():
    LOG.info("Deleting Edge Routers and Uplink Networks")
    mc = ctx.get_write_context()

    # Remove Uplink networks
    nets = mc.plugin.get_networks(mc.n_ctx)
    for net in nets:
        net_type = net.get("provider:network_type")
        if net_type == "uplink":
            ports = mc.plugin.get_ports(
                mc.n_ctx,
                filters={"network_id": [net["id"]]})
            for port in ports:
                if port['device_id']:
                    iface_obj = {'port_id': port["id"]}
                    LOG.debug("Removing uplink net router interface: " +
                              str(iface_obj))
                    mc.l3_plugin.remove_router_interface(mc.n_ctx,
                                                         port['device_id'],
                                                         iface_obj)
                else:
                    LOG.debug("Removing uplink net port: " + str(port))
                    mc.plugin.delete_port(mc.n_ctx, port['id'],
                                          l3_port_check=False)

            LOG.debug("Removing Uplink network: " + str(net))
            mc.plugin.delete_network(mc.n_ctx, net["id"])

    routers = mc.l3_plugin.get_routers(
        mc.n_ctx, filters={
            "name": map(lambda s: s[0] + '_edge_router',
                        const.PROVIDER_ROUTER_TO_EXT_NET_MAP.values())})

    for router in routers:
        er_id = router["id"]

        # Unlink from external subnets
        ports = mc.plugin.get_ports(
            mc.n_ctx,
            filters={'device_owner': [const.ROUTER_INTERFACE_PORT_TYPE],
                     'device_id': [er_id]})

        for port in ports:
            iface_obj = {'port_id': port["id"]}
            LOG.debug("Removing Edge Router Intf: " + str(iface_obj))
            mc.l3_plugin.remove_router_interface(mc.n_ctx, er_id, iface_obj)

        # Remove edge router
        LOG.debug("Removing Edge Router: " + str(router))
        mc.l3_plugin.delete_router(mc.n_ctx, er_id)
