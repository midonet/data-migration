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
        self._provider_router = None
        self._pr_port_map = {}
        super(ProviderRouterMixin, self).__init__()

    @property
    def provider_router(self):
        if not self._provider_router:
            routers = self._get_midonet_resources('routers')
            for router in routers:
                if router['name'] == const.PROVIDER_ROUTER_NAME:
                    self._provider_router = router
                    break

        if self._provider_router is None:
            raise ValueError("Provider Router not found")

        return self._provider_router

    @property
    def provider_router_ports(self):
        if not self._pr_port_map:
            port_map = self._get_midonet_resources('ports')
            ports = port_map[self.provider_router['id']]
            for port in ports:
                self._pr_port_map[port['id']] = port

        return self._pr_port_map

    @property
    def provider_router_port_ids(self):
        return self.provider_router_ports.keys()


class ProviderRouter(dm_data.CommonData, ProviderRouterMixin,
                     er.ExtraRoutesMixin):

    def provider_router_to_edge_router(self, tenant):

        edge_router = self._create_edge_router(tenant)
        for port in self.provider_router_ports.values():

            if not (port['hostId'] and port['interfaceName']):
                LOG.debug("Skipping unbound port: " + port['id'])
                continue

            self._create_uplink_network(port, edge_router, tenant)

        self._link_external_subnets(edge_router)

        # Migrate BGP
        self._migrate_bgp(edge_router)

        # Migrate extra routes
        self.routes_to_extra_routes(self.provider_router['id'],
                                    dest_router=edge_router, delete=False)

    def _link_external_subnets(self, edge_router):
        edge_router_id = edge_router['id'] if edge_router else None
        nets = self._get_neutron_resources('networks')
        subnet_ids = _get_external_subnet_ids(nets)
        for subnet in subnet_ids:
            iface_obj = {'subnet_id': subnet}
            LOG.debug("Create Edge Router Intf: " + str(iface_obj))
            self._create_neutron_data(self.mc.l3_plugin.add_router_interface,
                                      edge_router_id, iface_obj)

    def _create_edge_router(self, tenant):
        router_obj = {'router': {'name': self.provider_router['name'],
                                 'tenant_id': tenant,
                                 'admin_state_up':
                                     self.provider_router['adminStateUp']}}
        LOG.debug("Create Edge Router: " + str(router_obj))
        return self._create_neutron_data(self.mc.l3_plugin.create_router,
                                         router_obj)

    def _create_uplink_port(self, port, upl_net, upl_sub, tenant):
        net_id = upl_net['id'] if upl_net else None
        sub_id = upl_sub['id'] if upl_sub else None
        port_obj = {'port': {'name': port['id'] + "_uplink_port",
                             'tenant_id': tenant,
                             'network_id': net_id,
                             'device_id': '',
                             'device_owner': '',
                             'mac_address': port['portMac'],
                             'fixed_ips': [
                                 {'subnet_id': sub_id,
                                  'ip_address': port['portAddress']}],
                             'binding:host_id': port['hostId'],
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

    def _migrate_bgp(self, edge_router):
        bgp_objs = self._get_midonet_resources(const.MN_BGP)
        pr_bgp_objs = []
        for port_id, bgp_list in iter(bgp_objs.items()):
            if port_id in self.provider_router_port_ids:
                pr_bgp_objs.extend(bgp_list)
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
    pr.provider_router_to_edge_router(tenant)
