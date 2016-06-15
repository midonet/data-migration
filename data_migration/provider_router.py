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

    def provider_router_to_edge_router(self, tenant):
        LOG.info('Running Edge Router migration process')
        mc = ctx.get_write_context()
        router_obj = {'router': {'name': self._provider_router['name'],
                                 'tenant_id': tenant,
                                 'admin_state_up':
                                     self._provider_router['admin_state_up']}}
        LOG.debug("Create Edge Router: " + str(router_obj))
        upl_router = self._create_neutron_data(mc.l3_plugin.create_router,
                                               router_obj)

        for port in self.provider_router_ports.values():

            if not (port['hostId'] and port['interfaceName']):
                continue

            base_name = port['hostId'] + "_" + port['interfaceName']
            net_obj = {'network': {'name': base_name + "_uplink_net",
                                   'tenant_id': tenant,
                                   'shared': False,
                                   'provider:network_type': 'uplink',
                                   'admin_state_up': True}}
            LOG.debug("Create Uplink Network: " + str(net_obj))
            upl_net = self._create_neutron_data(mc.plugin.create_network,
                                                net_obj)

            cidr = port['networkAddress'] + "/" + str(port['networkLength'])
            subnet_obj = {'subnet': {'name': base_name + "_uplink_subnet",
                                     'network_id': upl_net.get('id'),
                                     'ip_version': 4,
                                     'cidr': cidr,
                                     'dns_nameservers': [],
                                     'host_routes': [],
                                     'allocation_pools': None,
                                     'enable_dhcp': False,
                                     'tenant_id': tenant,
                                     'admin_state_up': True}}
            LOG.debug("Create Uplink Subnet: " + str(subnet_obj))
            upl_sub = self._create_neutron_data(mc.plugin.create_subnet,
                                                subnet_obj)

            port_obj = {'port': {'name': base_name + "_uplink_port",
                                 'tenant_id': tenant,
                                 'network_id': upl_net.get('id'),
                                 'device_id': '',
                                 'device_owner': '',
                                 'mac_address': port['portMac'],
                                 'fixed_ips': [
                                     {'subnet_id': upl_sub.get('id'),
                                      'ip_address': port['portAddress']}],
                                 'binding:host_id': port['hostId'],
                                 'binding:profile': {
                                     'interface_name': port['interfaceName']},
                                 'admin_state_up': port['adminStateUp']}}
            LOG.debug("Create Uplink Port: " + str(port_obj))
            bound_port = self._create_neutron_data(mc.plugin.create_port,
                                                   port_obj)

            iface_obj = {'port_id': bound_port.get('id')}
            LOG.debug("Create Uplink Router Intf: " + str(iface_obj))
            self._create_neutron_data(mc.l3_plugin.add_router_interface,
                                      upl_router.get('id'), iface_obj)

        nets = self._get_neutron_resources('networks')
        subnet_ids = _get_external_subnet_ids(nets)
        for subnet in subnet_ids:
            iface_obj = {'subnet_id': subnet}
            LOG.debug("Create Edge Router Intf: " + str(iface_obj))
            self._create_neutron_data(mc.l3_plugin.add_router_interface,
                                      upl_router.get('id'), iface_obj)

        # Handle extra routes
        extra_route_map = self._get_extra_route_map(upl_router['id'])
        if extra_route_map:
            self._update_extra_routes(upl_router['id'],
                                      extra_route_map.values())
