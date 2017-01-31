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
from data_migration import provider_router as pr
import logging

LOG = logging.getLogger(name="data_migration")


class ExternalNet(dm_data.CommonData, dm_data.DataCounterMixin,
                  pr.ProviderRouterMixin):

    def _external_nets_exist(self):
        # Find the external network with the given name
        net_names = [p[0] + const.EXT_NET_SUFFIX
                     for p in const.PROVIDER_ROUTER_TO_EXT_NET_MAP.values()]
        nets = self.mc.plugin.get_networks(
            self.mc.n_ctx, filters={"name": net_names})
        return len(nets) > 0

    def _create_external_nets(self, tenant):
        nets = {}
        for net, cidr, gw_ip in const.PROVIDER_ROUTER_TO_EXT_NET_MAP.values():
            net_obj = {'network': {
                'name': net + const.EXT_NET_SUFFIX,
                'tenant_id': tenant,
                'admin_state_up': True,
                'shared': False,
                'router:external': True}}
            LOG.info("Create External Network: " + str(net_obj))
            neutron_net = self._create_neutron_data(
                self.mc.plugin.create_network,
                net_obj)

            if not neutron_net:
                neutron_net = {'id': net + '_AUTOMATICALLY_CREATED'}

            nets[net + const.EXT_NET_SUFFIX] = neutron_net

            subnet_obj = {'subnet': {
                'name': net + const.EXT_NET_SUFFIX + '_sub',
                'network_id': neutron_net['id'],
                'ip_version': 4,
                'cidr': cidr,
                'gateway_ip': gw_ip,
                'allocation_pools': None,
                'dns_nameservers': [],
                'host_routes': [],
                'enable_dhcp': False,
                'tenant_id': tenant,
                'admin_state_up': True}}
            LOG.info("Create External Subnet: " + str(subnet_obj))
            self._create_neutron_data(
                self.mc.plugin.create_subnet,
                subnet_obj)

        return nets

    @property
    def key(self):
        return "external_networks"

    def create(self, tenant):
        # Check that ext net does not exist
        if self._external_nets_exist():
            LOG.info("External nets already exist.  Delete before running "
                     "this command.")
            return

        # Create external networks/subnets
        ext_nets = self._create_external_nets(
            tenant)

        # For each provider router, check it's old MN data to see which
        # provider router it used to be attached to, and attach it to the
        # relevant external network (based on the mapping provided)
        for peer_rtr, ext_net_name in (
                self.provider_router_peer_port_map.items()):
            ext_net_obj = ext_nets[ext_net_name]
            rtr_update_obj = {'router': {
                'external_gateway_info': {
                    'network_id': ext_net_obj['id'],
                    'enable_snat': False
                },
                'tenant_id': tenant}}
            LOG.info("Updating router gateway: " + str(peer_rtr) +
                     " to external net: " + ext_net_obj['id'])
            self._create_neutron_data(
                self.mc.l3_plugin.update_router,
                peer_rtr,
                rtr_update_obj)


def migrate(data, tenant, dry_run=False):
    LOG.info('Running external network creation process')
    ext_net = ExternalNet(data, dry_run=dry_run)
    ext_net.create(tenant)
