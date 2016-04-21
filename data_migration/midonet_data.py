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
from data_migration import context
from data_migration import exceptions as exc
import logging
from webob import exc as wexc

LOG = logging.getLogger(name="data_migration")


def _is_lb_hm_interface(name):
    return (name and len(name) == const.MAX_INTF_LEN and
            name.endswith(const.LB_HM_INTF_SUFFIX))


def _port_is_bound(p):
    return p['type'] == const.EXT_RTR_PORT_TYPE and p['hostInterfacePort']


def _cidr_from_port(p):
    return p['networkAddress'] + "/" + str(p['networkLength'])


def _make_provider_router_port_dict(p, host, ifname):
    return {
        'admin_state_up': p['adminStateUp'],
        'network_cidr': _cidr_from_port(p),
        'mac': p['portMac'],
        'ip_address': p['portAddress'],
        'host': host,
        'iface': ifname
    }


def _convert_to_host_id_to_name_map(hosts):
    h_map = {}
    for h in hosts:
        h_map[h['id']] = h['name']
    return h_map


def _is_neutron_chain(chain):
    name = chain['name']
    return (name.startswith("OS_PRE_ROUTING_") or
            name.startswith("OS_POST_ROUTING_") or
            name.startswith("OS_PORT_") or
            name.startswith("OS_SG_"))


def _chain_filter(chains):
    return [c for c in chains if not _is_neutron_chain(c)]


class DataReader(object):

    def __init__(self, nd):
        self.mc = context.get_context()
        self._provider_router = None
        self._nd = nd

    def _get_objects_by_path(self, path, ids_exlude=None, filter_func=None):
        objs = self._get_objects_by_url(self.mc.mn_url + '/' + path + '/')

        if ids_exlude:
            objs = [o for o in objs if o['id'] not in ids_exlude]

        if filter_func:
            objs = filter_func(objs)

        return objs

    def _get_objects_by_url(self, url):
        return self.mc.mn_client.get(uri=url, media_type="*/*")

    def _get_provider_router(self):
        routers = self._get_objects_by_path('routers')
        try:
            provider_router = next(r for r in routers
                                   if r['name'] == const.PROVIDER_ROUTER_NAME)
        except StopIteration:
            # This should not happen
            raise exc.UpgradeScriptException("Provider Router not found")

        LOG.debug("[(MIDONET) Provider Router]: " + str(provider_router))
        return provider_router

    @property
    def provider_router(self):
        if self._provider_router is None:
            self._provider_router = self._get_provider_router()
        return self._provider_router

    def _convert_to_host2tz_map(self, tzs):
        host2tz = {}
        for tz in tzs:
            tz_id = tz['id']
            tzhs = self._get_objects_by_path('tunnel_zones/' + tz_id +
                                             "/hosts")
            for tzh in tzhs:
                hid = tzh['hostId']
                if hid not in host2tz:
                    host2tz[hid] = []
                host2tz[hid].append(
                    {"id": tzh["tunnelZoneId"],
                     "ip_address": tzh["ipAddress"]})
        return host2tz

    def _get_host_ports(self, host_id, pr_id):
        port_list = []
        ports = self._get_objects_by_path('hosts/' + host_id + "/ports")

        # Skip ports for health monitors
        for port in [p for p in ports
                     if not _is_lb_hm_interface(p['interfaceName'])]:
            port_obj = self._get_objects_by_url(port['port'])

            # Skip port bindings for external routers (provider router)
            if port_obj['deviceId'] != pr_id:
                port_list.append({"id": port_obj["id"],
                                  "interface": port['interfaceName']})
        return port_list

    def _prepare_host_bindings(self, hosts, host2tz_map):
        """Prepare the host bindings data

        The last step in the migration process is updating port bindings
        and host-tz memberships.  By the time this data is used, tunnel zones
        and ports should be already created.
        """
        bindings_map = {}
        pr = self.provider_router
        for h in hosts:
            hid = h['id']
            bindings_map[hid] = {
                "name": h['name'],
                "tunnel_zones": host2tz_map[hid],
                "ports": self._get_host_ports(hid, pr['id'])
            }

        return bindings_map

    def _get_port_with_host_intf_dict(self, p, host_id2name_map):
        hip = self._get_objects_by_url(p['hostInterfacePort'])
        h_name = host_id2name_map[hip['hostId']]
        return _make_provider_router_port_dict(p, h_name,
                                               hip['interfaceName'])

    def _prepare_provider_router(self, host_id2name_map):
        """Prepares the data required for provider router migration

        Gets 'router' and 'ports' portion of the provider router -> edge
        router migration.  See neutron_data's create_edge_router for more
        detail on the data.

        host_id2name_map is required to convert host ID to host name that
        Neutron expects.
        """
        ports = []
        pr_id = self.provider_router['id']
        pr_ports = self._get_objects_by_path('routers/' + pr_id + '/ports')
        for p in pr_ports:
            if _port_is_bound(p):
                port = self._get_port_with_host_intf_dict(p, host_id2name_map)
                ports.append(port)

        return {
            'router': {
                'name': self.provider_router['name'],
                'admin_state_up': self.provider_router['adminStateUp']
            },
            'ports': ports
        }

    def _neutron_ids(self, key):
        return set(self._nd[key].keys())

    def _router_exclude_ids(self):
        ids = self._neutron_ids('routers')
        ids.add(self.provider_router['id'])
        return ids

    def prepare(self):
        bridges = self._get_objects_by_path(
            "bridges", ids_exlude=self._neutron_ids('networks'))
        chains = self._get_objects_by_path("chains",
                                           filter_func=_chain_filter)
        routers = self._get_objects_by_path(
            "routers", ids_exlude=self._router_exclude_ids())
        tzs = self._get_objects_by_path('tunnel_zones')
        hosts = self._get_objects_by_path('hosts')
        host2tz_map = self._convert_to_host2tz_map(tzs)
        host_name_map = _convert_to_host_id_to_name_map(hosts)
        return {
            "hosts": hosts,
            "bridges": bridges,
            "routers": routers,
            "chains": chains,
            "tunnel_zones": tzs,
            "host_bindings": self._prepare_host_bindings(hosts, host2tz_map),
            "provider_router": self._prepare_provider_router(host_name_map)
        }


class DataWriter(object):

    def __init__(self, data, dry_run=False):
        self.mc = context.get_context()
        self.data = data
        self.dry_run = dry_run

    def _bind_hosts(self, bindings):
        for hid, h in iter(bindings.items()):
            tzs = h["tunnel_zones"]
            for tz in tzs:
                if self.dry_run:
                    print("tz.add_tunnel_zone_host()"
                          ".ip_address(" + tz['ip_address'] + ")"
                          ".host_id(" + hid + ").create()")
                else:
                    tz = self.mc.mn_api.get_tunnel_zone(tz['id'])
                    (tz.add_tunnel_zone_host()
                     .ip_address(h['ip_address'])
                     .host_id(hid).create())

            host = self.mc.mn_api.get_host(hid)
            ports = h["ports"]
            for p in ports:
                if self.dry_run:
                    print("api.add_host_interface_port(host, "
                          "port_id=" + p["id"] +
                          ", interface_name=" + p["interface"] + ")")
                else:
                    self.mc.mn_api.add_host_interface_port(
                        host, port_id=p["id"], interface_name=p["interface"])

    def _create_hosts(self, hosts):
        for h in hosts:
            if self.dry_run:
                print("api.add_host()"
                      ".id(" + h['id'] + ")"
                      ".name(" + h['name'] + ")"
                      ".create()")
            else:
                try:
                    (self.mc.mn_api.add_host()
                     .id(h['id'])
                     .name(h['name'])
                     .create())
                except wexc.HTTPClientError as e:
                    if e.code == wexc.HTTPConflict.code:
                        LOG.warn('Host already exists: ' + h['id'])

    def _create_chains(self, chains):
        for chain in chains:
            if self.dry_run:
                print("api.add_chain()"
                      ".name(" + chain['name'] + ")"
                      ".tenant_id(" + chain['tenantId'] + ")"
                      ".create()")
            else:
                return (self.mc.mn_api.add_chain()
                        .name(chain['name'])
                        .tenant_id(chain['tenantId'])
                        .create())

    def _create_bridges(self, bridges):
        for bridge in bridges:
            if self.dry_run:
                print("api.add_bridge()"
                      ".name(" + bridge['name'] + ")"
                      ".tenant_id(" + bridge['tenantId'] + ")"
                      ".inbound_filter_id(" + bridge['inboundFilterId'] + ")"
                      ".outbound_filter_id(" + bridge['outboundFilterId'] + ")"
                      ".admin_state_up(" + bridge['adminStateUp'] + ")"
                      ".create()")
            else:
                return (self.mc.mn_api.add_bridge()
                        .name(bridge['name'])
                        .tenant_id(bridge['tenantId'])
                        .inbound_filter_id(bridge['inboundFilterId'])
                        .outbound_filter_id(bridge['outboundFilterId'])
                        .admin_state_up(bridge['adminStateUp'])
                        .create())

    def _create_routers(self, routers):
        for router in routers:
            if self.dry_run:
                print("api.add_router()"
                      ".name(" + router['name'] + ")"
                      ".tenant_id(" + router['tenantId'] + ")"
                      ".inbound_filter_id(" + router['inboundFilterId'] + ")"
                      ".outbound_filter_id(" + router['outboundFilterId'] + ")"
                      ".admin_state_up(" + router['adminStateUp'] + ")"
                      ".create()")
            else:
                return (self.mc.mn_api.add_router()
                        .name(router['name'])
                        .tenant_id(router['tenantId'])
                        .inbound_filter_id(router['inboundFilterId'])
                        .outbound_filter_id(router['outboundFilterId'])
                        .admin_state_up(router['adminStateUp'])
                        .create())

    def _create_tunnel_zones(self, tzs):
        for tz in tzs:
            if self.dry_run:
                print("api.add_tunnel_zone()"
                      ".type(" + tz['type'] + ")"
                      ".name(" + tz['name'] + ")"
                      ".create()")
            else:
                try:
                    (self.mc.mn_api.add_tunnel_zone()
                     .type(tz['type'])
                     .name(tz['name'])
                     .create())
                except wexc.HTTPClientError as e:
                    if e.code == wexc.HTTPConflict.code:
                        LOG.warn('Tunnel zone already exists: ' + tz['name'])

    def create_objects(self):
        """Create all the midonet objects

        Expected input:

        {
           "hosts": [{"id": <host_id>, "name": <host_name>}, ...],
           "tunnel_zones": [{"type": <tz_type>, "name": <tz_name>, ...],
           "host_bindings": [
                       {"host_id": {"name": <hostname>,
                        "ports": [{"id": <port_id>,
                                   "interface": <interface>}, ...],
                        "tunnel_zones": [{"id": <tunnel_zone_id>,
                                          "ip_address": <ip_address>}, ...]
                       }, ...],
           "chains": [{"name": <chain_name>, "tenantId": <tenant_id>}, ...],
           "bridges": [{"name": <bridge_name>,
                        "tenantId": <tenant_id>,
                        "adminStateUp": <admin_state_up>,
                        "inboundFilterId": <inbound_chain_id>,
                        "outboundFilterId": <outbound_chain_id>}, ...],
           "routers": [{"name": <router_name>,
                        "tenantId": <tenant_id>,
                        "adminStateUp": <admin_state_up>,
                        "inboundFilterId": <inbound_chain_id>,
                        "outboundFilterId": <outbound_chain_id>}, ...],
        }
        """
        mido_data = self.data['midonet']
        self._create_hosts(mido_data['hosts'])
        self._create_tunnel_zones(mido_data["tunnel_zones"])
        self._create_chains(mido_data['chains'])
        self._create_bridges(mido_data['bridges'])
        self._create_routers(mido_data['routers'])
        self._bind_hosts(mido_data['host_bindings'])
