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
    return p.get_interface_name() is not None and p.get_host_id() is not None


def _cidr_from_port(p):
    return p.get_network_address() + "/" + str(p.get_network_length())


def _make_provider_router_port_dict(p, host, ifname):
    return {
        'admin_state_up': p.get_admin_state_up(),
        'network_cidr': _cidr_from_port(p),
        'mac': p.get_port_mac(),
        'ip_address': p.get_port_address(),
        'host': host,
        'iface': ifname
    }


def _convert_to_host_id_to_name_map(hosts):
    h_map = {}
    for h in hosts:
        h_map[h.get_id()] = h.get_name()
    return h_map


def _is_neutron_chain(chain):
    name = chain.get_name()
    return (name.startswith("OS_PRE_ROUTING_") or
            name.startswith("OS_POST_ROUTING_") or
            name.startswith("OS_PORT_") or
            name.startswith("OS_SG_"))


def _chain_filter(chains):
    return [c for c in chains if not _is_neutron_chain(c)]


def _convert_to_host2tz_map(tzs):
    host2tz = {}
    for tz in tzs:
        tzhs = tz.get_hosts()
        for tzh in tzhs:
            hid = tzh.get_host_id()
            if hid not in host2tz:
                host2tz[hid] = []
            host2tz[hid].append(
                {"id": tzh.get_tunnel_zone_id(),
                 "ip_address": tzh.get_ip_address()})
    return host2tz


def _convert_to_bridge_to_dhcp_subnet_map(bridges):
    subnet_map = {}
    for bridge in bridges:
        subnets = bridge.get_dhcp_subnets()
        if subnets:
            subnet_list = []
            for subnet in subnets:
                # Also add hosts
                subnet_list.append(
                    {"subnet": subnet.dto,
                     "hosts": _to_dto_dict(subnet.get_dhcp_hosts())})
            subnet_map[bridge.get_id()] = subnet_list
    return subnet_map


def _is_neutron_port(port, n_ports):
    peer_id = port.get_peer_id()
    return port.get_id() in n_ports or (peer_id is not None and
                                        peer_id in n_ports)


def _get_objects(f, exclude=None, filter_func=None):
    objs = f()
    if exclude:
        objs = [o for o in objs if o.get_id() not in exclude]

    if filter_func:
        objs = filter_func(objs)

    return objs


def _get_obj(f, obj_id, cache_map=None):
    if cache_map is None:
        cache_map = {}
    obj = cache_map.get(obj_id)
    if not obj:
        obj = f(obj_id)
    return obj


def _to_dto_dict(objs):
    return [o.dto for o in objs]


def _create_data(f, obj):
    try:
        return f()
    except wexc.HTTPClientError as e:
        if e.code == wexc.HTTPConflict.code:
            LOG.warn("Already exists: " + str(obj))


class DataReader(object):

    def __init__(self, nd):
        self.mc = context.get_read_context()
        self._provider_router = None
        self._nd = nd

    def _get_provider_router(self):
        routers = _get_objects(self.mc.mn_api.get_routers)
        try:
            provider_router = next(
                r for r in routers
                if r.get_name() == const.PROVIDER_ROUTER_NAME)
        except StopIteration:
            # This should not happen
            raise exc.UpgradeScriptException("Provider Router not found")

        return provider_router

    @property
    def provider_router(self):
        if self._provider_router is None:
            self._provider_router = self._get_provider_router()
            LOG.debug("Provider Router: " + str(self._provider_router))
        return self._provider_router

    def _port_filter(self, ports):
        """We want to exclude the following ports:

        1. ID matching one of the neutron port IDs
        2. Peer ID, if present, matching one of Neutron port IDs
        3. Provider router ports
        """
        n_ports = self._neutron_ids("ports")
        pr_id = self._provider_router.get_id()
        return [p for p in ports if (p.get_device_id() != pr_id
                                     and not _is_neutron_port(p, n_ports))]

    def _get_host_ports(self, host, pr_id):
        port_list = []
        ports = host.get_ports()

        # Skip ports for health monitors
        for port in [p for p in ports
                     if not _is_lb_hm_interface(p.get_interface_name())]:
            port_obj = self.mc.mn_api.get_port(port.get_port_id())

            # Skip port bindings for external routers (provider router)
            if port_obj.get_device_id() != pr_id:
                port_list.append({"id": port_obj.get_id(),
                                  "interface": port.get_interface_name()})
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
            hid = h.get_id()
            bindings_map[hid] = {
                "name": h.get_name(),
                "tunnel_zones": host2tz_map[hid],
                "ports": self._get_host_ports(h, pr.get_id())
            }

        return bindings_map

    def _prepare_provider_router(self, host_id2name_map):
        """Prepares the data required for provider router migration

        Gets 'router' and 'ports' portion of the provider router -> edge
        router migration.  See neutron_data's create_edge_router for more
        detail on the data.

        host_id2name_map is required to convert host ID to host name that
        Neutron expects.
        """
        ports = []
        pr_ports = self.provider_router.get_ports()
        for p in pr_ports:
            if _port_is_bound(p):
                h_name = host_id2name_map[p.get_host_id()]
                port = _make_provider_router_port_dict(p, h_name,
                                                       p.get_interface_name())
                ports.append(port)

        return {
            'router': {
                'name': self.provider_router.get_name(),
                'admin_state_up': self.provider_router.get_admin_state_up()
            },
            'ports': ports
        }

    def _neutron_ids(self, key):
        return set(self._nd[key].keys())

    def _router_exclude_ids(self):
        ids = self._neutron_ids('routers')
        ids.add(self.provider_router.get_id())
        return ids

    def prepare(self):
        bridges = _get_objects(self.mc.mn_api.get_bridges,
                               exclude=self._neutron_ids('networks'))
        chains = _get_objects(self.mc.mn_api.get_chains,
                              filter_func=_chain_filter)
        routers = _get_objects(self.mc.mn_api.get_routers,
                               exclude=self._router_exclude_ids())
        ports = _get_objects(self.mc.mn_api.get_ports,
                             filter_func=self._port_filter)
        ip_addr_groups = _get_objects(
            self.mc.mn_api.get_ip_addr_groups,
            exclude=self._neutron_ids("security-groups"))
        port_groups = _get_objects(self.mc.mn_api.get_port_groups)
        tzs = _get_objects(self.mc.mn_api.get_tunnel_zones)
        hosts = _get_objects(self.mc.mn_api.get_hosts)
        host2tz_map = _convert_to_host2tz_map(tzs)
        host_name_map = _convert_to_host_id_to_name_map(hosts)
        return {
            "hosts": _to_dto_dict(hosts),
            "bridges": _to_dto_dict(bridges),
            "dhcp_subnets": _convert_to_bridge_to_dhcp_subnet_map(bridges),
            "routers": _to_dto_dict(routers),
            "chains": _to_dto_dict(chains),
            "ip_addr_groups": _to_dto_dict(ip_addr_groups),
            "port_groups": _to_dto_dict(port_groups),
            "tunnel_zones": _to_dto_dict(tzs),
            "ports": _to_dto_dict(ports),
            "host_bindings": self._prepare_host_bindings(hosts, host2tz_map),
            "provider_router": self._prepare_provider_router(host_name_map)
        }


class DataWriter(object):

    def __init__(self, data, dry_run=False):
        self.mc = context.get_write_context()
        self.data = data
        self.dry_run = dry_run

    def _bind_hosts(self, bindings):
        for hid, h in iter(bindings.items()):
            tzhs = h["tunnel_zones"]
            for tzh in tzhs:
                LOG.debug("Binding host tz: " + str(tzh) + ", " + str(h))
                if not self.dry_run:
                    tz = self.mc.mn_api.get_tunnel_zone(tzh['id'])
                    (tz.add_tunnel_zone_host()
                     .ip_address(tzh['ip_address'])
                     .host_id(hid).create())

            if self.dry_run:
                host = {"id": "fake_host"}
            else:
                host = self.mc.mn_api.get_host(hid)

            ports = h["ports"]
            for p in ports:
                LOG.debug("Binding port host intf: " + str(p) + ", " +
                          str(host))
                if not self.dry_run:
                    self.mc.mn_api.add_host_interface_port(
                        host, port_id=p["id"], interface_name=p["interface"])

    def _create_hosts(self, hosts):
        for h in hosts:
            LOG.debug("Creating host " + str(h))
            f = (self.mc.mn_api.add_host()
                               .id(h['id'])
                               .name(h['name'])
                               .create)
            if not self.dry_run:
                _create_data(f, h)

    def _create_chains(self, chains):
        for chain in chains:
            LOG.debug("Creating chain " + str(chain))
            f = (self.mc.mn_api.add_chain()
                        .id(chain['id'])
                        .name(chain['name'])
                        .tenant_id(chain['tenantId'])
                        .create)
            if not self.dry_run:
                _create_data(f, chain)

    def _create_bridges(self, bridges):
        results = {}
        for bridge in bridges:
            LOG.debug("Creating bridge " + str(bridge))
            f = (self.mc.mn_api.add_bridge()
                        .id(bridge['id'])
                        .name(bridge['name'])
                        .tenant_id(bridge['tenantId'])
                        .inbound_filter_id(bridge['inboundFilterId'])
                        .outbound_filter_id(bridge['outboundFilterId'])
                        .admin_state_up(bridge['adminStateUp'])
                        .create)
            if not self.dry_run:
                results[bridge['id']] = _create_data(f, bridge)
        return results

    def _create_routers(self, routers):
        results = {}
        for router in routers:
            LOG.debug("Creating router " + str(router))
            f = (self.mc.mn_api.add_router()
                        .id(router['id'])
                        .name(router['name'])
                        .tenant_id(router['tenantId'])
                        .inbound_filter_id(router['inboundFilterId'])
                        .outbound_filter_id(router['outboundFilterId'])
                        .admin_state_up(router['adminStateUp'])
                        .create)
            if not self.dry_run:
                results[router['id']] = _create_data(f, router)
        return results

    def _create_dhcp_subnets(self, dhcp_subnets, bridges):
        for bid, subnets in iter(dhcp_subnets.items()):
            for subnet in subnets:
                LOG.debug("Creating dhcp subnet " + str(subnet) +
                          " for bridge " + str(bid))
                if self.dry_run:
                    continue

                # Putting this here instead of outside this loop only so that
                # dry-run does not crap out.
                bridge = _get_obj(self.mc.mn_api.get_bridge, bid,
                                  cache_map=bridges)
                s = subnet['subnet']
                f = (bridge.add_dhcp_subnet()
                     .default_gateway(s['defaultGateway'])
                     .server_addr(s['serverAddr'])
                     .dns_server_addrs(s['dnsServerAddrs'])
                     .subnet_prefix(s['subnetPrefix'])
                     .subnet_length(s['subnetLength'])
                     .interface_mtu(s['interfaceMTU'])
                     .opt121_routes(s['opt121Routes'])
                     .enabled(s['enabled'])
                     .create)
                subnet_obj = _create_data(f, s)

                hosts = subnet['hosts']
                for h in hosts:
                    f = (subnet_obj.add_dhcp_host()
                         .name(h['name'])
                         .ip_addr(h['ipAddr'])
                         .mac_addr(h['macAddr'])
                         .create)
                    _create_data(f, h)

    def _create_ports(self, ports, bridges, routers):
        results = {}
        for port in ports:
            LOG.debug("Creating port " + str(port))
            if self.dry_run:
                continue

            ptype = port['type']
            device_id = port['deviceId']
            pid = port['id']
            if ptype == const.BRG_PORT_TYPE:
                bridge = _get_obj(self.mc.mn_api.get_bridge, device_id,
                                  cache_map=bridges)
                f = (self.mc.mn_api.add_bridge_port(bridge)
                         .id(pid)
                         .type(ptype)
                         .admin_state_up(port['adminStateUp'])
                         .inbound_filter_id(port['inboundFilterId'])
                         .outbound_filter_id(port['outboundFilterId'])
                         .vif_id(port['vifId'])
                         .vlan_id(port['vlanId'])
                         .create)
            elif ptype == const.RTR_PORT_TYPE:
                router = _get_obj(self.mc.mn_api.get_router, device_id,
                                  cache_map=routers)
                f = (self.mc.mn_api.add_router_port(router)
                         .id(pid)
                         .type(ptype)
                         .admin_state_up(port['adminStateUp'])
                         .inbound_filter_id(port['inboundFilterId'])
                         .outbound_filter_id(port['outboundFilterId'])
                         .port_address(port['portAddress'])
                         .network_address(port['networkAddress'])
                         .network_length(port['networkLength'])
                         .port_mac(port['portMac'])
                         .create)
            else:
                LOG.warn("Unknown port type " + ptype + " detected for port " +
                         pid)
                continue

            results[pid] = _create_data(f, port)
        return results

    def _create_ip_addr_groups(self, ip_addr_groups):
        for ip_addr_group in ip_addr_groups:
            LOG.debug("Creating IP address group " + str(ip_addr_group))
            f = (self.mc.mn_api.add_ip_addr_group()
                        .id(ip_addr_group['id'])
                        .name(ip_addr_group['name'])
                        .create)
            if not self.dry_run:
                _create_data(f, ip_addr_group)

    def _create_port_groups(self, port_groups):
        for port_group in port_groups:
            LOG.debug("Creating port group " + str(port_group))
            f = (self.mc.mn_api.add_port_group()
                        .id(port_group['id'])
                        .name(port_group['name'])
                        .tenant_id(port_group['tenantId'])
                        .stateful(port_group['stateful'])
                        .create)
            if not self.dry_run:
                _create_data(f, port_group)

    def _create_tunnel_zones(self, tzs):
        for tz in tzs:
            LOG.debug("Creating tunnel zone " + str(tz))
            f = (self.mc.mn_api.add_tunnel_zone()
                     .id(tz['id'])
                     .type(tz['type'])
                     .name(tz['name'])
                     .create)
            if not self.dry_run:
                _create_data(f, tz)

    def migrate(self):
        """Create all the midonet objects

        Expected input:

        {
         "hosts": [{"id": UUID,
                    "name": String}, ...],
         "tunnel_zones": [{"id": UUID,
                           "type": String,
                           "name": String}, ...],
         "host_bindings": {UUID (host ID):
                            {"name": String,
                             "ports": [{"id": UUID,
                                        "interface": String}, ...],
                             "tunnel_zones": [{"id": UUID,
                                               "ip_address": String}, ...]
                            }
                           }, ...,
         "chains": [{"id": UUID,
                     "name": String,
                     "tenantId": String}, ...],
         "bridges": [{"id": UUID,
                      "name": String,
                      "tenantId": String,
                      "adminStateUp": Bool,
                      "inboundFilterId": UUID,
                      "outboundFilterId":UUID}, ...],
         "routers": [{"id": UUID,
                      "name": String,
                      "tenantId": String,
                      "adminStateUp": Bool,
                      "inboundFilterId": UUID,
                      "outboundFilterId": UUID}, ...],
         "ports": [{"id": UUID,
                    "deviceId": UUID,
                    "adminStateUp": Bool,
                    "inboundFilterId":, UUID,
                    "outboundFilterId": UUID,
                    "vifId": String,
                    "vlanId": Int,
                    "portAddress": String,
                    "networkAddress": String,
                    "networkLength": Int,
                    "portMac": String,
                    "type": String}, ...],
         "ip_addr_groups": [{"id": UUID,
                             "name": String}, ...],
         "port_groups": [{"id": UUID,
                          "name": String,
                          "tenantId": String,
                          "stateful": Bool, ...],
         "dhcp_subnets": {UUID (Bridge Id):
                          [{"subnet":
                            {"defaultGateway": String,
                             "serverAddr": String,
                             "dnsServerAddrs": [String],
                             "subnetPrefix": String,
                             "subnetLength": Int,
                             "interfaceMTU": Int,
                             "enabled", Bool,
                             "opt121Routes": [{"destinationPrefix": String,
                                               "destinationLength": Int,
                                               "gatewayAddr": String}, ...],
                            },
                           "hosts"; [{"name": String,
                                      "ipAddr": String,
                                      "macAddr": String}, ...]
                          ], ...}, ...
        }
        """
        LOG.info('Running MidoNet migration process')
        mido_data = self.data['midonet']
        self._create_hosts(mido_data['hosts'])
        self._create_tunnel_zones(mido_data["tunnel_zones"])
        self._create_chains(mido_data['chains'])
        bridges = self._create_bridges(mido_data['bridges'])
        routers = self._create_routers(mido_data['routers'])
        self._create_ip_addr_groups(mido_data['ip_addr_groups'])
        self._create_port_groups(mido_data['port_groups'])

        # Sub-resources
        self._create_dhcp_subnets(mido_data['dhcp_subnets'], bridges)
        self._create_ports(mido_data['ports'], bridges, routers)
        self._bind_hosts(mido_data['host_bindings'])
