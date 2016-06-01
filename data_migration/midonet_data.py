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


def _is_neutron_chain(chain):
    name = chain.get_name()
    return (name.startswith("OS_PRE_ROUTING_") or
            name.startswith("OS_POST_ROUTING_") or
            name.startswith("OS_PORT_") or
            name.startswith("OS_SG_"))


def _chain_filter(chains):
    return [c for c in chains if not _is_neutron_chain(c)]


def _create_tz_host_map(tzs):
    tz_host_map = {}
    for tz in tzs:
        tzhs = tz.get_hosts()
        if tzhs:
            tz_host_map[tz.get_id()] = _to_dto_dict(tzhs)
    return tz_host_map


def _create_host_interface_port_map(hosts):
    host_interface_port_map = {}
    for host in hosts:
        hiports = _get_objects(host.get_ports)
        if hiports:
            host_interface_port_map[host.get_id()] = _to_dto_dict(hiports)
    return host_interface_port_map


def _create_port_group_port_map(port_groups):
    pgp_map = {}

    def _extract_port_id(o):
        return o['portId']

    for port_group in port_groups:
        pg_ports = _get_objects(port_group.get_ports)
        if pg_ports:
            pgp_map[port_group.get_id()] = _to_dto_dict(
                pg_ports, modify=_extract_port_id)

    return pgp_map


def _create_bridge_to_dhcp_subnet_map(bridges):
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


def _create_ip_addr_group_addr_map(ip_addr_groups):
    addr_map = {}

    def _to_ipv4(o):
        o['version'] = 4
        return o

    for ip_addr_group in ip_addr_groups:
        addrs = ip_addr_group.get_addrs()
        if addrs:
            # There seems to be a bug where all IP address group addrs
            # return as version '6': MI-994.  Since we only support 4,
            # just always set it to version 4.
            addr_map[ip_addr_group.get_id()] = _to_dto_dict(addrs,
                                                            modify=_to_ipv4)
    return addr_map


def _create_rule_map(chains):
    rule_map = {}
    for chain in chains:
        rules = _get_objects(chain.get_rules)
        if rules:
            rule_map[chain.get_id()] = _to_dto_dict(rules)

    return rule_map


def _create_route_map(routers):
    route_map = {}
    for router in routers:
        routes = _get_objects(router.get_routes)
        if routes:
            # Remove metadata routes
            routes = [r for r in routes
                      if r.get_dst_network_addr() != const.METADATA_ROUTE_IP]
            route_map[router.get_id()] = _to_dto_dict(routes)

    return route_map


def _is_neutron_port(port, n_ports):
    peer_id = port.get_peer_id()
    return port.get_id() in n_ports or (peer_id is not None and
                                        peer_id in n_ports)


def _get_port_links(ports):
    links = {}
    for port in ports:
        peer_id = port.get_peer_id()
        if peer_id:
            port_id = port.get_id()
            if port_id not in links:
                links[peer_id] = port_id
    return links


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


def _to_dto_dict(objs, modify=None):
    if modify:
        return [modify(o.dto) for o in objs]
    else:
        return [o.dto for o in objs]


def _create_data(f, obj, *args, **kwargs):
    try:
        return f(*args, **kwargs)
    except wexc.HTTPClientError as e:
        if e.code == wexc.HTTPConflict.code:
            LOG.warn("Already exists: " + str(obj))


class DataReader(object):

    def __init__(self, nd):
        self.mc = context.get_read_context()
        self._nd = nd

    def _port_filter(self, ports):
        """We want to exclude the following ports:

        1. ID matching one of the neutron port IDs
        2. Peer ID, if present, matching one of Neutron port IDs
        """
        n_ports = self._neutron_ids("ports")
        return [p for p in ports if not (_is_neutron_port(p, n_ports))]

    def _neutron_ids(self, key):
        return set(self._nd[key].keys())

    def prepare(self):
        bridges = _get_objects(self.mc.mn_api.get_bridges,
                               exclude=self._neutron_ids('networks'))
        chains = _get_objects(self.mc.mn_api.get_chains,
                              filter_func=_chain_filter)
        routers = _get_objects(self.mc.mn_api.get_routers,
                               exclude=self._neutron_ids('routers'))
        ports = _get_objects(self.mc.mn_api.get_ports,
                             filter_func=self._port_filter)
        ip_addr_groups = _get_objects(
            self.mc.mn_api.get_ip_addr_groups,
            exclude=self._neutron_ids("security-groups"))
        port_groups = _get_objects(self.mc.mn_api.get_port_groups)
        tzs = _get_objects(self.mc.mn_api.get_tunnel_zones)
        hosts = _get_objects(self.mc.mn_api.get_hosts)
        return {
            "hosts": _to_dto_dict(hosts),
            "host_interface_ports": _create_host_interface_port_map(hosts),
            "bridges": _to_dto_dict(bridges),
            "dhcp_subnets": _create_bridge_to_dhcp_subnet_map(bridges),
            "routers": _to_dto_dict(routers),
            "chains": _to_dto_dict(chains),
            "routes": _create_route_map(routers),
            "rules": _create_rule_map(chains),
            "ip_addr_groups": _to_dto_dict(ip_addr_groups),
            "ip_addr_group_addrs": _create_ip_addr_group_addr_map(
                ip_addr_groups),
            "port_groups": _to_dto_dict(port_groups),
            "port_group_ports": _create_port_group_port_map(port_groups),
            "tunnel_zones": _to_dto_dict(tzs),
            "tunnel_zone_hosts": _create_tz_host_map(tzs),
            "ports": _to_dto_dict(ports),
            "port_links": _get_port_links(ports)
        }


class DataWriter(object):

    def __init__(self, data, dry_run=False):
        self.mc = context.get_write_context()
        self.data = data
        self.dry_run = dry_run
        self._pr_port_map = {}

    def _provider_router_ports(self):
        if not self._pr_port_map:
            mido_data = self.data['midonet']
            routers = mido_data['routers']
            for router in routers:
                if router['name'] == const.PROVIDER_ROUTER_NAME:
                    pr_id = router['id']
                    ports = mido_data['ports']
                    for port in ports:
                        if port['deviceId'] == pr_id:
                            self._pr_port_map[port['id']] = port
                    break

        return self._pr_port_map

    def _create_hosts(self, hosts):
        results = {}
        for h in hosts:
            LOG.debug("Creating host " + str(h))
            hid = h['id']
            f = (self.mc.mn_api.add_host()
                               .id(hid)
                               .name(h['name'])
                               .create)
            if not self.dry_run:
                results[hid] = _create_data(f, h)
        return results

    def _create_host_interface_ports(self, host_interface_ports, hosts):
        port_ids = self._pr_port_map.keys()
        for host_id, hiports in iter(host_interface_ports.items()):
            for hiport in hiports:
                port_id = hiport['portId']

                # Skip the provider router ports
                if port_id in port_ids:
                    LOG.debug("Skipping Provider Router port binding " +
                              str(port_id))
                    continue

                interface_name = hiport['interfaceName']
                if _is_lb_hm_interface(interface_name):
                    LOG.debug("Skipping HM port binding " + str(hiport))
                    continue

                LOG.debug("Creating host interface port " + str(hiport))
                if self.dry_run:
                    continue

                host = _get_obj(self.mc.mn_api.get_host, host_id,
                                cache_map=hosts)
                f = (host.add_host_interface_port()
                     .port_id(port_id)
                     .interface_name(interface_name)
                     .create)
                _create_data(f, hiport)

    def _create_chains(self, chains):
        results = {}
        for chain in chains:
            LOG.debug("Creating chain " + str(chain))
            chain_id = chain['id']
            f = (self.mc.mn_api.add_chain()
                        .id(chain_id)
                        .name(chain['name'])
                        .tenant_id(chain['tenantId'])
                        .create)
            if not self.dry_run:
                results[chain_id] = _create_data(f, chain)
        return results

    def _port_routes(self, router_id):
        mido_data = self.data['midonet']
        ports = mido_data['ports']
        route_map = {}
        for port in ports:
            if port['deviceId'] == router_id:
                route_map[port['id']] = port['portAddress']
        return route_map

    def _create_routes(self, routes, routers):
        for router_id, routes in iter(routes.items()):
            proute_map = self._port_routes(router_id)
            for route in routes:
                if route['learned']:
                    LOG.debug("Skipping learned route " + str(route))
                    continue

                # Skip the port routes
                next_hop_port = route['nextHopPort']
                if (route['srcNetworkAddr'] == "0.0.0.0" and
                    route['srcNetworkLength'] == 0 and
                    route['dstNetworkLength'] == 32 and
                    next_hop_port and
                    route['dstNetworkAddr'] == proute_map.get(next_hop_port)):
                    LOG.debug("Skipping port route " + str(route))
                    continue

                # TODO(RYU): HM routes?

                LOG.debug("Creating route " + str(route) + " on router " +
                          router_id)
                if self.dry_run:
                    continue

                router = _get_obj(self.mc.mn_api.get_router, router_id,
                                  cache_map=routers)
                f = (router.add_route()
                     .id(route['id'])
                     .type(route['type'])
                     .attributes(route.get('attributes'))
                     .dst_network_addr(route['dstNetworkAddr'])
                     .dst_network_length(route['srcNetworkLength'])
                     .src_network_addr(route['srcNetworkAddr'])
                     .src_network_length(route['srcNetworkLength'])
                     .next_hop_gateway(route['nextHopGateway'])
                     .next_hop_port(next_hop_port)
                     .weight(route['weight']).create)
                _create_data(f, route)

    def _create_rules(self, chain_rules, chains):
        for chain_id, rules in iter(chain_rules.items()):
            for rule in rules:
                LOG.debug("Creating rule " + str(rule) + " on chain " +
                          chain_id)
                if self.dry_run:
                    continue

                # TODO(RYU): Trace req?
                chain = _get_obj(self.mc.mn_api.get_chain, chain_id,
                                 cache_map=chains)
                f = (chain.add_rule()
                     .id(rule['id'])
                     .chain_id(chain_id)
                     .jump_chain_name(rule.get('jumpChainName'))
                     .jump_chain_id(rule.get('jumpChainName'))
                     .nat_targets(rule.get('natTargets'))
                     .type(rule['type'])
                     .flow_action(rule.get('flowAction'))
                     .cond_invert(rule['condInvert'])
                     .match_forward_flow(rule['matchForwardFlow'])
                     .match_return_flow(rule['matchReturnFlow'])
                     .port_group(rule['portGroup'])
                     .inv_port_group(rule['invPortGroup'])
                     .ip_addr_group_dst(rule['ipAddrGroupDst'])
                     .inv_ip_addr_group_dst(rule['invIpAddrGroupDst'])
                     .ip_addr_group_src(rule['ipAddrGroupSrc'])
                     .inv_ip_addr_group_src(rule['invIpAddrGroupSrc'])
                     .tp_dst(rule['tpDst'])
                     .inv_tp_dst(rule['invTpDst'])
                     .tp_src(rule['tpSrc'])
                     .inv_tp_src(rule['invTpSrc'])
                     .dl_dst(rule['dlDst'])
                     .inv_dl_dst(rule['invDlDst'])
                     .dl_src(rule['dlSrc'])
                     .inv_dl_src(rule['invDlSrc'])
                     .dl_dst_mask(rule['dlDstMask'])
                     .dl_src_mask(rule['dlSrcMask'])
                     .nw_dst_address(rule['nwDstAddress'])
                     .nw_dst_length(rule['nwDstLength'])
                     .inv_nw_dst(rule['invNwDst'])
                     .nw_src_address(rule['nwSrcAddress'])
                     .nw_src_length(rule['nwSrcLength'])
                     .inv_nw_src(rule['invNwSrc'])
                     .in_ports(rule['inPorts'])
                     .inv_in_ports(rule['invInPorts'])
                     .out_ports(rule['outPorts'])
                     .inv_out_ports(rule['invOutPorts'])
                     .dl_type(rule['dlType'])
                     .inv_dl_type(rule['invDlType'])
                     .nw_tos(rule['nwTos'])
                     .inv_nw_tos(rule['invNwTos'])
                     .nw_proto(rule['nwProto'])
                     .inv_nw_proto(rule['invNwProto'])
                     .fragment_policy(rule['fragmentPolicy']).create)

                _create_data(f, rule)

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

            pid = port['id']
            ptype = port['type']
            device_id = port['deviceId']
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

    def _link_ports(self, links, ports):
        port_ids = self._pr_port_map.keys()
        for port_id, peer_id in iter(links.items()):
            link = (port_id, peer_id)

            # Skip the provider router ports
            if port_id in port_ids or peer_id in port_ids:
                LOG.debug("Skipping Provider Router port linking " + str(link))
                continue

            LOG.debug("Linking ports " + str(link))
            if self.dry_run:
                continue

            port = _get_obj(self.mc.mn_api.get_port, port_id, cache_map=ports)
            _create_data(self.mc.mn_api.link, link, port, peer_id)

    def _create_ip_addr_groups(self, ip_addr_groups):
        results = {}
        for ip_addr_group in ip_addr_groups:
            LOG.debug("Creating IP address group " + str(ip_addr_group))
            ip_addr_group_id = ip_addr_group['id']
            f = (self.mc.mn_api.add_ip_addr_group()
                        .id(ip_addr_group_id)
                        .name(ip_addr_group['name'])
                        .create)
            if not self.dry_run:
                results[ip_addr_group_id] = _create_data(f, ip_addr_group)
        return results

    def _create_ip_addr_group_addrs(self, ip_address_group_addrs,
                                    ip_addr_groups):
        for addr_group_id, addrs in iter(ip_address_group_addrs.items()):
            for addr in addrs:
                LOG.debug("Creating ip addr group addr " + str(addr) +
                          " for ip addr group " + addr_group_id)
                if self.dry_run:
                    continue

                # Putting this here instead of outside this loop only so that
                # dry-run does not crap out.
                iag = _get_obj(self.mc.mn_api.get_ip_addr_group, addr_group_id,
                               cache_map=ip_addr_groups)

                version = addr['version']
                if version == 4:
                    f = iag.add_ipv4_addr().addr(addr['addr']).create
                else:
                    f = iag.add_ipv6_addr().addr(addr['addr']).create
                _create_data(f, addr)

    def _create_port_groups(self, port_groups):
        results = {}
        for port_group in port_groups:
            LOG.debug("Creating port group " + str(port_group))
            pg_id = port_group['id']
            f = (self.mc.mn_api.add_port_group()
                        .id(pg_id)
                        .name(port_group['name'])
                        .tenant_id(port_group['tenantId'])
                        .stateful(port_group['stateful'])
                        .create)
            if not self.dry_run:
                results[pg_id] = _create_data(f, port_group)
        return results

    def _create_port_group_ports(self, port_group_ports, port_groups):
        for pg_id, pg_port_ids in iter(port_group_ports.items()):
            for pg_port_id in pg_port_ids:
                LOG.debug("Creating port group port " + str(pg_port_id) +
                          " for port group " + pg_id)
                if self.dry_run:
                    continue

                # Putting this here instead of outside this loop only so that
                # dry-run does not crap out.
                pg = _get_obj(self.mc.mn_api.get_port_group, pg_id,
                              cache_map=port_groups)
                f = pg.add_port_group_port().port_id(pg_port_id).create
                _create_data(f, (pg_id, pg_port_id))

    def _create_tunnel_zones(self, tzs):
        results = {}
        for tz in tzs:
            LOG.debug("Creating tunnel zone " + str(tz))
            tz_id = tz['id']
            f = (self.mc.mn_api.add_tunnel_zone()
                     .id(tz_id)
                     .type(tz['type'])
                     .name(tz['name'])
                     .create)
            if not self.dry_run:
                results[tz_id] = _create_data(f, tz)
        return results

    def _create_tunnel_zone_hosts(self, tunnel_zone_hosts, tunnel_zones):
        for tz_id, tzhs in iter(tunnel_zone_hosts.items()):
            for tzh in tzhs:
                LOG.debug("Creating tunnzel zone host " + str(tzh))
                if self.dry_run:
                    continue

                tz = _get_obj(self.mc.mn_api.get_tunnel_zone, tz_id,
                              cache_map=tunnel_zones)
                f = (tz.add_tunnel_zone_host()
                     .host_id(tzh['hostId'])
                     .ip_address(tzh['ipAddress'])
                     .create)
                _create_data(f, tzh)

    def migrate(self):
        """Create all the midonet objects

        Expected input:

        {
         "hosts": [{"id": UUID,
                    "name": String}, ...],
         "host_interface_ports": {UUID (Host ID):
                                  [{"portId": UUID,
                                    "interfaceName": String}, ...]}, ...,
         "tunnel_zones": [{"id": UUID,
                           "type": String,
                           "name": String}, ...],
         "tunnel_zone_hosts": {UUID (Tunnel Zone ID):
                               [{"hostId": UUID,
                                 "ipAddress": String}, ...]}, ...
         "chains": [{"id": UUID,
                     "name": String,
                     "tenantId": String}, ...],
         "rules": {UUID (Chain ID):
                   [{"id": UUID,
                     "jumpChainName": String,
                     "jumpChainId": UUID,
                     "natTargets": [{"addressFrom": String,
                                     "addressTo": String,
                                     "portFrom": Int,
                                     "portTo": Int}, ...],
                     "type": String,
                     "flowAction": String,
                     "requestId": UUID,
                     "limit": Int,
                     "condInvert": Bool,
                     "invDlDst": Bool,
                     "invDlSrc": Bool,
                     "invDlType": Bool,
                     "invInPorts": Bool,
                     "invOutPorts": Bool,
                     "invNwDst": Bool,
                     "invNwProto": Bool,
                     "invNwSrc": Bool,
                     "invNwTos": Bool,
                     "invPortGroup": Bool,
                     "invIpAddrGroupDst": Bool,
                     "invIpAddrGroupSrc": Bool,
                     "invTpDst": Bool,
                     "invTpSrc": Bool,
                     "matchForwardFlow": Bool,
                     "matchReturnFlow": Bool,
                     "dlDst": String,
                     "dlDstMask": String,
                     "dlSrc": String,
                     "dlSrcMask": String,
                     "dlType": String,
                     "inPorts": [UUID (Port ID)],
                     "outPorts": [UUID (Port ID)],
                     "nwDstAddress": String,
                     "nwDstLength": Int,
                     "nwProto": Int,
                     "nwSrcAddress": String,
                     "nwSrcLength": Int,
                     "nwTos": String,
                     "portGroup": UUID,
                     "ipAddrGroupDst": String,
                     "ipAddrGroupSrc": String,
                     "tpSrc": String,
                     "tpDst": String,
                     "fragmentPolicy": String
                    }, ...]}, ...,
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
         "routes": {UUID (Router ID):
                     [{"id": UUID,
                       "learned": Bool,
                       "attributes": String,
                       "dstNetworkAddr": String,
                       "dstNetworkLength": Int,
                       "srcNetworkAddr": String,
                       "srcNetworkLength": Int,
                       "nextHopGateway": String,
                       "nextHopPort": UUID,
                       "type": String,
                       "weight": Int}, ...]}, ...,
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
                             "name": String,}, ...],
         "ip_addr_group_addrs": {UUID (IP addr group ID):
                                  [{"addr": String,
                                    "version": Int}, ...]}, ...,
         "port_groups": [{"id": UUID,
                          "name": String,
                          "tenantId": String,
                          "stateful": Bool, ...],
         "port_group_ports": {UUID (Port group ID):
                              [UUID (Port ID)]}, ...
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
                          ], ...}, ...,
         "port_links": {UUID [Port ID]: UUID [PeerPort ID]}
        }
        """
        LOG.info('Running MidoNet migration process')
        mido_data = self.data['midonet']
        hosts = self._create_hosts(mido_data['hosts'])
        tunnel_zones = self._create_tunnel_zones(mido_data["tunnel_zones"])
        chains = self._create_chains(mido_data['chains'])
        bridges = self._create_bridges(mido_data['bridges'])
        routers = self._create_routers(mido_data['routers'])
        ip_addr_groups = self._create_ip_addr_groups(
            mido_data['ip_addr_groups'])
        port_groups = self._create_port_groups(mido_data['port_groups'])

        # Sub-resources
        self._create_dhcp_subnets(mido_data['dhcp_subnets'], bridges)
        self._create_ip_addr_group_addrs(mido_data['ip_addr_group_addrs'],
                                         ip_addr_groups)
        ports = self._create_ports(mido_data['ports'], bridges, routers)
        self._create_port_group_ports(mido_data['port_group_ports'],
                                      port_groups)
        self._create_rules(mido_data['rules'], chains)
        self._create_routes(mido_data['routes'], routers)
        self._link_ports(mido_data['port_links'], ports)

        # Host Bindings
        self._create_tunnel_zone_hosts(mido_data['tunnel_zone_hosts'],
                                       tunnel_zones)
        self._create_host_interface_ports(mido_data['host_interface_ports'],
                                          hosts)
