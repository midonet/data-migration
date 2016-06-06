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

import abc
from data_migration import constants as const
from data_migration import context
import logging
import six
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


def _extract_fields(obj, fields):
    return dict((k, obj.get(k)) for k in fields)


def _to_dto_dict(objs, modify=None, fields=None):

    def _modify(obj):
        if fields:
            obj = _extract_fields(obj, fields)

        if modify:
            obj = modify(obj)

        return obj

    return [_modify(o.dto) for o in objs]


class ProviderRouterMixin(object):

    def __init__(self):
        self._pr_port_map = {}

    @property
    def provider_router_ports(self):
        if not self._pr_port_map:
            routers = self._get_resources('routers')
            port_map = self._get_resources('ports')
            for router in routers:
                if router['name'] == const.PROVIDER_ROUTER_NAME:
                    ports = port_map[router['id']]
                    for port in ports:
                        self._pr_port_map[port['id']] = port
                    break

        return self._pr_port_map

    @property
    def provider_router_port_ids(self):
        return self.provider_router_ports.keys()


@six.add_metaclass(abc.ABCMeta)
class MidonetRead(object):

    def __init__(self, nd):
        self.mc = context.get_read_context()
        self._nd = nd

    def create_resource_data(self):
        objs = _get_objects(self.get_resources_f, exclude=self.exclude_ids,
                            filter_func=self.filter_objs)
        return objs, self.to_dicts(objs, modify=self.modify_dto_f,
                                   fields=self.read_fields)

    def create_sub_resource_data(self, parent_objs):
        obj_map = {}
        obj_list = []
        for p_obj in parent_objs:
            if self.skip_parent(p_obj):
                continue

            objs = self.get_sub_resources(p_obj)
            objs = self.filter_objs(objs)
            if objs:
                objs = self._modify_objs(objs)
                obj_list.extend(objs)
                obj_map[p_obj.get_id()] = self.to_dicts(
                    objs, modify=self.modify_dto_f, fields=self.read_fields)
        return obj_map, obj_list

    def to_dicts(self, objs, modify=None, fields=None):
        return _to_dto_dict(objs, modify=modify, fields=fields)

    @property
    def get_resources_f(self):
        return None

    def get_sub_resources(self, p_obj):
        return []

    def _neutron_ids(self, key):
        return set(self._nd[key].keys())

    @property
    def exclude_ids(self):
        return []

    def filter_objs(self, objs):
        return objs

    @property
    def modify_dto_f(self):
        return None

    def _modify_objs(self, objs):
        return objs

    def skip_parent(self, obj):
        return False

    @property
    def read_fields(self):
        return set()


@six.add_metaclass(abc.ABCMeta)
class MidonetWrite(ProviderRouterMixin):

    def __init__(self, data, dry_run=False):
        self.mc = context.get_write_context()
        self.data = data
        self.dry_run = dry_run
        self.created = 0
        self.updated = 0
        self.conflicted = 0
        self.skipped = 0
        super(MidonetWrite, self).__init__()

    def print_summary(self):
        print("\n")
        print("***** %s *****\n" % self.key)
        print("%d created" % self.created)
        print("%d updated" % self.updated)
        print("%d skipped due to conflict" % self.conflicted)
        print("%d skipped for other reasons" % self.skipped)

    def _update_data(self, f, *args, **kwargs):
        o = f(*args, **kwargs)
        self.updated += 1
        return o

    def _create_data(self, f, obj, *args, **kwargs):
        try:
            o = f(*args, **kwargs)
            self.created += 1
            return o
        except wexc.HTTPClientError as e:
            if e.code == wexc.HTTPConflict.code:
                LOG.warn("Already exists: " + str(obj))
                self.conflicted += 1
                return None

    def _get_resources(self, key):
        mido_data = self.data['midonet']
        return mido_data[key]

    def _get_port_device_id(self, port_id):
        port_map = self._get_resources('ports')
        for device_id, ports in iter(port_map.items()):
            for port in ports:
                if port['id'] == port_id:
                    return device_id
        return None

    def create_objects(self):
        results = {}
        objs = self._get_resources(self.key)
        for obj in objs:
            LOG.debug("Creating " + self.key + " obj " + str(obj))
            obj_id = obj['id']

            if self.dry_run:
                self.skipped += 1
                continue

            o = self._create_data(self.create_f(obj), obj)
            if o:
                results[obj_id] = o
        return results

    def create_child_objects(self, parents):
        results = {}
        obj_map = self._get_resources(self.key)
        for p_id, objs in iter(obj_map.items()):
            for obj in objs:
                if self.skip_create_child(obj, p_id):
                    self.skipped += 1
                    continue

                LOG.debug("Creating " + self.key + " child obj " + str(obj))
                if self.dry_run:
                    self.skipped += 1
                    continue

                o = self._create_data(self.create_child_f(obj, p_id, parents),
                                      obj)
                if o:
                    self.process_child_sub_objects(obj, o)
                    if hasattr(o, 'get_id'):
                        results[o.get_id()] = o
        return results

    @property
    def key(self):
        return ""

    def create_f(self, obj):
        return None

    def create_child_f(self, obj, p_id, parents):
        return None

    def process_child_sub_objects(self, data, obj):
        pass

    def skip_create_child(self, obj, p_id):
        return False


class AdRouteRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "nwPrefix", "prefixLength"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_ad_routes()


class AdRouteWrite(MidonetWrite):
    """Expected format:

    "ad_routes": {UUID (BGP ID):
                  [{"id": UUID,
                    "nwPrefix": String,
                    "prefixLength": Int}, ...], ...,
    """

    @property
    def key(self):
        return const.MN_AD_ROUTES

    def _get_bgp_router_id(self, bgp_id):
        bgp_map = self._get_resources('bgp')
        for port_id, bgp_list in iter(bgp_map.items()):
            for bgp in bgp_list:
                if bgp['id'] == bgp_id:
                    return self._get_port_device_id(port_id)
        return None

    def create_child_f(self, obj, p_id, parents):
        router_id = self._get_bgp_router_id(p_id)
        router = _get_obj(self.mc.mn_api.get_router, router_id,
                          cache_map=parents)
        return (router.add_bgp_network()
                .id(obj['id'])
                .subnet_address(obj['nwPrefix'])
                .subnet_length(obj['prefixLength']).create)


class BgpRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "localAS", "peerAS", "peerAddr"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_bgps()

    def skip_parent(self, p_obj):
        return p_obj.get_type() != const.RTR_PORT_TYPE


class BgpWrite(MidonetWrite):
    """Expected format:

    "bgp": {UUID (Port ID):
            [{"id": UUID,
              "localAS": Int,
              "peerAS": Int,
              "peerAddr": String}, ...]}, ...,
    """

    @property
    def key(self):
        return const.MN_BGP

    def create_child_f(self, obj, p_id, parents):
        router_id = self._get_port_device_id(p_id)
        router = _get_obj(self.mc.mn_api.get_router, router_id,
                          cache_map=parents)

        # Update router with local AS
        LOG.debug("Updating router " + router_id + " with asn " +
                  str(obj['localAS']))
        self._update_data(router.asn(obj['localAS']).update)

        return (router.add_bgp_peer()
                .id(obj['id'])
                .asn(obj['peerAS'])
                .address(obj['peerAddr']).create)


class BridgeRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "name", "tenantId", "adminStateUp", "inboundFilterId",
                "outboundFilterId"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_bridges

    @property
    def exclude_ids(self):
        return self._neutron_ids('networks')


class BridgeWrite(MidonetWrite):
    """Expected format:

    "bridges": [{"id": UUID,
                 "name": String,
                 "tenantId": String,
                 "adminStateUp": Bool,
                 "inboundFilterId": UUID,
                 "outboundFilterId":UUID}, ...],
    """

    @property
    def key(self):
        return const.MN_BRIDGES

    def create_f(self, obj):
        return (self.mc.mn_api.add_bridge()
                .id(obj['id'])
                .name(obj['name'])
                .tenant_id(obj['tenantId'])
                .inbound_filter_id(obj['inboundFilterId'])
                .outbound_filter_id(obj['outboundFilterId'])
                .admin_state_up(obj['adminStateUp'])
                .create)


class ChainRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "name", "tenantId"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_chains

    def filter_objs(self, objs):
        return [c for c in objs if not _is_neutron_chain(c)]


class ChainWrite(MidonetWrite):
    """Expected format:

    "chains": [{"id": UUID,
                "name": String,
                "tenantId": String}, ...],
    """
    @property
    def key(self):
        return const.MN_CHAINS

    def create_f(self, obj):
        return (self.mc.mn_api.add_chain()
                .id(obj['id'])
                .name(obj['name'])
                .tenant_id(obj['tenantId'])
                .create)


class DhcpSubnetRead(MidonetRead):

    @property
    def read_fields(self):
        return {"defaultGateway", "serverAddr", "dnsServerAddrs",
                "subnetPrefix", "subnetLength", "interfaceMTU", "enabled",
                "opt121Routes"}

    @property
    def _host_fields(self):
        return {"name", "ipAddr", "macAddr"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_dhcp_subnets()

    def to_dicts(self, objs, modify=None, fields=None):
        subnet_list = []
        for subnet in objs:
            # Also add hosts
            subnet_list.append(
                {"subnet": _extract_fields(subnet.dto, self.read_fields),
                 "hosts": _to_dto_dict(subnet.get_dhcp_hosts(),
                                       fields=self._host_fields)})
        return subnet_list


class DhcpSubnetWrite(MidonetWrite):
    """Expected format:

    "dhcp_subnets": {UUID (Bridge Id):
                     [{"subnet":
                       {"defaultGateway": String,
                        "serverAddr": String,
                        "dnsServerAddrs": String,
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

    """

    @property
    def key(self):
        return const.MN_DHCP

    def create_child_f(self, obj, p_id, parents):
        bridge = _get_obj(self.mc.mn_api.get_bridge, p_id,
                          cache_map=parents)
        s = obj['subnet']
        return (bridge.add_dhcp_subnet()
                .default_gateway(s['defaultGateway'])
                .server_addr(s['serverAddr'])
                .dns_server_addrs(s['dnsServerAddrs'])
                .subnet_prefix(s['subnetPrefix'])
                .subnet_length(s['subnetLength'])
                .interface_mtu(s['interfaceMTU'])
                .opt121_routes(s['opt121Routes'])
                .enabled(s['enabled'])
                .create)

    def process_child_sub_objects(self, obj, parent):

        def _create_dhcp_host_f(obj, parent):
            return (parent.add_dhcp_host()
                    .name(obj['name'])
                    .ip_addr(obj['ipAddr'])
                    .mac_addr(obj['macAddr'])
                    .create)

        if obj['hosts']:
            for host in obj['hosts']:
                LOG.debug("Creating sub child obj " + str(host))
                self._create_data(_create_dhcp_host_f, obj, host, parent)


class HealthMonitorRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "type", "adminStateUp", "delay", "maxRetries", "timeout"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_health_monitors


class HealthMonitorWrite(MidonetWrite):
    """Expected format:

    "health_monitors": [{"id": UUID,
                         "type": String,
                         "adminStateUp": Bool,
                         "delay": Int,
                         "maxRetries": Int,
                         "timeout": Int}, ...],
    """

    @property
    def key(self):
        return const.MN_HEALTH_MONITORS

    def create_f(self, obj):
        return (self.mc.mn_api.add_health_monitor()
                .id(obj['id'])
                .type(obj['type'])
                .admin_state_up(obj['adminStateUp'])
                .delay(obj['delay'])
                .max_retries(obj['maxRetries'])
                .timeout(obj['timeout'])
                .create)


class HostRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "name"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_hosts


class HostWrite(MidonetWrite):
    """Expected format:

    "hosts": [{"id": UUID,
               "name": String}, ...],
    """

    @property
    def key(self):
        return const.MN_HOSTS

    def create_f(self, obj):
        return (self.mc.mn_api.add_host()
                .id(obj['id'])
                .name(obj['name'])
                .create)


class HostInterfacePortRead(MidonetRead):

    @property
    def read_fields(self):
        return {"portId", "interfaceName"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_ports()


class HostInterfacePortWrite(MidonetWrite):
    """Expected format:

    "host_interface_ports": {UUID (Host ID):
                          [{"portId": UUID,
                            "interfaceName": String}, ...]}, ...,
    """

    @property
    def key(self):
        return const.MN_HI_PORTS

    def skip_create_child(self, obj, p_id):
        pr_port_ids = self.provider_router_port_ids
        if obj['portId'] in pr_port_ids:
            LOG.debug("Skipping Provider Router port binding " + str(obj))
            return True

        if _is_lb_hm_interface(obj['interfaceName']):
            LOG.debug("Skipping HM port binding " + str(obj))
            return True

        return False

    def create_child_f(self, obj, p_id, parents):
        host = _get_obj(self.mc.mn_api.get_host, p_id, cache_map=parents)
        return (host.add_host_interface_port()
                .port_id(obj['portId'])
                .interface_name(obj['interfaceName'])
                .create)


class IpAddrGroupRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "name"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_ip_addr_groups

    @property
    def exclude_ids(self):
        return self._neutron_ids('security-groups')


class IpAddrGroupWrite(MidonetWrite):
    """Expected format:

    "ip_addr_groups": [{"id": UUID,
                     "name": String,}, ...],
    """
    @property
    def key(self):
        return const.MN_IPA_GROUPS

    def create_f(self, obj):
        return (self.mc.mn_api.add_ip_addr_group()
                .id(obj['id'])
                .name(obj['name'])
                .create)


class IpAddrGroupAddrRead(MidonetRead):

    @property
    def read_fields(self):
        return {"addr", "version"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_addrs()

    @property
    def modify_dto_f(self):
        def _to_ipv4(o):
            o['version'] = 4
            return o

        # There seems to be a bug where all IP address group addrs
        # return as version '6': MI-994.  Since we only support 4,
        # just always set it to version 4.
        return _to_ipv4


class IpAddrGroupAddrWrite(MidonetWrite):
    """Expected format:

    "ip_addr_group_addrs": {UUID (IP addr group ID):
                          [{"addr": String,
                            "version": Int}, ...]}, ...
    """
    @property
    def key(self):
        return const.MN_IPAG_ADDRS

    def create_child_f(self, obj, p_id, parents):
        iag = _get_obj(self.mc.mn_api.get_ip_addr_group, p_id,
                       cache_map=parents)
        version = obj['version']
        if version == 4:
            return iag.add_ipv4_addr().addr(obj['addr']).create
        else:
            return iag.add_ipv6_addr().addr(obj['addr']).create


class LinkWrite(MidonetWrite):
    """Expected format:

    "port_links": {UUID [Port ID]: UUID [PeerPort ID]}
    """

    @property
    def key(self):
        return "port_links"

    def link_ports(self, ports):
        links = self._get_resources('port_links')
        port_ids = self.provider_router_port_ids
        for port_id, peer_id in iter(links.items()):
            link = (port_id, peer_id)

            # Skip the provider router ports
            if port_id in port_ids or peer_id in port_ids:
                LOG.debug("Skipping Provider Router port linking " + str(link))
                self.skipped += 1
                continue

            LOG.debug("Linking ports " + str(link))
            if self.dry_run:
                self.skipped += 1
                continue

            port = _get_obj(self.mc.mn_api.get_port, port_id, cache_map=ports)
            o = self._create_data(self.mc.mn_api.link, link, port, peer_id)
            if o:
                self.created += 1
            else:
                self.conflicted += 1


class LoadBalancerRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "routerId", "adminStateUp"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_load_balancers

    def filter_objs(self, objs):
        # Filter out LBs that are either not associated with a router created
        # by Neutron.
        n_router_ids = self._neutron_ids('routers')
        objs = [o for o in objs if o.get_router_id() not in n_router_ids]
        return objs


class LoadBalancerWrite(MidonetWrite):
    """Expected Format:

    "load_balancers": [{"id": UUID,
                        "routerId": UUID,
                        "adminStateUp": Bool
                       }, ...],
    """

    @property
    def key(self):
        return const.MN_LOAD_BALANCERS

    def create_f(self, obj):
        return (self.mc.mn_api.add_load_balancer()
                .id(obj['id'])
                .admin_state_up(obj['adminStateUp'])
                .create)


class PoolRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "loadBalancerId", "lbMethod", "adminStateUp", "protocol",
                "healthMonitorId"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_pools()

    @property
    def exclude_ids(self):
        return self._neutron_ids('pools')


class PoolWrite(MidonetWrite):
    """Expected format:

    "pools": {UUID (LoadBalancer ID):
              [{"id": UUID,
                "loadBalancerId": UUID,
                "lbMethod": String,
                "protocol": String,
                "healthMonitorId": UUID",
                "adminStateUp": Bool}, ...]}, ...,
    """

    @property
    def key(self):
        return const.MN_POOLS

    def create_child_f(self, obj, p_id, parents):
        lb = _get_obj(self.mc.mn_api.get_load_balancer, p_id,
                      cache_map=parents)
        return (lb.add_pool()
                .id(obj['id'])
                .load_balancer_id(obj['loadBalancerId'])
                .lb_method(obj['lbMethod'])
                .protocol(obj['protocol'])
                .health_monitor_id(obj['healthMonitorId'])
                .admin_state_up(obj['adminStateUp'])
                .create)


class PoolMemberRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "poolId", "address", "adminStateUp", "protocolPort",
                "weight"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_pool_members()

    @property
    def exclude_ids(self):
        return self._neutron_ids('pool_members')


class PoolMemberWrite(MidonetWrite):
    """Expected format:

    "pool_members": {UUID (Pool ID):
                     [{"id": UUID,
                       "poolId': UUID,
                       "address": String,
                       "protocolPort": Int,
                       "weight": Int",
                       "adminStateUp": Bool}, ...]}, ...,
    """

    @property
    def key(self):
        return const.MN_POOL_MEMBERS

    def create_child_f(self, obj, p_id, parents):
        pool = _get_obj(self.mc.mn_api.get_pool, p_id, cache_map=parents)
        return (pool.add_pool_member()
                .id(obj['id'])
                .pool_id(obj['poolId'])
                .address(obj['address'])
                .protocol_port(obj['protocolPort'])
                .weight(obj['weight'])
                .admin_state_up(obj['adminStateUp'])
                .create)


class PortRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "deviceId", "adminStateUp", "inboundFilterId",
                "outboundFilterId", "vifId", "vlanId", "portAddress",
                "networkAddress", "networkLength", "portMac", "type"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_ports()

    def filter_objs(self, objs):
        """We want to exclude the following ports:

        1. ID matching one of the neutron port IDs
        2. Peer ID, if present, matching one of Neutron port IDs
        """
        n_ports = self._neutron_ids("ports")
        return [p for p in objs if not (_is_neutron_port(p, n_ports))]


class PortWrite(MidonetWrite):
    """Expected format:

    "ports": {"id" UUID (device ID):
              [{"id": UUID,
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
                "type": String}, ...],, ...}
    """

    @property
    def key(self):
        return const.MN_PORTS

    def create_child_f(self, obj, p_id, parents):
        pid = obj['id']
        ptype = obj['type']
        device_id = obj['deviceId']
        if ptype == const.BRG_PORT_TYPE:
            bridge = _get_obj(self.mc.mn_api.get_bridge, device_id,
                              cache_map=parents)
            return (self.mc.mn_api.add_bridge_port(bridge)
                    .id(pid)
                    .type(ptype)
                    .admin_state_up(obj['adminStateUp'])
                    .inbound_filter_id(obj['inboundFilterId'])
                    .outbound_filter_id(obj['outboundFilterId'])
                    .vif_id(obj['vifId'])
                    .vlan_id(obj['vlanId'])
                    .create)
        elif ptype == const.RTR_PORT_TYPE:
            router = _get_obj(self.mc.mn_api.get_router, device_id,
                              cache_map=parents)
            return (self.mc.mn_api.add_router_port(router)
                    .id(pid)
                    .type(ptype)
                    .admin_state_up(obj['adminStateUp'])
                    .inbound_filter_id(obj['inboundFilterId'])
                    .outbound_filter_id(obj['outboundFilterId'])
                    .port_address(obj['portAddress'])
                    .network_address(obj['networkAddress'])
                    .network_length(obj['networkLength'])
                    .port_mac(obj['portMac'])
                    .create)
        else:
            raise ValueError("Unknown port type " + ptype +
                             " detected for port " + pid)


class PortGroupRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "name", "tenantId", "stateful"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_port_groups


class PortGroupWrite(MidonetWrite):
    """Expected format:

    "port_groups": [{"id": UUID,
                  "name": String,
                  "tenantId": String,
                  "stateful": Bool, ...],
    """

    @property
    def key(self):
        return const.MN_PORT_GROUPS

    def create_f(self, obj):
        return (self.mc.mn_api.add_port_group()
                .id(obj['id'])
                .name(obj['name'])
                .tenant_id(obj['tenantId'])
                .stateful(obj['stateful'])
                .create)


class PortGroupPortRead(MidonetRead):

    @property
    def read_fields(self):
        return {"portId"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_ports()

    @property
    def modify_dto_f(self):
        def _extract_port_id(o):
            return o['portId']

        return _extract_port_id


class PortGroupPortWrite(MidonetWrite):
    """Expected format:

    "port_group_ports": {UUID (Port group ID):
                      [UUID (Port ID)]}, ...
    """

    @property
    def key(self):
        return const.MN_PG_PORTS

    def create_child_f(self, obj, p_id, parents):
        pg = _get_obj(self.mc.mn_api.get_port_group, p_id, cache_map=parents)
        return (pg.add_port_group_port()
                .port_id(obj)
                .create)


class RouteRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "learned", "attributes", "dstNetworkAddr",
                "dstNetworkLength", "srcNetworkAddr", "srcNetworkLength",
                "nextHopGateway", "nextHopPort", "type", "weight"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_routes()

    def filter_objs(self, objs):
        # Remove metadata routes
        return [r for r in objs
                if r.get_dst_network_addr() != const.METADATA_ROUTE_IP]


class RouteWrite(MidonetWrite):
    """Expected format:

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
    """

    @property
    def key(self):
        return const.MN_ROUTES

    def _port_routes(self, router_id):
        port_map = self._get_resources('ports')
        ports = port_map[router_id]
        route_map = {}
        for port in ports:
            route_map[port['id']] = port['portAddress']
        return route_map

    def skip_create_child(self, obj, parent_id):
        if obj['learned']:
            LOG.debug("Skipping learned route " + str(obj))
            return True

        # Skip the port routes
        next_hop_port = obj['nextHopPort']
        proute_map = self._port_routes(parent_id)
        if (obj['srcNetworkAddr'] == "0.0.0.0" and
            obj['srcNetworkLength'] == 0 and
            obj['dstNetworkLength'] == 32 and
            next_hop_port and
            obj['dstNetworkAddr'] == proute_map.get(next_hop_port)):
            LOG.debug("Skipping port route " + str(obj))
            return True

        return False

    def create_child_f(self, obj, p_id, parents):
        # TODO(RYU): HM routes?
        router = _get_obj(self.mc.mn_api.get_router, p_id,
                          cache_map=parents)
        return (router.add_route()
                .id(obj['id'])
                .type(obj['type'])
                .attributes(obj.get('attributes'))
                .dst_network_addr(obj['dstNetworkAddr'])
                .dst_network_length(obj['srcNetworkLength'])
                .src_network_addr(obj['srcNetworkAddr'])
                .src_network_length(obj['srcNetworkLength'])
                .next_hop_gateway(obj['nextHopGateway'])
                .next_hop_port(obj['nextHopPort'])
                .weight(obj['weight']).create)


class RouterRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "name", "tenantId", "adminStateUp", "loadBalancerId",
                "inboundFilterId", "outboundFilterId"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_routers

    @property
    def exclude_ids(self):
        return self._neutron_ids('routers')


class RouterWrite(MidonetWrite):
    """Expected format:

    "routers": [{"id": UUID,
              "name": String,
              "tenantId": String,
              "adminStateUp": Bool,
              "inboundFilterId": UUID,
              "outboundFilterId": UUID},
              "loadBalancerId": UUID, ...],
    """

    @property
    def key(self):
        return const.MN_ROUTERS

    def create_f(self, obj):
        return (self.mc.mn_api.add_router()
                .id(obj['id'])
                .name(obj['name'])
                .tenant_id(obj['tenantId'])
                .inbound_filter_id(obj['inboundFilterId'])
                .outbound_filter_id(obj['outboundFilterId'])
                .admin_state_up(obj['adminStateUp'])
                .load_balancer_id(obj['loadBalancerId'])
                .create)


class RuleRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "jumpChainName", "jumpChainId", "natTargets", "type",
                "flowAction", "requestId", "limit", "condInvert", "invDlDst",
                "invDlSrc", "invDlType", "invInPorts", "invOutPorts",
                "invNwDst", "invNwProto", "invNwSrc", "invNwTos",
                "invPortGroup", "invIpAddrGroupDst", "invIpAddrGroupSrc",
                "invTpDst", "invTpSrc", "matchForwardFlow", "matchReturnFlow",
                "dlDst", "dlDstMask", "dlSrc", "dlSrcMask", "dlType",
                "inPorts", "outPorts", "nwDstAddress", "nwDstLength",
                "nwProto", "nwSrcAddress", "nwSrcLength", "nwTos", "portGroup",
                "ipAddrGroupDst", "ipAddrGroupSrc", "tpSrc", "tpDst",
                "fragmentPolicy"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_rules()


class RuleWrite(MidonetWrite):
    """"Expected format:

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
    """

    @property
    def key(self):
        return const.MN_RULES

    def create_child_f(self, obj, p_id, parents):
        # TODO(RYU): Trace req?
        chain = _get_obj(self.mc.mn_api.get_chain, p_id, cache_map=parents)
        return (chain.add_rule()
                .id(obj['id'])
                .chain_id(p_id)
                .jump_chain_name(obj.get('jumpChainName'))
                .jump_chain_id(obj.get('jumpChainName'))
                .nat_targets(obj.get('natTargets'))
                .type(obj['type'])
                .flow_action(obj.get('flowAction'))
                .cond_invert(obj['condInvert'])
                .match_forward_flow(obj['matchForwardFlow'])
                .match_return_flow(obj['matchReturnFlow'])
                .port_group(obj['portGroup'])
                .inv_port_group(obj['invPortGroup'])
                .ip_addr_group_dst(obj['ipAddrGroupDst'])
                .inv_ip_addr_group_dst(obj['invIpAddrGroupDst'])
                .ip_addr_group_src(obj['ipAddrGroupSrc'])
                .inv_ip_addr_group_src(obj['invIpAddrGroupSrc'])
                .tp_dst(obj['tpDst'])
                .inv_tp_dst(obj['invTpDst'])
                .tp_src(obj['tpSrc'])
                .inv_tp_src(obj['invTpSrc'])
                .dl_dst(obj['dlDst'])
                .inv_dl_dst(obj['invDlDst'])
                .dl_src(obj['dlSrc'])
                .inv_dl_src(obj['invDlSrc'])
                .dl_dst_mask(obj['dlDstMask'])
                .dl_src_mask(obj['dlSrcMask'])
                .nw_dst_address(obj['nwDstAddress'])
                .nw_dst_length(obj['nwDstLength'])
                .inv_nw_dst(obj['invNwDst'])
                .nw_src_address(obj['nwSrcAddress'])
                .nw_src_length(obj['nwSrcLength'])
                .inv_nw_src(obj['invNwSrc'])
                .in_ports(obj['inPorts'])
                .inv_in_ports(obj['invInPorts'])
                .out_ports(obj['outPorts'])
                .inv_out_ports(obj['invOutPorts'])
                .dl_type(obj['dlType'])
                .inv_dl_type(obj['invDlType'])
                .nw_tos(obj['nwTos'])
                .inv_nw_tos(obj['invNwTos'])
                .nw_proto(obj['nwProto'])
                .inv_nw_proto(obj['invNwProto'])
                .fragment_policy(obj['fragmentPolicy']).create)


class TunnelZoneRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "type", "name"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_tunnel_zones


class TunnelZoneWrite(MidonetWrite):
    """Expected format:

    "tunnel_zones": [{"id": UUID,
                   "type": String,
                   "name": String}, ...],
    """

    @property
    def key(self):
        return const.MN_TUNNEL_ZONES

    def create_f(self, obj):
        return (self.mc.mn_api.add_tunnel_zone()
                .id(obj['id'])
                .type(obj['type'])
                .name(obj['name'])
                .create)


class TunnelZoneHostRead(MidonetRead):

    @property
    def read_fields(self):
        return {"hostId", "ipAddress"}

    def get_sub_resources(self, p_obj):
        return p_obj.get_hosts()


class TunnelZoneHostWrite(MidonetWrite):
    """Expected format:

    "tunnel_zone_hosts": {UUID (Tunnel Zone ID):
                       [{"hostId": UUID,
                         "ipAddress": String}, ...]}, ...
    """

    @property
    def key(self):
        return const.MN_TZ_HOSTS

    def create_child_f(self, obj, p_id, parents):
        tz = _get_obj(self.mc.mn_api.get_tunnel_zone, p_id, cache_map=parents)
        return (tz.add_tunnel_zone_host()
                .host_id(obj['hostId'])
                .ip_address(obj['ipAddress'])
                .create)


class VipRead(MidonetRead):

    @property
    def read_fields(self):
        return {"id", "loadBalancerId", "poolId", "address", "protocolPort",
                "sessionPersistence"}

    @property
    def get_resources_f(self):
        return self.mc.mn_api.get_vips

    @property
    def exclude_ids(self):
        return self._neutron_ids('vips')


class VipWrite(MidonetWrite):
    """Expected format:

    "vips": [{"id": UUID,
              "loadBalancerId": UUID,
              "poolId": UUID,
              "address": String,
              "protocolPort": Int,
              "sessionPersistence": String}, ...],
    """

    @property
    def key(self):
        return const.MN_VIPS

    def create_f(self, obj):
        return (self.mc.mn_api.add_vip()
                .id(obj['id'])
                .load_balancer_id(obj['loadBalancerId'])
                .pool_id(obj['poolId'])
                .address(obj['address'])
                .protocol_port(obj['protocolPort'])
                .session_persistence(obj['sessionPersistence'])
                .create)


class DataReader(object):

    def __init__(self, nd):
        self.host = HostRead(nd)
        self.tz = TunnelZoneRead(nd)
        self.bridge = BridgeRead(nd)
        self.dhcp = DhcpSubnetRead(nd)
        self.router = RouterRead(nd)
        self.chain = ChainRead(nd)
        self.rule = RuleRead(nd)
        self.ip_addr_group = IpAddrGroupRead(nd)
        self.iag_addr = IpAddrGroupAddrRead(nd)
        self.port_group = PortGroupRead(nd)
        self.port = PortRead(nd)
        self.pgp = PortGroupPortRead(nd)
        self.route = RouteRead(nd)
        self.bgp = BgpRead(nd)
        self.ad_route = AdRouteRead(nd)
        self.hi_port = HostInterfacePortRead(nd)
        self.tzh = TunnelZoneHostRead(nd)
        self.lb = LoadBalancerRead(nd)
        self.hm = HealthMonitorRead(nd)
        self.pool = PoolRead(nd)
        self.pool_member = PoolMemberRead(nd)
        self.vip = VipRead(nd)

    def prepare(self):
        # Top level objects
        bridge_objs, bridge_dicts = self.bridge.create_resource_data()
        chain_objs, chain_dicts = self.chain.create_resource_data()
        host_objs, host_dicts = self.host.create_resource_data()
        ipag_objs, ipag_dicts = self.ip_addr_group.create_resource_data()
        pg_objs, pg_dicts = self.port_group.create_resource_data()
        router_objs, router_dicts = self.router.create_resource_data()
        tz_objs, tz_dicts = self.tz.create_resource_data()
        lb_objs, lb_dicts = self.lb.create_resource_data()
        _, hm_dicts = self.hm.create_resource_data()
        _, vip_dicts = self.vip.create_resource_data()

        # Sub-resources
        pool_map, pool_objs = self.pool.create_sub_resource_data(lb_objs)
        pool_member_map, _ = self.pool_member.create_sub_resource_data(
            pool_objs)
        port_map, port_objs = self.port.create_sub_resource_data(
            bridge_objs + router_objs)
        bgp_map, bgp_objs = self.bgp.create_sub_resource_data(port_objs)
        ar_map, _ = self.ad_route.create_sub_resource_data(bgp_objs)
        dhcp_map, _ = self.dhcp.create_sub_resource_data(bridge_objs)
        hip_map, _ = self.hi_port.create_sub_resource_data(host_objs)
        iag_addr_map, _ = self.iag_addr.create_sub_resource_data(ipag_objs)
        pgp_map, _ = self.pgp.create_sub_resource_data(pg_objs)
        route_map, _ = self.route.create_sub_resource_data(router_objs)
        rule_map, _ = self.rule.create_sub_resource_data(chain_objs)
        tzh_map, _ = self.tzh.create_sub_resource_data(tz_objs)

        return {
            const.MN_AD_ROUTES: ar_map,
            const.MN_BGP: bgp_map,
            const.MN_BRIDGES: bridge_dicts,
            const.MN_CHAINS: chain_dicts,
            const.MN_DHCP: dhcp_map,
            const.MN_HEALTH_MONITORS: hm_dicts,
            const.MN_HOSTS: host_dicts,
            const.MN_HI_PORTS: hip_map,
            const.MN_IPA_GROUPS: ipag_dicts,
            const.MN_IPAG_ADDRS: iag_addr_map,
            const.MN_LOAD_BALANCERS: lb_dicts,
            const.MN_POOLS: pool_map,
            const.MN_POOL_MEMBERS: pool_member_map,
            const.MN_PORT_GROUPS: pg_dicts,
            const.MN_PG_PORTS: pgp_map,
            const.MN_PORTS: port_map,
            const.MN_PORT_LINKS: _get_port_links(port_objs),
            const.MN_ROUTERS: router_dicts,
            const.MN_ROUTES: route_map,
            const.MN_RULES: rule_map,
            const.MN_TUNNEL_ZONES: tz_dicts,
            const.MN_TZ_HOSTS: tzh_map,
            const.MN_VIPS: vip_dicts
        }


class DataWriter(object):

    def __init__(self, data, dry_run=False):
        self.host = HostWrite(data, dry_run=dry_run)
        self.tz = TunnelZoneWrite(data, dry_run=dry_run)
        self.bridge = BridgeWrite(data, dry_run=dry_run)
        self.dhcp = DhcpSubnetWrite(data, dry_run=dry_run)
        self.router = RouterWrite(data, dry_run=dry_run)
        self.chain = ChainWrite(data, dry_run=dry_run)
        self.rule = RuleWrite(data, dry_run=dry_run)
        self.ip_addr_group = IpAddrGroupWrite(data, dry_run=dry_run)
        self.iag_addr = IpAddrGroupAddrWrite(data, dry_run=dry_run)
        self.link = LinkWrite(data, dry_run=dry_run)
        self.port_group = PortGroupWrite(data, dry_run=dry_run)
        self.port = PortWrite(data, dry_run=dry_run)
        self.pgp = PortGroupPortWrite(data, dry_run=dry_run)
        self.route = RouteWrite(data, dry_run=dry_run)
        self.bgp = BgpWrite(data, dry_run=dry_run)
        self.ad_route = AdRouteWrite(data, dry_run=dry_run)
        self.hi_port = HostInterfacePortWrite(data, dry_run=dry_run)
        self.tzh = TunnelZoneHostWrite(data, dry_run=dry_run)
        self.lb = LoadBalancerWrite(data, dry_run=dry_run)
        self.hm = HealthMonitorWrite(data, dry_run=dry_run)
        self.pool = PoolWrite(data, dry_run=dry_run)
        self.pool_member = PoolMemberWrite(data, dry_run=dry_run)
        self.vip = VipWrite(data, dry_run=dry_run)

    def _print_summary(self):
        self.ad_route.print_summary()
        self.bgp.print_summary()
        self.bridge.print_summary()
        self.chain.print_summary()
        self.dhcp.print_summary()
        self.hm.print_summary()
        self.host.print_summary()
        self.hi_port.print_summary()
        self.ip_addr_group.print_summary()
        self.iag_addr.print_summary()
        self.lb.print_summary()
        self.pool.print_summary()
        self.pool_member.print_summary()
        self.port.print_summary()
        self.link.print_summary()
        self.port_group.print_summary()
        self.pgp.print_summary()
        self.route.print_summary()
        self.router.print_summary()
        self.route.print_summary()
        self.rule.print_summary()
        self.tz.print_summary()
        self.tzh.print_summary()
        self.vip.print_summary()

    def migrate(self):
        LOG.info('Running MidoNet migration process')
        hosts = self.host.create_objects()
        tunnel_zones = self.tz.create_objects()
        lbs = self.lb.create_objects()
        chains = self.chain.create_objects()
        bridges = self.bridge.create_objects()
        routers = self.router.create_objects()
        ip_addr_groups = self.ip_addr_group.create_objects()
        port_groups = self.port_group.create_objects()
        self.hm.create_objects()

        # Sub-resources
        pools = self.pool.create_child_objects(lbs)
        self.vip.create_objects()
        self.pool_member.create_child_objects(pools)

        self.bgp.create_child_objects(routers)
        self.ad_route.create_child_objects(routers)
        self.dhcp.create_child_objects(bridges)
        self.iag_addr.create_child_objects(ip_addr_groups)

        # Merge bridges and routers for ports
        device_map = bridges.copy()
        device_map.update(routers)
        ports = self.port.create_child_objects(device_map)

        self.pgp.create_child_objects(port_groups)
        self.rule.create_child_objects(chains)
        self.route.create_child_objects(routers)

        self.link.link_ports(ports)

        # Host Bindings
        self.tzh.create_child_objects(tunnel_zones)
        self.hi_port.create_child_objects(hosts)

        self._print_summary()
