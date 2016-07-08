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
from data_migration import data as dm_data
from data_migration import provider_router as pr
from data_migration import routes as dm_routes
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


def _is_neutron_chain_name(name):
    return (name.startswith("OS_PRE_ROUTING_") or
            name.startswith("OS_POST_ROUTING_") or
            name.startswith("OS_PORT_") or
            name.startswith("OS_SG_"))


def _midonet_only_chain_ids(chains):
    return [c['id'] for c in chains if not _is_neutron_chain_name(c['name'])]


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


@six.add_metaclass(abc.ABCMeta)
class MidonetReader(object):

    def __init__(self, nd, obj_map):
        self.mc = context.get_read_context()
        self._nd = nd
        self.obj_map = obj_map

    def get(self):
        if self.parent_keys:
            return self._get_sub_objects()
        else:
            objs = self.get_resources()
            self.obj_map[self.key] = objs
            return self.to_dicts(objs, modify=self.modify_dto_f,
                                 fields=self.fields)

    def _get_sub_objects(self):
        parent_objs = []
        for p_key in self.parent_keys:
            parent_objs.extend(self.obj_map[p_key])

        dict_map = {}
        obj_list = []
        for p_obj in parent_objs:
            pid = p_obj.get_id()
            objs = self.get_resources(parent=p_obj)
            if objs:
                obj_list.extend(objs)
                dict_map[pid] = self.to_dicts(objs,
                                              modify=self.modify_dto_f,
                                              fields=self.fields)
        self.obj_map[self.key] = obj_list
        return dict_map

    def get_resources(self, parent=None):
        return []

    def to_dicts(self, objs, modify=None, fields=None):
        return _to_dto_dict(objs, modify=modify, fields=fields)

    @property
    def modify_dto_f(self):
        return None

    @property
    def key(self):
        return ""

    @property
    def fields(self):
        return set()

    @property
    def parent_keys(self):
        return []


@six.add_metaclass(abc.ABCMeta)
class MidonetWriter(dm_data.CommonData, dm_data.DataCounterMixin,
                    pr.ProviderRouterMixin):

    def __init__(self, data, created_map, dry_run=False):
        super(MidonetWriter, self).__init__(data, dry_run=dry_run)
        self.created_map = created_map
        self.created_map[self.key] = {}

    def _update_data(self, f, obj, *args, **kwargs):
        o = f(*args, **kwargs)
        self.updated.append(obj)
        return o

    def _create_data(self, f, obj, *args, **kwargs):
        try:
            if self.dry_run:
                self.created.append(obj)
                return None

            o = f(*args, **kwargs)
            self.created.append(obj)
            return o
        except wexc.HTTPClientError as e:
            if e.code == wexc.HTTPConflict.code:
                LOG.warn("Already exists: " + str(obj))
                self.conflicted.append(obj)
                return None
            raise e

    def _get_port_device_id(self, port_id):
        port_map = self._get_midonet_resources(key='ports')
        for device_id, ports in iter(port_map.items()):
            for port in ports:
                if port['id'] == port_id:
                    return device_id
        return None

    def create(self):
        if self.parent_keys:
            self._create_child_objects()
        else:
            self._create_objects()

    def _create_objects(self):
        objs = self._get_midonet_resources(key=self.key)
        n_ids = self._neutron_ids(self.neutron_key) if self.neutron_key else []

        for obj in objs:
            LOG.debug("Creating " + self.key + " obj " + str(obj))
            obj_id = obj['id']
            if self.skip_create_object(obj, n_ids=n_ids):
                continue

            o = self._create_data(self.create_f(obj), obj)
            if o:
                self.created_map[self.key][obj_id] = o

    def _build_parent_cache(self):
        parent_cache = {}
        for p_key in self.parent_keys:
            parent_cache.update(self.created_map[p_key])
        return parent_cache

    def _create_child_sub_objects(self, obj, o):
        self.process_child_sub_objects(obj, o)
        if hasattr(o, 'get_id'):
            self.created_map[self.key][o.get_id()] = o

    def _get_parent_object(self, p_id):
        return None

    def _create_child_objects(self):
        parents = self._build_parent_cache()
        obj_map = self._get_midonet_resources(key=self.key)
        n_ids = self._neutron_ids(self.neutron_key) if self.neutron_key else []
        for p_id, objs in iter(obj_map.items()):
            for obj in objs:
                if self.skip_create_object(obj, parent_id=p_id, n_ids=n_ids,
                                           parents=parents):
                    continue

                LOG.debug("Creating " + self.key + " child obj " + str(obj))
                if self.dry_run:
                    self.created.append(obj)
                    continue

                o = self._create_data(self.create_child_f(obj, p_id, parents),
                                      obj)
                if o:
                    self._create_child_sub_objects(obj, o)

    @property
    def key(self):
        return ""

    @property
    def neutron_key(self):
        return ""

    @property
    def parent_keys(self):
        return []

    def create_f(self, obj):
        return None

    def create_child_f(self, obj, p_id, parents):
        return None

    def process_child_sub_objects(self, data, obj):
        pass

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        if n_ids:
            is_neutron_generated = obj['id'] in n_ids
            if is_neutron_generated:
                self.add_skip(obj['id'], "Neutron generated object")
            return is_neutron_generated
        else:
            return False


class NoIdMixin(object):

    def __init__(self, data, created_map, dry_run=False):
        super(NoIdMixin, self).__init__(data, created_map, dry_run=dry_run)
        self.no_id_res_map = {}

    @property
    def _get_parent_resource_f(self):
        return None

    def _get_sub_resources(self, parent):
        return []

    def _sub_resource_cmp_field(self, res):
        return None

    @property
    def _sub_resource_cmp_key(self):
        return ""

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        if self.dry_run:
            # Cannot run this in dry run
            return False

        parent = _get_obj(self._get_parent_resource_f, parent_id,
                          cache_map=parents)
        children = self.no_id_res_map.get(parent_id)
        if not children:
            children = self._get_sub_resources(parent)
            self.no_id_res_map[parent_id] = children
        res = next((c for c in children
                    if (self._sub_resource_cmp_field(c) ==
                        obj[self._sub_resource_cmp_key])), None)
        if res:
            LOG.debug("Duplicate " + self.key + " exists: " + str(res))
            self.add_skip(obj[self._sub_resource_cmp_key],
                          self._sub_resource_cmp_key + " of " + self.key +
                          " already exists")
            return True
        return False


class AdRouteBase(object):
    """Expected format:

    "ad_routes": {UUID (BGP ID):
                  [{"id": UUID,
                    "nwPrefix": String,
                    "prefixLength": Int}, ...], ...,
    """
    @property
    def fields(self):
        return {"id", "nwPrefix", "prefixLength"}

    @property
    def key(self):
        return const.MN_AD_ROUTES


class AdRouteReader(AdRouteBase, MidonetReader):

    @property
    def parent_keys(self):
        return [const.MN_BGP]

    def get_resources(self, parent=None):
        LOG.info("Getting Ad Route objects for BGP " + parent.get_id())
        return parent.get_ad_routes()


class AdRouteWriter(AdRouteBase, MidonetWriter):

    @property
    def parent_keys(self):
        return [const.MN_ROUTERS]

    def _get_bgp_router_id(self, bgp_id):
        bgp_map = self._get_midonet_resources(key='bgp')
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


class BgpBase(object):
    """Expected format:

    "bgp": {UUID (Port ID):
            [{"id": UUID,
              "localAS": Int,
              "peerAS": Int,
              "peerAddr": String}, ...]}, ...,
    """
    @property
    def fields(self):
        return {"id", "localAS", "peerAS", "peerAddr"}

    @property
    def key(self):
        return const.MN_BGP


class BgpReader(BgpBase, MidonetReader):

    @property
    def parent_keys(self):
        return [const.MN_PORTS]

    def get_resources(self, parent=None):
        # Skip the non-router ports
        if parent.get_type() != const.RTR_PORT_TYPE:
            return []
        LOG.info("Getting BGP objects for port " + parent.get_id())
        return parent.get_bgps()


class BgpWriter(BgpBase, MidonetWriter):

    def __init__(self, data, created_map, dry_run=None):
        super(BgpWriter, self).__init__(data, created_map, dry_run=dry_run)
        self.port_map = self._get_midonet_resource_map('ports')

    @property
    def parent_keys(self):
        return [const.MN_ROUTERS]

    def create_child_f(self, obj, p_id, parents):
        router_id = self._get_port_device_id(p_id)
        router = _get_obj(self.mc.mn_api.get_router, router_id,
                          cache_map=parents)

        # Update router with local AS
        LOG.debug("Updating router " + router_id + " with asn " +
                  str(obj['localAS']))
        self._update_data(router.asn(obj['localAS']).update, obj)

        return (router.add_bgp_peer()
                .id(obj['id'])
                .asn(obj['peerAS'])
                .address(obj['peerAddr']).create)

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        port = self.port_map[parent_id]
        if port['type'] != const.RTR_PORT_TYPE:
            LOG.debug("Skipping BGP on non-router port " + str(obj))
            self.add_skip(port['id'], "BGP on non-router port")
            return True
        return False


class BridgeBase(object):
    """Expected format:

    "bridges": [{"id": UUID,
                 "name": String,
                 "tenantId": String,
                 "adminStateUp": Bool,
                 "inboundFilterId": UUID,
                 "outboundFilterId":UUID}, ...],
    """
    @property
    def fields(self):
        return {"id", "name", "tenantId", "adminStateUp", "inboundFilterId",
                "outboundFilterId"}

    @property
    def key(self):
        return const.MN_BRIDGES

    @property
    def neutron_key(self):
        return const.NEUTRON_NETWORKS


class BridgeReader(BridgeBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Bridge objects")
        return self.mc.mn_api.get_bridges(query={})


class BridgeWriter(BridgeBase, MidonetWriter):

    def create_f(self, obj):
        return (self.mc.mn_api.add_bridge()
                .id(obj['id'])
                .name(obj['name'])
                .tenant_id(obj['tenantId'])
                .inbound_filter_id(obj['inboundFilterId'])
                .outbound_filter_id(obj['outboundFilterId'])
                .admin_state_up(obj['adminStateUp'])
                .create)


class ChainBase(object):
    """Expected format:

    "chains": [{"id": UUID,
                "name": String,
                "tenantId": String}, ...],
    """
    @property
    def fields(self):
        return {"id", "name", "tenantId"}

    @property
    def key(self):
        return const.MN_CHAINS


class ChainReader(ChainBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Chain objects")
        return self.mc.mn_api.get_chains(query={})


class ChainWriter(ChainBase, MidonetWriter):

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        skip = _is_neutron_chain_name(obj['name'])
        if skip:
            self.add_skip(obj['id'], "Neutron generated chain")
        return skip

    def create_f(self, obj):
        return (self.mc.mn_api.add_chain()
                .id(obj['id'])
                .name(obj['name'])
                .tenant_id(obj['tenantId'])
                .create)


class DhcpSubnetBase(object):
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
    def fields(self):
        return {"defaultGateway", "serverAddr", "dnsServerAddrs",
                "subnetPrefix", "subnetLength", "interfaceMTU", "enabled",
                "opt121Routes"}

    @property
    def _host_fields(self):
        return {"name", "ipAddr", "macAddr"}

    @property
    def key(self):
        return const.MN_DHCP

    @property
    def parent_keys(self):
        return [const.MN_BRIDGES]


class DhcpSubnetReader(DhcpSubnetBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting DHCP Subnet objects for bridge " + parent.get_id())
        return parent.get_dhcp_subnets()

    def to_dicts(self, objs, modify=None, fields=None):
        subnet_list = []
        for subnet in objs:
            # Also add hosts
            s = _extract_fields(subnet.dto, self.fields)
            s["hosts"] = _to_dto_dict(subnet.get_dhcp_hosts(),
                                      fields=self._host_fields)
            subnet_list.append(s)
        return subnet_list


class DhcpSubnetWriter(DhcpSubnetBase, NoIdMixin, MidonetWriter):

    @property
    def _get_parent_resource_f(self):
        return self.mc.mn_api.get_bridge

    def _get_sub_resources(self, parent):
        return parent.get_dhcp_subnets()

    def _sub_resource_cmp_field(self, res):
        return res.get_subnet_prefix()

    @property
    def _sub_resource_cmp_key(self):
        return 'subnetPrefix'

    def create_child_f(self, obj, p_id, parents):
        bridge = _get_obj(self._get_parent_resource_f, p_id, cache_map=parents)
        return (bridge.add_dhcp_subnet()
                .default_gateway(obj['defaultGateway'])
                .server_addr(obj['serverAddr'])
                .dns_server_addrs(obj['dnsServerAddrs'])
                .subnet_prefix(obj['subnetPrefix'])
                .subnet_length(obj['subnetLength'])
                .interface_mtu(obj['interfaceMTU'])
                .opt121_routes(obj['opt121Routes'])
                .enabled(obj['enabled'])
                .create)

    def process_child_sub_objects(self, obj, parent):

        def _create_dhcp_host_f(o, p):
            return (p.add_dhcp_host()
                    .name(o['name'])
                    .ip_addr(o['ipAddr'])
                    .mac_addr(o['macAddr'])
                    .create)

        if obj['hosts']:
            for host in obj['hosts']:
                LOG.debug("Creating sub child obj " + str(host))
                self._create_data(_create_dhcp_host_f, obj, host, parent)


class HealthMonitorBase(object):
    """Expected format:

    "health_monitors": [{"id": UUID,
                         "type": String,
                         "adminStateUp": Bool,
                         "delay": Int,
                         "maxRetries": Int,
                         "timeout": Int}, ...],
    """
    @property
    def fields(self):
        return {"id", "type", "adminStateUp", "delay", "maxRetries", "timeout"}

    @property
    def key(self):
        return const.MN_HEALTH_MONITORS


class HealthMonitorReader(HealthMonitorBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Health Monitor objects")
        return self.mc.mn_api.get_health_monitors()


class HealthMonitorWriter(HealthMonitorBase, MidonetWriter):

    def create_f(self, obj):
        return (self.mc.mn_api.add_health_monitor()
                .id(obj['id'])
                .type(obj['type'])
                .admin_state_up(obj['adminStateUp'])
                .delay(obj['delay'])
                .max_retries(obj['maxRetries'])
                .timeout(obj['timeout'])
                .create)


class HostBase(object):
    """Expected format:

    "hosts": [{"id": UUID,
               "name": String}, ...],
    """
    @property
    def fields(self):
        return {"id", "name"}

    @property
    def key(self):
        return const.MN_HOSTS


class HostReader(HostBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Hosts objects")
        return self.mc.mn_api.get_hosts()


class HostWriter(HostBase, MidonetWriter):

    def create_f(self, obj):
        return (self.mc.mn_api.add_host()
                .id(obj['id'])
                .name(obj['name'])
                .create)


class HostInterfaceBase(object):
    """Expected format:

    "host_interface_ports": {UUID (Host ID):
                          [{"portId": UUID,
                            "interfaceName": String}, ...]}, ...,
    """
    @property
    def fields(self):
        return {"portId", "interfaceName"}

    @property
    def key(self):
        return const.MN_HI_PORTS

    @property
    def parent_keys(self):
        return [const.MN_HOSTS]


class HostInterfacePortReader(HostInterfaceBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Host Interface Port objects for host " +
                 parent.get_id())
        return parent.get_ports()


class HostInterfacePortWriter(HostInterfaceBase, MidonetWriter):

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        pr_port_ids = self.provider_router_port_ids
        if obj['portId'] in pr_port_ids:
            LOG.debug("Skipping Provider Router port binding " + str(obj))
            self.add_skip(obj['portId'], "Provider Router port binding")
            return True

        if _is_lb_hm_interface(obj['interfaceName']):
            LOG.debug("Skipping HM port binding " + str(obj))
            self.add_skip(obj['portId'], "Health monitor port binding")
            return True

        return False

    def create_child_f(self, obj, p_id, parents):
        host = _get_obj(self.mc.mn_api.get_host, p_id, cache_map=parents)
        return (host.add_host_interface_port()
                .port_id(obj['portId'])
                .interface_name(obj['interfaceName'])
                .create)


class IpAddrGroupBase(object):
    """Expected format:

    "ip_addr_groups": [{"id": UUID,
                     "name": String,}, ...],
    """
    @property
    def fields(self):
        return {"id", "name"}

    @property
    def key(self):
        return const.MN_IPA_GROUPS

    @property
    def neutron_key(self):
        return const.NEUTRON_SECURITY_GROUPS


class IpAddrGroupReader(IpAddrGroupBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting IP Address Group objects")
        return self.mc.mn_api.get_ip_addr_groups()


class IpAddrGroupWriter(IpAddrGroupBase, MidonetWriter):

    def create_f(self, obj):
        return (self.mc.mn_api.add_ip_addr_group()
                .id(obj['id'])
                .name(obj['name'])
                .create)


class IpAddrGroupAddrBase(object):
    """Expected format:

    "ip_addr_group_addrs": {UUID (IP addr group ID):
                          [{"addr": String,
                            "version": Int}, ...]}, ...
    """
    @property
    def fields(self):
        return {"addr", "version"}

    @property
    def key(self):
        return const.MN_IPAG_ADDRS

    @property
    def parent_keys(self):
        return [const.MN_IPA_GROUPS]


class IpAddrGroupAddrReader(IpAddrGroupAddrBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting IP Address Group Addr objects for IP addr group " +
                 parent.get_id())
        return parent.get_addrs()

    @property
    def modify_dto_f(self):
        def _to_ipv4(o):
            o['version'] = 4
            return o

        # There seems to be a bug where all IP address group addrs
        # return as version '6': MI-994.  Since we only support 4,
        # just always set it to version 4.
        return _to_ipv4


class IpAddrGroupAddrWriter(IpAddrGroupAddrBase, NoIdMixin, MidonetWriter):

    @property
    def _get_parent_resource_f(self):
        return self.mc.mn_api.get_ip_addr_group

    def _get_sub_resources(self, parent):
        return parent.get_addrs()

    def _sub_resource_cmp_field(self, res):
        return res.get_addr()

    @property
    def _sub_resource_cmp_key(self):
        return 'addr'

    def create_child_f(self, obj, p_id, parents):
        iag = _get_obj(self._get_parent_resource_f, p_id, cache_map=parents)
        version = obj['version']
        if version == 4:
            return iag.add_ipv4_addr().addr(obj['addr']).create
        else:
            return iag.add_ipv6_addr().addr(obj['addr']).create


class LinkBase(object):
    """Expected format:

    "port_links": {UUID [Port ID]: UUID [PeerPort ID]}
    """
    @property
    def key(self):
        return "port_links"


class LinkReader(LinkBase, MidonetReader):

    def __init__(self, nd, obj_map):
        super(LinkReader, self).__init__(nd, obj_map)
        self.ports = self.obj_map[const.MN_PORTS]

    def get(self, parent_key=None):
        links = {}
        for port in self.ports:
            peer_id = port.get_peer_id()
            if peer_id:
                port_id = port.get_id()
                if port_id not in links:
                    links[peer_id] = port_id
        return links


class LinkWriter(LinkBase, MidonetWriter):

    def __init__(self, data, created_map, dry_run=False):
        super(LinkWriter, self).__init__(data, created_map, dry_run=dry_run)
        self._n_port_ids = self._neutron_ids(const.NEUTRON_PORTS)

    def create(self):
        links = self._get_midonet_resources(key='port_links')
        port_ids = self.provider_router_port_ids
        for port_id, peer_id in iter(links.items()):
            link = (port_id, peer_id)

            # Skip the provider router ports
            if port_id in port_ids or peer_id in port_ids:
                LOG.debug("Skipping Provider Router port linking " + str(link))
                self.add_skip(link, "Provider Router port linking")
                continue

            # Skip if either of the ports are Neutron generated
            if port_id in self._n_port_ids or peer_id in self._n_port_ids:
                LOG.debug("Skipping Neutron port linking " + str(link))
                self.add_skip(link, "Neutron port linking")
                continue

            LOG.debug("Linking ports " + str(link))
            if self.dry_run:
                self.created.append(link)
                continue

            port = _get_obj(self.mc.mn_api.get_port, port_id,
                            cache_map=self.created_map[const.MN_PORTS])
            self._create_data(self.mc.mn_api.link, link, port, peer_id)


class LoadBalancerBase(object):
    """Expected Format:

    "load_balancers": [{"id": UUID,
                        "routerId": UUID,
                        "adminStateUp": Bool
                       }, ...],
    """
    @property
    def fields(self):
        return {"id", "routerId", "adminStateUp"}

    @property
    def key(self):
        return const.MN_LOAD_BALANCERS


class LoadBalancerReader(LoadBalancerBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Load Balancer objects")
        return self.mc.mn_api.get_load_balancers()


class LoadBalancerWriter(LoadBalancerBase, MidonetWriter):

    def __init__(self, data, created_map, dry_run=False):
        super(LoadBalancerWriter, self).__init__(data, created_map,
                                                 dry_run=dry_run)
        self.n_router_ids = self._neutron_ids('routers')

    def create_f(self, obj):
        return (self.mc.mn_api.add_load_balancer()
                .id(obj['id'])
                .admin_state_up(obj['adminStateUp'])
                .create)

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        # Filter out LBs that are either not associated with a router created
        # by Neutron.
        if obj['routerId'] in self.n_router_ids:
            LOG.debug("Skipping LB on Neutron router " + str(obj))
            self.add_skip(obj['id'], "Load balancer on a Neutron router")
            return True
        return False


class PoolBase(object):
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
    def fields(self):
        return {"id", "loadBalancerId", "lbMethod", "adminStateUp", "protocol",
                "healthMonitorId"}

    @property
    def key(self):
        return const.MN_POOLS

    @property
    def neutron_key(self):
        return const.NEUTRON_POOLS

    @property
    def parent_keys(self):
        return [const.MN_LOAD_BALANCERS]


class PoolReader(PoolBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Pool objects for lb " + parent.get_id())
        return parent.get_pools()


class PoolWriter(PoolBase, MidonetWriter):

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


class PoolMemberBase(object):
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
    def fields(self):
        return {"id", "poolId", "address", "adminStateUp", "protocolPort",
                "weight"}

    @property
    def key(self):
        return const.MN_POOL_MEMBERS

    @property
    def neutron_key(self):
        return const.NEUTRON_MEMBERS

    @property
    def parent_keys(self):
        return [const.MN_POOLS]


class PoolMemberReader(PoolMemberBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Pool Member objects for pool " + parent.get_id())
        return parent.get_pool_members()


class PoolMemberWriter(PoolMemberBase, MidonetWriter):

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


class PortBase(object):
    """Expected format:

    "ports": {"id" UUID (device ID):
              [{"id": UUID,
                "deviceId": UUID,
                "peerId": UUID,
                "hostId": UUID,
                "interfaceName": String,
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
    def fields(self):
        return {"id", "deviceId", "adminStateUp", "inboundFilterId", "peerId",
                "outboundFilterId", "vifId", "vlanId", "portAddress",
                "networkAddress", "networkLength", "portMac", "type", "hostId",
                "interfaceName"}

    @property
    def key(self):
        return const.MN_PORTS

    @property
    def neutron_key(self):
        return const.NEUTRON_PORTS

    @property
    def parent_keys(self):
        return [const.MN_BRIDGES, const.MN_ROUTERS]


class PortReader(PortBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Port objects for device " + parent.get_id())
        return parent.get_ports()


class PortWriter(PortBase, MidonetWriter):

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
            # Should never reach here
            raise ValueError("Unknown port type " + ptype +
                             " detected for port " + pid)

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        """We want to exclude the following ports:

        1. ID matching one of the neutron port IDs
        2. Peer ID, if present, matching one of Neutron port IDs
        """
        port_id = obj["id"]
        peer_id = obj["peerId"]
        is_neutron_generated = port_id in n_ids or (peer_id is not None and
                                                    peer_id in n_ids)
        if is_neutron_generated:
            self.add_skip(port_id, "Neutron generated port")
            return True

        # Skip unknown port types (VxLAN not supported yet)
        port_type = obj['type']
        if port_type not in [const.RTR_PORT_TYPE, const.BRG_PORT_TYPE]:
            self.add_skip(port_id, "Unknown port type " + port_type)
            return True

        return False


class PortGroupBase(object):
    """Expected format:

    "port_groups": [{"id": UUID,
                  "name": String,
                  "tenantId": String,
                  "stateful": Bool, ...],
    """
    @property
    def fields(self):
        return {"id", "name", "tenantId", "stateful"}

    @property
    def key(self):
        return const.MN_PORT_GROUPS


class PortGroupReader(PortGroupBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Port Group objects")
        return self.mc.mn_api.get_port_groups(query={})


class PortGroupWriter(PortGroupBase, MidonetWriter):

    def create_f(self, obj):
        return (self.mc.mn_api.add_port_group()
                .id(obj['id'])
                .name(obj['name'])
                .tenant_id(obj['tenantId'])
                .stateful(obj['stateful'])
                .create)


class PortGroupPortBase(object):
    """Expected format:

    "port_group_ports": {UUID (Port group ID):
                      [UUID (Port ID)]}, ...
    """
    @property
    def fields(self):
        return {"portId"}

    @property
    def key(self):
        return const.MN_PG_PORTS

    @property
    def parent_keys(self):
        return [const.MN_PORT_GROUPS]


class PortGroupPortReader(PortGroupPortBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Port Group Port objects for port group " +
                 parent.get_id())
        return parent.get_ports()

    @property
    def modify_dto_f(self):
        def _extract_port_id(o):
            return o['portId']

        return _extract_port_id


class PortGroupPortWriter(PortGroupPortBase, MidonetWriter):

    def create_child_f(self, obj, p_id, parents):
        pg = _get_obj(self.mc.mn_api.get_port_group, p_id, cache_map=parents)
        return (pg.add_port_group_port()
                .port_id(obj)
                .create)


class RouteBase(object):
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
    def fields(self):
        return {"id", "learned", "attributes", "dstNetworkAddr",
                "dstNetworkLength", "srcNetworkAddr", "srcNetworkLength",
                "nextHopGateway", "nextHopPort", "type", "weight"}

    @property
    def key(self):
        return const.MN_ROUTES

    @property
    def parent_keys(self):
        return [const.MN_ROUTERS]


class RouteReader(RouteBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Route objects for router " + parent.get_id())
        return parent.get_routes()


class RouteWriter(RouteBase, MidonetWriter, dm_routes.RouteMixin,
                  pr.ProviderRouterMixin):

    def __init__(self, data, created_map, dry_run=False):
        super(RouteWriter, self).__init__(data, created_map, dry_run=dry_run)
        links = self._get_midonet_resources(key="port_links")
        n_port_ids = self._neutron_ids('ports')
        self.n_port_and_peer_ids = set()
        for port_id, peer_id in iter(links.items()):
            if port_id in n_port_ids or peer_id in n_port_ids:
                self.n_port_and_peer_ids.add(port_id)
                self.n_port_and_peer_ids.add(peer_id)

        # Save all the FIP IP addresses
        fips = self._get_neutron_resources(const.NEUTRON_FLOATINGIPS)
        self._fip_ips = set([fip["floating_ip_address"]
                             for fip in fips.values()])

        # Save gateway IPs (should only be one IP)
        ports = self._get_neutron_resources(const.NEUTRON_PORTS)
        self._gw_ips = [p["fixed_ips"][0]["ip_address"] for p in ports.values()
                        if p["device_owner"] == const.ROUTER_GATEWAY_PORT_TYPE]

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        if obj['learned']:
            LOG.debug("Skipping learned route " + str(obj))
            self.add_skip(obj['id'], "Learned route")
            return True

        # Skip the port routes
        if self.is_port_route(obj, parent_id):
            LOG.debug("Skipping port route " + str(obj))
            self.add_skip(obj['id'], "Local port route")
            return True

        # Skip metadata routes
        dest_addr = obj['dstNetworkAddr']
        if dest_addr == const.METADATA_ROUTE_IP:
            LOG.debug("Skipping metadata route " + str(obj))
            self.add_skip(obj['id'], "Metadata service route")
            return True

        # Skip the routes whose next hop port is either the neutron ports or
        # their peers and the it is a network route
        if (obj['nextHopPort'] in self.n_port_and_peer_ids and
                self.is_network_route(obj, parent_id)):
            LOG.debug("Skipping neutron network route " + str(obj))
            self.add_skip(obj['id'], "Neutron generated network route")
            return True

        # Skip default routes where the next hop port is a Neutron port.
        if (obj['nextHopPort'] in self.n_port_and_peer_ids and
                dm_routes.is_default_route(obj)):
            LOG.debug("Skipping neutron default route " + str(obj))
            self.add_skip(obj['id'], "Neutron generated default route")
            return True

        # Special handling for provider router routes
        if parent_id == self.provider_router["id"]:
            dest_len = obj["dstNetworkLength"]

            # Skip FIP routes
            if dest_addr in self._fip_ips and dest_len == 32:
                LOG.debug("Skipping provider router FIP route " + str(obj))
                self.add_skip(obj['id'], "Provder Router FIP route")
                return True

            # Skip Router Gateway routes
            if dest_addr in self._gw_ips and dest_len == 32:
                LOG.debug("Skipping provider router gateway route " + str(obj))
                self.add_skip(obj['id'], "Provder Router gateway route")
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
                .dst_network_length(obj['dstNetworkLength'])
                .src_network_addr(obj['srcNetworkAddr'])
                .src_network_length(obj['srcNetworkLength'])
                .next_hop_gateway(obj['nextHopGateway'])
                .next_hop_port(obj['nextHopPort'])
                .weight(obj['weight']).create)


class RouterBase(object):
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
    def fields(self):
        return {"id", "name", "tenantId", "adminStateUp", "loadBalancerId",
                "inboundFilterId", "outboundFilterId"}

    @property
    def key(self):
        return const.MN_ROUTERS

    @property
    def neutron_key(self):
        return const.NEUTRON_ROUTERS


class RouterReader(RouterBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Router objects")
        return self.mc.mn_api.get_routers(query={})


class RouterWriter(RouterBase, MidonetWriter):

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


class RuleBase(object):
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
    def fields(self):
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

    @property
    def key(self):
        return const.MN_RULES

    @property
    def parent_keys(self):
        return [const.MN_CHAINS]


class RuleReader(RuleBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Rule objects for chain " + parent.get_id())
        return parent.get_rules()


class RuleWriter(RuleBase, MidonetWriter):

    def __init__(self, data, created_map, dry_run=False):
        super(RuleWriter, self).__init__(data, created_map, dry_run=dry_run)
        chains = self._get_midonet_resources('chains')
        self.m_chain_ids = _midonet_only_chain_ids(chains)

    def skip_create_object(self, obj, parent_id=None, n_ids=None,
                           parents=None):
        # Skip if the rule belongs to a chain generated by Neutron
        rule_id = obj['id']
        if parent_id not in self.m_chain_ids:
            self.add_skip(rule_id, "Chain is Neutron generated")
            return True

        jump_chain = obj.get('jumpChainId')
        if jump_chain and jump_chain in self.m_chain_ids:
            self.add_skip(rule_id, "Jump chain is Neutron generated")
            return True

        return False

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


class TunnelZoneBase(object):
    """Expected format:

    "tunnel_zones": [{"id": UUID,
                   "type": String,
                   "name": String}, ...],
    """
    @property
    def fields(self):
        return {"id", "type", "name"}

    @property
    def key(self):
        return const.MN_TUNNEL_ZONES


class TunnelZoneReader(TunnelZoneBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Tunnel Zone objects")
        return self.mc.mn_api.get_tunnel_zones()


class TunnelZoneWriter(TunnelZoneBase, MidonetWriter):

    def create_f(self, obj):
        return (self.mc.mn_api.add_tunnel_zone()
                .id(obj['id'])
                .type(obj['type'])
                .name(obj['name'])
                .create)


class TunnelZoneHostBase(object):
    """Expected format:

    "tunnel_zone_hosts": {UUID (Tunnel Zone ID):
                       [{"hostId": UUID,
                         "ipAddress": String}, ...]}, ...
    """
    @property
    def fields(self):
        return {"hostId", "ipAddress"}

    @property
    def key(self):
        return const.MN_TZ_HOSTS

    @property
    def parent_keys(self):
        return [const.MN_TUNNEL_ZONES]


class TunnelZoneHostReader(TunnelZoneHostBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting Tunnel Zone Host objects for tunnel zone " +
                 parent.get_id())
        return parent.get_hosts()


class TunnelZoneHostWriter(TunnelZoneHostBase, MidonetWriter):

    def create_child_f(self, obj, p_id, parents):
        tz = _get_obj(self.mc.mn_api.get_tunnel_zone, p_id, cache_map=parents)
        return (tz.add_tunnel_zone_host()
                .host_id(obj['hostId'])
                .ip_address(obj['ipAddress'])
                .create)


class VipBase(object):
    """Expected format:

    "vips": [{"id": UUID,
              "loadBalancerId": UUID,
              "poolId": UUID,
              "address": String,
              "protocolPort": Int,
              "sessionPersistence": String}, ...],
    """
    @property
    def fields(self):
        return {"id", "loadBalancerId", "poolId", "address", "protocolPort",
                "sessionPersistence"}

    @property
    def key(self):
        return const.MN_VIPS

    @property
    def neutron_key(self):
        return const.NEUTRON_VIPS


class VipReader(VipBase, MidonetReader):

    def get_resources(self, parent=None):
        LOG.info("Getting VIP objects")
        return self.mc.mn_api.get_vips()


class VipWriter(VipBase, MidonetWriter):

    def create_f(self, obj):
        return (self.mc.mn_api.add_vip()
                .id(obj['id'])
                .load_balancer_id(obj['loadBalancerId'])
                .pool_id(obj['poolId'])
                .address(obj['address'])
                .protocol_port(obj['protocolPort'])
                .session_persistence(obj['sessionPersistence'])
                .create)


_MIDONET_OBJECTS = [
    (HostReader, HostWriter),
    (TunnelZoneReader, TunnelZoneWriter),
    (ChainReader, ChainWriter),
    (HealthMonitorReader, HealthMonitorWriter),
    (IpAddrGroupReader, IpAddrGroupWriter),
    (PortGroupReader, PortGroupWriter),
    (BridgeReader, BridgeWriter),
    (RouterReader, RouterWriter),
    (LoadBalancerReader, LoadBalancerWriter),
    (PoolReader, PoolWriter),
    (VipReader, VipWriter),
    (DhcpSubnetReader, DhcpSubnetWriter),
    (IpAddrGroupAddrReader, IpAddrGroupAddrWriter),
    (PoolMemberReader, PoolMemberWriter),
    (PortReader, PortWriter),
    (BgpReader, BgpWriter),
    (AdRouteReader, AdRouteWriter),
    (PortGroupPortReader, PortGroupPortWriter),
    (RouteReader, RouteWriter),
    (RuleReader, RuleWriter),
    (LinkReader, LinkWriter),
    (TunnelZoneHostReader, TunnelZoneHostWriter),
    (HostInterfacePortReader, HostInterfacePortWriter)
]


def prepare(neutron_data):
    """Prepares a map of objects from MidoNet API"""
    LOG.info('Preparing MidoNet data')
    data_map = {}
    obj_map = {}
    for clz, _ in _MIDONET_OBJECTS:
        obj = clz(neutron_data, obj_map)
        data_map[obj.key] = obj.get()
    return data_map


def migrate(data, dry_run=False):
    LOG.info('Running MidoNet migration process')
    created_map = {}
    for _, clz in _MIDONET_OBJECTS:
        obj = clz(data, created_map, dry_run=dry_run)
        obj.create()
        obj.print_summary()
