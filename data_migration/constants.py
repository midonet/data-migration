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

RTR_PORT_TYPE = "Router"
BRG_PORT_TYPE = "Bridge"

ROUTER_INTERFACE_PORT_TYPE = "network:router_interface"
ROUTER_GATEWAY_PORT_TYPE = "network:router_gateway"

STATUS_PENDING_DELETE = "PENDING_DELETE"

LB_HM_INTF_SUFFIX = "_hm_dp"
MAX_INTF_LEN = 15
PROVIDER_ROUTER_NAME = 'MidoNet Provider Router'

LEGACY_PLUGIN = "neutron.plugins.midonet.plugin.MidonetPluginV2"
V1_PLUGIN = "midonet.neutron.plugin_v1.MidonetPluginV2"
V2_PLUGIN = "midonet.neutron.plugin_v2.MidonetPluginV2"
L3_PLUGIN = "midonet.neutron.services.l3.l3_midonet.MidonetL3ServicePlugin"

# Neutron data resource names
NEUTRON_SECURITY_GROUPS = "security_groups"
NEUTRON_NETWORKS = "networks"
NEUTRON_SUBNETS = "subnets"
NEUTRON_PORTS = "ports"
NEUTRON_ROUTERS = "routers"
NEUTRON_ROUTER_INTERFACES = "router_interfaces"
NEUTRON_FLOATINGIPS = "floating_ips"
NEUTRON_POOLS = "pools"
NEUTRON_MEMBERS = "members"
NEUTRON_VIPS = "vips"
NEUTRON_HEALTH_MONITORS = "health_monitors"

METADATA_ROUTE_IP = "169.254.169.254"

# MidoNet data keys
MN_AD_ROUTES = "ad_routes"
MN_BGP = "bgp"
MN_BRIDGES = "bridges"
MN_CHAINS = "chains"
MN_DHCP = "dhcp_subnets"
MN_HEALTH_MONITORS = "health_monitors"
MN_HOSTS = "hosts"
MN_HI_PORTS = "host_interface_ports"
MN_IPA_GROUPS = "ip_addr_groups"
MN_IPAG_ADDRS = "ip_addr_group_addrs"
MN_LOAD_BALANCERS = "load_balancers"
MN_POOLS = "pools"
MN_POOL_MEMBERS = "pool_members"
MN_PORT_GROUPS = "port_groups"
MN_PG_PORTS = "port_group_ports"
MN_PORTS = "ports"
MN_PORT_LINKS = "port_links"
MN_ROUTERS = "routers"
MN_ROUTES = "routes"
MN_RULES = "rules"
MN_TUNNEL_ZONES = "tunnel_zones"
MN_TZ_HOSTS = "tunnel_zone_hosts"
MN_VIPS = "vips"

ZOOM_ZK_ROOT = "/midonet/zoom"
