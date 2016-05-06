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

EXT_RTR_PORT_TYPE = "ExteriorRouter"
LB_HM_INTF_SUFFIX = "_hm_dp"
MAX_INTF_LEN = 15
PROVIDER_ROUTER_NAME = 'MidoNet Provider Router'

LEGACY_PLUGIN = "neutron.plugins.midonet.plugin.MidonetPluginV2"
V1_PLUGIN = "midonet.neutron.plugin_v1.MidonetPluginV2"
V2_PLUGIN = "midonet.neutron.plugin_v2.MidonetPluginV2"

# Neutron data resource names
NEUTRON_SECURITY_GROUPS = "security-groups"
NEUTRON_NETWORKS = "networks"
NEUTRON_SUBNETS = "subnets"
NEUTRON_PORTS = "ports"
NEUTRON_ROUTERS = "routers"
NEUTRON_ROUTER_INTERFACES = "router-interfaces"
NEUTRON_SUBNET_GATEWAYS = "subnet-gateways"
NEUTRON_FLOATINGIPS = "floating-ips"
NEUTRON_POOLS = "load-balancer-pools"
NEUTRON_MEMBERS = "members"
NEUTRON_VIPS = "vips"
NEUTRON_HEALTH_MONITORS = "health-monitors"
