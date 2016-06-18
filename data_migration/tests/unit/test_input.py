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

HOST_ID = "host-0"
TENANT_ID = "35e1a5f7b3a243499c27293b282d6274"
DEFAULT_SG_ID = "062fe832-5b74-413f-b7cb-7084009392c4"

EXT_NET_ID = "5a6ce10b-7fb9-4e3a-8a8c-e6d5e2026c0d"
NET_ID = "05a9dc8c-76f7-43de-9b03-d48ddf37f24e"

EXT_SUBNET_ID = "e4651204-b4f4-4ca8-8679-843b6c4dd356"
SUBNET_ID = "c9743828-c635-473e-a2bb-56f45432ef8f"

DHCP_PORT_ID = "489a0a65-782c-4838-8d07-3642563fff87"
FIP_PORT_ID = "8a1fab3c-40bb-4742-9fce-e92b06a1a1da"
GW_PORT_ID = "4572512d-01af-4609-8ed5-b75f94c60b5e"
RTR_INTF_PORT_ID = "89006b7b-cf42-4475-9ecb-848841a4c2a0"
VIF_PORT_ID = "017cd4ca-d47d-4d30-acee-7cbc9ab32cf6"
VIP_PORT_ID = "e687367c-5db1-4d00-800d-163fcd591199"

FIP_ID = "8856064f-8fd2-47f1-9ad2-d43acc38f006"
UNASSOC_FIP_ID = "2b0acf41-b828-4416-b057-0d7403292f98"
ROUTER_ID = "465bd386-debf-4a34-ba45-0b1836b6d5fd"

POOL_ID = "7c148bc2-5072-492c-baf2-45f426efee71"
BAD_SUBNET_POOL_ID = "1947d168-5268-4895-8bac-71d022bd939b"

MEMBER_ID = "03042fed-9456-4710-8119-7b6c7994e788"
VIP_ID = "fb3b7ca7-a345-40b7-a0df-beb255576890"

# Add Neutron FIPs returned from get_floatingips
NEUTRON_FIPS = [
    {
        "id": FIP_ID,
        "fixed_ip_address": "10.0.0.3",
        "floating_ip_address": "200.0.0.3",
        "floating_network_id": EXT_NET_ID,
        "port_id": VIF_PORT_ID,
        "router_id": ROUTER_ID,
        "status": "ACTIVE",
        "tenant_id": TENANT_ID
    },
    {
        "id": UNASSOC_FIP_ID,
        "fixed_ip_address": None,
        "floating_ip_address": "200.0.0.4",
        "floating_network_id": EXT_NET_ID,
        "port_id": None,
        "router_id": None,
        "status": "ACTIVE",
        "tenant_id": TENANT_ID
    }
]

# Add Neutron Health Monitors returned from get_health_monitors
# TODO(RYU): Add entries
NEUTRON_HEALTH_MONITORS = []

# Add Neutron members returned from get_members
NEUTRON_MEMBERS = [
    {
        "id": MEMBER_ID,
        "pool_id": POOL_ID,
        "address": "10.0.0.3",
        "admin_state_up": True,
        "protocol_port": 80,
        "status": "ACTIVE",
        "status_description": None,
        "tenant_id": TENANT_ID,
        "weight": 1
    }
]

# Add Neutron networks returned from get_networks
NEUTRON_NETWORKS = [
    {
        "id": NET_ID,
        "admin_state_up": True,
        "mtu": 0,
        "name": "net-0",
        "router:external": False,
        "shared": False,
        "status": "ACTIVE",
        "subnets": [
            SUBNET_ID
        ],
        "tenant_id": TENANT_ID,
        "vlan_transparent": None
    },
    {
        "id": EXT_NET_ID,
        "admin_state_up": True,
        "mtu": None,
        "name": "external",
        "router:external": True,
        "shared": True,
        "status": "ACTIVE",
        "subnets": [
            EXT_SUBNET_ID
        ],
        "tenant_id": TENANT_ID,
        "vlan_transparent": None
    }
]

# Add Neutron pools returned from get_pools
NEUTRON_POOLS = [
    {
        "id": POOL_ID,
        "subnet_id": SUBNET_ID,
        "admin_state_up": True,
        "description": "",
        "health_monitors": [],
        "health_monitors_status": [],
        "lb_method": "ROUND_ROBIN",
        "members": [

            MEMBER_ID
        ],
        "name": "pool0",
        "protocol": "TCP",
        "provider": "midonet",
        "status": "ACTIVE",
        "status_description": None,
        "tenant_id": TENANT_ID,
        "vip_id": VIP_ID
    },
    {
        # Bad pool with invalid subnet ID
        "id": BAD_SUBNET_POOL_ID,
        "subnet_id": "ecda8ec3-5abb-4ab5-97bb-62c1ea5a00f9",
        "admin_state_up": True,
        "description": "",
        "health_monitors": [],
        "health_monitors_status": [],
        "lb_method": "ROUND_ROBIN",
        "members": [],
        "name": "bad-subnet-pool",
        "protocol": "HTTP",
        "provider": "midonet",
        "status": "ACTIVE",
        "status_description": None,
        "tenant_id": TENANT_ID,
        "vip_id": None
    }
]


# Add Neutron ports returned from get_ports
NEUTRON_PORTS = [
    {
        "id": RTR_INTF_PORT_ID,
        "network_id": NET_ID,
        "binding:host_id": None,
        "binding:vif_details": {
            "port_filter": True
        },
        "binding:vif_type": "midonet",
        "binding:vnic_type": "normal",
        "device_id": ROUTER_ID,
        "device_owner": "network:router_interface",
        "extra_dhcp_opts": [],
        "fixed_ips": [
            {
                "ip_address": "10.0.0.1",
                "subnet_id": SUBNET_ID
            }
        ],
        "mac_address": "fa:16:3e:fd:d5:eb",
        "name": "",
        "security_groups": [],
        "status": "ACTIVE",
        "tenant_id": TENANT_ID
    },
    {
        "id": DHCP_PORT_ID,
        "network_id": NET_ID,
        "admin_state_up": True,
        "binding:host_id": HOST_ID,
        "binding:vif_details": {
            "port_filter": True
        },
        "binding:vif_type": "midonet",
        "binding:vnic_type": "normal",
        "device_id": "dhcp7fe5d5f7-2727-511e-8e9d-5be8d91a9845-" + NET_ID,
        "device_owner": "network:dhcp",
        "extra_dhcp_opts": [],
        "fixed_ips": [
            {
                "ip_address": "10.0.0.2",
                "subnet_id": SUBNET_ID
            }
        ],
        "mac_address": "fa:16:3e:21:3a:48",
        "name": "dhcp-port-0",
        "security_groups": [],
        "status": "ACTIVE",
        "tenant_id": TENANT_ID
    },
    {
        "id": VIF_PORT_ID,
        "network_id": NET_ID,
        "admin_state_up": True,
        "binding:host_id": HOST_ID,
        "binding:vif_details": {
            "port_filter": True
        },
        "binding:vif_type": "midonet",
        "binding:vnic_type": "normal",
        "device_id": "27a0fa5e-562a-400d-b457-346ada73481f",
        "device_owner": "compute:nova",
        "extra_dhcp_opts": [],
        "fixed_ips": [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": SUBNET_ID
            }
        ],
        "mac_address": "fa:16:3e:f5:e0:2e",
        "name": "vif-port-0",
        "security_groups": [
            DEFAULT_SG_ID
        ],
        "status": "ACTIVE",
        "tenant_id": TENANT_ID
    },
    {
        "id": GW_PORT_ID,
        "network_id": EXT_NET_ID,
        "admin_state_up": True,
        "binding:host_id": None,
        "binding:vif_details": {
            "port_filter": True
        },
        "binding:vif_type": "midonet",
        "binding:vnic_type": "normal",
        "device_id": ROUTER_ID,
        "device_owner": "network:router_gateway",
        "extra_dhcp_opts": [],
        "fixed_ips": [
            {
                "ip_address": "200.0.0.2",
                "subnet_id": EXT_SUBNET_ID
            }
        ],
        "mac_address": "fa:16:3e:b0:62:bf",
        "name": "",
        "security_groups": [],
        "status": "ACTIVE",
        "tenant_id": ""
    },
    {
        "id": FIP_PORT_ID,
        "network_id": EXT_NET_ID,
        "admin_state_up": True,
        "binding:host_id": None,
        "binding:vif_details": {
            "port_filter": True
        },
        "binding:vif_type": "midonet",
        "binding:vnic_type": "normal",
        "device_id": FIP_ID,
        "device_owner": "network:floatingip",
        "extra_dhcp_opts": [],
        "fixed_ips": [
            {
                "ip_address": "200.0.0.3",
                "subnet_id": EXT_SUBNET_ID
            }
        ],
        "mac_address": "fa:16:3e:b2:bf:2a",
        "name": "",
        "security_groups": [],
        "status": "N/A",
        "tenant_id": ""
    },
    {
        "id": VIP_PORT_ID,
        "admin_state_up": True,
        "binding:host_id": None,
        "binding:vif_details": {
            "port_filter": True
        },
        "binding:vif_type": "midonet",
        "binding:vnic_type": "normal",
        "device_id": "",
        "device_owner": "",
        "dns_name": None,
        "extra_dhcp_opts": [],
        "fixed_ips": [
            {
                "ip_address": "200.0.0.5",
                "subnet_id": EXT_SUBNET_ID
            }
        ],
        "mac_address": "fa:16:3e:6d:42:4d",
        "name": "vip-port0",
        "network_id": EXT_NET_ID,
        "security_groups": [],
        "status": "ACTIVE",
        "tenant_id": TENANT_ID
    }
]

# Add Neutron routers returned from get_routers
NEUTRON_ROUTERS = [
    {
        "id": ROUTER_ID,
        "admin_state_up": True,
        "external_gateway_info": {
            "enable_snat": True,
            "external_fixed_ips": [
                {
                    "ip_address": "200.0.0.2",
                    "subnet_id": EXT_SUBNET_ID
                }
            ],
            "network_id": EXT_NET_ID
        },
        "gw_port_id": GW_PORT_ID,
        "name": "router-0",
        "status": "ACTIVE",
        "tenant_id": TENANT_ID
    }
]

# Add Neutron SGs returned from get_security_groups
NEUTRON_SECURITY_GROUPS = [
    {
        "id": DEFAULT_SG_ID,
        "description": "Default Security Group",
        "name": "default",
        "tenant_id": TENANT_ID,
        "security_group_rules": [
            {
                "id": "7d5feb50-06d3-428f-8530-047f5e6e10e4",
                "security_group_id": DEFAULT_SG_ID,
                "direction": "ingress",
                "ethertype": "IPv6",
                "port_range_max": None,
                "port_range_min": None,
                "protocol": None,
                "remote_group_id": DEFAULT_SG_ID,
                "remote_ip_prefix": None,
                "tenant_id": TENANT_ID
            },
            {
                "id": "ccf1a219-0c1c-45bd-a750-eafa2439fa38",
                "security_group_id": DEFAULT_SG_ID,
                "direction": "egress",
                "ethertype": "IPv6",
                "port_range_max": None,
                "port_range_min": None,
                "protocol": None,
                "remote_group_id": None,
                "remote_ip_prefix": None,
                "tenant_id": TENANT_ID
            },
            {
                "id": "d5947a12-38dc-49b0-be94-e4bdb9939749",
                "security_group_id": DEFAULT_SG_ID,
                "direction": "ingress",
                "ethertype": "IPv4",
                "port_range_max": None,
                "port_range_min": None,
                "protocol": None,
                "remote_group_id": DEFAULT_SG_ID,
                "remote_ip_prefix": None,
                "tenant_id": TENANT_ID
            },
            {
                "id": "e0797e2b-48f8-4b40-b42d-757d61834349",
                "security_group_id": DEFAULT_SG_ID,
                "direction": "egress",
                "ethertype": "IPv4",
                "port_range_max": None,
                "port_range_min": None,
                "protocol": None,
                "remote_group_id": None,
                "remote_ip_prefix": None,
                "tenant_id": TENANT_ID
            },
            {
                "id": "0498d61d-0d34-4bf6-9745-6e8599c6c2b6",
                "security_group_id": DEFAULT_SG_ID,
                "direction": "ingress",
                "ethertype": "IPv4",
                "port_range_max": 22,
                "port_range_min": 22,
                "protocol": "tcp",
                "remote_group_id": None,
                "remote_ip_prefix": "0.0.0.0/0",
                "tenant_id": TENANT_ID
            }
        ]
    }
]

# Add Neutron subnets returned from get_subnets
NEUTRON_SUBNETS = [
    {
        "id": SUBNET_ID,
        "network_id": NET_ID,
        "allocation_pools": [
            {
                "end": "10.0.0.254",
                "start": "10.0.0.2"
            }
        ],
        "cidr": "10.0.0.0/24",
        "dns_nameservers": [
            "8.8.4.4",
            "8.8.8.8"
        ],
        "enable_dhcp": True,
        "gateway_ip": "10.0.0.1",
        "host_routes": [
            {
                "destination": "6.6.6.0/24",
                "nexthop": "11.12.13.2"
            }
        ],
        "ip_version": 4,
        "ipv6_address_mode": None,
        "ipv6_ra_mode": None,
        "name": "subnet-0",
        "shared": False,
        "subnetpool_id": None,
        "tenant_id": TENANT_ID
    },
    {
        "id": EXT_SUBNET_ID,
        "network_id": EXT_NET_ID,
        "allocation_pools": [
            {
                "end": "200.0.0.254",
                "start": "200.0.0.2"
            }
        ],
        "cidr": "200.0.0.0/24",
        "dns_nameservers": [],
        "enable_dhcp": False,
        "gateway_ip": "200.0.0.1",
        "host_routes": [],
        "ip_version": 4,
        "ipv6_address_mode": None,
        "ipv6_ra_mode": None,
        "name": "ext-subnet-0",
        "shared": True,
        "subnetpool_id": None,
        "tenant_id": TENANT_ID
    }
]

# Add Neutron VIPs returned from get_vips
NEUTRON_VIPS = [
    {
        "id": VIP_ID,
        "pool_id": POOL_ID,
        "address": "200.0.0.5",
        "admin_state_up": True,
        "connection_limit": -1,
        "description": "",
        "name": "vip0",
        "port_id": VIP_PORT_ID,
        "protocol": "HTTP",
        "protocol_port": 80,
        "session_persistence": None,
        "status": "ACTIVE",
        "status_description": None,
        "subnet_id": EXT_SUBNET_ID,
        "tenant_id": TENANT_ID
    }

]
