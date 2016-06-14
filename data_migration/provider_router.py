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


class ProviderRouterMixin(object):

    def __init__(self):
        self._pr_port_map = {}

    @property
    def provider_router_ports(self):
        if not self._pr_port_map:
            routers = self._get_midonet_resources('routers')
            port_map = self._get_midonet_resources('ports')
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
