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
import json
import logging

LOG = logging.getLogger(name="data_migration")


def _is_lb_hm_interface(name):
    return (name and len(name) == const.MAX_INTF_LEN and
            name.endswith(const.LB_HM_INTF_SUFFIX))


class MidonetDataMigrator(object):

    def __init__(self):
        self.mc = context.get_context()

    def _get_objects_by_path(self, path):
        return self._get_objects_by_url(self.mc.mn_url + '/' + path + '/')

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

    def _prepare_host_map(self):
        LOG.debug("[(MIDONET) hosts]")
        host_map = {}
        pr = self._get_provider_router()

        hosts = self._get_objects_by_path('hosts')
        for host in hosts if hosts else []:
            LOG.debug("\t[(MIDONET) host " + host['id'] + "]: " + str(host))
            host_map[host['id']] = {}
            h = host_map[host['id']]
            h['host'] = host
            h['ports'] = {}
            port_map = h['ports']

            # Skip ports for health monitors
            ports = self._get_objects_by_path('hosts/' + host['id'] + "/ports")
            for port in [p for p in ports
                         if not _is_lb_hm_interface(p['interfaceName'])]:
                port_obj = self._get_objects_by_url(port['port'])

                # Skip port bindings for external routers (provider router
                # device)
                if port_obj['deviceId'] != pr['id']:
                    LOG.debug("\t\t[(MIDONET) port binding " +
                              port['interfaceName'] + "=" + port[
                                  'portId'] + "]")
                    port_map[port['interfaceName']] = port['portId']
        return host_map

    def _prepare_tz_list(self):
        LOG.debug("[(MIDONET) tunnel zones]")
        tz_list = []
        tzs = self._get_objects_by_path('tunnel_zones')
        for tz in tzs if tzs else []:
            LOG.debug("\t[(MIDONET) tz " + tz['id'] + "]: " + str(tz))
            hosts = self._get_objects_by_path('tunnel_zones/' + tz['id'] +
                                              "/hosts")

            tz_map = {'tz': tz, 'hosts': {}}
            host_map = tz_map['hosts']
            for host in hosts:
                LOG.debug("\t\t[(MIDONET) tz host]: " + str(host))
                host_map[host['hostId']] = host

            tz_list.append(tz_map)
        return tz_list

    def prepare(self):
        data = {
            "hosts": self._prepare_host_map(),
            "tunnel_zones": self._prepare_tz_list()
        }

        # For now just print it out
        print(json.dumps(data))
