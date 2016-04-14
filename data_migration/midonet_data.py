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
        pr = self._get_provider_router()
        for h in hosts:
            hid = h['id']
            bindings_map[hid] = {
                "name": h['name'],
                "tunnel_zones": host2tz_map[hid],
                "ports": self._get_host_ports(hid, pr['id'])
            }

        return bindings_map

    def prepare(self):
        tzs = self._get_objects_by_path('tunnel_zones') or []
        hosts = self._get_objects_by_path('hosts') or []
        host2tz_map = self._convert_to_host2tz_map(tzs)
        return {
            "tunnel_zones": tzs,
            "host_bindings": self._prepare_host_bindings(hosts, host2tz_map)
        }

    def bind_hosts(self, bindings, dry_run=False):
        """Execute the migration

        Input format (see '_prepare_host_bindings'):

            {"host_id": {"name": <hostname>,
                         "ports": [{"id": <port_id>,
                                   "interface": <interface>}, ...],
                         "tunnel_zones": [{"id": <tunnel_zone_id>,
                                           "ip_address": <ip_address>}, ...]
                         },
            }

        This is expected to be executed AFTER the hosts are upgraded.
        Otherwise, MidoNet will reject hosts that are unknown.
        """
        for hid, h in iter(bindings.items()):
            tzs = h["tunnel_zones"]
            for tz in tzs:
                if dry_run:
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
                if dry_run:
                    print("api.add_host_interface_port(host, "
                          "port_id=" + p["id"] +
                          ", interface_name=" + p["interface"] + ")")
                else:
                    self.mc.mn_api.add_host_interface_port(
                        host, port_id=p["id"], interface_name=p["interface"])
