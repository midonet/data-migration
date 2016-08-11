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
from data_migration import data as dm_data
import logging

LOG = logging.getLogger(name="data_migration")


def _is_ip_anti_spoof_rule(rule):
    return (rule["type"] == "drop" and
            rule["invNwSrc"] and
            rule["nwSrcAddress"] and
            rule["nwSrcLength"] == 32)


def _is_mac_anti_spoof_rule(rule):
    return (rule["type"] == "drop" and
            rule["invDlSrc"] and
            rule["dlSrc"])


class AntiSpoof(dm_data.CommonData, dm_data.DataCounterMixin):

    def __init__(self, data, dry_run=None):
        super(AntiSpoof, self).__init__(data, dry_run=dry_run)
        self.ip_as_rules = []
        self.mac_as_rules = []

    def _is_port_inbound_chain(self, chain_id):
        chains = self._get_midonet_resources("chains")
        chain = next((c for c in chains if c["id"] == chain_id), None)
        return (chain and
                "name" in chain and
                chain["name"].startswith("OS_PORT_") and
                chain["name"].endswith("_INBOUND"))

    def migrate(self):
        rules = self._get_midonet_resources("rules")
        ports = self._get_midonet_resource_list("ports")
        for port in ports:
            if port["type"] != const.BRG_PORT_TYPE:
                continue

            try:
                if not self.mc.plugin.get_port(self.mc.n_ctx, port["id"]):
                    self.add_skip(port["id"], "Port is no longer valid")
                    continue

            except Exception:
                self.add_skip(port["id"], "Port is no longer valid")
                continue

            chain_id = port.get("inboundFilterId")
            if not chain_id:
                continue

            if not self._is_port_inbound_chain(chain_id):
                continue

            # Find MAC antispoof rule
            chain_rules = rules.get(chain_id)
            if not chain_rules:
                self.add_skip(port["id"], "Port's chain has no rules")
                continue

            ip_as_rules = [r for r in chain_rules
                           if _is_ip_anti_spoof_rule(r)]

            if len(ip_as_rules) == 0:
                p = {"port": {
                        "id": port["id"],
                        "allowed_address_pairs":
                        [{"ip_address": "0.0.0.0/0"}]}}
                LOG.debug("Updating Port with allowed address pair: " + str(p))
                self.ip_as_rules.append(port)
                if not self.dry_run:
                    self.mc.plugin.update_port(self.mc.n_ctx, port["id"], p)
                    self.updated.append(p)

            mac_as_rules = [r for r in chain_rules
                            if _is_mac_anti_spoof_rule(r)]
            if len(mac_as_rules) == 0:
                LOG.debug("MAC antispoof rule was not found on this port: " +
                          str(port))
                self.mac_as_rules.append(port)

    def print_summary(self):
        print("\n")
        print("***** Anti-Spoof Migration *****\n")
        print("%d IP antispoof replaced" % len(self.ip_as_rules))
        print("%d MAC antispoof found" % len(self.mac_as_rules))
        print("%d ports updated" % len(self.updated))
        print("%d ports skipped" % len(self.skipped))

        if self.skipped:
            print("The skip reasons:")
            for skip in self.skipped:
                print("Object " + str(skip['object']) + " skipped because " +
                      skip['reason'])
        print("\n")


def migrate(data, dry_run=False):
    LOG.info('Running antispoof migration process')
    ap = AntiSpoof(data, dry_run=dry_run)
    ap.migrate()
    ap.print_summary()
