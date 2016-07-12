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

import data_migration
from data_migration import constants as cnst
import json
import mock
from mock import patch
import os
from oslo_utils import importutils
import test_input as ti
import testtools

# To avoid dealing with import statements in these modules that may attempt to
# import what we want to mock too early, import them dynamically after all the
# mocks are setup.
MIDONET_DATA_MODULE = "data_migration.midonet_data"
NEUTRON_DATA_MODULE = "data_migration.neutron_data"
ANTISPOOF_MODULE = "data_migration.antispoof"
ROUTES_MODULE = "data_migration.routes"


def _get_ports(context=None, filters=None):
    if filters:
        f = filters["device_owner"]
        return [p for p in ti.NEUTRON_PORTS if p["device_owner"] in f]
    else:
        return ti.NEUTRON_PORTS


class BaseTestCase(testtools.TestCase):

    def setUp(self):
        self._setup_mock()
        super(BaseTestCase, self).setUp()

    def _setup_mock(self):
        pmc_mock = mock.MagicMock()
        modules = {
            'midonetclient': pmc_mock
        }

        self.module_patcher = patch.dict('sys.modules', modules)
        self.module_patcher.start()

        context_mock = mock.MagicMock()
        data_migration.context = context_mock
        read_context_mock = mock.MagicMock()
        context_mock.get_read_context.return_value = read_context_mock
        self.plugin_mock = mock.MagicMock()
        self.lb_plugin_mock = mock.MagicMock()
        read_context_mock.plugin = self.plugin_mock
        read_context_mock.lb_plugin = self.lb_plugin_mock

        self.plugin_mock.get_networks.return_value = ti.NEUTRON_NETWORKS
        self.plugin_mock.get_subnets.return_value = ti.NEUTRON_SUBNETS
        self.plugin_mock.get_ports = _get_ports
        self.plugin_mock.get_security_groups.return_value = (
            ti.NEUTRON_SECURITY_GROUPS)
        self.plugin_mock.get_routers.return_value = ti.NEUTRON_ROUTERS
        self.plugin_mock.get_floatingips.return_value = ti.NEUTRON_FIPS
        self.lb_plugin_mock.get_pools.return_value = ti.NEUTRON_POOLS
        self.lb_plugin_mock.get_members.return_value = ti.NEUTRON_MEMBERS
        self.lb_plugin_mock.get_vips.return_value = ti.NEUTRON_VIPS
        self.lb_plugin_mock.get_health_monitors.return_value = (
            ti.NEUTRON_HEALTH_MONITORS)

        write_context_mock = mock.MagicMock()
        context_mock.get_write_context.return_value = write_context_mock
        self.mn_api_mock = mock.MagicMock()
        write_context_mock.mn_api = self.mn_api_mock


class TestDataReader(BaseTestCase):

    def setUp(self):
        super(TestDataReader, self).setUp()
        self.n_test_obj = importutils.import_module(NEUTRON_DATA_MODULE)

    def _assert_neutron_objs(self, result, res_key, exp_objs):
        res_objs = result.get(res_key)
        self.assertIsNotNone(res_objs)
        self.assertEqual(len(exp_objs), len(res_objs))

        # For now, just check the IDs
        exp_ids = set([i['id'] for i in exp_objs])
        for res_obj in res_objs.values():
            self.assertIn(res_obj['id'], exp_ids)

    def test_neutron_prepare(self):
        result = self.n_test_obj.prepare()

        # verify result
        self._assert_neutron_objs(result, cnst.NEUTRON_NETWORKS,
                                  ti.NEUTRON_NETWORKS)
        self._assert_neutron_objs(result, cnst.NEUTRON_SUBNETS,
                                  ti.NEUTRON_SUBNETS)
        self._assert_neutron_objs(result, cnst.NEUTRON_PORTS, ti.NEUTRON_PORTS)
        self._assert_neutron_objs(result, cnst.NEUTRON_SECURITY_GROUPS,
                                  ti.NEUTRON_SECURITY_GROUPS)
        self._assert_neutron_objs(result, cnst.NEUTRON_ROUTERS,
                                  ti.NEUTRON_ROUTERS)
        self._assert_neutron_objs(result, cnst.NEUTRON_FLOATINGIPS,
                                  ti.NEUTRON_FIPS)
        self._assert_neutron_objs(result, cnst.NEUTRON_POOLS, ti.NEUTRON_POOLS)
        self._assert_neutron_objs(result, cnst.NEUTRON_MEMBERS,
                                  ti.NEUTRON_MEMBERS)
        self._assert_neutron_objs(result, cnst.NEUTRON_VIPS, ti.NEUTRON_VIPS)
        self._assert_neutron_objs(result, cnst.NEUTRON_HEALTH_MONITORS,
                                  ti.NEUTRON_HEALTH_MONITORS)


class TestAntiSpoof(BaseTestCase):

    def setUp(self):
        super(TestAntiSpoof, self).setUp()
        self.test_module = importutils.import_module(ANTISPOOF_MODULE)

    def test_antispoof_enabled(self):
        f = os.path.join(os.path.dirname(__file__), "antispoof_enabled.json")
        in_data = open(f).read()
        test_obj = self.test_module.AntiSpoof(json.loads(in_data),
                                              dry_run=False)
        test_obj.migrate()
        test_obj.print_summary()

        self.assertEqual(0, len(test_obj.ip_as_rules))
        self.assertEqual(0, len(test_obj.mac_as_rules))
        self.assertEqual(0, len(test_obj.updated))

    def test_antispoof_rules_removed(self):
        f = os.path.join(os.path.dirname(__file__),
                         "antispoof_rules_removed.json")
        in_data = open(f).read()
        test_obj = self.test_module.AntiSpoof(json.loads(in_data),
                                              dry_run=False)
        test_obj.migrate()
        test_obj.print_summary()

        self.assertEqual(1, len(test_obj.ip_as_rules))
        self.assertEqual(1, len(test_obj.mac_as_rules))
        self.assertEqual(1, len(test_obj.updated))


class TestExtraRoutes(BaseTestCase):

    def setUp(self):
        super(TestExtraRoutes, self).setUp()
        self.test_module = importutils.import_module(ROUTES_MODULE)

    def test_extra_routes(self):
        f = os.path.join(os.path.dirname(__file__), "extra_routes.json")

        in_data = open(f).read()
        test_obj = self.test_module.ExtraRoute(json.loads(in_data),
                                               dry_run=False)
        test_obj.migrate()
        test_obj.print_summary()

        self.assertEqual(1, len(test_obj.deleted))
        self.assertEqual(1, len(test_obj.updated))
        self.assertEqual(7, len(test_obj.skipped))


class TestMidonetNeutronMismatch(BaseTestCase):

    def setUp(self):
        super(TestMidonetNeutronMismatch, self).setUp()
        self.test_module = importutils.import_module(MIDONET_DATA_MODULE)

    def test_router_with_no_neutron(self):
        f = os.path.join(os.path.dirname(__file__), "non_existent_chain.json")
        in_data = open(f).read()

        test_obj = self.test_module.RouterWriter(json.loads(in_data),
                                                 {"chains": {}}, {},
                                                 dry_run=False)
        test_obj.create()
        test_obj.print_summary()

        self.assertEqual(0, len(test_obj.created))
        self.assertEqual(1, len(test_obj.skipped))
        self.assertEqual(1, len(test_obj._skipped_mn_res_map))

    def test_bridge_with_no_neutron(self):
        f = os.path.join(os.path.dirname(__file__), "non_existent_chain.json")
        in_data = open(f).read()

        test_obj = self.test_module.BridgeWriter(json.loads(in_data),
                                                 {"chains": {}}, {},
                                                 dry_run=False)
        test_obj.create()
        test_obj.print_summary()

        self.assertEqual(0, len(test_obj.created))
        self.assertEqual(1, len(test_obj.skipped))
        self.assertEqual(1, len(test_obj._skipped_mn_res_map))

    def test_port_parent_skipped(self):
        f = os.path.join(os.path.dirname(__file__), "non_existent_chain.json")
        in_data = open(f).read()

        created_map = {"chains": {}, "bridges": {}, "routers": {}}
        mn_skipped_map = {"bridges": {"49d50278-890b-4eae-9166-89831c8c217f"}}

        test_obj = self.test_module.PortWriter(json.loads(in_data),
                                               created_map,
                                               mn_skipped_map,
                                               dry_run=False)
        test_obj.create()
        test_obj.print_summary()

        self.assertEqual(0, len(test_obj.created))
        self.assertEqual(1, len(test_obj.skipped))
        self.assertEqual(1, len(test_obj._skipped_mn_res_map["ports"]))


class TestDhcpSubnets(BaseTestCase):

    def setUp(self):
        super(TestDhcpSubnets, self).setUp()
        self.test_module = importutils.import_module(MIDONET_DATA_MODULE)

    def test_dhcp_subnets(self):
        bridge_mock = mock.MagicMock()
        bridge_mock.get_dhcp_subnets.return_value = []
        self.mn_api_mock.get_bridge.return_value = bridge_mock

        create_map = {
            "bridges": {
                "49d50278-890b-4eae-9166-89831c8c217f": bridge_mock}}

        f = os.path.join(os.path.dirname(__file__), "dhcp_subnets.json")
        in_data = open(f).read()
        test_obj = self.test_module.DhcpSubnetWriter(json.loads(in_data),
                                                     create_map, {},
                                                     dry_run=False)
        test_obj.create()
        test_obj.print_summary()

        self.assertEqual(2, len(test_obj.created))
        self.assertEqual(0, len(test_obj.skipped))

    def test_duplicate_dhcp_subnet(self):
        bridge_mock = mock.MagicMock()
        dhcp_subnet_mock = mock.MagicMock()
        dhcp_subnet_mock.get_subnet_prefix.return_value = "10.0.0.0"
        bridge_mock.get_dhcp_subnets.return_value = [dhcp_subnet_mock]
        self.mn_api_mock.get_bridge.return_value = bridge_mock

        create_map = {
            "bridges": {
                "49d50278-890b-4eae-9166-89831c8c217f": bridge_mock}}

        f = os.path.join(os.path.dirname(__file__), "dhcp_subnets.json")
        in_data = open(f).read()
        test_obj = self.test_module.DhcpSubnetWriter(json.loads(in_data),
                                                     create_map, {},
                                                     dry_run=False)
        test_obj.create()
        test_obj.print_summary()

        self.assertEqual(0, len(test_obj.created))
        self.assertEqual(1, len(test_obj.skipped))


class TestIpAddrGroupAddrs(BaseTestCase):

    def setUp(self):
        super(TestIpAddrGroupAddrs, self).setUp()
        self.test_module = importutils.import_module(MIDONET_DATA_MODULE)

    def test_ip_addr_group_addrs(self):
        ip_addr_group_mock = mock.MagicMock()
        ip_addr_group_mock.get_addrs.return_value = []
        self.mn_api_mock.get_ip_addr_group.return_value = ip_addr_group_mock

        create_map = {
            "ip_addr_groups": {
                "2114fa0b-536e-49d5-9532-f6f37f1eedca": ip_addr_group_mock}}

        f = os.path.join(os.path.dirname(__file__), "ip_addr_group_addrs.json")
        in_data = open(f).read()
        test_obj = self.test_module.IpAddrGroupAddrWriter(json.loads(in_data),
                                                          create_map, {},
                                                          dry_run=False)
        test_obj.create()
        test_obj.print_summary()

        self.assertEqual(1, len(test_obj.created))
        self.assertEqual(0, len(test_obj.skipped))

    def test_duplicate_ip_addr_group_addr(self):
        ip_addr_group_mock = mock.MagicMock()
        ip_addr_group_addr_mock = mock.MagicMock()
        ip_addr_group_addr_mock.get_addr.return_value = "10.1.2.3"
        ip_addr_group_mock.get_addrs.return_value = [ip_addr_group_addr_mock]
        self.mn_api_mock.get_ip_addr_group.return_value = ip_addr_group_mock

        create_map = {
            "ip_addr_groups": {
                "2114fa0b-536e-49d5-9532-f6f37f1eedca": ip_addr_group_mock}}

        f = os.path.join(os.path.dirname(__file__), "ip_addr_group_addrs.json")
        in_data = open(f).read()
        test_obj = self.test_module.IpAddrGroupAddrWriter(json.loads(in_data),
                                                          create_map, {},
                                                          dry_run=False)
        test_obj.create()
        test_obj.print_summary()

        self.assertEqual(0, len(test_obj.created))
        self.assertEqual(1, len(test_obj.skipped))
