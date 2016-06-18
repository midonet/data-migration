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
import mock
from oslo_utils import importutils
import test_input as ti
import testtools


NEUTRON_DATA_MODULE = "data_migration.neutron_data"


def _get_ports(context=None, filters=None):
    if filters:
        f = filters["device_owner"]
        return [p for p in ti.NEUTRON_PORTS if p["device_owner"] in f]
    else:
        return ti.NEUTRON_PORTS


class TestDataReader(testtools.TestCase):

    def setUp(self):
        self._setup_mock()

        # To avoid dealing with import statements in the neutron data module
        # that may attempt to import what we want to mock too early, import it
        # dynamically after all the mocks are setup.
        self.n_test_obj = importutils.import_module(NEUTRON_DATA_MODULE)
        super(TestDataReader, self).setUp()

    def _setup_mock(self):
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
