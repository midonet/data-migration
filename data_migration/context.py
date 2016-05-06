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

from data_migration import constants as cnst
from midonetclient import api
from neutron.common import rpc
from neutron import context as ncntxt
from neutron_lbaas.db.loadbalancer import loadbalancer_db
from oslo_config import cfg
from oslo_utils import importutils


_migration_read_context = None
_migration_write_context = None


class MigrationContext(object):

    def __init__(self):
        self.mn_api = None
        self.n_ctx = None

        # Required to bypass an error when instantiating Midonet plugin.
        rpc.init(cfg.CONF)

    def init_common(self):
        # This cannot be in __init__ since the plugin must be loaded first
        # before accessing MIDONET config section.
        config = cfg.CONF.MIDONET
        self.mn_api = api.MidonetApi(config.midonet_uri,
                                     config.username,
                                     config.password,
                                     project_id=config.project_id)
        self.n_ctx = ncntxt.get_admin_context()


class MigrationReadContext(MigrationContext):

    def __init__(self):
        super(MigrationReadContext, self).__init__()

        # Only v1 plugin should be loaded.  The path differs between Kilo and
        # the later versions.
        try:
            self.plugin = importutils.import_object(cnst.V1_PLUGIN)
        except ImportError:
            self.plugin = importutils.import_object(cnst.LEGACY_PLUGIN)

        self.lb_plugin = loadbalancer_db.LoadBalancerPluginDb()
        self.init_common()


class MigrationWriteContext(MigrationContext):

    def __init__(self):
        super(MigrationWriteContext, self).__init__()

        # Only v2 plugin should be loaded
        self.plugin = importutils.import_object(cnst.V2_PLUGIN)
        self.init_common()


def get_read_context():
    global _migration_read_context
    if _migration_read_context is None:
        _migration_read_context = MigrationReadContext()
    return _migration_read_context


def get_write_context():
    global _migration_write_context
    if _migration_write_context is None:
        _migration_write_context = MigrationWriteContext()
    return _migration_write_context
