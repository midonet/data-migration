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
from neutron.common import config as n_config  # noqa
from neutron import context as ncntxt
from neutron.db import l3_db
from neutron_lbaas.db.loadbalancer import loadbalancer_db
from oslo_config import cfg
from oslo_utils import importutils


_migration_read_context = None
_migration_write_context = None


def _import_plugin(clazz_path):
    clazz = importutils.import_class(clazz_path)

    def _setup_rpc(_self):
        pass

    def _notify_router_deleted(_self, _context, _router_id):
        pass

    def _notify_routers_updated(_self, _context, _router_ids, _operation=None,
                                _data=None):
        pass

    def _notify_router_interface_action(_self, _context,
                                        _router_interface_info, _action):
        pass

    # HACK to get around the issue of the plugin setting up rpc
    setattr(clazz, 'setup_rpc', _setup_rpc)
    l3_db.L3RpcNotifierMixin.notify_router_deleted = _notify_router_deleted
    l3_db.L3RpcNotifierMixin.notify_routers_updated = _notify_routers_updated
    l3_db.L3_NAT_db_mixin.notify_router_interface_action = (
        _notify_router_interface_action)

    return clazz()


class MigrationContext(object):

    def __init__(self):
        self.config = cfg.CONF.MIDONET
        self.mn_api = api.MidonetApi(self.config.midonet_uri,
                                     self.config.username,
                                     self.config.password,
                                     project_id=self.config.project_id)
        self.n_ctx = ncntxt.get_admin_context()


class MigrationReadContext(MigrationContext):

    def __init__(self):
        # Only v1 plugin should be loaded.  The path differs between Kilo and
        # the later versions.
        try:
            self.plugin = _import_plugin(cnst.V1_PLUGIN)
        except ImportError:
            self.plugin = _import_plugin(cnst.LEGACY_PLUGIN)

        self.lb_plugin = loadbalancer_db.LoadBalancerPluginDb()
        super(MigrationReadContext, self).__init__()


class MigrationWriteContext(MigrationContext):

    def __init__(self):
        # Only v2 plugin should be loaded
        self.plugin = _import_plugin(cnst.V2_PLUGIN)
        self.l3_plugin = importutils.import_object(cnst.L3_PLUGIN)
        super(MigrationWriteContext, self).__init__()
        self.client = importutils.import_object(self.config.client,
                                                self.config)
        # This is required to bypass the issue when loading service plugins in
        # Liberty onward.
        cfg.CONF.set_override('core_plugin', cnst.V2_PLUGIN)
        self.zk_servers = cfg.CONF.zookeeper.servers


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


zk_opts = [
    cfg.StrOpt('servers', default='127.0.0.1:2181',
               help="Zookeeper servers")
]

cfg.CONF.register_opts(zk_opts, "zookeeper")
