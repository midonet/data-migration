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

from midonetclient import api
from neutron.common import rpc
from neutron import context as ncntxt
from neutron_lbaas.db.loadbalancer import loadbalancer_db
from oslo_config import cfg
from oslo_utils import importutils


_migration_context = None


class MigrationContext(object):

    def __init__(self):

        # Required to bypass an error when instantiating Midonet plugin.
        rpc.init(cfg.CONF)

        neutron_config = cfg.CONF

        # Load the plugin dynamically
        self.client = importutils.import_object(neutron_config.core_plugin)
        mn_config = neutron_config.MIDONET
        self.mn_url = mn_config.midonet_uri
        self.mn_api = api.MidonetApi(mn_config.midonet_uri,
                                     mn_config.username,
                                     mn_config.password,
                                     project_id=mn_config.project_id)

        self.ctx = ncntxt.get_admin_context()
        self.lb_client = loadbalancer_db.LoadBalancerPluginDb()


def get_context():
    global _migration_context
    if _migration_context is None:
        _migration_context = MigrationContext()
    return _migration_context
