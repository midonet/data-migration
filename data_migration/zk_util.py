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

from data_migration import constants as cnt
from data_migration import context as ctx
import logging
import zookeeper

LOG = logging.getLogger(name="data_migration")


def _recursive_delete(handle, root, dry_run=False):
    children = zookeeper.get_children(handle, root)
    for child in children:
        path = root + "/" + child
        _recursive_delete(handle, path, dry_run=dry_run)
    LOG.debug("Deleting node " + root)
    if not dry_run:
        zookeeper.delete(handle, root)


def delete(dry_run=False):
    wc = ctx.get_write_context()
    LOG.info("Deleting recursively " + str(cnt.ZOOM_ZK_ROOTS) +
             " from server(s) " + wc.zk_servers)

    handle = zookeeper.init(wc.zk_servers)
    for root in cnt.ZOOM_ZK_ROOTS:
        if zookeeper.exists(handle, root):
            _recursive_delete(handle, root, dry_run=dry_run)
