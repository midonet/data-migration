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

import abc
from data_migration import constants as const
from data_migration import context as ctx
from data_migration import data as dm_data
import logging
import six
from webob import exc as wexc

LOG = logging.getLogger(name="data_migration")


def _is_gw_port(port, subnet):
    return ('fixed_ips' in port and len(port['fixed_ips']) > 0 and
            port['fixed_ips'][0]['ip_address'] == subnet['gateway_ip'] and
            port['fixed_ips'][0]['subnet_id'] == subnet['id'])


def _find_gw_port(ports, subnet):
    return next((p for p in ports if _is_gw_port(p, subnet)), None)


def _find_gw_router(ports, subnet):
    gw_port = _find_gw_port(ports, subnet)
    return gw_port['device_id'] if gw_port else None


@six.add_metaclass(abc.ABCMeta)
class NeutronReader(object):

    def __init__(self):
        super(NeutronReader, self).__init__()
        self.context = ctx.get_read_context()

    def get(self):
        obj_map = {}
        LOG.info("Getting " + str(self.key) + " objects")
        for obj in self._get_objects():
            obj_map[obj['id']] = obj

        return {self.key: obj_map}

    @property
    def key(self):
        return None

    def _get_objects(self):
        return []


@six.add_metaclass(abc.ABCMeta)
class NeutronWriter(dm_data.CommonData, dm_data.DataCounterMixin):

    def __init__(self, data, created_map, dry_run=False):
        super(NeutronWriter, self).__init__(data, dry_run=dry_run)
        self.created_map = created_map
        self.created_map[self.key] = []

    def _is_created(self, key, res_id):
        objs = self.created_map.get(key)
        if not objs:
            return False
        res = next((o for o in objs if o['id'] == res_id), None)
        return res is not None

    def try_create_obj(self, f, *args):
        obj = args[-1]
        try:
            if not self.dry_run:
                f(*args)
            self.created.append(obj)
        except wexc.HTTPConflict as e:
            LOG.warn("WARNING: Creation failed with ID conflict: " + str(e))
            self.conflicted.append(obj)

    @property
    def key(self):
        return None

    def _create_obj(self, obj):
        pass

    def create(self):
        obj_map = self._get_neutron_resources(key=self.key)
        for obj in obj_map.values():
            LOG.debug("Creating object " + str(obj))
            self._create_obj(obj)
        self.created_map[self.key].extend(self.created)

    def check_skip_status(self, data, status):
        if data.get('status') == status:
            LOG.debug("Skipping " + str(self.key) + " because it has " +
                      status + " status " + str(data))
            self.add_skip(data['id'], str(self.key) + " status is " + status)
            return True
        return False

    def check_skip_not_created(self, key, data, field):
        # Skip if the obj was not created
        if not self._is_created(key, data[field]):
            LOG.debug("Skipping " + str(self.key) + " because " + key +
                      " was not created " + str(data))
            self.add_skip(data['id'], field + " does not exist")
            return True
        return False


class SecurityGroupBase(object):

    @property
    def key(self):
        return const.NEUTRON_SECURITY_GROUPS


class SecurityGroupReader(SecurityGroupBase, NeutronReader):

    def _get_objects(self):
        return self.context.plugin.get_security_groups(self.context.n_ctx)


class SecurityGroupWriter(SecurityGroupBase, NeutronWriter):

    def _create_obj(self, data):
        self.try_create_obj(
            self.mc.client.create_security_group_postcommit, data)


class NetworkBase(object):

    @property
    def key(self):
        return const.NEUTRON_NETWORKS


class NetworkReader(NetworkBase, NeutronReader):

    def _get_objects(self):
        return self.context.plugin.get_networks(self.context.n_ctx)


class NetworkWriter(NetworkBase, NeutronWriter):

    def _create_obj(self, data):
        self.try_create_obj(self.mc.client.create_network_postcommit, data)


class SubnetBase(object):

    @property
    def key(self):
        return const.NEUTRON_SUBNETS


class SubnetReader(SubnetBase, NeutronReader):

    def _get_objects(self):
        return self.context.plugin.get_subnets(self.context.n_ctx)


class SubnetWriter(SubnetBase, NeutronWriter):

    def _create_obj(self, data):
        self.try_create_obj(self.mc.client.create_subnet_postcommit, data)


class PortBase(object):

    @property
    def key(self):
        return const.NEUTRON_PORTS


class PortReader(PortBase, NeutronReader):

    def _get_objects(self):
        return self.context.plugin.get_ports(self.context.n_ctx)


class PortWriter(PortBase, NeutronWriter):

    def _create_obj(self, data):
        self.try_create_obj(self.mc.client.create_port_postcommit, data)


class RouterBase(object):

    @property
    def key(self):
        return const.NEUTRON_ROUTERS


class RouterReader(RouterBase, NeutronReader):

    def _get_objects(self):
        return self.context.plugin.get_routers(self.context.n_ctx)


class RouterWriter(RouterBase, NeutronWriter):

    def _create_obj(self, data):
        self.try_create_obj(self.mc.client.create_router_postcommit, data)


class RouterInterfaceBase(object):

    @property
    def key(self):
        return const.NEUTRON_ROUTER_INTERFACES


class RouterInterfaceReader(RouterInterfaceBase, NeutronReader):

    def _get_objects(self):
        f = {'device_owner': [const.ROUTER_INTERFACE_PORT_TYPE]}
        ports = self.context.plugin.get_ports(self.context.n_ctx, filters=f)
        ri_ports = []
        for port in ports:
            interface_dict = {'id': port['id'],
                              'router_id': port['device_id'],
                              'port_id': port['id'],
                              'subnet_id': port['fixed_ips'][0]['subnet_id']}
            ri_ports.append(interface_dict)
        return ri_ports


class RouterInterfaceWriter(RouterInterfaceBase, NeutronWriter):

    def _create_obj(self, data):
        # For neutron, the ID of this object is NOT unique. It is actually
        # a special case, where this interface object needs the ID to be
        # set to the router ID
        data['id'] = data['router_id']
        self.try_create_obj(
            self.mc.client.add_router_interface_postcommit,
            data['router_id'], data)


class FloatingIpBase(object):

    @property
    def key(self):
        return const.NEUTRON_FLOATINGIPS


class FloatingIpReader(FloatingIpBase, NeutronReader):

    def _get_objects(self):
        return self.context.plugin.get_floatingips(self.context.n_ctx)


class FloatingIpWriter(FloatingIpBase, NeutronWriter):

    def _create_obj(self, data):
        self.try_create_obj(self.mc.client.create_floatingip_postcommit, data)


class PoolBase(object):

    @property
    def key(self):
        return const.NEUTRON_POOLS


class PoolReader(PoolBase, NeutronReader):

    def _get_objects(self):
        return self.context.lb_plugin.get_pools(self.context.n_ctx)


class PoolWriter(PoolBase, NeutronWriter):

    def __init__(self, data, created_map, dry_run=False):
        super(PoolWriter, self).__init__(data, created_map, dry_run=dry_run)
        ri_ports = self._get_router_interfaces()
        self.subnet_gw_map = {}
        subnets = self._get_neutron_resources(key=const.NEUTRON_SUBNETS)
        for subnet in subnets.values():
            router = _find_gw_router(ri_ports, subnet)
            if router:
                self.subnet_gw_map[subnet['id']] = router

    def _get_router_interfaces(self):
        ports = self._get_neutron_resources(key=const.NEUTRON_PORTS)
        return [p for p in ports.values()
                if p['device_owner'] == const.ROUTER_INTERFACE_PORT_TYPE]

    def _create_obj(self, data):
        # PENDING_DELETE ones can be ignored
        if self.check_skip_status(data, const.STATUS_PENDING_DELETE):
            return

        subnet_id = data['subnet_id']

        # Data corruption may cause subnet to not exist here.  There is no
        # foreign key constraint enforced.
        router_id = self.subnet_gw_map.get(subnet_id)

        # Stale data may not have router ID associated.  Skip such data.
        if not router_id:
            LOG.debug("Skipping pool because of no router association: " +
                      str(data))
            self.add_skip(data['id'], "Pool has no router association")
            return

        pool = data.copy()
        pool['health_monitors'] = []
        pool['health_monitors_status'] = []
        pool['members'] = []
        pool['vip_id'] = None
        pool['router_id'] = router_id

        self.try_create_obj(self.mc.client.create_pool, self.mc.n_ctx, pool)


class MemberBase(object):

    @property
    def key(self):
        return const.NEUTRON_MEMBERS


class MemberReader(MemberBase, NeutronReader):

    def _get_objects(self):
        return self.context.lb_plugin.get_members(self.context.n_ctx)


class MemberWriter(MemberBase, NeutronWriter):

    def _create_obj(self, data):
        # PENDING_DELETE ones can be ignored
        if self.check_skip_status(data, const.STATUS_PENDING_DELETE):
            return

        # Skip if the pool was not created
        if self.check_skip_not_created(const.NEUTRON_POOLS, data, 'pool_id'):
            return

        self.try_create_obj(self.mc.client.create_member, self.mc.n_ctx, data)


class VipBase(object):

    @property
    def key(self):
        return const.NEUTRON_VIPS


class VipReader(VipBase, NeutronReader):

    def _get_objects(self):
        return self.context.lb_plugin.get_vips(self.context.n_ctx)


class VipWriter(VipBase, NeutronWriter):

    def _create_obj(self, data):
        # PENDING_DELETE ones can be ignored
        if self.check_skip_status(data, const.STATUS_PENDING_DELETE):
            return

        # Skip if the pool was not created
        if self.check_skip_not_created(const.NEUTRON_POOLS, data, 'pool_id'):
            return

        self.try_create_obj(self.mc.client.create_vip, self.mc.n_ctx, data)


class HealthMonitorBase(object):

    @property
    def key(self):
        return const.NEUTRON_HEALTH_MONITORS


class HealthMonitorReader(HealthMonitorBase, NeutronReader):

    def _get_objects(self):
        return self.context.lb_plugin.get_health_monitors(self.context.n_ctx)


class HealthMonitorWriter(HealthMonitorBase, NeutronWriter):

    def _create_obj(self, data):
        # PENDING_DELETE ones can be ignored
        if self.check_skip_status(data, const.STATUS_PENDING_DELETE):
            return

        # Skip HM if it has no pool association
        pool_assocs = data.get('pools')
        if pool_assocs is None or len(pool_assocs) == 0:
            LOG.debug("Skipping Health Monitor without pool association " +
                      str(data))
            self.add_skip(data['id'], "Health Monitor has no pool association")
            return

        # Skip if pool was not created
        assoc = pool_assocs[0]
        if self.check_skip_not_created(const.NEUTRON_POOLS, assoc, 'pool_id'):
            return

        self.try_create_obj(self.mc.client.create_health_monitor,
                            self.mc.n_ctx, data)


_NEUTRON_OBJECTS = [
    (SecurityGroupReader, SecurityGroupWriter),
    (NetworkReader, NetworkWriter),
    (SubnetReader, SubnetWriter),
    (PortReader, PortWriter),
    (RouterReader, RouterWriter),
    (RouterInterfaceReader, RouterInterfaceWriter),
    (FloatingIpReader, FloatingIpWriter),
    (PoolReader, PoolWriter),
    (MemberReader, MemberWriter),
    (VipReader, VipWriter),
    (HealthMonitorReader, HealthMonitorWriter)
]


def prepare():
    """Prepares a map of object ID -> object from Neutron DB"""
    LOG.info('Preparing Neutron data')
    obj_map = {}
    for clz, _ in _NEUTRON_OBJECTS:
        obj = clz()
        obj_map.update(obj.get())
    return obj_map


def migrate(data, dry_run=False):
    LOG.info('Running Neutron migration process')
    created_map = {}
    for _, clz in _NEUTRON_OBJECTS:
        obj = clz(data, created_map, dry_run=dry_run)
        obj.create()
        obj.print_summary()
