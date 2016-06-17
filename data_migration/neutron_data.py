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
from data_migration import provider_router as pr
from data_migration import routes as er
import logging
import six
from webob import exc as wexc

LOG = logging.getLogger(name="data_migration")


def _get_neutron_objects(key, func, context, filters=None, post_f=None):
    retmap = {key: {}}
    submap = retmap[key]

    object_list = func(context=context, filters=filters)
    if post_f:
        object_list = post_f(object_list)

    for obj in object_list:
        submap[obj['id']] = obj

    return retmap


def _print_op(t):
    return 'Op: ' + ', '.join([t['type'], str(t['data'])])


def _create_op_list(obj_map):
    """Creates a list of ops to run given a map of object ID -> object"""
    op_list = []
    for res_type, n_obj in _NEUTRON_OBJS:
        for obj in iter(obj_map[res_type].values()):
            elem = n_obj.make_op_dict(obj_map, obj)
            if elem:
                op_list.append(elem)
    return op_list


def _router_has_gateway(r):
    return ('external_gateway_info' in r and
            'external_fixed_ips' in r['external_gateway_info'])


def _try_create_obj(f, *args):
    try:
        f(*args)
    except wexc.HTTPConflict as e:
        LOG.warn("WARNING: Creation failed with ID conflict: " + str(e))


def _make_op_dict(res_type, obj):
    LOG.debug("_make_op_dict: res_type=" + res_type + ", obj=" + str(obj))
    return {"type": res_type, "data": obj}


@six.add_metaclass(abc.ABCMeta)
class Neutron(object):

    def get(self):
        pass

    def create(self, data):
        pass

    def make_op_dict(self, obj_map, obj):
        return None


class SecurityGroup(Neutron):

    def get(self):
        LOG.info("Getting Security Group objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_SECURITY_GROUPS,
                                    func=c.plugin.get_security_groups,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        c.client.create_security_group_precommit(c.n_ctx, data)
        _try_create_obj(c.client.create_security_group_postcommit, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_SECURITY_GROUPS, obj)


class Network(Neutron):

    def get(self):
        LOG.info("Getting Network objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_NETWORKS,
                                    func=c.plugin.get_networks,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        c.client.create_network_precommit(c.n_ctx, data)
        _try_create_obj(c.client.create_network_postcommit, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_NETWORKS, obj)


class Subnet(Neutron):

    def get(self):
        LOG.info("Getting Subnet objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_SUBNETS,
                                    func=c.plugin.get_subnets,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        c.client.create_subnet_precommit(c.n_ctx, data)
        _try_create_obj(c.client.create_subnet_postcommit, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_SUBNETS, obj)


class Port(Neutron):

    def get(self):
        LOG.info("Getting Pool objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_PORTS,
                                    func=c.plugin.get_ports,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        c.client.create_port_precommit(c.n_ctx, data)
        _try_create_obj(c.client.create_port_postcommit, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_PORTS, obj)


class Router(Neutron):

    def get(self):
        LOG.info("Getting Router objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_ROUTERS,
                                    func=c.plugin.get_routers,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        c.client.create_router_precommit(c.n_ctx, data)
        _try_create_obj(c.client.create_router_postcommit, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_ROUTERS, obj)


class RouterInterface(Neutron):

    def get(self):
        LOG.info("Getting RouterInterface objects")
        c = ctx.get_read_context()
        f = {'device_owner': ['network:router_interface']}
        return _get_neutron_objects(key=const.NEUTRON_ROUTER_INTERFACES,
                                    func=c.plugin.get_ports,
                                    context=c.n_ctx,
                                    filters=f)

    def create(self, data):
        c = ctx.get_write_context()
        c.client.add_router_interface_precommit(c.n_ctx, data['id'], data)
        _try_create_obj(c.client.add_router_interface_postcommit, data['id'],
                        data)

    def make_op_dict(self, obj_map, obj):
        pid = obj['id']
        router_obj = obj_map[const.NEUTRON_ROUTERS][obj['device_id']]
        router_id = router_obj['id']
        subnet_id = obj['fixed_ips'][0]['subnet_id']
        interface_dict = {'id': router_id,
                          'port_id': pid,
                          'subnet_id': subnet_id}
        return _make_op_dict(const.NEUTRON_ROUTER_INTERFACES, interface_dict)


class SubnetGateway(Neutron):

    def _is_gw_port(self, port, subnet):
        return ('fixed_ips' in port and len(port['fixed_ips']) > 0 and
                port['fixed_ips'][0]['ip_address'] == subnet['gateway_ip'] and
                port['fixed_ips'][0]['subnet_id'] == subnet['id'])

    def _find_gw_port(self, ports, subnet):
        return next((p for p in ports if self._is_gw_port(p, subnet)), None)

    def _find_gw_router(self, ports, subnet):
        gw_port = self._find_gw_port(ports, subnet)
        return gw_port['device_id'] if gw_port else None

    def _to_subnet_gateways(self, objs):
        l = []
        c = ctx.get_read_context()
        f = {'device_owner': ['network:router_interface']}
        ports = c.plugin.get_ports(context=c.n_ctx, filters=f)
        for subnet in objs:
            l.append({'id': subnet['id'],
                      'gw_router_id': self._find_gw_router(ports, subnet)})
        return l

    def get(self):
        LOG.info("Getting SubnetGateway objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_SUBNET_GATEWAYS,
                                    func=c.plugin.get_subnets,
                                    context=c.n_ctx,
                                    post_f=self._to_subnet_gateways)


class FloatingIp(Neutron):

    def get(self):
        LOG.info("Getting FloatingIp objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_FLOATINGIPS,
                                    func=c.plugin.get_floatingips,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        c.client.create_floatingip_precommit(c.n_ctx, data)
        _try_create_obj(c.client.create_floatingip_postcommit, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_FLOATINGIPS, obj)


class Pool(Neutron):

    def get(self):
        LOG.info("Getting Pool objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_POOLS,
                                    func=c.lb_plugin.get_pools,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        _try_create_obj(c.client.create_pool, c.n_ctx, data)

    def make_op_dict(self, obj_map, obj):
        LOG.debug("Pool.make_op_dict: obj=" + str(obj))
        lb_subnet = obj['subnet_id']
        router_id = obj_map[
            const.NEUTRON_SUBNET_GATEWAYS][lb_subnet]['gw_router_id']
        if not router_id:
            raise ValueError("LB Pool's subnet has no associated gateway "
                             "router: " + str(obj))

        new_lb_obj = obj.copy()
        new_lb_obj['health_monitors'] = []
        new_lb_obj['health_monitors_status'] = []
        new_lb_obj['members'] = []
        new_lb_obj['vip_id'] = None
        new_lb_obj['router_id'] = router_id
        return _make_op_dict(const.NEUTRON_POOLS, new_lb_obj)


class Member(Neutron):

    def get(self):
        LOG.info("Getting Member objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_MEMBERS,
                                    func=c.lb_plugin.get_members,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        _try_create_obj(c.client.create_member, c.n_ctx, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_MEMBERS, obj)


class Vip(Neutron):

    def get(self):
        LOG.info("Getting Vip objects")
        c = ctx.get_read_context()
        return _get_neutron_objects(key=const.NEUTRON_VIPS,
                                    func=c.lb_plugin.get_vips,
                                    context=c.n_ctx)

    def create(self, data):
        c = ctx.get_write_context()
        _try_create_obj(c.client.create_vip, c.n_ctx, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_VIPS, obj)


class HealthMonitor(Neutron):

    def get(self):
        LOG.info("Getting HealthMonitor objects")
        c = ctx.get_read_context()

        def _filter_non_associated_hm(objs):
            return [o for o in objs if 'pools' in o and len(o['pools']) > 0]

        return _get_neutron_objects(key=const.NEUTRON_HEALTH_MONITORS,
                                    func=c.lb_plugin.get_health_monitors,
                                    context=c.n_ctx,
                                    post_f=_filter_non_associated_hm)

    def create(self, data):
        c = ctx.get_write_context()
        _try_create_obj(c.client.create_health_monitor, c.n_ctx, data)

    def make_op_dict(self, obj_map, obj):
        return _make_op_dict(const.NEUTRON_HEALTH_MONITORS, obj)


_NEUTRON_OBJS = [
    (const.NEUTRON_SECURITY_GROUPS, SecurityGroup()),
    (const.NEUTRON_NETWORKS, Network()),
    (const.NEUTRON_SUBNETS, Subnet()),
    (const.NEUTRON_PORTS, Port()),
    (const.NEUTRON_ROUTERS, Router()),
    (const.NEUTRON_ROUTER_INTERFACES, RouterInterface()),
    (const.NEUTRON_SUBNET_GATEWAYS, SubnetGateway()),
    (const.NEUTRON_FLOATINGIPS, FloatingIp()),
    (const.NEUTRON_POOLS, Pool()),
    (const.NEUTRON_MEMBERS, Member()),
    (const.NEUTRON_VIPS, Vip()),
    (const.NEUTRON_HEALTH_MONITORS, HealthMonitor())
]

_NEUTRON_OBJ_MAP = {key: value for (key, value) in _NEUTRON_OBJS}


def prepare():
    """Prepares a map of object ID -> object from Neutron DB

    It also includes 'ops' key that includes a list of ops entries that
    will be created in migration.
    """
    LOG.info('Preparing Neutron data')
    obj_map = {}
    for res_type, obj in _NEUTRON_OBJS:
        obj_map.update(obj.get())
    obj_map["ops"] = _create_op_list(obj_map)
    return obj_map


class DataWriter(dm_data.CommonData, pr.ProviderRouterMixin,
                 er.ExtraRoutesMixin):

    def __init__(self, data, dry_run=False):
        self.dry_run = dry_run
        super(DataWriter, self).__init__(data)

    def migrate(self):
        LOG.info('Running Neutron migration process')
        ops = self._get_neutron_resources('ops')
        for op in ops:
            LOG.debug(_print_op(op))
            obj = _NEUTRON_OBJ_MAP[op['type']]
            if not self.dry_run:
                obj.create(op['data'])

    def _create_neutron_data(self, f, *args):
        if self.dry_run:
            return {}
        else:
            mc = ctx.get_write_context()
            return f(mc.n_ctx, *args)
