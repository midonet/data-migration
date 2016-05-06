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
from data_migration import exceptions as exc
from data_migration import utils
import logging
import six

LOG = logging.getLogger(name="data_migration")


def _get_neutron_objects(key, func, context, filter_list=None):
    if filter_list is None:
        filter_list = []

    retmap = {key: {}}
    submap = retmap[key]

    filters = {}
    for f in filter_list:
        new_filter = f.func_filter()
        if new_filter:
            filters.update({new_filter[0]: new_filter[1]})

    object_list = func(context=context, filters=filters if filters else None)

    for f in filter_list:
        f.post_filter(object_list)

    for obj in object_list:
        if 'id' not in obj:
            raise exc.UpgradeScriptException(
                'Trying to parse an object with no ID field: ' + str(obj))
        submap[obj['id']] = obj

    return retmap


def _create_op_dict(_topo, res_type, obj):
    LOG.debug("Op: " + res_type + " -> " + str(obj))
    return {"type": res_type, "data": obj}


def _create_lb_op_dict(topo, res_type, lb_obj):
    lb_subnet = lb_obj['subnet_id']
    router_id = topo[const.NEUTRON_SUBNET_GATEWAYS][lb_subnet]['gw_router_id']
    if not router_id:
        raise exc.UpgradeScriptException(
            "LB Pool's subnet has no associated gateway router: " + lb_obj)

    new_lb_obj = lb_obj.copy()
    new_lb_obj['health_monitors'] = []
    new_lb_obj['health_monitors_status'] = []
    new_lb_obj['members'] = []
    new_lb_obj['vip_id'] = None
    new_lb_obj['router_id'] = router_id
    return _create_op_dict(topo, res_type, new_lb_obj)


def _create_router_interface_op_dict(topo, res_type, port):
    pid = port['id']
    router_obj = topo[const.NEUTRON_ROUTERS][port['device_id']]
    router_id = router_obj['id']
    if 'fixed_ips' not in port:
        raise exc.UpgradeScriptException(
            'Router interface port has no fixed IPs:' + str(port))
    subnet_id = port['fixed_ips'][0]['subnet_id']
    interface_dict = {'id': router_id,
                      'port_id': pid,
                      'subnet_id': subnet_id}
    return _create_op_dict(topo, res_type, interface_dict)


def _print_op(t):
    return 'Op: ' + ', '.join([t['type'], str(t['data'])])


def _create_op_list(obj_map):
    """Creates a list of ops to run given a map of object ID -> object"""
    op_list = []
    for res_type, func in _OPS:
        for oid, obj in iter(obj_map[res_type].items()):
            elem = func(obj_map, res_type, obj)
            if elem:
                op_list.append(elem)
    return op_list


def _router_has_gateway(r):
    return ('external_gateway_info' in r and
            'external_fixed_ips' in r['external_gateway_info'])


def _get_external_subnet_ids(nets):
    subnet_ids = []
    networks = [net for net in iter(nets.values())
                if net['router:external']]
    for net in networks:
        for sub in net['subnets']:
            subnet_ids.append(sub)

    return subnet_ids


_OPS = [
    (const.NEUTRON_SECURITY_GROUPS, _create_op_dict),
    (const.NEUTRON_NETWORKS, _create_op_dict),
    (const.NEUTRON_SUBNETS, _create_op_dict),
    (const.NEUTRON_PORTS, _create_op_dict),
    (const.NEUTRON_ROUTERS, _create_op_dict),
    (const.NEUTRON_ROUTER_INTERFACES, _create_router_interface_op_dict),
    (const.NEUTRON_FLOATINGIPS, _create_op_dict),
    (const.NEUTRON_POOLS, _create_lb_op_dict),
    (const.NEUTRON_MEMBERS, _create_op_dict),
    (const.NEUTRON_VIPS, _create_op_dict),
    (const.NEUTRON_HEALTH_MONITORS, _create_op_dict)
]


@six.add_metaclass(abc.ABCMeta)
class Neutron(object):

    def __init__(self, client):
        self.client = client

    def create(self, n_ctx, data):
        pass


class SecurityGroup(Neutron):

    def create(self, n_ctx, data):
        self.client.create_security_group_precommit(n_ctx, data)
        self.client.create_security_group_postcommit(data)


class Network(Neutron):

    def create(self, n_ctx, data):
        self.client.create_network_precommit(n_ctx, data)
        self.client.create_network_postcommit(data)


class Subnet(Neutron):

    def create(self, n_ctx, data):
        self.client.create_subnet_precommit(n_ctx, data)
        self.client.create_subnet_postcommit(data)


class Port(Neutron):

    def create(self, n_ctx, data):
        self.client.create_port_precommit(n_ctx, data)
        self.client.create_port_postcommit(data)


class Router(Neutron):

    def create(self, n_ctx, data):
        self.client.create_router_precommit(n_ctx, data)
        self.client.create_router_postcommit(data)


class RouterInterface(Neutron):

    def create(self, n_ctx, data):
        self.client.add_router_interface_precommit(n_ctx, data['id'], data)
        self.client.add_router_interface_postcommit(data['id'], data)


class FloatingIp(Neutron):

    def create(self, n_ctx, data):
        self.client.create_floatingip_precommit(n_ctx, data)
        self.client.create_floatingip_postcommit(data)


class Pool(Neutron):

    def create(self, n_ctx, data):
        self.client.create_pool(n_ctx, data)


class Member(Neutron):

    def create(self, n_ctx, data):
        self.client.create_member(n_ctx, data)


class Vip(Neutron):

    def create(self, n_ctx, data):
        self.client.create_vip(n_ctx, data)


class HealthMonitor(Neutron):

    def create(self, n_ctx, data):
        self.client.create_health_monitor(n_ctx, data)


def _get_neutron_obj(key, *args, **kwargs):
    return {
        const.NEUTRON_SECURITY_GROUPS: SecurityGroup,
        const.NEUTRON_NETWORKS: Network,
        const.NEUTRON_SUBNETS: Subnet,
        const.NEUTRON_PORTS: Port,
        const.NEUTRON_ROUTERS: Router,
        const.NEUTRON_ROUTER_INTERFACES: RouterInterface,
        const.NEUTRON_FLOATINGIPS: FloatingIp,
        const.NEUTRON_POOLS: Pool,
        const.NEUTRON_MEMBERS: Member,
        const.NEUTRON_VIPS: Vip,
        const.NEUTRON_HEALTH_MONITORS: HealthMonitor
    }[key](*args, **kwargs)


class DataReader(object):

    def __init__(self):
        self.mc = ctx.get_read_context()

    def _get_subnet_router(self, context, filters=None):
        new_list = []
        client = self.mc.plugin
        subnets = client.get_subnets(context=context)
        for subnet in subnets:
            subnet_id = subnet['id']
            subnet_gw_ip = subnet['gateway_ip']
            interfaces = client.get_ports(context=context, filters=filters)
            gw_iface = next(
                (i for i in interfaces
                    if ('fixed_ips' in i and len(i['fixed_ips']) > 0 and
                        i['fixed_ips'][0]['ip_address'] == subnet_gw_ip and
                        i['fixed_ips'][0]['subnet_id'] == subnet_id)),
                None)
            gw_id = None
            if gw_iface:
                gw_id = gw_iface['device_id']

            new_list.append({'id': subnet_id, 'gw_router_id': gw_id})
        return new_list

    @property
    def _get_queries(self):
        return [
            (const.NEUTRON_SECURITY_GROUPS,
             self.mc.plugin.get_security_groups, []),
            (const.NEUTRON_NETWORKS, self.mc.plugin.get_networks, []),
            (const.NEUTRON_SUBNETS, self.mc.plugin.get_subnets, []),
            (const.NEUTRON_PORTS, self.mc.plugin.get_ports, []),
            (const.NEUTRON_ROUTERS, self.mc.plugin.get_routers, []),
            (const.NEUTRON_ROUTER_INTERFACES, self.mc.plugin.get_ports,
             [utils.ListFilter(check_key='device_owner',
                               check_list=['network:router_interface'])]),
            (const.NEUTRON_SUBNET_GATEWAYS, self._get_subnet_router,
             [utils.ListFilter(check_key='device_owner',
                               check_list=['network:router_interface'])]),
            (const.NEUTRON_FLOATINGIPS,
             self.mc.plugin.get_floatingips, []),
            (const.NEUTRON_POOLS, self.mc.lb_plugin.get_pools, []),
            (const.NEUTRON_MEMBERS, self.mc.lb_plugin.get_members, []),
            (const.NEUTRON_VIPS, self.mc.lb_plugin.get_vips, []),
            (const.NEUTRON_HEALTH_MONITORS,
             self.mc.lb_plugin.get_health_monitors,
             [utils.MinLengthFilter(field='pools', min_len=1)]),
        ]

    def prepare(self):
        """Prepares a map of object ID -> object from Neutron DB

        It also includes 'ops' key that includes a list of ops entries that
        will be created in migration.
        """
        LOG.info('Preparing Neutron data')
        obj_map = {}
        for key, func, filter_list in self._get_queries:
            obj_map.update(_get_neutron_objects(key=key, func=func,
                                                context=self.mc.n_ctx,
                                                filter_list=filter_list))
        obj_map["ops"] = _create_op_list(obj_map)
        return obj_map


class DataWriter(object):

    def __init__(self, data, dry_run=False):
        self.mc = ctx.get_write_context()
        self.data = data
        self.dry_run = dry_run

    def migrate(self):
        LOG.info('Running Neutron migration process')
        ops = self.data['neutron']['ops']
        for op in ops:
            LOG.debug(_print_op(op))
            obj = _get_neutron_obj(op['type'], self.mc.client)
            if not self.dry_run:
                obj.create(self.mc.n_ctx, op['data'])

    def _create_data(self, name, f, *args):
        LOG.debug('create ' + name + ":" + map(str, args))
        if self.dry_run:
            return {"id": name}
        else:
            return f(self.mc.n_ctx, *args)

    def create_edge_router(self, tenant):
        """Create the edge router

        The expected input is:
        {
            'router': {
                           'name': <name>,
                           'admin_state_up': <admin_state_up>
                      },
            'ports': [{
                           'admin_state_up': <admin_state_up>,
                           'network_cidr': <network_cidr>,
                           'mac': <mac>,
                           'ip_address': <ip_address>,
                           'host': <host>,
                           'iface': <iface>,

                      }, ...].
        }

        nets is a list of Neutron network objects.
        """
        LOG.info('Running Edge Router migration process')

        provider_router = self.data['midonet']['provider_router']
        nets = self.data['neutron']['networks']
        ports = provider_router['ports']
        router = provider_router['router']

        router_obj = {'router': {'name': router['name'],
                                 'tenant_id': tenant,
                                 'admin_state_up': router['admin_state_up']}}
        upl_router = self._create_data("router", self.mc.plugin.create_router,
                                       router_obj)

        for port in ports:
            base_name = port['host'] + "_" + port['iface']
            net_obj = {'network': {'name': base_name + "_uplink_net",
                                   'tenant_id': tenant,
                                   'shared': False,
                                   'provider:network_type': 'uplink',
                                   'admin_state_up': True}}
            upl_net = self._create_data("network",
                                        self.mc.plugin.create_network, net_obj)

            subnet_obj = {'subnet': {'name': base_name + "_uplink_subnet",
                                     'network_id': upl_net['id'],
                                     'ip_version': 4,
                                     'cidr': port['network_cidr'],
                                     'dns_nameservers': [],
                                     'host_routes': [],
                                     'allocation_pools': None,
                                     'enable_dhcp': False,
                                     'tenant_id': tenant,
                                     'admin_state_up': True}}
            upl_sub = self._create_data("subnet", self.mc.plugin.create_subnet,
                                        subnet_obj)

            port_obj = {'port': {'name': base_name + "_uplink_port",
                                 'tenant_id': 'admin',
                                 'network_id': upl_net['id'],
                                 'device_id': '',
                                 'device_owner': '',
                                 'mac_address': port['mac'],
                                 'fixed_ips': [
                                     {'subnet_id': upl_sub['id'],
                                      'ip_address': port['ip_address']}],
                                 'binding:host_id': port['host'],
                                 'binding:profile': {
                                     'interface_name': port['iface']},
                                 'admin_state_up': port['admin_state_up']}}
            bound_port = self._create_data("port", self.mc.plugin.create_port,
                                           port_obj)

            iface_obj = {'port_id': bound_port['id']}
            self._create_data("router_interface",
                              self.mc.plugin.add_router_interface,
                              upl_router['id'], iface_obj)

        subnet_ids = _get_external_subnet_ids(nets)
        for subnet in subnet_ids:
            iface_obj = {'subnet_id': subnet}
            self._create_data("router_interface",
                              self.mc.plugin.add_router_interface,
                              upl_router['id'], iface_obj)
