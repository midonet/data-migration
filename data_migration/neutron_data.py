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

from data_migration import context as ctx
from data_migration import exceptions as exc
from data_migration import utils
import logging
import midonet.neutron.db.task_db as task

LOG = logging.getLogger(name="data_migration")


def _get_neutron_objects(key, func, context, filter_list=None):
    if filter_list is None:
        filter_list = []

    retmap = {key: {}}
    submap = retmap[key]

    LOG.debug("\n[" + key + "]")

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

        singular_noun = key[:-1] if key.endswith('s') else key
        LOG.debug("\t[" + singular_noun + " " + obj['id'] + "]: " + str(obj))

        submap[obj['id']] = obj

    return retmap


def _task_create_by_id(_topo, task_model, oid, obj):
    LOG.debug("Preparing " + task_model + ": " + str(oid))
    return {'type': "CREATE",
            'data_type': task_model,
            'resource_id': oid,
            'data': obj}


def _task_lb(topo, task_model, pid, lb_obj):
    lb_subnet = lb_obj['subnet_id']
    router_id = topo['subnet-gateways'][lb_subnet]['gw_router_id']
    if not router_id:
        raise exc.UpgradeScriptException(
            "LB Pool's subnet has no associated gateway router: " + lb_obj)
    LOG.debug("Preparing " + task_model + ": " + str(pid) +
              " on router " + router_id)
    new_lb_obj = lb_obj.copy()
    new_lb_obj['health_monitors'] = []
    new_lb_obj['health_monitors_status'] = []
    new_lb_obj['members'] = []
    new_lb_obj['vip_id'] = None
    new_lb_obj['router_id'] = router_id
    return {'type': task.CREATE,
            'data_type': task_model,
            'resource_id': pid,
            'data': new_lb_obj}


def _task_router(_topo, task_model, rid, router_obj):
    LOG.debug("Preparing " + task_model + ": " + str(rid))

    # Create a router with no routes and update them later
    routeless_router = {k: v
                        for k, v in iter(router_obj.items())
                        if k != 'routes'}

    return {'type': task.CREATE,
            'data_type': task_model,
            'resource_id': rid,
            'data': routeless_router}


def _task_router_interface(topo, task_model, pid, port):
    router_obj = topo['routers'][port['device_id']]
    router_id = router_obj['id']
    LOG.debug("Preparing " + task_model + " on ROUTER: " + str(pid) +
              " on router: " + router_id)
    if 'fixed_ips' not in port:
        raise exc.UpgradeScriptException(
            'Router interface port has no fixed IPs:' + str(port))
    subnet_id = port['fixed_ips'][0]['subnet_id']
    interface_dict = {'id': router_id,
                      'port_id': pid,
                      'subnet_id': subnet_id}
    return {'type': task.CREATE,
            'data_type': task_model,
            'resource_id': router_id,
            'data': interface_dict}


def _task_router_routes(_topo, task_model, rid, router_obj):
    # Update routes if present
    if 'routes' in router_obj:
        LOG.debug("Updating " + task_model + ": " + router_obj['id'])
        return {'type': task.UPDATE,
                'data_type': task_model,
                'resource_id': rid,
                'data': router_obj}
    return None


def _print_task(t):
    return 'Task: ' + ', '.join([t['type'], t['data_type'], t['resource_id']])


def _create_task_list(obj_map):
    """Creates a list of tasks to run given a map of object ID -> object"""
    task_list = []
    for key, model, func in _CREATES:
        for oid, obj in iter(obj_map[key].items()):
            elem = func(obj_map, model, oid, obj)
            if elem:
                task_list.append(elem)
    return task_list


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


_CREATES = [
    ('security-groups', task.SECURITY_GROUP, _task_create_by_id),
    ('networks', task.NETWORK, _task_create_by_id),
    ('subnets', task.SUBNET, _task_create_by_id),
    ('ports', task.PORT, _task_create_by_id),
    ('routers', task.ROUTER, _task_router),
    ('router-interfaces', "ROUTERINTERFACE", _task_router_interface),
    ('routers', task.ROUTER, _task_router_routes),
    ('floating-ips', task.FLOATING_IP, _task_create_by_id),
    ('load-balancer-pools', task.POOL, _task_lb),
    ('members', task.MEMBER, _task_create_by_id),
    ('vips', task.VIP, _task_create_by_id),
    ('health-monitors', task.HEALTH_MONITOR, _task_create_by_id)
]


class DataReader(object):

    def __init__(self):
        self.mc = ctx.get_context()

    def _get_subnet_router(self, context, filters=None):
        new_list = []
        client = self.mc.client
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
                ('security-groups', self.mc.client.get_security_groups, []),
                ('networks', self.mc.client.get_networks, []),
                ('subnets', self.mc.client.get_subnets, []),
                ('ports', self.mc.client.get_ports, []),
                ('routers', self.mc.client.get_routers, []),
                ('router-interfaces', self.mc.client.get_ports,
                 [utils.ListFilter(check_key='device_owner',
                                   check_list=['network:router_interface'])]),
                ('subnet-gateways', self._get_subnet_router,
                 [utils.ListFilter(check_key='device_owner',
                                   check_list=['network:router_interface'])]),
                ('floating-ips', self.mc.client.get_floatingips, []),
                ('load-balancer-pools', self.mc.lb_client.get_pools, []),
                ('members', self.mc.lb_client.get_members, []),
                ('vips', self.mc.lb_client.get_vips, []),
                ('health-monitors', self.mc.lb_client.get_health_monitors,
                 [utils.MinLengthFilter(field='pools', min_len=1)]),
        ]

    def prepare(self):
        """Prepares a map of object ID -> object from Neutron DB

        It also includes 'tasks' key that includes a list of task entries that
        will be created in migration.
        """
        LOG.info('Preparing Neutron data')
        obj_map = {}
        for key, func, filter_list in self._get_queries:
            obj_map.update(_get_neutron_objects(key=key, func=func,
                                                context=self.mc.ctx,
                                                filter_list=filter_list))
        obj_map["tasks"] = _create_task_list(obj_map)
        return obj_map


class DataWriter(object):

    def __init__(self, data, dry_run=False):
        self.mc = ctx.get_context()
        self.data = data
        self.dry_run = dry_run

    def migrate(self):
        LOG.info('Running Neutron migration process')
        tasks = self.data['neutron']['tasks']
        for t in tasks:
            LOG.debug(_print_task(t))
            if not self.dry_run:
                task.create_task(self.mc.ctx, **t)

    def _create_data(self, name, f, *args):
        LOG.debug('create ' + name + ":" + map(str, args))
        if self.dry_run:
            return {"id": name}
        else:
            return f(self.mc.ctx, *args)

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
        upl_router = self._create_data("router", self.mc.client.create_router,
                                       router_obj)

        for port in ports:
            base_name = port['host'] + "_" + port['iface']
            net_obj = {'network': {'name': base_name + "_uplink_net",
                                   'tenant_id': tenant,
                                   'shared': False,
                                   'provider:network_type': 'uplink',
                                   'admin_state_up': True}}
            upl_net = self._create_data("network",
                                        self.mc.client.create_network, net_obj)

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
            upl_sub = self._create_data("subnet", self.mc.client.create_subnet,
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
            bound_port = self._create_data("port", self.mc.client.create_port,
                                           port_obj)

            iface_obj = {'port_id': bound_port['id']}
            self._create_data("router_interface",
                              self.mc.client.add_router_interface,
                              upl_router['id'], iface_obj)

        subnet_ids = _get_external_subnet_ids(nets)
        for subnet in subnet_ids:
            iface_obj = {'subnet_id': subnet}
            self._create_data("router_interface",
                              self.mc.client.add_router_interface,
                              upl_router['id'], iface_obj)
