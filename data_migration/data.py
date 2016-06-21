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


class CommonData(object):

    def __init__(self, data):
        self.data = data
        super(CommonData, self).__init__()

    def _get_resources(self, topic, key=None):
        data = self.data[topic]
        return data if key is None else data[key]

    def _get_midonet_resources(self, key=None):
        return self._get_resources('midonet', key=key)

    def _get_neutron_resources(self, key=None):
        return self._get_resources('neutron', key=key)

    def _neutron_ids(self, key):
        nd = self._get_neutron_resources(key=key)
        return set(nd.keys())

    def _get_resource_list(self, topic, key):
        res_map = self._get_resources(topic, key=key)
        return [elem for res_list in res_map.values() for elem in res_list]

    def _get_resource_map(self, topic, key):
        res_list = self._get_resource_list(topic, key=key)
        res_map = dict()
        for res in res_list:
            res_map[res['id']] = res
        return res_map

    def _get_midonet_resource_map(self, key):
        return self._get_resource_map('midonet', key)
