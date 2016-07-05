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

from data_migration import context


class CommonData(object):

    def __init__(self, data, dry_run=None):
        self.mc = context.get_write_context()
        self.data = data
        self.dry_run = dry_run
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

    def _get_midonet_resource_list(self, key):
        return self._get_resource_list('midonet', key)

    def _get_midonet_resource_map(self, key):
        return self._get_resource_map('midonet', key)

    def _create_neutron_data(self, f, *args):
        if self.dry_run:
            return None
        else:
            return f(self.mc.n_ctx, *args)


class DataCounterMixin(object):

    def __init__(self):
        self.skipped = []
        self.created = []
        self.deleted = []
        self.updated = []
        self.conflicted = []
        super(DataCounterMixin, self).__init__()

    def add_skip(self, obj, reason):
        self.skipped.append({
            "object": obj,
            "reason": reason
        })

    def print_summary(self):
        print("\n")
        print("***** %s *****\n" % self.key)
        print("%d created" % len(self.created))
        print("%d deleted" % len(self.deleted))
        print("%d updated" % len(self.updated))
        print("%d skipped due to conflict" % len(self.conflicted))
        print("%d skipped for other reasons" % len(self.skipped))

        if self.skipped:
            print("The skip reasons:")
            for skip in self.skipped:
                print("Object " + str(skip['object']) + " skipped because " +
                      skip['reason'])
        print("\n")
