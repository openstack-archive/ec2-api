#    Copyright 2014 Cloudscaling Group, Inc
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


from ec2api import exception


class OnCrashCleaner(object):

    def __init__(self):
        self._cleanups = []
        self._first_cleanups = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            return
        self._run_cleanups(self._first_cleanups)
        self._run_cleanups(self._cleanups)

    def addCleanup(self, function, *args, **kwargs):
        self._cleanups.append((function, args, kwargs))

    def addFirstCleanup(self, function, *args, **kwargs):
        self._first_cleanups.append((function, args, kwargs))

    def _run_cleanups(self, cleanups):
        for function, args, kwargs in reversed(cleanups):
            try:
                function(*args, **kwargs)
            except Exception:
                # TODO(ft): log the error
                pass


def filtered_out(item, filters, filter_map):
    if filters is None:
        return False
    for filter in filters:
        filter_name = filter_map.get(filter['name'])
        if filter_name is None:
            raise exception.InvalidParameterValue(
                value=filter['name'], parameter='filter',
                reason='invalid filter')
        if type(filter_name) is list:
            value_set = item.get(filter_name[0])
            if value_set is not None:
                values = [value[filter_name[1]] for value in value_set]
        else:
            values = [item.get(filter_name)]
        if not values:
            return True
        # NOTE(Alex): Two modes are supported for values here:
        # Dict like it comes from the outside: {'1': 'value1', '2', 'value2'}
        # And simple list of values.
        filter_values = filter['value']
        if isinstance(filter_values, dict):
            filter_values = filter_values.values()
        for filter_value in filter_values:
            if filter_value not in values:
                return True
    return False
