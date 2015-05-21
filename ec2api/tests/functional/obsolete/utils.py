# Copyright 2014
# The Cloudscaling Group, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
logging.getLogger('boto').setLevel(logging.INFO)
logging.getLogger('paramiko').setLevel(logging.WARNING)
LOG = logging.getLogger(__name__)


def detect_new_volume(proc_partitions, proc_partitions_new):
    devices = get_devices(proc_partitions)
    devices_new = get_devices(proc_partitions_new)
    devices_new -= devices
    return devices_new.pop()


def get_devices(proc_partitions):
    devices = set()
    for line in proc_partitions:
        items = [item for item in line.split(' ') if len(item) > 0]
        if len(items) > 0:
            devices.add(items[3])

    return devices
