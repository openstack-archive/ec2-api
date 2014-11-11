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


import copy


def update_dict(dict1, dict2):
    """Get a copy of union of two dicts."""
    res = copy.deepcopy(dict1)
    res.update(dict2)
    return res


def purge_dict(dict1, trash_keys):
    """Get a copy of dict, removed keys."""
    res = copy.deepcopy(dict1)
    for key in trash_keys:
        res.pop(key, None)
    return res


def patch_dict(dict1, dict2, trash_iter):
    """Get a copy of union of two dicts, removed keys."""
    res = update_dict(dict1, dict2)
    res = purge_dict(res, trash_iter)
    return res
