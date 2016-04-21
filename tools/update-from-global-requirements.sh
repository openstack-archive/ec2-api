#!/bin/bash
# Copyright (c) 2016 OpenStack Foundation
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

GLOBAL_REQS_PATH=${1:-$HOME/openstack/requirements/global-requirements.txt}

function update() {
  rm -f temp-requirements.txt
  touch temp-requirements.txt
  while read line ; do
    local module=`echo $line | sed 's/\([.A-Za-z0-9\-]*\)[ ><!=\t]*.*/\1/'`
    local newm=`grep -e "^$module[ ><!=\t]" $GLOBAL_REQS_PATH`
    if ! grep "$newm" temp-requirements.txt >/dev/null ; then
      echo "$newm" >> temp-requirements.txt
    fi
  done < $1
  mv temp-requirements.txt $1
}

echo "Update requirements"
update requirements.txt
echo "Update test-requirements"
update test-requirements.txt
