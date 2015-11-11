# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import itertools

import ec2api.api
import ec2api.api.auth
import ec2api.api.availability_zone
import ec2api.api.common
import ec2api.api.dhcp_options
import ec2api.api.ec2utils
import ec2api.api.image
import ec2api.api.instance


def list_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             ec2api.api.ec2_opts,
             ec2api.api.auth.auth_opts,
             ec2api.api.availability_zone.availability_zone_opts,
             ec2api.api.common.ec2_opts,
             ec2api.api.dhcp_options.ec2_opts,
             ec2api.api.ec2utils.ec2_opts,
             ec2api.api.image.s3_opts,
             ec2api.api.image.rpcapi_opts,
             ec2api.api.instance.ec2_opts,
         )),
    ]
