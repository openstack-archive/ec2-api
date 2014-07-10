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


"""
Cloud Controller: Implementation of EC2 REST API calls, which are
dispatched to other nodes via AMQP RPC. State is via distributed
datastore.
"""

from oslo.config import cfg

from ec2api.openstack.common import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class CloudController(object):
    """Cloud Controller

        Provides the critical dispatch between
        inbound API calls through the endpoint and messages
        sent to the other nodes.
    """
    def __init__(self):
        pass

    def __str__(self):
        return 'CloudController'