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

"""RequestContext: context for requests that persist through all of ec2."""

import uuid

from oslo_utils import timeutils
import six

from ec2api import exception
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import local
from ec2api.openstack.common import log as logging


LOG = logging.getLogger(__name__)


def generate_request_id():
    return 'req-' + str(uuid.uuid4())


class RequestContext(object):
    """Security context and request information.

    Represents the user taking a given action within the system.

    """

    def __init__(self, user_id, project_id,
                 is_admin=None, roles=None, remote_address=None,
                 auth_token=None, user_name=None, project_name=None,
                 overwrite=True, service_catalog=None, api_version=None,
                 cross_tenants=None, **kwargs):
        """Parameters

            :param overwrite: Set to False to ensure that the greenthread local
                copy of the index is not overwritten.


            :param kwargs: Extra arguments that might be present, but we ignore
                because they possibly came in from older rpc messages.
        """
        if kwargs:
            LOG.warn(_('Arguments dropped when creating context: %s') %
                    str(kwargs))

        self.user_id = user_id
        self.project_id = project_id
        self.cached_secret_key = None
        self.roles = roles or []
        self.remote_address = remote_address
        timestamp = timeutils.utcnow()
        if isinstance(timestamp, six.string_types):
            timestamp = timeutils.parse_strtime(timestamp)
        self.timestamp = timestamp
        self.request_id = generate_request_id()
        self.auth_token = auth_token

        self.service_catalog = service_catalog
        if self.service_catalog is None:
            # if list is empty or none
            self.service_catalog = []

        self.user_name = user_name
        self.project_name = project_name
        self.is_admin = is_admin
        # TODO(ft): call policy.check_is_admin if is_admin is None
        self.cross_tenants = cross_tenants
        self.api_version = api_version
        if overwrite or not hasattr(local.store, 'context'):
            self.update_store()

    def update_store(self):
        local.store.context = self

    def to_dict(self):
        return {'user_id': self.user_id,
                'project_id': self.project_id,
                'is_admin': self.is_admin,
                'roles': self.roles,
                'remote_address': self.remote_address,
                'timestamp': timeutils.strtime(self.timestamp),
                'request_id': self.request_id,
                'auth_token': self.auth_token,
                'user_name': self.user_name,
                'service_catalog': self.service_catalog,
                'project_name': self.project_name,
                'tenant': self.tenant,
                'user': self.user}

    @classmethod
    def from_dict(cls, values):
        values.pop('user', None)
        values.pop('tenant', None)
        return cls(**values)

    # NOTE(sirp): the openstack/common version of RequestContext uses
    # tenant/user whereas the ec2 version uses project_id/user_id. We need
    # this shim in order to use context-aware code from openstack/common, like
    # logging, until we make the switch to using openstack/common's version of
    # RequestContext.
    @property
    def tenant(self):
        return self.project_id

    @property
    def user(self):
        return self.user_id


def get_admin_context(project_id=None, read_deleted="no"):
    return RequestContext(user_id=None,
                          project_id=project_id,
                          access_key=None,
                          is_admin=True,
                          read_deleted=read_deleted,
                          overwrite=False)


def is_user_context(context):
    """Indicates if the request context is a normal user."""
    if not context:
        return False
    if context.is_admin:
        return False
    if not context.user_id or not context.project_id:
        return False
    return True


def require_context(ctxt):
    """Raise exception.Forbidden()

    if context is not a user or an admin context.
    """
    if not ctxt.is_admin and not is_user_context(ctxt):
        raise exception.Forbidden()
