# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Implementation of SQLAlchemy backend."""

import functools
import sys

from oslo_config import cfg
from oslo_db.sqlalchemy import session as db_session
from oslo_log import log as logging
from sqlalchemy import or_

import ec2api.context
from ec2api import exception
from ec2api.i18n import _
from ec2api.novadb.sqlalchemy import models

connection_opts = [
    cfg.StrOpt('connection_nova',
               secret=True,
               help='The SQLAlchemy connection string used to connect to the '
                    'nova database'),
]

CONF = cfg.CONF
CONF.register_opts(connection_opts, group='database')

LOG = logging.getLogger(__name__)


_MASTER_FACADE = None


def _create_facade_lazily():
    global _MASTER_FACADE

    if _MASTER_FACADE is None:
        _MASTER_FACADE = db_session.EngineFacade(
            CONF.database.connection_nova,
            **dict(CONF.database.iteritems())
        )
    return _MASTER_FACADE


def get_engine():
    facade = _create_facade_lazily()
    return facade.get_engine()


def get_session(**kwargs):
    facade = _create_facade_lazily()
    return facade.get_session(**kwargs)


def get_backend():
    """The backend is this module itself."""
    return sys.modules[__name__]


def require_context(f):
    """Decorator to require *any* user or admin context.

    This does no authorization for user or project access matching, see
    :py:func:`ec2api.context.authorize_project_context` and
    :py:func:`ec2api.context.authorize_user_context`.

    The first argument to the wrapped function must be the context.

    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ec2api.context.require_context(args[0])
        return f(*args, **kwargs)
    return wrapper


def model_query(context, model, *args, **kwargs):
    """Query helper that accounts for context's `read_deleted` field.

    :param context: context to query under
    :param session: if present, the session to use
    :param read_deleted: if present, overrides context's read_deleted field.
    :param project_only: if present and context is user-type, then restrict
            query to match the context's project_id. If set to 'allow_none',
            restriction includes project_id = None.
    :param base_model: Where model_query is passed a "model" parameter which is
            not a subclass of NovaBase, we should pass an extra base_model
            parameter that is a subclass of NovaBase and corresponds to the
            model parameter.
    """

    session = kwargs.get('session') or get_session()
    read_deleted = kwargs.get('read_deleted') or context.read_deleted
    project_only = kwargs.get('project_only', False)

    def issubclassof_nova_base(obj):
        return isinstance(obj, type) and issubclass(obj, models.NovaBase)

    base_model = model
    if not issubclassof_nova_base(base_model):
        base_model = kwargs.get('base_model', None)
        if not issubclassof_nova_base(base_model):
            raise Exception(_("model or base_model parameter should be "
                              "subclass of NovaBase"))

    query = session.query(model, *args)

    default_deleted_value = base_model.__mapper__.c.deleted.default.arg
    if read_deleted == 'no':
        query = query.filter(base_model.deleted == default_deleted_value)
    elif read_deleted == 'yes':
        pass  # omit the filter to include deleted and active
    elif read_deleted == 'only':
        query = query.filter(base_model.deleted != default_deleted_value)
    else:
        raise Exception(_("Unrecognized read_deleted value '%s'")
                        % read_deleted)

    if ec2api.context.is_user_context(context) and project_only:
        if project_only == 'allow_none':
            query = (query.
                     filter(or_(base_model.project_id == context.project_id,
                                base_model.project_id == None)))
        else:
            query = query.filter_by(project_id=context.project_id)

    return query


####################


@require_context
def instance_get_by_uuid(context, uuid, columns_to_join=None):
    return _instance_get_by_uuid(context, uuid,
            columns_to_join=columns_to_join)


def _instance_get_by_uuid(context, uuid, session=None,
                          columns_to_join=None):
    result = (_build_instance_get(context, session=session,
                                 columns_to_join=columns_to_join).
                filter_by(uuid=uuid).
                first())

    if not result:
        LOG.error("Instance %s could not be found in nova DB" % str(uuid))
        raise exception.NovaDbInstanceNotFound()

    return result


def _build_instance_get(context, session=None,
                        columns_to_join=None):
    query = model_query(context, models.Instance, session=session,
                        project_only=True, read_deleted="no")
    return query


def _block_device_mapping_get_query(context, session=None,
        columns_to_join=None):
    if columns_to_join is None:
        columns_to_join = []

    query = model_query(context, models.BlockDeviceMapping,
                        session=session, read_deleted="no")

    return query


@require_context
def block_device_mapping_get_all_by_instance(context, instance_uuid):
    return (_block_device_mapping_get_query(context).
                 filter_by(instance_uuid=instance_uuid).
                 all())
