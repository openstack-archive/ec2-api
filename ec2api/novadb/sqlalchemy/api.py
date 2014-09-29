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

from oslo.config import cfg
from sqlalchemy import or_

import ec2api.context
from ec2api import exception
from ec2api.novadb.sqlalchemy import models
from ec2api.openstack.common.db.sqlalchemy import session as db_session
from ec2api.openstack.common.gettextutils import _
from ec2api.openstack.common import log as logging

connection_opts = [
    cfg.StrOpt('connection_nova',
               secret=True,
               help='The SQLAlchemy connection string used to connect to the '
                    'nova database'),
    cfg.StrOpt('slave_connection',
               secret=True,
               help='The SQLAlchemy connection string used to connect to the '
                    'slave database'),
]

CONF = cfg.CONF
CONF.register_opts(connection_opts, group='database')

LOG = logging.getLogger(__name__)


_MASTER_FACADE = None
_SLAVE_FACADE = None


def _create_facade_lazily(use_slave=False):
    global _MASTER_FACADE
    global _SLAVE_FACADE

    return_slave = use_slave and CONF.database.slave_connection
    if not return_slave:
        if _MASTER_FACADE is None:
            _MASTER_FACADE = db_session.EngineFacade(
                CONF.database.connection_nova,
                **dict(CONF.database.iteritems())
            )
        return _MASTER_FACADE
    else:
        if _SLAVE_FACADE is None:
            _SLAVE_FACADE = db_session.EngineFacade(
                CONF.database.slave_connection,
                **dict(CONF.database.iteritems())
            )
        return _SLAVE_FACADE


def get_engine(use_slave=False):
    facade = _create_facade_lazily(use_slave)
    return facade.get_engine()


def get_session(use_slave=False, **kwargs):
    facade = _create_facade_lazily(use_slave)
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
    :param use_slave: If true, use slave_connection
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

    use_slave = kwargs.get('use_slave') or False
    if CONF.database.slave_connection == '':
        use_slave = False

    session = kwargs.get('session') or get_session(use_slave=use_slave)
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


def s3_image_get(context, image_id):
    """Find local s3 image represented by the provided id."""
    result = (model_query(context, models.S3Image, read_deleted="yes").
              filter_by(id=image_id).
              first())

    if not result:
        raise exception.ImageNotFound(image_id=image_id)

    return result


##################


@require_context
def get_volume_uuid_by_ec2_id(context, ec2_id):
    result = (model_query(context, models.VolumeIdMapping, read_deleted='yes').
              filter_by(id=ec2_id).
              first())

    if not result:
        raise exception.VolumeNotFound(volume_id=ec2_id)

    return result['uuid']


@require_context
def get_snapshot_uuid_by_ec2_id(context, ec2_id):
    result = (model_query(context, models.SnapshotIdMapping,
                          read_deleted='yes').
              filter_by(id=ec2_id).
              first())

    if not result:
        raise exception.SnapshotNotFound(snapshot_id=ec2_id)

    return result['uuid']


###################


@require_context
def ec2_instance_create(context, instance_uuid, id=None):
    """Create ec2 compatible instance by provided uuid."""
    ec2_instance_ref = models.InstanceIdMapping()
    ec2_instance_ref.update({'uuid': instance_uuid})
    if id is not None:
        ec2_instance_ref.update({'id': id})

    ec2_instance_ref.save()

    return ec2_instance_ref


@require_context
def ec2_instance_get_by_uuid(context, instance_uuid):
    result = (_ec2_instance_get_query(context).
              filter_by(uuid=instance_uuid).
              first())

    if not result:
        raise exception.InstanceNotFound(instance_id=instance_uuid)

    return result


@require_context
def get_ec2_instance_id_by_uuid(context, instance_id):
    result = ec2_instance_get_by_uuid(context, instance_id)
    return result['id']


@require_context
def ec2_instance_get_by_id(context, instance_id):
    result = (_ec2_instance_get_query(context).
              filter_by(id=instance_id).
              first())

    if not result:
        raise exception.InstanceNotFound(instance_id=instance_id)

    return result


@require_context
def get_instance_uuid_by_ec2_id(context, ec2_id):
    result = ec2_instance_get_by_id(context, ec2_id)
    return result['uuid']


def _ec2_instance_get_query(context, session=None):
    return model_query(context,
                       models.InstanceIdMapping,
                       session=session,
                       read_deleted='yes')
