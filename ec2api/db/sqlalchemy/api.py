#    Copyright 2013 Cloudscaling Group, Inc
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

import ast
import copy
import functools
import random
import sys

from oslo.config import cfg

from ec2api.api import ec2utils
import ec2api.context
from ec2api.db.sqlalchemy import models
from ec2api.openstack.common.db.sqlalchemy import session as db_session

CONF = cfg.CONF
CONF.import_opt('connection',
                'ec2api.openstack.common.db.sqlalchemy.session',
                group='database')


_MASTER_FACADE = None


def _create_facade_lazily(use_slave=False):
    global _MASTER_FACADE

    if _MASTER_FACADE is None:
        _MASTER_FACADE = db_session.EngineFacade(
            CONF.database.connection,
            **dict(CONF.database.iteritems())
        )
    return _MASTER_FACADE


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
    """
    session = kwargs.get('session') or get_session()

    return session.query(model, *args)


@require_context
def add_item(context, kind, data):
    # NOTE(ft): obtaining new id from Nova DB is temporary solution
    # while we don't implmenet all Nova EC2 methods
    if kind == 'i':
        obj_id = ec2utils.id_to_ec2_inst_id(data['os_id'])
    elif kind == 'vol':
        obj_id = ec2utils.id_to_ec2_vol_id(data['os_id'])
    else:
        obj_id = "%(kind)s-%(id)08x" % {"kind": kind,
                                        "id": random.randint(1, 0xffffffff)}
    item_ref = models.Item()
    item_ref.update({
        "project_id": context.project_id,
        "id": obj_id,
    })
    item_ref.update(_pack_item_data(data))
    item_ref.save()
    return _unpack_item_data(item_ref)


@require_context
def update_item(context, item):
    item_ref = (model_query(context, models.Item).
                filter_by(project_id=context.project_id,
                          id=item["id"]).
                one())
    item_ref.update(_pack_item_data(item))
    item_ref.save()
    return _unpack_item_data(item_ref)


@require_context
def delete_item(context, item_id):
    (model_query(context, models.Item).
                filter_by(project_id=context.project_id,
                          id=item_id).
                          delete())


@require_context
def restore_item(context, kind, data):
    item_ref = models.Item()
    item_ref.update({
        "project_id": context.project_id,
    })
    item_ref.id = data['id']
    item_ref.update(_pack_item_data(data))
    item_ref.save()
    return _unpack_item_data(item_ref)


@require_context
def get_items(context, kind):
    return [_unpack_item_data(item)
            for item in model_query(context, models.Item).
                    filter_by(project_id=context.project_id).
                    filter(models.Item.id.like('%s-%%' % kind)).
                    all()]


@require_context
def get_item_by_id(context, kind, item_id):
    return _unpack_item_data(model_query(context, models.Item).
            filter_by(project_id=context.project_id,
                      id=item_id).
            filter(models.Item.id.like('%s-%%' % kind)).
            first())


@require_context
def get_items_by_ids(context, kind, item_ids):
    if item_ids is None or item_ids == []:
        return get_items(context, kind)
    return [_unpack_item_data(item)
            for item in (model_query(context, models.Item).
                         filter_by(project_id=context.project_id).
                         filter(models.Item.id.in_(item_ids))).
                         filter(models.Item.id.like('%s-%%' % kind)).
                         all()]


def _pack_item_data(item_data):
    data = copy.deepcopy(item_data)
    data.pop("id", None)
    return {
        "os_id": data.pop("os_id", None),
        "vpc_id": data.pop("vpc_id", None),
        "data": str(data),
    }


def _unpack_item_data(item_ref):
    if item_ref is None:
        return None
    data = ast.literal_eval(item_ref.data)
    data["id"] = item_ref.id
    data["os_id"] = item_ref.os_id
    data["vpc_id"] = item_ref.vpc_id
    return data
