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

import copy
import functools
import json
import random
import sys

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_db.sqlalchemy import session as db_session
from sqlalchemy import and_
from sqlalchemy import or_
from sqlalchemy.sql import bindparam

import ec2api.context
from ec2api.db.sqlalchemy import models
from ec2api import exception

CONF = cfg.CONF


_MASTER_FACADE = None


def _create_facade_lazily():
    global _MASTER_FACADE

    if _MASTER_FACADE is None:
        _MASTER_FACADE = db_session.EngineFacade.from_config(CONF)
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


def _new_id(kind):
    obj_id = "%(kind)s-%(id)08x" % {"kind": kind,
                                    "id": random.randint(1, 0xffffffff)}
    return obj_id


@require_context
def add_item(context, kind, data):
    item_ref = models.Item()
    item_ref.update({
        "project_id": context.project_id,
        "id": _new_id(kind),
    })
    item_ref.update(_pack_item_data(data))
    try:
        item_ref.save()
    except db_exception.DBDuplicateEntry as ex:
        if (models.ITEMS_OS_ID_INDEX_NAME not in ex.columns and
                'os_id' not in ex.columns):
            raise
        item_ref = (model_query(context, models.Item).
                    filter_by(os_id=data["os_id"]).
                    filter(or_(models.Item.project_id == context.project_id,
                               models.Item.project_id.is_(None))).
                    filter(models.Item.id.like('%s-%%' % kind)).
                    one())
        item_data = _unpack_item_data(item_ref)
        item_data.update(data)
        item_ref.update(_pack_item_data(item_data))
        item_ref.project_id = context.project_id
        item_ref.save()
    return _unpack_item_data(item_ref)


@require_context
def add_item_id(context, kind, os_id, project_id=None):
    item_ref = models.Item()
    item_ref.update({
        "id": _new_id(kind),
        "os_id": os_id,
    })
    if project_id:
        item_ref.project_id = project_id
    try:
        item_ref.save()
    except db_exception.DBDuplicateEntry as ex:
        if (models.ITEMS_OS_ID_INDEX_NAME not in ex.columns and
                ex.columns != ['os_id']):
            raise
        item_ref = (model_query(context, models.Item).
                    filter_by(os_id=os_id).
                    one())
    return item_ref.id


@require_context
def update_item(context, item):
    item_ref = (model_query(context, models.Item).
                filter_by(project_id=context.project_id,
                          id=item['id']).
                one())
    if item_ref.os_id and item_ref.os_id != item['os_id']:
        raise exception.EC2DBInvalidOsIdUpdate(item_id=item['id'],
                                               old_os_id=item_ref.os_id,
                                               new_os_id=item['os_id'])
    item_ref.update(_pack_item_data(item))
    item_ref.save()
    return _unpack_item_data(item_ref)


@require_context
def delete_item(context, item_id):
    session = get_session()
    deleted_count = (model_query(context, models.Item, session=session).
                     filter_by(project_id=context.project_id,
                               id=item_id).
                     delete(synchronize_session=False))
    if not deleted_count:
        return
    try:
        (model_query(context, models.Tag, session=session).
         filter_by(project_id=context.project_id,
                   item_id=item_id).
         delete(synchronize_session=False))
    except Exception:
        # NOTE(ft): ignore all exceptions because DB integrity is insignificant
        # for tags
        pass


@require_context
def restore_item(context, kind, data):
    try:
        item_ref = models.Item()
        item_ref.update({
            "project_id": context.project_id,
        })
        item_ref.id = data['id']
        item_ref.update(_pack_item_data(data))
        item_ref.save()
        return _unpack_item_data(item_ref)
    except db_exception.DBDuplicateEntry:
        raise exception.EC2DBDuplicateEntry(id=data['id'])


@require_context
def get_items(context, kind):
    return [_unpack_item_data(item)
            for item in (model_query(context, models.Item).
                         filter_by(project_id=context.project_id).
                         filter(models.Item.id.like('%s-%%' % kind)).
                         all())]


@require_context
def get_item_by_id(context, item_id):
    return (_unpack_item_data(model_query(context, models.Item).
            filter_by(project_id=context.project_id,
                      id=item_id).
            first()))


@require_context
def get_items_by_ids(context, item_ids):
    if not item_ids:
        return []
    return [_unpack_item_data(item)
            for item in (model_query(context, models.Item).
                         filter_by(project_id=context.project_id).
                         filter(models.Item.id.in_(item_ids)).
                         all())]


@require_context
def get_public_items(context, kind, item_ids=None):
    query = (model_query(context, models.Item).
             filter(models.Item.id.like('%s-%%' % kind)).
             filter(models.Item.data.like('%"is_public": True%')))
    if item_ids:
        query = query.filter(models.Item.id.in_(item_ids))
    return [_unpack_item_data(item)
            for item in query.all()]


@require_context
def get_items_ids(context, kind, item_ids=None, item_os_ids=None):
    query = (model_query(context, models.Item).
             filter(models.Item.id.like('%s-%%' % kind)))
    if item_ids:
        query = query.filter(models.Item.id.in_(item_ids))
    if item_os_ids:
        query = query.filter(models.Item.os_id.in_(item_os_ids))
    return [(item['id'], item['os_id'])
            for item in query.all()]


@require_context
def add_tags(context, tags):
    session = get_session()
    get_query = (model_query(context, models.Tag, session=session).
                 filter_by(project_id=context.project_id,
                           # NOTE(ft): item_id param name is reserved for
                           # sqlalchemy internal use
                           item_id=bindparam('tag_item_id'),
                           key=bindparam('tag_key')))
    with session.begin():
        for tag in tags:
            tag_ref = models.Tag(project_id=context.project_id,
                                 item_id=tag['item_id'],
                                 key=tag['key'],
                                 value=tag['value'])
            try:
                with session.begin(nested=True):
                    tag_ref.save(session)
            except db_exception.DBDuplicateEntry as ex:
                if ('PRIMARY' not in ex.columns and
                        ex.columns != ['project_id', 'item_id', 'key']):
                    raise
                (get_query.params(tag_item_id=tag['item_id'],
                                  tag_key=tag['key']).
                 update({'value': tag['value']}))


@require_context
def delete_tags(context, item_ids, tag_pairs=None):
    if not item_ids:
        return

    query = (model_query(context, models.Tag).
             filter_by(project_id=context.project_id).
             filter(models.Tag.item_id.in_(item_ids)))

    if tag_pairs:
        tag_fltr = None
        for tag_pair in tag_pairs:
            pair_fltr = None
            for col in ('key', 'value'):
                if col in tag_pair:
                    expr = getattr(models.Tag, col) == tag_pair[col]
                    pair_fltr = (expr if pair_fltr is None else
                                 and_(pair_fltr, expr))
            if pair_fltr is not None:
                tag_fltr = (pair_fltr if tag_fltr is None else
                            or_(tag_fltr, pair_fltr))
        if tag_fltr is not None:
            query = query.filter(tag_fltr)

    query.delete(synchronize_session=False)


@require_context
def get_tags(context, kinds=None, item_ids=None):
    query = (model_query(context, models.Tag).
             filter_by(project_id=context.project_id))
    if kinds:
        fltr = None
        for kind in kinds:
            expr = models.Tag.item_id.like('%s-%%' % kind)
            fltr = expr if fltr is None else or_(fltr, expr)
        query = query.filter(fltr)
    if item_ids:
        query = query.filter(models.Tag.item_id.in_(item_ids))
    return [dict(item_id=tag.item_id,
                 key=tag.key,
                 value=tag.value)
            for tag in query.all()]


def _pack_item_data(item_data):
    data = copy.deepcopy(item_data)
    data.pop("id", None)
    return {
        "os_id": data.pop("os_id", None),
        "vpc_id": data.pop("vpc_id", None),
        "data": json.dumps(data),
    }


def _unpack_item_data(item_ref):
    if item_ref is None:
        return None
    data = item_ref.data
    data = json.loads(data) if data is not None else {}
    data["id"] = item_ref.id
    data["os_id"] = item_ref.os_id
    data["vpc_id"] = item_ref.vpc_id
    return data
