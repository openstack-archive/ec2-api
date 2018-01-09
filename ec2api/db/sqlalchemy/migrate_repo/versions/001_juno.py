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

from sqlalchemy import Column, MetaData
from sqlalchemy import PrimaryKeyConstraint, String, Table, Text
from sqlalchemy import UniqueConstraint


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    items = Table('items', meta,
        Column("id", String(length=30)),
        Column("project_id", String(length=64)),
        Column("vpc_id", String(length=12)),
        Column("os_id", String(length=36)),
        Column("data", Text()),
        PrimaryKeyConstraint('id'),
        UniqueConstraint('os_id', name='items_os_id_idx'),
        mysql_engine="InnoDB",
        mysql_charset="utf8"
    )
    items.create()

    tags = Table('tags', meta,
        Column("project_id", String(length=64)),
        Column("item_id", String(length=30)),
        Column("key", String(length=127)),
        Column("value", String(length=255)),
        PrimaryKeyConstraint('project_id', 'item_id', 'key'),
        mysql_engine="InnoDB",
        mysql_charset="utf8"
    )
    tags.create()

    if migrate_engine.name == "mysql":
        # In Folsom we explicitly converted migrate_version to UTF8.
        sql = "ALTER TABLE migrate_version CONVERT TO CHARACTER SET utf8;"
        migrate_engine.execute(sql)
        # Set default DB charset to UTF8.
        sql = (" ALTER DATABASE %s DEFAULT CHARACTER SET utf8;" %
               migrate_engine.url.database)
        migrate_engine.execute(sql)


def downgrade(migrate_engine):
    raise NotImplementedError("Downgrade from Juno is unsupported.")
