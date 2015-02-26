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

"""
SQLAlchemy models for ec2api data.
"""

from oslo_db.sqlalchemy import models
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, PrimaryKeyConstraint, String, Text
from sqlalchemy import UniqueConstraint

BASE = declarative_base()

ITEMS_OS_ID_INDEX_NAME = 'items_os_id_idx'


class EC2Base(models.ModelBase):
    metadata = None

    def save(self, session=None):
        from ec2api.db.sqlalchemy import api

        if session is None:
            session = api.get_session()

        super(EC2Base, self).save(session=session)


class Item(BASE, EC2Base):
    __tablename__ = 'items'
    __table_args__ = (
        PrimaryKeyConstraint('id'),
        UniqueConstraint('os_id', name=ITEMS_OS_ID_INDEX_NAME),
    )
    id = Column(String(length=30))
    project_id = Column(String(length=64))
    vpc_id = Column(String(length=12))
    os_id = Column(String(length=36))
    data = Column(Text())


class Tag(BASE, EC2Base):
    __tablename__ = 'tags'
    __table_args__ = (
        PrimaryKeyConstraint('project_id', 'item_id', 'key'),
    )
    project_id = Column(String(length=64))
    item_id = Column(String(length=30))
    key = Column(String(length=127))
    value = Column(String(length=255))
