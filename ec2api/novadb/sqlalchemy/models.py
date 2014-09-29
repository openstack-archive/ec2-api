# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Piston Cloud Computing, Inc.
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
"""
SQLAlchemy models for nova data.
"""

from oslo.config import cfg
from sqlalchemy import Column, Index, Integer, String
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Text

from ec2api.openstack.common.db.sqlalchemy import models

CONF = cfg.CONF
BASE = declarative_base()


def MediumText():
    return Text().with_variant(MEDIUMTEXT(), 'mysql')


class NovaBase(models.SoftDeleteMixin,
               models.TimestampMixin,
               models.ModelBase):
    metadata = None

    def save(self, session=None):
        from ec2api.novadb.sqlalchemy import api

        if session is None:
            session = api.get_session()

        super(NovaBase, self).save(session=session)


class S3Image(BASE, NovaBase):
    """Compatibility layer for the S3 image service talking to Glance."""
    __tablename__ = 's3_images'
    __table_args__ = ()
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), nullable=False)


class VolumeIdMapping(BASE, NovaBase):
    """Compatibility layer for the EC2 volume service."""
    __tablename__ = 'volume_id_mappings'
    __table_args__ = ()
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), nullable=False)


class SnapshotIdMapping(BASE, NovaBase):
    """Compatibility layer for the EC2 snapshot service."""
    __tablename__ = 'snapshot_id_mappings'
    __table_args__ = ()
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), nullable=False)


class InstanceIdMapping(BASE, NovaBase):
    """Compatibility layer for the EC2 instance service."""
    __tablename__ = 'instance_id_mappings'
    __table_args__ = (
        Index('ix_instance_id_mappings_uuid', 'uuid'),
    )
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), nullable=False)
