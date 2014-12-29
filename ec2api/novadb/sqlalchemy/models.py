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
from sqlalchemy import Column, Index, Integer, Enum, String
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import DateTime, Boolean, Text
from sqlalchemy.orm import object_mapper

from ec2api.novadb.sqlalchemy import types
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


class Instance(BASE, NovaBase):
    """Represents a guest VM."""
    __tablename__ = 'instances'
    __table_args__ = (
        Index('uuid', 'uuid', unique=True),
        Index('project_id', 'project_id'),
        Index('instances_host_deleted_idx',
              'host', 'deleted'),
        Index('instances_reservation_id_idx',
              'reservation_id'),
        Index('instances_terminated_at_launched_at_idx',
              'terminated_at', 'launched_at'),
        Index('instances_uuid_deleted_idx',
              'uuid', 'deleted'),
        Index('instances_task_state_updated_at_idx',
              'task_state', 'updated_at'),
        Index('instances_host_node_deleted_idx',
              'host', 'node', 'deleted'),
        Index('instances_host_deleted_cleaned_idx',
              'host', 'deleted', 'cleaned'),
    )
    injected_files = []

    id = Column(Integer, primary_key=True, autoincrement=True)

    @property
    def name(self):
        try:
            base_name = CONF.instance_name_template % self.id
        except TypeError:
            # Support templates like "uuid-%(uuid)s", etc.
            info = {}
            # NOTE(russellb): Don't use self.iteritems() here, as it will
            # result in infinite recursion on the name property.
            for column in iter(object_mapper(self).columns):
                key = column.name
                # prevent recursion if someone specifies %(name)s
                # %(name)s will not be valid.
                if key == 'name':
                    continue
                info[key] = self[key]
            try:
                base_name = CONF.instance_name_template % info
            except KeyError:
                base_name = self.uuid
        return base_name

    @property
    def _extra_keys(self):
        return ['name']

    user_id = Column(String(255))
    project_id = Column(String(255))

    image_ref = Column(String(255))
    kernel_id = Column(String(255))
    ramdisk_id = Column(String(255))
    hostname = Column(String(255))

    launch_index = Column(Integer)
    key_name = Column(String(255))
    key_data = Column(MediumText())

    power_state = Column(Integer)
    vm_state = Column(String(255))
    task_state = Column(String(255))

    memory_mb = Column(Integer)
    vcpus = Column(Integer)
    root_gb = Column(Integer)
    ephemeral_gb = Column(Integer)
    ephemeral_key_uuid = Column(String(36))

    # This is not related to hostname, above.  It refers
    #  to the nova node.
    host = Column(String(255))  # , ForeignKey('hosts.id'))
    # To identify the "ComputeNode" which the instance resides in.
    # This equals to ComputeNode.hypervisor_hostname.
    node = Column(String(255))

    # *not* flavorid, this is the internal primary_key
    instance_type_id = Column(Integer)

    user_data = Column(MediumText())

    reservation_id = Column(String(255))

    scheduled_at = Column(DateTime)
    launched_at = Column(DateTime)
    terminated_at = Column(DateTime)

    availability_zone = Column(String(255))

    # User editable field for display in user-facing UIs
    display_name = Column(String(255))
    display_description = Column(String(255))

    # To remember on which host an instance booted.
    # An instance may have moved to another host by live migration.
    launched_on = Column(MediumText())

    # NOTE(jdillaman): locked deprecated in favor of locked_by,
    # to be removed in Icehouse
    locked = Column(Boolean)
    locked_by = Column(Enum('owner', 'admin'))

    os_type = Column(String(255))
    architecture = Column(String(255))
    vm_mode = Column(String(255))
    uuid = Column(String(36))

    root_device_name = Column(String(255))
    default_ephemeral_device = Column(String(255))
    default_swap_device = Column(String(255))
    config_drive = Column(String(255))

    # User editable field meant to represent what ip should be used
    # to connect to the instance
    access_ip_v4 = Column(types.IPAddress())
    access_ip_v6 = Column(types.IPAddress())

    auto_disk_config = Column(Boolean())
    progress = Column(Integer)

    # EC2 instance_initiated_shutdown_terminate
    # True: -> 'terminate'
    # False: -> 'stop'
    # Note(maoy): currently Nova will always stop instead of terminate
    # no matter what the flag says. So we set the default to False.
    shutdown_terminate = Column(Boolean(), default=False)

    # EC2 disable_api_termination
    disable_terminate = Column(Boolean(), default=False)

    # OpenStack compute cell name.  This will only be set at the top of
    # the cells tree and it'll be a full cell name such as 'api!hop1!hop2'
    cell_name = Column(String(255))
    internal_id = Column(Integer)

    # Records whether an instance has been deleted from disk
    cleaned = Column(Integer, default=0)


class BlockDeviceMapping(BASE, NovaBase):
    """Represents block device mapping that is defined by EC2."""
    __tablename__ = "block_device_mapping"
    __table_args__ = (
        Index('snapshot_id', 'snapshot_id'),
        Index('volume_id', 'volume_id'),
        Index('block_device_mapping_instance_uuid_device_name_idx',
              'instance_uuid', 'device_name'),
        Index('block_device_mapping_instance_uuid_volume_id_idx',
              'instance_uuid', 'volume_id'),
        Index('block_device_mapping_instance_uuid_idx', 'instance_uuid'),
        # TODO(sshturm) Should be dropped. `virtual_name` was dropped
        # in 186 migration,
        # Duplicates `block_device_mapping_instance_uuid_device_name_idx`index.
        Index("block_device_mapping_instance_uuid_virtual_name"
              "_device_name_idx", 'instance_uuid', 'device_name'),
    )
    id = Column(Integer, primary_key=True, autoincrement=True)

    instance_uuid = Column(String(36))
    source_type = Column(String(255))
    destination_type = Column(String(255))
    guest_format = Column(String(255))
    device_type = Column(String(255))
    disk_bus = Column(String(255))

    boot_index = Column(Integer)

    device_name = Column(String(255))

    # default=False for compatibility of the existing code.
    # With EC2 API,
    # default True for ami specified device.
    # default False for created with other timing.
    # TODO(sshturm) add default in db
    delete_on_termination = Column(Boolean, default=False)

    snapshot_id = Column(String(36))

    volume_id = Column(String(36))
    volume_size = Column(Integer)

    image_id = Column(String(36))

    # for no device to suppress devices.
    no_device = Column(Boolean)

    connection_info = Column(MediumText())
