truncate table ec2api.items;
truncate table ec2api.tags;

insert into ec2api.items (project_id, id, os_id, data)
select
  i.owner,
  concat(if(i.container_format in ("ari","aki"), i.container_format, "ami"),
    "-", lpad(hex(m.id), 8, "0")),
  m.uuid,
  concat("{'is_public': ", if(i.is_public=1, "True", "False"), "}")
from nova.s3_images m join glance.images i on i.id=m.uuid and i.deleted=0;

insert into ec2api.items (project_id, id, os_id, data)
select v.project_id, concat("vol-", lpad(hex(m.id), 8, "0")), m.uuid, "{}"
from nova.volume_id_mappings m join cinder.volumes v on v.id=m.uuid and v.deleted=0;

insert into ec2api.items (project_id, id, os_id, data)
select s.project_id, concat("snap-", lpad(hex(m.id), 8, "0")), m.uuid, "{}"
from nova.snapshot_id_mappings m join cinder.snapshots s on s.id=m.uuid and s.deleted=0;

insert into ec2api.items (project_id, id, os_id, data)
select i.project_id, concat("i-", lpad(hex(m.id), 8, "0")), m.uuid,
  concat("{'reservation_id': '", i.reservation_id, "', 'launch_index': ", i.launch_index,
    ifnull(concat(", 'client_token': '", ism.value, "'}"), "}"))
from nova.instance_id_mappings m join nova.instances i on i.uuid=m.uuid and i.deleted=0
  left outer join nova.instance_system_metadata ism
    on ism.instance_uuid=i.uuid and ism.key="EC2_client_token" and ism.deleted=0;

insert into ec2api.tags (project_id, item_id, `key`, value)
select i.project_id, concat("i-", lpad(hex(m.id), 8, "0")), im.key, im.value
from nova.instance_id_mappings m join nova.instances i on i.uuid=m.uuid and i.deleted=0
  join nova.instance_metadata im on im.instance_uuid=i.uuid and im.deleted=0;

