# Copyright 2014 OpenStack Foundation
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

import functools
import logging
import sys
import time
import traceback

import botocore.exceptions
from oslo_log import log
from tempest_lib import base
from tempest_lib import exceptions
import testtools

from ec2api.tests.functional import botocoreclient
from ec2api.tests.functional import config as cfg

CONF = cfg.CONF
LOG = log.getLogger(__name__)

logging.getLogger('botocore').setLevel(logging.INFO)
logging.getLogger(
    'botocore.vendored.requests.packages.urllib3.connectionpool'
).setLevel(logging.WARNING)
logging.getLogger('paramiko.transport').setLevel(logging.WARNING)


class EC2Waiter(object):

    def __init__(self, wait_func):
        self.wait_func = wait_func
        self.default_timeout = CONF.aws.build_timeout
        self.default_check_interval = CONF.aws.build_interval

    def _state_wait(self, f, f_args=None, f_kwargs=None,
                    final_set=set(), error_set=('error')):
        if not isinstance(final_set, set):
            final_set = set((final_set,))
        if not isinstance(error_set, set):
            error_set = set((error_set,))
        interval = self.default_check_interval
        start_time = time.time()
        args = f_args if f_args is not None else []
        kwargs = f_kwargs if f_kwargs is not None else {}
        try:
            old_status = status = f(*args, **kwargs)
        except exceptions.NotFound:
            old_status = status = "NotFound"
        while True:
            if status != old_status:
                LOG.info('State transition "%s" ==> "%s" %d second',
                         old_status, status, time.time() - start_time)
            if status in final_set:
                return status
            if error_set is not None and status in error_set:
                raise testtools.TestCase.failureException(
                    'State changes to error state! '
                    'While waiting for %s at "%s"' %
                    (final_set, status))
            dtime = time.time() - start_time
            if dtime > self.default_timeout:
                raise testtools.TestCase.failureException(
                    'State change timeout exceeded! '
                    '(%ds) While waiting for %s at "%s"' %
                    (dtime, final_set, status))
            time.sleep(interval)
            interval += self.default_check_interval
            old_status = status
            try:
                status = f(*args, **kwargs)
            except exceptions.NotFound:
                status = "NotFound"

    def _state_wait_gone(self, f, f_args=None, f_kwargs=None):
        interval = self.default_check_interval
        start_time = time.time()
        args = f_args if f_args is not None else []
        kwargs = f_kwargs if f_kwargs is not None else {}
        try:
            old_status = status = f(*args, **kwargs)
            while True:
                if status != old_status:
                    LOG.info('State transition "%s" ==> "%s" %d second',
                             old_status, status, time.time() - start_time)
                dtime = time.time() - start_time
                if dtime > self.default_timeout:
                    raise testtools.TestCase.failureException(
                        "State change timeout exceeded while waiting"
                        " for deleting")
                time.sleep(interval)
                interval += self.default_check_interval
                old_status = status
                status = f(*args, **kwargs)
        except exceptions.NotFound:
            pass

    def wait_available(self, obj_id, final_set=('available')):
        self._state_wait(self.wait_func, f_args=[obj_id],
                         final_set=final_set)

    def wait_delete(self, obj_id):
        self._state_wait_gone(self.wait_func, f_args=[obj_id])

    def wait_no_exception(self, *args, **kwargs):
        interval = self.default_check_interval
        start_time = time.time()
        while True:
            try:
                self.wait_func(*args, **kwargs)
                return
            except Exception:
                pass

            dtime = time.time() - start_time
            if dtime > self.default_timeout:
                raise testtools.TestCase.failureException(
                    "Timeout exceeded while waiting")
            time.sleep(interval)
            interval += self.default_check_interval


def safe_setup(f):
    """A decorator used to wrap the setUpClass for safe setup."""

    def decorator(cls):
        try:
            f(cls)
        except Exception as se:
            exc_info = sys.exc_info()
            LOG.exception("setUpClass failed: %s" % se)
            try:
                cls.tearDownClass()
            except Exception as te:
                LOG.exception("tearDownClass failed: %s" % te)
            raise exc_info[1], None, exc_info[2]

    return decorator


class TesterStateHolder(object):

    ec2_client = None
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(TesterStateHolder, cls).__new__(
                cls, *args, **kwargs)
        return cls._instance

    _vpc_enabled = None

    def get_vpc_enabled(self):
        if self._vpc_enabled:
            return self._vpc_enabled

        self._vpc_enabled = False
        data = self.ec2_client.describe_account_attributes()
        for item in data.get('AccountAttributes', []):
            if item['AttributeName'] == 'supported-platforms':
                for value in item['AttributeValues']:
                    if value['AttributeValue'] == 'VPC':
                        self._vpc_enabled = True

        return self._vpc_enabled


def skip_without_vpc(*args, **kwargs):
    """A decorator useful to skip tests if VPC is not supported."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            if not TesterStateHolder().get_vpc_enabled():
                msg = "Skipped because VPC is disabled"
                raise testtools.TestCase.skipException(msg)
            return f(self, *func_args, **func_kwargs)
        return wrapper
    return decorator


class EC2TestCase(base.BaseTestCase):
    """Recommended to use as base class for boto related test."""

    # The trash contains cleanup functions and paramaters in tuples
    # (function, *args, **kwargs)
    _global_resource_trash_bin = {}
    _global_sequence = -1

    @classmethod
    @safe_setup
    def setUpClass(cls):
        super(EC2TestCase, cls).setUpClass()
        cls.client = botocoreclient._get_ec2_client(
            CONF.aws.ec2_url, CONF.aws.aws_region,
            CONF.aws.aws_access, CONF.aws.aws_secret)
        TesterStateHolder().ec2_client = cls.client

    @classmethod
    def addResourceCleanUpStatic(cls, function, *args, **kwargs):
        """Adds CleanUp callable, used by tearDownClass.

        Recommended to a use (deep)copy on the mutable args.
        """
        tb = traceback.extract_stack(limit=2)
        cls._global_sequence = cls._global_sequence + 1
        cls._global_resource_trash_bin[cls._global_sequence] = (function,
                                                                args, kwargs,
                                                                tb[0])
        return cls._global_sequence

    def setUp(self):
        super(EC2TestCase, self).setUp()
        self._resource_trash_bin = {}
        self._sequence = -1

    def tearDown(self):
        fail_count = self.cleanUp(self._resource_trash_bin)
        super(EC2TestCase, self).tearDown()
        if fail_count:
            raise exceptions.TempestException("%d cleanUp operation failed"
                                              % fail_count)

    def addResourceCleanUp(self, function, *args, **kwargs):
        """Adds CleanUp callable, used by tearDown.

        Recommended to a use (deep)copy on the mutable args.
        """
        tb = traceback.extract_stack(limit=2)[0]
        self._sequence = self._sequence + 1
        self._resource_trash_bin[self._sequence] = (function, args, kwargs, tb)

        LOG.debug("For cleaning up: %s\n    From: %s" %
                  (self.friendly_function_call_str(function, *args, **kwargs),
                   str((tb[0], tb[1], tb[2]))))

        return self._sequence

    def cancelResourceCleanUp(self, key):
        """Cancel Clean up request."""
        del self._resource_trash_bin[key]

    # NOTE(andrey-mp): if ERROR in responce_code then skip logging
    _VALID_CLEANUP_ERRORS = [
        'NotFound',
        'Gateway.NotAttached'
    ]

    _CLEANUP_WAITERS = {
        'delete_vpc': (
            'get_vpc_waiter',
            lambda kwargs: kwargs['VpcId']),
        'delete_subnet': (
            'get_subnet_waiter',
            lambda kwargs: kwargs['SubnetId']),
        'delete_network_interface': (
            'get_network_interface_waiter',
            lambda kwargs: kwargs['NetworkInterfaceId']),
        'terminate_instances': (
            'get_instance_waiter',
            lambda kwargs: kwargs['InstanceIds'][0]),
        'delete_volume': (
            'get_volume_waiter',
            lambda kwargs: kwargs['VolumeId']),
        'detach_volume': (
            'get_volume_attachment_waiter',
            lambda kwargs: kwargs['VolumeId']),
        'delete_snapshot': (
            'get_snapshot_waiter',
            lambda kwargs: kwargs['SnapshotId']),
        'deregister_image': (
            'get_image_waiter',
            lambda kwargs: kwargs['ImageId']),
    }

    @classmethod
    def tearDownClass(cls):
        fail_count = cls.cleanUp(cls._global_resource_trash_bin)
        super(EC2TestCase, cls).tearDownClass()
        if fail_count:
            raise exceptions.TempestException("%d cleanUp operation failed"
                                              % fail_count)

    @classmethod
    def cleanUp(cls, trash_bin):
        """Calls the callables added by addResourceCleanUp,

        when you overwire this function dont't forget to call this too.
        """
        fail_count = 0
        trash_keys = sorted(trash_bin, reverse=True)
        for key in trash_keys:
            (function, pos_args, kw_args, tb) = trash_bin[key]
            try:
                LOG.debug("Cleaning up: %s\n    From: %s" %
                          (cls.friendly_function_call_str(function, *pos_args,
                                                          **kw_args),
                           str((tb[0], tb[1], tb[2]))))
                cls.cleanUpItem(function, pos_args, kw_args)
            except BaseException:
                fail_count += 1
                LOG.exception('Failure in cleanup')
            finally:
                del trash_bin[key]
        return fail_count

    @classmethod
    def cleanUpItem(cls, function, pos_args, kw_args):
        try:
            function(*pos_args, **kw_args)
            if function.__name__ in cls._CLEANUP_WAITERS:
                (waiter, obj_id) = cls._CLEANUP_WAITERS[function.__name__]
                waiter = getattr(cls, waiter)
                obj_id = obj_id(kw_args)
                waiter().wait_delete(obj_id)
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            for err in cls._VALID_CLEANUP_ERRORS:
                if err in error_code:
                    break
            else:
                LOG.error("Cleanup failed: %s", e, exc_info=True)

    @classmethod
    def friendly_function_name_simple(cls, call_able):
        name = ""
        if hasattr(call_able, "im_class"):
            name += call_able.im_class.__name__ + "."
        name += call_able.__name__
        return name

    @classmethod
    def friendly_function_call_str(cls, call_able, *args, **kwargs):
        string = cls.friendly_function_name_simple(call_able)
        string += "(" + ", ".join(map(str, args))
        if len(kwargs):
            if len(args):
                string += ", "
        string += ", ".join("=".join(map(str, (key, value)))
                            for (key, value) in kwargs.items())
        return string + ")"

    @classmethod
    def _vpc_get_state(cls, vpc_id):
        try:
            data = cls.client.describe_vpcs(VpcIds=[vpc_id])
            if not data['Vpcs']:
                raise exceptions.NotFound()
            return data['Vpcs'][0]['State']
        except botocore.exceptions.ClientError:
            error_code = sys.exc_info()[1].response['Error']['Code']
            if error_code == 'InvalidVpcID.NotFound':
                raise exceptions.NotFound()
            raise

    @classmethod
    def get_vpc_waiter(cls):
        return EC2Waiter(cls._vpc_get_state)

    @classmethod
    def _subnet_get_state(cls, subnet_id):
        try:
            data = cls.client.describe_subnets(SubnetIds=[subnet_id])
            if not data['Subnets']:
                raise exceptions.NotFound()
            return data['Subnets'][0]['State']
        except botocore.exceptions.ClientError:
            error_code = sys.exc_info()[1].response['Error']['Code']
            if error_code == 'InvalidSubnetID.NotFound':
                raise exceptions.NotFound()
            raise

    @classmethod
    def get_subnet_waiter(cls):
        return EC2Waiter(cls._subnet_get_state)

    @classmethod
    def _instance_get_state(cls, instance_id):
        try:
            data = cls.client.describe_instances(InstanceIds=[instance_id])
            if not data['Reservations']:
                raise exceptions.NotFound()
            if not data['Reservations'][0]['Instances']:
                raise exceptions.NotFound()
            state = data['Reservations'][0]['Instances'][0]['State']['Name']
            if state != 'terminated':
                return state
            raise exceptions.NotFound()
        except botocore.exceptions.ClientError:
            error_code = sys.exc_info()[1].response['Error']['Code']
            if error_code == 'InvalidInstanceID.NotFound':
                raise exceptions.NotFound()
            raise

    @classmethod
    def get_instance_waiter(cls):
        return EC2Waiter(cls._instance_get_state)

    @classmethod
    def _network_interface_get_state(cls, ni_id):
        try:
            data = cls.client.describe_network_interfaces(
                NetworkInterfaceIds=[ni_id])
            if not data['NetworkInterfaces']:
                raise exceptions.NotFound()
            return data['NetworkInterfaces'][0]['Status']
        except botocore.exceptions.ClientError:
            error_code = sys.exc_info()[1].response['Error']['Code']
            if error_code == 'InvalidNetworkInterfaceID.NotFound':
                raise exceptions.NotFound()
            raise

    @classmethod
    def get_network_interface_waiter(cls):
        return EC2Waiter(cls._network_interface_get_state)

    @classmethod
    def _volume_get_state(cls, volume_id):
        try:
            data = cls.client.describe_volumes(VolumeIds=[volume_id])
            if not data['Volumes']:
                raise exceptions.NotFound()
            return data['Volumes'][0]['State']
        except botocore.exceptions.ClientError:
            error_code = sys.exc_info()[1].response['Error']['Code']
            if error_code == 'InvalidVolume.NotFound':
                raise exceptions.NotFound()
            raise

    @classmethod
    def get_volume_waiter(cls):
        return EC2Waiter(cls._volume_get_state)

    @classmethod
    def _volume_attachment_get_state(cls, volume_id):
        try:
            data = cls.client.describe_volumes(VolumeIds=[volume_id])
            volume = data['Volumes'][0]
            if 'Attachments' in volume and len(volume['Attachments']) > 0:
                return volume['Attachments'][0]['State']
            raise exceptions.NotFound()
        except botocore.exceptions.ClientError:
            error_code = sys.exc_info()[1].response['Error']['Code']
            if error_code == 'InvalidVolume.NotFound':
                raise exceptions.NotFound()
            raise

    @classmethod
    def get_volume_attachment_waiter(cls):
        return EC2Waiter(cls._volume_attachment_get_state)

    @classmethod
    def _snapshot_get_state(cls, volume_id):
        try:
            data = cls.client.describe_snapshots(SnapshotIds=[volume_id])
            if not data['Snapshots']:
                raise exceptions.NotFound()
            return data['Snapshots'][0]['State']
        except botocore.exceptions.ClientError:
            error_code = sys.exc_info()[1].response['Error']['Code']
            if error_code == 'InvalidSnapshot.NotFound':
                raise exceptions.NotFound()
            raise

    @classmethod
    def get_snapshot_waiter(cls):
        return EC2Waiter(cls._snapshot_get_state)

    @classmethod
    def _image_get_state(cls, image_id):
        try:
            data = cls.client.describe_images(ImageIds=[image_id])
            if not data['Images']:
                raise exceptions.NotFound()
            return data['Images'][0]['State']
        except botocore.exceptions.ClientError:
            error_code = sys.exc_info()[1].response['Error']['Code']
            if error_code == 'InvalidAMIID.NotFound':
                raise exceptions.NotFound()
            raise

    @classmethod
    def get_image_waiter(cls):
        return EC2Waiter(cls._image_get_state)

    def assertEmpty(self, list_obj, msg=None):
        self.assertTrue(len(list_obj) == 0, msg)

    def assertNotEmpty(self, list_obj, msg=None):
        self.assertTrue(len(list_obj) > 0, msg)

    def assertRaises(self, error_code, fn, rollback_fn=None, **kwargs):
        try:
            fn_data = fn(**kwargs)
            if rollback_fn:
                try:
                    rollback_fn(fn_data)
                except Exception:
                    LOG.exception('Rollback failed')
            msg = ("%s hasn't returned exception for params %s"
                   % (str(fn.__name__), str(kwargs)))
            raise self.failureException(msg)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(error_code, e.response['Error']['Code'])

    # NOTE(andrey-mp): Helpers zone

    def get_instance(self, instance_id):
        data = self.client.describe_instances(InstanceIds=[instance_id])
        self.assertEqual(1, len(data.get('Reservations', [])))
        instances = data['Reservations'][0].get('Instances', [])
        self.assertEqual(1, len(instances))
        return instances[0]

    def get_instance_bdm(self, instance_id, device_name):
        """

        device_name=None means getting bdm of root instance device
        """
        instance = self.get_instance(instance_id)
        if not device_name:
            device_name = instance.get('RootDeviceName')
        if not device_name:
            return None
        bdms = instance.get('BlockDeviceMappings')
        if bdms is None:
            return None
        bdt = [bdt for bdt in bdms if bdt['DeviceName'] == device_name]
        return None if len(bdt) == 0 else bdt[0]

    def run_instance(self, clean_dict=None, **kwargs):
        kwargs.setdefault('ImageId', CONF.aws.image_id)
        kwargs.setdefault('InstanceType', CONF.aws.instance_type)
        kwargs.setdefault('Placement', {'AvailabilityZone': CONF.aws.aws_zone})
        kwargs['MinCount'] = 1
        kwargs['MaxCount'] = 1
        data = self.client.run_instances(*[], **kwargs)
        instance_id = data['Instances'][0]['InstanceId']
        res_clean = self.addResourceCleanUp(self.client.terminate_instances,
                                            InstanceIds=[instance_id])
        self.get_instance_waiter().wait_available(instance_id,
                                                  final_set=('running'))

        # NOTE(andrey-mp): openstack has a bug - it doesn't delete volume
        # that is created from EBS image
        volume_ids = list()
        instance = self.get_instance(instance_id)
        bdms = instance.get('BlockDeviceMappings')
        if bdms is None:
            return instance_id
        for bdm in bdms:
            if 'Ebs' not in bdm:
                continue
            if not bdm['Ebs'].get('DeleteOnTermination', False):
                volume_id = bdm['Ebs'].get('VolumeId')
                volume_ids.append(volume_id)
        if volume_ids:
            # NOTE(andrey-mp): instance must be deleted first.
            self.cancelResourceCleanUp(res_clean)
            for volume_id in volume_ids:
                self.addResourceCleanUp(self.client.delete_volume,
                                        VolumeId=volume_id)
            res_clean = self.addResourceCleanUp(
                self.client.terminate_instances, InstanceIds=[instance_id])

        if clean_dict is not None:
            clean_dict['instance'] = res_clean

        return instance_id
