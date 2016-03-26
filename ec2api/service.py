# Copyright 2014
# The Cloudscaling Group, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generic Node base class for all workers that run on hosts."""

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service
from oslo_utils import importutils

from ec2api import exception
from ec2api.i18n import _
from ec2api import wsgi

LOG = logging.getLogger(__name__)

service_opts = [
    cfg.StrOpt('ec2api_listen',
               default="0.0.0.0",
               help='The IP address on which the EC2 API will listen.'),
    cfg.IntOpt('ec2api_listen_port',
               default=8788,
               help='The port on which the EC2 API will listen.'),
    cfg.BoolOpt('ec2api_use_ssl',
                default=False,
                help='Enable ssl connections or not for EC2 API'),
    cfg.IntOpt('ec2api_workers',
               help='Number of workers for EC2 API service. The default will '
                    'be equal to the number of CPUs available.'),
    cfg.StrOpt('metadata_listen',
               default="0.0.0.0",
               help='The IP address on which the metadata API will listen.'),
    cfg.IntOpt('metadata_listen_port',
               default=8789,
               help='The port on which the metadata API will listen.'),
    cfg.BoolOpt('metadata_use_ssl',
                default=False,
                help='Enable ssl connections or not for EC2 API Metadata'),
    cfg.IntOpt('metadata_workers',
               help='Number of workers for metadata service. The default will '
                    'be the number of CPUs available.'),
    cfg.IntOpt('service_down_time',
               default=60,
               help='Maximum time since last check-in for up service'),
]

CONF = cfg.CONF
CONF.register_opts(service_opts)


class WSGIService(service.ServiceBase):
    """Provides ability to launch API from a 'paste' configuration."""

    def __init__(self, name, loader=None, max_url_len=None):
        """Initialize, but do not start the WSGI server.

        :param name: The name of the WSGI server given to the loader.
        :param loader: Loads the WSGI application using the given name.
        :returns: None

        """
        self.name = name
        self.manager = self._get_manager()
        self.loader = loader or wsgi.Loader()
        self.app = self.loader.load_app(name)
        self.host = getattr(CONF, '%s_listen' % name, "0.0.0.0")
        self.port = getattr(CONF, '%s_listen_port' % name, 0)
        self.use_ssl = getattr(CONF, '%s_use_ssl' % name, False)
        self.workers = (getattr(CONF, '%s_workers' % name, None) or
                        processutils.get_worker_count())
        if self.workers and self.workers < 1:
            worker_name = '%s_workers' % name
            msg = (_("%(worker_name)s value of %(workers)s is invalid, "
                     "must be greater than 0") %
                   {'worker_name': worker_name,
                    'workers': str(self.workers)})
            raise exception.InvalidInput(msg)
        self.server = wsgi.Server(name,
                                  self.app,
                                  host=self.host,
                                  port=self.port,
                                  use_ssl=self.use_ssl,
                                  max_url_len=max_url_len)
        # Pull back actual port used
        self.port = self.server.port

    def reset(self):
        """Reset server greenpool size to default.

        :returns: None

        """
        self.server.reset()

    def _get_manager(self):
        """Initialize a Manager object appropriate for this service.

        Use the service name to look up a Manager subclass from the
        configuration and initialize an instance. If no class name
        is configured, just return None.

        :returns: a Manager instance, or None.

        """
        fl = '%s_manager' % self.name
        if fl not in CONF:
            return None

        manager_class_name = CONF.get(fl, None)
        if not manager_class_name:
            return None

        manager_class = importutils.import_class(manager_class_name)
        return manager_class()

    def start(self):
        """Start serving this service using loaded configuration.

        Also, retrieve updated port number in case '0' was passed in, which
        indicates a random port should be used.

        :returns: None

        """
        if self.manager:
            self.manager.init_host()
            self.manager.pre_start_hook()
        self.server.start()
        if self.manager:
            self.manager.post_start_hook()

    def stop(self):
        """Stop serving this API.

        :returns: None

        """
        self.server.stop()

    def wait(self):
        """Wait for the service to stop serving this API.

        :returns: None

        """
        self.server.wait()


# NOTE(vish): the global launcher is to maintain the existing
#             functionality of calling service.serve +
#             service.wait
_launcher = None


def serve(server, workers=None):
    global _launcher
    if _launcher:
        raise RuntimeError(_('serve() can only be called once'))

    _launcher = service.launch(CONF, server, workers=workers)


def wait():
    _launcher.wait()
