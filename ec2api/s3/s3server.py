# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2010 OpenStack Foundation
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Implementation of an S3-like storage server based on local files.

Useful to test features that will eventually run on S3, or if you want to
run something locally that was once running on S3.

We don't support all the features of S3, but it does work with the
standard S3 client for the most basic semantics. To use the standard
S3 client with this module::

    c = S3.AWSAuthConnection("", "", server="localhost", port=8888,
                             is_secure=False)
    c.create_bucket("mybucket")
    c.put("mybucket", "mykey", "a value")
    print c.get("mybucket", "mykey").body

"""

import bisect
import datetime
import os.path

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils
import routes
from urllib import parse
import webob

from ec2api import paths
from ec2api import utils
from ec2api import wsgi


s3_opts = [
    cfg.StrOpt('buckets_path',
               default=paths.state_path_def('buckets'),
               help='Path to S3 buckets'),
    cfg.StrOpt('s3_listen',
               default="0.0.0.0",
               help='IP address for S3 API to listen'),
    cfg.IntOpt('s3_listen_port',
               default=3334,
               help='Port for S3 API to listen'),
]

CONF = cfg.CONF
CONF.register_opts(s3_opts)
LOG = logging.getLogger(__name__)


def get_wsgi_server():
    return wsgi.Server("S3 Objectstore",
                       S3Application(CONF.buckets_path),
                       port=CONF.s3_listen_port,
                       host=CONF.s3_listen)


class S3Application(wsgi.Router):
    """Implementation of an S3-like storage server based on local files.

    If bucket depth is given, we break files up into multiple directories
    to prevent hitting file system limits for number of files in each
    directories. 1 means one level of directories, 2 means 2, etc.

    """

    def __init__(self, root_directory, bucket_depth=0, mapper=None):
        if mapper is None:
            mapper = routes.Mapper()

        mapper.connect(
                '/',
                controller=lambda *a, **kw: RootHandler(self)(*a, **kw))
        mapper.connect(
                '/{bucket}/{object_name}',
                controller=lambda *a, **kw: ObjectHandler(self)(*a, **kw))
        mapper.connect(
                '/{bucket_name}',
                controller=lambda *a, **kw: BucketHandler(self)(*a, **kw),
                requirements={'bucket_name': '[^/]+/?'})
        self.directory = os.path.abspath(root_directory)
        fileutils.ensure_tree(self.directory)
        self.bucket_depth = bucket_depth
        super(S3Application, self).__init__(mapper)


class BaseRequestHandler(object):
    """Base class emulating Tornado's web framework pattern in WSGI.

    This is a direct port of Tornado's implementation, so some key decisions
    about how the code interacts have already been chosen.

    The two most common ways of designing web frameworks can be
    classified as async object-oriented and sync functional.

    Tornado's is on the OO side because a response is built up in and using
    the shared state of an object and one of the object's methods will
    eventually trigger the "finishing" of the response asynchronously.

    Most WSGI stuff is in the functional side, we pass a request object to
    every call down a chain and the eventual return value will be a response.

    Part of the function of the routing code in S3Application as well as the
    code in BaseRequestHandler's __call__ method is to merge those two styles
    together enough that the Tornado code can work without extensive
    modifications.

    To do that it needs to give the Tornado-style code clean objects that it
    can modify the state of for each request that is processed, so we use a
    very simple factory lambda to create new state for each request, that's
    the stuff in the router, and when we let the Tornado code modify that
    object to handle the request, then we return the response it generated.
    This wouldn't work the same if Tornado was being more async'y and doing
    other callbacks throughout the process, but since Tornado is being
    relatively simple here we can be satisfied that the response will be
    complete by the end of the get/post method.

    """

    def __init__(self, application):
        self.application = application

    @webob.dec.wsgify
    def __call__(self, request):
        try:
            method = request.method.lower()
            f = getattr(self, method, self.invalid)
            self.request = request
            self.response = webob.Response()
            params = request.environ['wsgiorg.routing_args'][1]
            del params['controller']
            f(**params)
        except Exception:
            # TODO(andrey-mp): improve this block
            LOG.exception('Unhandled error')
            self.render_xml({"Error": {
                "Code": "BadRequest",
                "Message": "Unhandled error"
            }})
            self.set_status(501)

        return self.response

    def get_argument(self, arg, default):
        return self.request.params.get(arg, default)

    def set_header(self, header, value):
        self.response.headers[header] = value

    def set_status(self, status_code):
        self.response.status = status_code

    def set_404(self):
        self.render_xml({"Error": {
            "Code": "NoSuchKey",
            "Message": "The resource you requested does not exist"
        }})
        self.set_status(404)

    def finish(self, body=''):
        if isinstance(body, bytes):
            self.response.body = body
        else:
            self.response.body = body.encode("utf-8")

    def invalid(self, **kwargs):
        pass

    def render_xml(self, value):
        assert isinstance(value, dict) and len(value) == 1
        self.set_header("Content-Type", "application/xml; charset=UTF-8")
        name = next(iter(value.keys()))
        parts = []
        parts.append('<' + name +
                     ' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">')
        self._render_parts(next(iter(value.values())), parts)
        parts.append('</' + name + '>')
        self.finish('<?xml version="1.0" encoding="UTF-8"?>\n' +
                    ''.join(parts))

    def _render_parts(self, value, parts=None):
        if not parts:
            parts = []

        if isinstance(value, str):
            parts.append(utils.xhtml_escape(value))
        elif isinstance(value, int):
            parts.append(str(value))
        elif isinstance(value, datetime.datetime):
            parts.append(value.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        elif isinstance(value, dict):
            for name, subvalue in value.items():
                if not isinstance(subvalue, list):
                    subvalue = [subvalue]
                for subsubvalue in subvalue:
                    parts.append('<' + name + '>')
                    self._render_parts(subsubvalue, parts)
                    parts.append('</' + name + '>')
        else:
            raise Exception("Unknown S3 value type %r", value)

    def _object_path(self, bucket, object_name):
        if self.application.bucket_depth < 1:
            return os.path.abspath(os.path.join(
                self.application.directory, bucket, object_name))
        name_hash = utils.get_hash_str(object_name)
        path = os.path.abspath(os.path.join(
            self.application.directory, bucket))
        for i in range(self.application.bucket_depth):
            path = os.path.join(path, name_hash[:2 * (i + 1)])
        return os.path.join(path, object_name)


class RootHandler(BaseRequestHandler):
    def get(self):
        names = os.listdir(self.application.directory)
        buckets = []
        for name in names:
            path = os.path.join(self.application.directory, name)
            info = os.stat(path)
            buckets.append({
                "Name": name,
                "CreationDate": datetime.datetime.utcfromtimestamp(
                    info.st_ctime),
            })
        self.render_xml({"ListAllMyBucketsResult": {
            "Buckets": {"Bucket": buckets},
        }})


class BucketHandler(BaseRequestHandler):
    def get(self, bucket_name):
        prefix = self.get_argument("prefix", u"")
        marker = self.get_argument("marker", u"")
        max_keys = int(self.get_argument("max-keys", 50000))
        path = os.path.abspath(os.path.join(self.application.directory,
                                            bucket_name))
        terse = int(self.get_argument("terse", 0))
        if (not path.startswith(self.application.directory) or
                not os.path.isdir(path)):
            self.set_404()
            return
        object_names = []
        for root, _dirs, files in os.walk(path):
            for file_name in files:
                object_names.append(os.path.join(root, file_name))
        skip = len(path) + 1
        for i in range(self.application.bucket_depth):
            skip += 2 * (i + 1) + 1
        object_names = [n[skip:] for n in object_names]
        object_names.sort()
        contents = []

        start_pos = 0
        if marker:
            start_pos = bisect.bisect_right(object_names, marker, start_pos)
        if prefix:
            start_pos = bisect.bisect_left(object_names, prefix, start_pos)

        truncated = False
        for object_name in object_names[start_pos:]:
            if not object_name.startswith(prefix):
                break
            if len(contents) >= max_keys:
                truncated = True
                break
            object_path = self._object_path(bucket_name, object_name)
            c = {"Key": object_name}
            if not terse:
                info = os.stat(object_path)
                c.update({
                    "LastModified": datetime.datetime.utcfromtimestamp(
                        info.st_mtime),
                    "Size": info.st_size,
                })
            contents.append(c)
            marker = object_name
        self.render_xml({"ListBucketResult": {
            "Name": bucket_name,
            "Prefix": prefix,
            "Marker": marker,
            "MaxKeys": max_keys,
            "IsTruncated": truncated,
            "Contents": contents,
        }})

    def put(self, bucket_name):
        path = os.path.abspath(os.path.join(
            self.application.directory, bucket_name))
        if (not path.startswith(self.application.directory) or
                os.path.exists(path)):
            self.set_status(403)
            return
        fileutils.ensure_tree(path)
        self.finish()

    def delete(self, bucket_name):
        path = os.path.abspath(os.path.join(
            self.application.directory, bucket_name))
        if (not path.startswith(self.application.directory) or
                not os.path.isdir(path)):
            self.set_404()
            return
        if len(os.listdir(path)) > 0:
            self.set_status(403)
            return
        os.rmdir(path)
        self.set_status(204)
        self.finish()

    def head(self, bucket_name):
        path = os.path.abspath(os.path.join(self.application.directory,
                                            bucket_name))
        if (not path.startswith(self.application.directory) or
                not os.path.isdir(path)):
            self.set_404()
            return
        self.set_status(200)
        self.finish()


class ObjectHandler(BaseRequestHandler):
    def get(self, bucket, object_name):
        object_name = parse.unquote(object_name)
        path = self._object_path(bucket, object_name)
        if (not path.startswith(self.application.directory) or
                not os.path.isfile(path)):
            self.set_404()
            return
        info = os.stat(path)
        self.set_header("Content-Type", "application/unknown")
        self.set_header("Last-Modified", datetime.datetime.utcfromtimestamp(
            info.st_mtime))
        object_file = open(path, "rb")
        try:
            self.finish(object_file.read())
        finally:
            object_file.close()

    def put(self, bucket, object_name):
        object_name = parse.unquote(object_name)
        bucket_dir = os.path.abspath(os.path.join(
            self.application.directory, bucket))
        if (not bucket_dir.startswith(self.application.directory) or
                not os.path.isdir(bucket_dir)):
            self.set_404()
            return
        path = self._object_path(bucket, object_name)
        if not path.startswith(bucket_dir) or os.path.isdir(path):
            self.set_status(403)
            return
        directory = os.path.dirname(path)
        fileutils.ensure_tree(directory)
        object_file = open(path, "wb")
        object_file.write(self.request.body)
        object_file.close()
        self.set_header('ETag',
                        '"%s"' % utils.get_hash_str(self.request.body))
        self.finish()

    def delete(self, bucket, object_name):
        object_name = parse.unquote(object_name)
        path = self._object_path(bucket, object_name)
        if (not path.startswith(self.application.directory) or
                not os.path.isfile(path)):
            self.set_404()
            return
        os.unlink(path)
        self.set_status(204)
        self.finish()
