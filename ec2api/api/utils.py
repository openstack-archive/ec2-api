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


class OnCrashCleaner(object):

    def __init__(self):
        self._cleanups = []
        self._suppress_exception = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            return
        self._run_cleanups(self._cleanups)
        return self._suppress_exception

    def addCleanup(self, function, *args, **kwargs):
        self._cleanups.append((function, args, kwargs))

    def approveChanges(self):
        del self._cleanups[:]
        self._suppress_exception = True

    def _run_cleanups(self, cleanups):
        for function, args, kwargs in reversed(cleanups):
            try:
                function(*args, **kwargs)
            except Exception:
                # TODO(ft): log the error
                pass
