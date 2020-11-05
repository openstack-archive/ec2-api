# Copyright 2014 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""oslo.i18n integration module.

See http://docs.openstack.org/developer/oslo.i18n/usage.html .

"""

import oslo_i18n

DOMAIN = 'ec2-api'

_translators = oslo_i18n.TranslatorFactory(domain=DOMAIN)

# The primary translation function using the well-known name "_"
_ = _translators.primary


def translate(value, user_locale):
    """
    Translate locale to locale.

    Args:
        value: (todo): write your description
        user_locale: (todo): write your description
    """
    return oslo_i18n.translate(value, user_locale)


def get_available_languages():
    """
    Return available languages.

    Args:
    """
    return oslo_i18n.get_available_languages(DOMAIN)
