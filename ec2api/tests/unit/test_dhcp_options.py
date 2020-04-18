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

from unittest import mock

from oslo_config import cfg

from ec2api.tests.unit import base
from ec2api.tests.unit import fakes
from ec2api.tests.unit import matchers
from ec2api.tests.unit import tools


class DhcpOptionsTestCase(base.ApiTestCase):

    def test_create_dhcp_options(self):

        def gen_opt(count, value):
            return 'DhcpConfiguration.' + str(count) + '.' + value

        def gen_ec2_param_dhcp_options(dhcp_options):
            dhcp_configuration = dhcp_options['dhcpConfigurationSet']
            result_param = {}
            opt_count = 0
            for opt in dhcp_configuration:
                opt_count += 1
                result_param[gen_opt(opt_count, 'Key')] = opt['key']
                value_count = 0
                for value in opt['valueSet']:
                    value_count += 1
                    result_param[gen_opt(opt_count,
                                         'Value.' + str(value_count))] = (
                                            str(value['value']))
            return result_param

        def check(ec2_fake, db_fake):
            self.db_api.add_item.return_value = db_fake
            resp = self.execute(
                    'CreateDhcpOptions',
                    gen_ec2_param_dhcp_options(ec2_fake))
            self.assertThat(ec2_fake, matchers.DictMatches(
                    resp['dhcpOptions'], orderless_lists=True))
            self.assert_any_call(self.db_api.add_item,
                                 mock.ANY, 'dopt',
                                 tools.purge_dict(db_fake, ('id',)))
            self.db_api.reset_mock()

        check(fakes.EC2_DHCP_OPTIONS_1, fakes.DB_DHCP_OPTIONS_1)
        check(fakes.EC2_DHCP_OPTIONS_2, fakes.DB_DHCP_OPTIONS_2)

    def test_create_dhcp_options_invalid_parameters(self):
        self.assert_execution_error(
            'InvalidParameterValue', 'CreateDhcpOptions',
            {'DhcpConfiguration.1.Key': 'InvalidParameter',
             'DhcpConfiguration.1.Value.1': 'Value'})

    def test_delete_dhcp_options(self):
        self.set_mock_db_items(fakes.DB_DHCP_OPTIONS_1)
        resp = self.execute('DeleteDhcpOptions',
                            {'dhcpOptionsId': fakes.ID_EC2_DHCP_OPTIONS_1})
        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_any_call(
                mock.ANY,
                fakes.ID_EC2_DHCP_OPTIONS_1)
        self.db_api.get_items.assert_any_call(
                mock.ANY,
                'vpc')
        self.db_api.delete_item.assert_called_once_with(
                mock.ANY,
                fakes.ID_EC2_DHCP_OPTIONS_1)

    def test_delete_dhcp_options_with_dependencies(self):
        self.set_mock_db_items(
            fakes.DB_DHCP_OPTIONS_1,
            tools.update_dict(
                fakes.DB_VPC_1,
                {'dhcp_options_id': fakes.ID_EC2_DHCP_OPTIONS_1}))
        self.assert_execution_error(
            'DependencyViolation', 'DeleteDhcpOptions',
            {'dhcpOptionsId': fakes.ID_EC2_DHCP_OPTIONS_1})

    def test_describe_dhcp_options(self):
        self.set_mock_db_items(fakes.DB_DHCP_OPTIONS_1,
                               fakes.DB_DHCP_OPTIONS_2)

        resp = self.execute('DescribeDhcpOptions', {})
        self.assertThat(resp['dhcpOptionsSet'],
                        matchers.ListMatches([fakes.EC2_DHCP_OPTIONS_1,
                                              fakes.EC2_DHCP_OPTIONS_2],
                                             orderless_lists=True))

        resp = self.execute('DescribeDhcpOptions',
                            {'DhcpOptionsId.1': fakes.ID_EC2_DHCP_OPTIONS_1})
        self.assertThat(resp['dhcpOptionsSet'],
                        matchers.ListMatches([fakes.EC2_DHCP_OPTIONS_1],
                                             orderless_lists=True))
        self.db_api.get_items_by_ids.assert_called_once_with(
                mock.ANY, set([fakes.ID_EC2_DHCP_OPTIONS_1]))

        self.check_filtering(
            'DescribeDhcpOptions', 'dhcpOptionsSet',
            [('dhcp_options_id', fakes.ID_EC2_DHCP_OPTIONS_1),
             ('key', 'netbios-node-type'),
             ('value', '8.8.8.8')])
        self.check_tag_support(
            'DescribeDhcpOptions', 'dhcpOptionsSet',
            fakes.ID_EC2_DHCP_OPTIONS_1, 'dhcpOptionsId')

    def test_associate_dhcp_options(self):
        self.set_mock_db_items(fakes.DB_VPC_1, fakes.DB_DHCP_OPTIONS_1,
                               fakes.DB_NETWORK_INTERFACE_1)
        self.neutron.list_ports.return_value = (
                {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})

        def check(ec2_dhcp_options_id, db_dhcp_options_id, os_dhcp_options):
            resp = self.execute('AssociateDhcpOptions',
                                {'dhcpOptionsId': ec2_dhcp_options_id,
                                 'vpcId': fakes.ID_EC2_VPC_1})
            self.assertEqual(True, resp['return'])
            self.db_api.update_item.assert_any_call(
                    mock.ANY,
                    tools.update_dict(
                            fakes.DB_VPC_1,
                            {'dhcp_options_id': db_dhcp_options_id}))
            self.assert_any_call(
                self.neutron.update_port,
                fakes.ID_OS_PORT_1,
                {'port': self._effective_os_dhcp_options(os_dhcp_options)})

        check(fakes.ID_EC2_DHCP_OPTIONS_1, fakes.ID_EC2_DHCP_OPTIONS_1,
              fakes.OS_DHCP_OPTIONS_1)

        check('default', None, {'extra_dhcp_opts': []})

    @tools.screen_unexpected_exception_logs
    def test_associate_dhcp_options_rollback(self):
        vpc = tools.update_dict(
                fakes.DB_VPC_1,
                {'dhcp_options_id': fakes.ID_EC2_DHCP_OPTIONS_1})
        self.set_mock_db_items(
            vpc, fakes.DB_DHCP_OPTIONS_1, fakes.DB_DHCP_OPTIONS_2,
            fakes.DB_NETWORK_INTERFACE_1, fakes.DB_NETWORK_INTERFACE_2)
        self.neutron.list_ports.return_value = (
                {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})

        def update_port_func(port_id, _port_data):
            if port_id == fakes.ID_OS_PORT_2:
                raise Exception()

        self.neutron.update_port.side_effect = update_port_func

        self.assert_execution_error(
            self.ANY_EXECUTE_ERROR, 'AssociateDhcpOptions',
            {'dhcpOptionsId': fakes.ID_EC2_DHCP_OPTIONS_2,
             'vpcId': fakes.ID_EC2_VPC_1})

        self.assert_any_call(self.neutron.update_port,
                             fakes.ID_OS_PORT_1,
                             {'port': fakes.OS_DHCP_OPTIONS_1})
        self.db_api.update_item.assert_any_call(
                mock.ANY, vpc)

    def _effective_os_dhcp_options(self, os_dhcp_options):
        CONF = cfg.CONF
        dhcp_opts = {
            'extra_dhcp_opts': [{'opt_name': 'mtu',
                                 'opt_value': str(CONF.network_device_mtu)}]}
        dhcp_opts['extra_dhcp_opts'].extend(
            os_dhcp_options.get('extra_dhcp_opts', []))
        return dhcp_opts
