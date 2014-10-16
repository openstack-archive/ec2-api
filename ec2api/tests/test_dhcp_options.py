#    Copyright 2014 Cloudscaling Group, Inc
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

import mock

from ec2api.tests import base
from ec2api.tests import fakes
from ec2api.tests import matchers
from ec2api.tests import tools


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
            self.assertEqual(200, resp['status'])
            self.assertThat(ec2_fake, matchers.DictMatches(
                    resp['dhcpOptions'], orderless_lists=True))
            self.assert_any_call(self.db_api.add_item,
                                 mock.ANY, 'dopt',
                                 tools.purge_dict(db_fake, ('id',)))
            self.db_api.reset_mock()

        check(fakes.EC2_DHCP_OPTIONS_1, fakes.DB_DHCP_OPTIONS_1)
        check(fakes.EC2_DHCP_OPTIONS_2, fakes.DB_DHCP_OPTIONS_2)

    def test_create_dhcp_options_invalid_parameters(self):
        resp = self.execute('CreateDhcpOptions',
                            {'DhcpConfiguration.1.Key': 'InvalidParameter',
                             'DhcpConfiguration.1.Value.1': 'Value'})
        self.assertEqual(400, resp['status'])
        self.assertEqual('InvalidParameterValue', resp['Error']['Code'])

    def test_delete_dhcp_options(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_DHCP_OPTIONS_1
        self.db_api.get_items.return_value = []
        resp = self.execute('DeleteDhcpOptions',
                            {'dhcpOptionsId': fakes.ID_EC2_DHCP_OPTIONS_1})
        self.assertEqual(200, resp['status'])
        self.assertEqual(True, resp['return'])
        self.db_api.get_item_by_id.assert_has_call(
                mock.ANY,
                fakes.ID_EC2_DHCP_OPTIONS_1)
        self.db_api.get_items.assert_has_call(
                mock.ANY,
                'vpc')
        self.db_api.delete_item.assert_called_once_with(
                mock.ANY,
                fakes.ID_EC2_DHCP_OPTIONS_1)

    def test_delete_dhcp_options_with_dependencies(self):
        self.db_api.get_item_by_id.return_value = fakes.DB_DHCP_OPTIONS_1
        self.db_api.get_items.return_value = [tools.update_dict(
                            fakes.DB_VPC_1,
                            {'dhcp_options_id': fakes.ID_EC2_DHCP_OPTIONS_1})]
        resp = self.execute('DeleteDhcpOptions',
                            {'dhcpOptionsId': fakes.ID_EC2_DHCP_OPTIONS_1})
        self.assertEqual(400, resp['status'])
        self.assertEqual('DependencyViolation', resp['Error']['Code'])

    def test_describe_dhcp_options(self):
        self.db_api.get_items.return_value = (
                [fakes.DB_DHCP_OPTIONS_1, fakes.DB_DHCP_OPTIONS_2])
        resp = self.execute('DescribeDhcpOptions', {})
        self.assertEqual(200, resp['status'])
        self.assertThat(resp['dhcpOptionsSet'],
                        matchers.ListMatches([fakes.EC2_DHCP_OPTIONS_1,
                                              fakes.EC2_DHCP_OPTIONS_2],
                                             orderless_lists=True))

    def test_associate_dhcp_options(self):
        self.db_api.get_item_by_id.side_effect = (
                fakes.get_db_api_get_item_by_id(
                    {fakes.ID_EC2_VPC_1: fakes.DB_VPC_1,
                     fakes.ID_EC2_DHCP_OPTIONS_1: fakes.DB_DHCP_OPTIONS_1}))
        self.db_api.get_items.return_value = [fakes.DB_NETWORK_INTERFACE_1]
        self.neutron.list_ports.return_value = (
                {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})

        def check(ec2_dhcp_options_id, db_dhcp_options_id, os_dhcp_options):
            resp = self.execute('AssociateDhcpOptions',
                                {'dhcpOptionsId': ec2_dhcp_options_id,
                                 'vpcId': fakes.ID_EC2_VPC_1})
            self.assertEqual(200, resp['status'])
            self.assertEqual(True, resp['return'])
            self.db_api.update_item.assert_has_call(
                    mock.ANY,
                    tools.update_dict(
                            fakes.DB_VPC_1,
                            {'dhcp_options_id': db_dhcp_options_id}))
            self.neutron.update_port.assert_has_call(
                        mock.ANY, fakes.ID_OS_PORT_1,
                        {'port': os_dhcp_options})

        check(fakes.ID_EC2_DHCP_OPTIONS_1, fakes.ID_EC2_DHCP_OPTIONS_1,
              fakes.OS_DHCP_OPTIONS_1)

        check('default', None, {'extra_dhcp_opts': []})

    def test_associate_dhcp_options_rollback(self):
        vpc = tools.update_dict(
                fakes.DB_VPC_1,
                {'dhcp_options_id': fakes.ID_EC2_DHCP_OPTIONS_1})
        self.db_api.get_item_by_id.side_effect = (
                fakes.get_db_api_get_item_by_id(
                    {fakes.ID_EC2_VPC_1: vpc,
                     fakes.ID_EC2_DHCP_OPTIONS_1: fakes.DB_DHCP_OPTIONS_1,
                     fakes.ID_EC2_DHCP_OPTIONS_2: fakes.DB_DHCP_OPTIONS_2}))
        self.db_api.get_items.return_value = [fakes.DB_NETWORK_INTERFACE_1,
                                              fakes.DB_NETWORK_INTERFACE_2]
        self.neutron.list_ports.return_value = (
                {'ports': [fakes.OS_PORT_1, fakes.OS_PORT_2]})

        def update_port_func(port_id, _port_data):
            if port_id == fakes.ID_OS_PORT_2:
                raise Exception()

        self.neutron.update_port.side_effect = update_port_func

        self.execute('AssociateDhcpOptions',
                     {'dhcpOptionsId': fakes.ID_EC2_DHCP_OPTIONS_2,
                      'vpcId': fakes.ID_EC2_VPC_1})

        self.assert_any_call(self.neutron.update_port,
                             fakes.ID_OS_PORT_1,
                             {'port': fakes.OS_DHCP_OPTIONS_1})
        self.db_api.update_item.assert_any_call(
                mock.ANY, vpc)
