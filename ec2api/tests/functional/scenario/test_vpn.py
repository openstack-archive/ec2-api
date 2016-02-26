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

import os
import sys
import time
import urllib2

from lxml import etree
from oslo_log import log
import paramiko
from tempest.lib.common import ssh
from tempest.lib.common.utils import data_utils
import testtools

from ec2api.tests.functional import base
from ec2api.tests.functional import config
from ec2api.tests.functional.scenario import base as scenario_base

CONF = config.CONF
LOG = log.getLogger(__name__)


class VpnTest(scenario_base.BaseScenarioTest):

    CUSTOMER_GATEWAY_IP = '198.51.100.77'
    CUSTOMER_VPN_CIDR = '172.16.25.0/24'
    OPENSWAN_LINK = ('http://mirrors.kernel.org/ubuntu/pool/universe/o/'
                     'openswan/openswan_2.6.38-1_i386.deb')

    @classmethod
    @base.safe_setup
    def setUpClass(cls):
        super(VpnTest, cls).setUpClass()
        if not base.TesterStateHolder().get_vpc_enabled():
            raise cls.skipException('VPC is disabled')

    def test_vpn_routing(self):
        vpc_id, _subnet_id = self.create_vpc_and_subnet('10.42.0.0/20')

        vpn_data = self._create_and_configure_vpn(
            vpc_id, self.CUSTOMER_GATEWAY_IP, self.CUSTOMER_VPN_CIDR)
        vgw_id = vpn_data['VpnGatewayId']

        data = self.client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        rtb_id = data['RouteTables'][0]['RouteTableId']
        data = self.client.describe_route_tables(RouteTableIds=[rtb_id])
        data = data['RouteTables'][0]
        route = next((r for r in data['Routes']
                      if r['DestinationCidrBlock'] == self.CUSTOMER_VPN_CIDR),
                     None)
        if route:
            self.assertEqual('active', route['State'])
            self.assertEqual('EnableVgwRoutePropagation', route['Origin'])
        self.assertIn('PropagatingVgws', data)
        self.assertNotEmpty(data['PropagatingVgws'])
        self.assertEqual(vgw_id, data['PropagatingVgws'][0]['GatewayId'])

    @testtools.skipUnless(CONF.aws.run_ssh, 'SSH tests are disabled.')
    @testtools.skipUnless(CONF.aws.run_long_tests, 'Slow test has skipped.')
    @testtools.skipUnless(CONF.aws.image_id_ubuntu,
                          "ubuntu image id is not defined")
    @testtools.skipUnless(CONF.aws.image_id,
                          "image id is not defined")
    def test_vpn_connectivity(self):
        is_amazon = 'amazon' in CONF.aws.ec2_url

        response = urllib2.urlopen(self.OPENSWAN_LINK, timeout=30)
        content = response.read()
        if not is_amazon:
            # NOTE(andrey-mp): gating in openstack doesn't have internet access
            # so we need to download this package and install it with dpkg
            filename = os.path.basename(self.OPENSWAN_LINK)
            f = open(filename, 'w')
            f.write(content)
            f.close()

        key_name = data_utils.rand_name('testkey')
        pkey = self.create_key_pair(key_name)

        # run ubuntu instance to create one of VPN endpoint inside
        sec_group_name = self.create_standard_security_group()
        instance_id_ubuntu = self.run_instance(
            KeyName=key_name, ImageId=CONF.aws.image_id_ubuntu,
            SecurityGroups=[sec_group_name])
        public_ip_ubuntu = self.get_instance_ip(instance_id_ubuntu)
        instance = self.get_instance(instance_id_ubuntu)
        private_ip_ubuntu = instance['PrivateIpAddress']

        # create VPC, ..., VPN
        vpc_id, subnet_id = self.create_vpc_and_subnet('10.43.0.0/20')
        self.prepare_vpc_default_security_group(vpc_id)
        vpn_data = self._create_and_configure_vpn(
            vpc_id, public_ip_ubuntu, private_ip_ubuntu + '/32')

        # run general instance inside VPC
        instance_id = self.run_instance(KeyName=key_name,
                                        ImageId=CONF.aws.image_id,
                                        SubnetId=subnet_id)
        instance = self.get_instance(instance_id)
        private_ip_in_vpc = instance['PrivateIpAddress']

        # configure ubuntu, install openswan and run it
        ssh_client = ssh.Client(public_ip_ubuntu, CONF.aws.image_user_ubuntu,
                                pkey=pkey)
        if not is_amazon:
            self._upload_file(ssh_client, filename, filename)
            ssh_client.exec_command('sudo DEBIAN_FRONTEND=noninteractive'
                                    ' dpkg -i ' + filename)
        else:
            ssh_client.exec_command('DEBIAN_FRONTEND=noninteractive sudo '
                                    'apt-get install -fqy openswan')
        ssh_client.exec_command('sudo -s su -c "'
                                'echo 1 > /proc/sys/net/ipv4/ip_forward"')
        ssh_client.exec_command(
            'for vpn in /proc/sys/net/ipv4/conf/*;  do sudo -s su -c'
            ' "echo 0 > $vpn/accept_redirects; echo 0 > $vpn/send_redirects";'
            ' done')
        sysctl_additions = [
            'net.ipv4.ip_forward = 1',
            'net.ipv4.conf.all.accept_redirects = 0',
            'net.ipv4.conf.all.send_redirects = 0']
        for item in sysctl_additions:
            ssh_client.exec_command(
                'sudo -s su -c "echo \'' + item + '\' >> /etc/sysctl.conf"')
        ssh_client.exec_command('sudo sysctl -p')
        ipsec_conf, ipsec_secrets = self._get_ipsec_conf(
            vpn_data['VpnConnectionId'], private_ip_ubuntu)
        ssh_client.exec_command('sudo -s su -c "echo \'\' > /etc/ipsec.conf"')
        for fstr in ipsec_conf:
            ssh_client.exec_command(
                'sudo -s su -c "echo \'%s\' >> /etc/ipsec.conf"' % fstr)
        ssh_client.exec_command(
            'sudo -s su -c "echo \'%s\' > /etc/ipsec.secrets"' % ipsec_secrets)

        ssh_client.exec_command('sudo service ipsec restart')

        try:
            self.get_vpn_connection_tunnel_waiter().wait_available(
                vpn_data['VpnConnectionId'], ('UP'))
        except Exception:
            exc_info = sys.exc_info()
            try:
                output = ssh_client.exec_command('sudo ipsec auto --status')
                LOG.warning(output)
            except Exception:
                pass
            raise exc_info[1], None, exc_info[2]
        time.sleep(10)

        ssh_client.exec_command('ping -c 4 %s' % private_ip_in_vpc)

    def _upload_file(self, ssh_client, local_path, remote_path):
        ssh = ssh_client._get_ssh_connection()
        transport = ssh.get_transport()
        sftp_client = paramiko.SFTPClient.from_transport(transport)
        sftp_client.put(local_path, remote_path)

    def _create_and_configure_vpn(self, vpc_id, cgw_ip, customer_subnet):
        data = self.client.create_customer_gateway(
            Type='ipsec.1', PublicIp=cgw_ip, BgpAsn=65000)
        cgw_id = data['CustomerGateway']['CustomerGatewayId']
        self.addResourceCleanUp(
            self.client.delete_customer_gateway, CustomerGatewayId=cgw_id)
        self.get_customer_gateway_waiter().wait_available(cgw_id)

        data = self.client.create_vpn_gateway(
            Type='ipsec.1', AvailabilityZone=CONF.aws.aws_zone)
        vgw_id = data['VpnGateway']['VpnGatewayId']
        self.addResourceCleanUp(
            self.client.delete_vpn_gateway, VpnGatewayId=vgw_id)
        self.get_vpn_gateway_waiter().wait_available(vgw_id)

        data = self.client.attach_vpn_gateway(VpnGatewayId=vgw_id,
                                              VpcId=vpc_id)
        self.addResourceCleanUp(self.client.detach_vpn_gateway,
                                VpnGatewayId=vgw_id, VpcId=vpc_id)
        self.get_vpn_gateway_attachment_waiter().wait_available(
            vgw_id, 'attached')

        data = self.client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        rtb_id = data['RouteTables'][0]['RouteTableId']
        data = self.client.enable_vgw_route_propagation(RouteTableId=rtb_id,
                                                        GatewayId=vgw_id)
        self.addResourceCleanUp(self.client.disable_vgw_route_propagation,
            RouteTableId=rtb_id, GatewayId=vgw_id)

        data = self.client.create_vpn_connection(
            CustomerGatewayId=cgw_id, VpnGatewayId=vgw_id,
            Options={'StaticRoutesOnly': True}, Type='ipsec.1')
        vpn_data = data['VpnConnection']
        vpn_id = data['VpnConnection']['VpnConnectionId']
        self.addResourceCleanUp(self.client.delete_vpn_connection,
                                VpnConnectionId=vpn_id)
        self.get_vpn_connection_waiter().wait_available(vpn_id)

        data = self.client.create_vpn_connection_route(
            VpnConnectionId=vpn_id,
            DestinationCidrBlock=customer_subnet)
        self.get_vpn_connection_route_waiter(customer_subnet).wait_available(
            vpn_id)

        return vpn_data

    def _get_ipsec_conf(self, vpn_connection_id, private_ip_ubuntu):
        data = self.client.describe_vpn_connections(
            VpnConnectionIds=[vpn_connection_id])
        vpn_data = data['VpnConnections'][0]
        vpn_config = etree.fromstring(
            vpn_data['CustomerGatewayConfiguration'])
        psks = vpn_config.xpath(
            '/vpn_connection/ipsec_tunnel/ike/pre_shared_key')
        self.assertNotEmpty(psks)
        vgw_ip = vpn_config.xpath(
            '/vpn_connection/ipsec_tunnel/vpn_gateway/tunnel_outside_address'
            '/ip_address')
        self.assertTrue(vgw_ip)

        ipsec_key = psks[0].text
        vgw_ip = vgw_ip[0].text

        ipsec_conf = []
        for item in self._ipsec_conf:
            ipsec_conf.append(item % {
                'vpc_cidr': '10.43.0.0/20',
                'vgw_ip': vgw_ip,
                'private_ip_ubuntu': private_ip_ubuntu})

        ipsec_secrets = ('%(private_ip_ubuntu)s  %(vgw_ip)s:  '
            'PSK  \\"%(ipsec_key)s\\"' % {
                'private_ip_ubuntu': private_ip_ubuntu,
                'vgw_ip': vgw_ip,
                'ipsec_key': ipsec_key})

        return ipsec_conf, ipsec_secrets

    _ipsec_conf = [
        '## general configuration parameters ##',
        'config setup',
        '    plutodebug=all',
        '    plutostderrlog=/var/log/pluto.log',
        '    protostack=netkey',
        '    nat_traversal=yes',
        '    virtual_private=%%v4:%(vpc_cidr)s',
        '    nhelpers=0',
        '## connection definition in Debian ##',
        'conn my-conn',
        '    authby=secret',
        '    auto=start',
        '    pfs=yes',
        '    type=tunnel',
        '    #left side (myside)',
        '    left=%(private_ip_ubuntu)s',
        '    leftsubnet=%(private_ip_ubuntu)s/32',
        '    leftnexthop=%(vgw_ip)s',
        '    leftsourceip=%(private_ip_ubuntu)s',
        '    #right security gateway (VPN side)',
        '    right=%(vgw_ip)s',
        '    rightsubnet=%(vpc_cidr)s',
        '    rightnexthop=%(private_ip_ubuntu)s']
