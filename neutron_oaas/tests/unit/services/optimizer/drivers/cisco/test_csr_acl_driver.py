# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import copy
import mock
import requests
import sys

from neutron.tests import base

with mock.patch.dict(sys.modules, {
    'networking_cisco': mock.Mock(),
    'networking_cisco.plugins': mock.Mock().plugins,
    'networking_cisco.plugins.cisco': mock.Mock().cisco,
    'networking_cisco.plugins.cisco.cfg_agent': mock.Mock().cfg_agent,
    'networking_cisco.plugins.cisco.cfg_agent.device_drivers':
        mock.Mock().device_drivers,
}):
    from neutron_oaas.services.optimizer.drivers.cisco import csr_acl_driver


FAKE_ACL_ID = 'acl123'
FAKE_FW = {
    'id': '123456789',
    'admin_state_up': True,
    'vendor_ext': {
        'acl_id': FAKE_ACL_ID,
        'host_mngt_ip': '192.169.101.5',
        'host_usr_nm': 'lab',
        'host_usr_pw': 'lab',
        'if_list': [
            {
                'direction': 'inside',
                'port': {
                    'id': 'fake_port_id',
                    'hosting_info': {
                        # map to interface GigabitEthernet3.101
                        'segmentation_id': 101,
                        'hosting_port_name': 't2_p:1',
                    },
                },
            },
        ]
    },
    'optimizer_rule_list': [
        {
            'enabled': True,
            'name': 'r1',
            'ip_version': 4,
            'protocol': 'tcp',
            'action': 'allow',
            'source_port': '3001',
            'destination_port': '3001',
        },
    ]
}


class TestCsrAclDriver(base.BaseTestCase):

    def setUp(self):
        super(TestCsrAclDriver, self).setUp()

        self.csr = mock.Mock()

        self.csracl = csr_acl_driver.CsrAclDriver()
        self.csracl._get_csr_host = mock.Mock(return_value=self.csr)

        self.acl_data = self.csracl._get_acl_rule_data(FAKE_FW)
        self.aclapi_response = 'https://' + FAKE_FW[
                'vendor_ext']['host_mngt_ip'] + '/' + FAKE_ACL_ID

    def _set_csracl_mocks(self):
        self.csracl._post_acl = mock.Mock()
        self.csracl._post_acl_to_interfaces = mock.Mock()
        self.csracl._delete_acl = mock.Mock()
        self.csracl._put_acl = mock.Mock()
        self.csracl._delete_acl_on_interface = mock.Mock()
        self.csracl._get_acl_interface = mock.Mock()

    def _set_csr_mocks(self):
        self.csr.post_request = mock.Mock()
        self.csr.delete_request = mock.Mock()
        self.csr.get_request = mock.Mock()
        self.csr.put_request = mock.Mock()

    def _test_post_acl(self):
        self._set_csr_mocks()
        self.csr.post_request.return_value = self.aclapi_response
        acl_id = self.csracl._post_acl(self.csr, self.acl_data)

        self.csr.post_request.assert_called_once_with('acl', self.acl_data)
        if self.csr.status == requests.codes.CREATED:
            self.assertEqual(FAKE_ACL_ID, acl_id)
        else:
            self.assertEqual('', acl_id)

    def test_post_acl_error(self):
        self.csr.status = requests.codes.SERVER_ERROR
        self._test_post_acl()

    def test_post_acl(self):
        self.csr.status = requests.codes.CREATED
        self._test_post_acl()

    def _test_delete_acl(self):
        self._set_csr_mocks()
        success = self.csracl._delete_acl(self.csr, FAKE_ACL_ID)

        self.csr.delete_request.assert_called_once_with('acl/' + FAKE_ACL_ID)
        if self.csr.status == requests.codes.NO_CONTENT:
            self.assertTrue(success)
        else:
            self.assertEqual(False, success)

    def test_delete_acl_error(self):
        self.csr.status = requests.codes.SERVER_ERROR
        self._test_delete_acl()

    def test_delete_acl(self):
        self.csr.status = requests.codes.NO_CONTENT
        self._test_delete_acl()

    def _test_put_acl(self):
        self._set_csr_mocks()
        success = self.csracl._put_acl(
            self.csr, FAKE_ACL_ID, self.acl_data)

        self.csr.put_request.assert_called_once_with(
            'acl/' + FAKE_ACL_ID, self.acl_data)
        if self.csr.status == requests.codes.NO_CONTENT:
            self.assertTrue(success)
        else:
            self.assertEqual(False, success)

    def test_put_acl_error(self):
        self.csr.status = requests.codes.SERVER_ERROR
        self._test_put_acl()

    def test_put_acl(self):
        self.csr.status = requests.codes.NO_CONTENT
        self._test_put_acl()

    def _test_post_acl_to_interfaces(self):
        self._set_csr_mocks()
        self.csr.post_request.return_value = 'fake_post_response'
        status_data = {
            'opt_id': FAKE_FW['id'],
            'acl_id': FAKE_ACL_ID,
            'if_list': []
        }
        optimizer_interface = FAKE_FW['vendor_ext']['if_list'][0]
        interface_name = self.csracl._get_interface_name_from_hosting_port(
            optimizer_interface['port'])
        acl_interface_data = {
            'if-id': interface_name,
            'direction': optimizer_interface['direction']}
        api = 'acl/' + FAKE_ACL_ID + '/interfaces'

        self.csracl._post_acl_to_interfaces(FAKE_FW, self.csr,
            FAKE_ACL_ID, status_data)

        self.csr.post_request.assert_called_once_with(api, acl_interface_data)
        if self.csr.status == requests.codes.CREATED:
            self.assertEqual(
                [{'port_id': optimizer_interface['port']['id'],
                  'status': 'OK'}],
                status_data['if_list'])
        else:
            self.assertEqual(
                [{'port_id': optimizer_interface['port']['id'],
                  'status': 'ERROR'}],
                status_data['if_list'])

    def test_post_acl_to_interfaces_error(self):
        self.csr.status = requests.codes.SERVER_ERROR
        self._test_post_acl_to_interfaces()

    def test_post_acl_to_interfaces(self):
        self.csr.status = requests.codes.CREATED
        self._test_post_acl_to_interfaces()

    def test_delete_acl_on_interface(self):
        self._set_csr_mocks()
        self.csr.status = requests.codes.NO_CONTENT
        csr_acl_interfaces = [
            {
                'acl-id': FAKE_ACL_ID,
                'if-id': 'GigabitEthernet3.101',
                'direction': 'inside'
            }
        ]
        api = 'acl/%s/interfaces/%s_%s' % (
            FAKE_ACL_ID, csr_acl_interfaces[0]['if-id'],
            csr_acl_interfaces[0]['direction'])

        self.csracl._delete_acl_on_interface(
            self.csr, FAKE_ACL_ID, csr_acl_interfaces)
        self.csr.delete_request.assert_called_once_with(api)

    def _test_get_acl_interface(self):
        self._set_csr_mocks()
        api = 'acl/%s/interfaces' % FAKE_ACL_ID
        get_rsp = {'items': [{'fake_k1': 'fake_d1'}]}
        self.csr.get_request.return_value = get_rsp
        rsp = self.csracl._get_acl_interface(self.csr, FAKE_ACL_ID)

        self.csr.get_request.assert_called_once_with(api)
        if self.csr.status == requests.codes.OK:
            self.assertEqual(get_rsp['items'], rsp)
        else:
            self.assertEqual('', rsp)

    def test_get_acl_interface_err(self):
        self.csr.status = requests.codes.SERVER_ERROR
        self._test_get_acl_interface()

    def test_get_acl_interface(self):
        self.csr.status = requests.codes.OK
        self._test_get_acl_interface()

    def test_create_optimizer_admin_state_not_up(self):
        optimizer = copy.deepcopy(FAKE_FW)
        optimizer['admin_state_up'] = False
        self._set_csracl_mocks()
        self.csracl._post_acl.return_value = FAKE_ACL_ID
        success, status = self.csracl.create_optimizer(None, None, optimizer)

        self.csracl._post_acl.assert_called_once_with(self.csr, self.acl_data)
        self.assertTrue(success)
        self.assertEqual(
            {'opt_id': FAKE_FW['id'], 'acl_id': FAKE_ACL_ID, 'if_list': []},
            status)

    def test_create_optimizer_post_acl_error(self):
        self._set_csracl_mocks()
        self.csracl._post_acl.return_value = ''
        success, status = self.csracl.create_optimizer(None, None, FAKE_FW)

        self.csracl._post_acl.assert_called_once_with(self.csr, self.acl_data)
        self.assertEqual(False, success)

    def test_create_optimizer(self):
        self._set_csracl_mocks()
        self.csracl._post_acl.return_value = FAKE_ACL_ID
        status_data = {
            'opt_id': FAKE_FW['id'],
            'acl_id': FAKE_ACL_ID,
            'if_list': []
        }
        success, status = self.csracl.create_optimizer(None, None, FAKE_FW)

        self.csracl._post_acl.assert_called_once_with(self.csr, self.acl_data)
        self.csracl._post_acl_to_interfaces.assert_called_once_with(
            FAKE_FW, self.csr, FAKE_ACL_ID, status_data)
        self.assertTrue(success)

    def _test_delete_optimizer(self, delete_acl_success):
        self._set_csracl_mocks()
        self.csracl._delete_acl.return_value = delete_acl_success
        success = self.csracl.delete_optimizer(None, None, FAKE_FW)

        self.csracl._delete_acl.assert_called_once_with(self.csr, FAKE_ACL_ID)
        self.assertEqual(delete_acl_success, success)

    def test_delete_optimizer(self):
        self._test_delete_optimizer(True)

    def test_delete_optimizer_error(self):
        self._test_delete_optimizer(False)

    def test_udpate_optimizer_put_acl_error(self):
        self._set_csracl_mocks()
        self.csracl._put_acl.return_value = False
        acldata = self.acl_data
        acldata['acl-id'] = FAKE_ACL_ID
        success, status = self.csracl.update_optimizer(None, None, FAKE_FW)

        self.csracl._put_acl.assert_called_once_with(
            self.csr, FAKE_ACL_ID, acldata)
        self.assertEqual(False, success)

    def _test_update_optimizer(self, admin_stat_up):
        optimizer = copy.deepcopy(FAKE_FW)
        optimizer['admin_state_up'] = admin_stat_up
        self._set_csracl_mocks()
        self.csracl._put_acl.return_value = True
        acldata = self.acl_data
        acldata['acl-id'] = FAKE_ACL_ID
        fake_acl_interface_list = [{'if-id': 'GigabitEthernet3.101'}]
        self.csracl._get_acl_interface.return_value = fake_acl_interface_list
        status_data = {
            'opt_id': optimizer['id'],
            'acl_id': FAKE_ACL_ID,
            'if_list': []
        }

        success, status = self.csracl.update_optimizer(None, None, optimizer)

        self.csracl._put_acl.assert_called_once_with(
            self.csr, FAKE_ACL_ID, acldata)
        self.csracl._get_acl_interface.assert_called_once_with(
            self.csr, FAKE_ACL_ID)
        self.csracl._delete_acl_on_interface.assert_called_once_with(
            self.csr, FAKE_ACL_ID, fake_acl_interface_list)
        self.assertTrue(success)
        if not admin_stat_up:
            self.assertEqual(status_data, status)
        else:
            self.csracl._post_acl_to_interfaces.assert_called_once_with(
                optimizer, self.csr, FAKE_ACL_ID, status_data)

    def test_update_optimizer_admin_state_not_up(self):
        self._test_update_optimizer(False)

    def test_update_optimizer(self):
        self._test_update_optimizer(True)


class TestCsrAclDriverValidation(base.BaseTestCase):
    def setUp(self):
        super(TestCsrAclDriverValidation, self).setUp()
        self.csracl = csr_acl_driver.CsrAclDriver()
        self.optimizer = copy.deepcopy(FAKE_FW)

    def test_create_optimizer_no_admin_state(self):
        del self.optimizer['admin_state_up']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_vendor_ext(self):
        del self.optimizer['vendor_ext']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_host_mngt_ip(self):
        del self.optimizer['vendor_ext']['host_mngt_ip']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_host_usr_name(self):
        del self.optimizer['vendor_ext']['host_usr_nm']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_host_usr_password(self):
        del self.optimizer['vendor_ext']['host_usr_pw']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_if_list(self):
        del self.optimizer['vendor_ext']['if_list']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_direction(self):
        del self.optimizer['vendor_ext']['if_list'][0]['direction']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_invalid_direction(self):
        self.optimizer['vendor_ext']['if_list'][0]['direction'] = 'dir'
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_port(self):
        del self.optimizer['vendor_ext']['if_list'][0]['port']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_host_info(self):
        del self.optimizer['vendor_ext']['if_list'][0]['port']['hosting_info']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_segmentation_id(self):
        del self.optimizer['vendor_ext']['if_list'][0]['port']['hosting_info'][
            'segmentation_id']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_host_port_name(self):
        del self.optimizer['vendor_ext']['if_list'][0]['port']['hosting_info'][
            'hosting_port_name']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_invalid_host_port_name(self):
        self.optimizer['vendor_ext']['if_list'][0]['port']['hosting_info'][
            'hosting_port_name'] = 't3_p:1'
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_no_rule_list(self):
        del self.optimizer['optimizer_rule_list']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_rule_no_name(self):
        del self.optimizer['optimizer_rule_list'][0]['name']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_rule_no_ip_version(self):
        del self.optimizer['optimizer_rule_list'][0]['ip_version']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_rule_not_ipv4(self):
        self.optimizer['optimizer_rule_list'][0]['ip_version'] = 6
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_rule_no_protocol(self):
        del self.optimizer['optimizer_rule_list'][0]['protocol']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_rule_no_action(self):
        del self.optimizer['optimizer_rule_list'][0]['action']
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_create_optimizer_rule_invalid_action(self):
        self.optimizer['optimizer_rule_list'][0]['action'] = 'action'
        success, status = self.csracl.create_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_update_optimizer_no_acl_id(self):
        del self.optimizer['vendor_ext']['acl_id']
        success, status = self.csracl.update_optimizer(
            None, None, self.optimizer)
        self.assertEqual(False, success)

    def test_delete_optimizer_no_acl_id(self):
        del self.optimizer['vendor_ext']['acl_id']
        success = self.csracl.delete_optimizer(None, None, self.optimizer)
        self.assertEqual(False, success)
