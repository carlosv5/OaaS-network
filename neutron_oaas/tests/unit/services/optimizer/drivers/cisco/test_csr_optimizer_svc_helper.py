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

import mock
import sys

from neutron import context as n_context
from neutron.plugins.common import constants
from neutron.tests import base

# Mocking imports of 3rd party cisco library in unit tests and all modules
# that depends on this libary.
with mock.patch.dict(sys.modules, {
    'networking_cisco': mock.Mock(),
    'networking_cisco.plugins': mock.Mock().plugins,
    'networking_cisco.plugins.cisco': mock.Mock().cisco,
    'networking_cisco.plugins.cisco.cfg_agent': mock.Mock().cfg_agent,
    'networking_cisco.plugins.cisco.cfg_agent.device_drivers':
        mock.Mock().device_drivers,
    'networking_cisco.plugins.cisco.cfg_agent.service_helpers':
        mock.Mock().service_helpers,
}):
    from neutron_oaas.services.optimizer.drivers.cisco import (
        csr_optimizer_svc_helper)

HOST = 'myhost'
FAKE_FW = {'id': '1234'}
FAKE_FW_STATUS = {
    'opt_id': '1234',
    'acl_id': 'acl123',
    'if_list': []
}


class TestCsrOptimizerServiceHelper(base.BaseTestCase):

    def setUp(self):
        super(TestCsrOptimizerServiceHelper, self).setUp()

        self.optimizer_plugin_api_cls_p = mock.patch(
            'neutron_oaas.services.optimizer.drivers.cisco.'
            'csr_optimizer_svc_helper.CsrOptimizerlPluginApi')
        self.optimizer_plugin_api_cls = self.optimizer_plugin_api_cls_p.start()
        self.optimizer_plugin_api = mock.Mock()
        self.optimizer_plugin_api_cls.return_value = self.optimizer_plugin_api
        self.optimizer_plugin_api.get_optimizers_for_device = mock.MagicMock()
        self.optimizer_plugin_api.get_optimizers_for_tenant = mock.MagicMock()
        self.optimizer_plugin_api.get_tenants_with_optimizers = mock.MagicMock()
        self.optimizer_plugin_api.optimizer_deleted = mock.MagicMock()
        self.optimizer_plugin_api.set_optimizer_status = mock.MagicMock()
        mock.patch('neutron.common.rpc.create_connection').start()

        self.opt_svc_helper = csr_optimizer_svc_helper.CsrOptimizerServiceHelper(
            HOST, mock.Mock(), mock.Mock())
        self.opt_svc_helper.acl_driver = mock.Mock()
        self.opt_svc_helper.event_q = mock.Mock()
        self.opt_svc_helper.event_q.enqueue = mock.Mock()

        self.ctx = mock.Mock()

    def _test_optimizer_even_enqueue(self, event_name):
        optimizer_event = {'event': event_name,
                          'context': self.ctx,
                          'optimizer': FAKE_FW,
                          'host': HOST}
        self.opt_svc_helper.event_q.enqueue.assert_called_with(
            'csr_opt_event_q', optimizer_event)

    def test_create_optimizer(self):
        self.opt_svc_helper.create_optimizer(self.ctx, FAKE_FW, HOST)
        self._test_optimizer_even_enqueue('FW_EVENT_CREATE')

    def test_update_optimizer(self):
        self.opt_svc_helper.update_optimizer(self.ctx, FAKE_FW, HOST)
        self._test_optimizer_even_enqueue('FW_EVENT_UPDATE')

    def test_delete_optimizer(self):
        self.opt_svc_helper.delete_optimizer(self.ctx, FAKE_FW, HOST)
        self._test_optimizer_even_enqueue('FW_EVENT_DELETE')

    def _test_fullsync(self, optimizer_status, function_name):
        self.opt_svc_helper._invoke_optimizer_driver = mock.Mock()
        self.opt_svc_helper.fullsync = True
        self.optimizer_plugin_api.get_tenants_with_optimizers.return_value = [
            '1']
        optimizer = FAKE_FW
        optimizer['status'] = optimizer_status
        self.optimizer_plugin_api.get_optimizers_for_tenant.return_value = [
            optimizer]
        ctx_p = mock.patch.object(n_context, 'Context').start()
        ctx_p.return_value = self.ctx
        self.opt_svc_helper.process_service()
        self.opt_svc_helper._invoke_optimizer_driver.assert_called_with(
            self.ctx, optimizer, function_name)
        self.assertFalse(self.opt_svc_helper.fullsync)

    def test_proc_service_fullsync_optimizer_pending_create(self):
        self._test_fullsync('PENDING_CREATE', 'create_optimizer')

    def test_proc_service_fullsync_optimizer_pending_update(self):
        self._test_fullsync('PENDING_UPDATE', 'update_optimizer')

    def test_proc_service_fullsync_frewall_pending_delete(self):
        self._test_fullsync('PENDING_DELETE', 'delete_optimizer')

    def _test_proc_service_device_ids(self, optimizer_status, function_name):
        self.opt_svc_helper._invoke_optimizer_driver = mock.Mock()
        self.opt_svc_helper.fullsync = False
        ctx_p = mock.patch.object(n_context, 'Context').start()
        ctx_p.return_value = self.ctx
        optimizer = FAKE_FW
        optimizer['status'] = optimizer_status
        self.optimizer_plugin_api.get_optimizers_for_device.return_value = [
            optimizer]
        self.opt_svc_helper.process_service(device_ids=['123'])
        self.opt_svc_helper._invoke_optimizer_driver.assert_called_with(
            self.ctx, optimizer, function_name)

    def test_proc_service_device_ids_optimizer_pending_create(self):
        self._test_proc_service_device_ids(
            'PENDING_CREATE', 'create_optimizer')

    def test_proc_service_device_ids_optimizer_pending_update(self):
        self._test_proc_service_device_ids(
            'PENDING_UPDATE', 'update_optimizer')

    def test_proc_service_device_ids_optimizer_pending_delete(self):
        self._test_proc_service_device_ids(
            'PENDING_DELETE', 'delete_optimizer')

    def _test_optimizer_event(self, event, function_name):
        self.opt_svc_helper._invoke_optimizer_driver = mock.Mock()
        self.opt_svc_helper.fullsync = False
        event_data = {'event': event, 'context': self.ctx,
                      'optimizer': FAKE_FW, 'host': HOST}
        event_q_returns = [event_data, None]

        def _ev_dequeue_side_effect(*args):
            return event_q_returns.pop(0)

        self.opt_svc_helper.event_q.dequeue = mock.Mock(
            side_effect=_ev_dequeue_side_effect)

        self.opt_svc_helper.process_service()
        self.opt_svc_helper._invoke_optimizer_driver.assert_called_once_with(
            self.ctx, FAKE_FW, function_name)

    def test_proc_service_optimizer_event_create(self):
        self._test_optimizer_event('FW_EVENT_CREATE', 'create_optimizer')

    def test_proc_service_optimizer_event_update(self):
        self._test_optimizer_event('FW_EVENT_UPDATE', 'update_optimizer')

    def test_proc_service_optimizer_event_delete(self):
        self._test_optimizer_event('FW_EVENT_DELETE', 'delete_optimizer')

    def test_invoke_optimizer_driver_for_delete(self):
        self.opt_svc_helper.acl_driver.delete_optimizer = mock.Mock()

        self.opt_svc_helper.acl_driver.delete_optimizer.return_value = True
        self.opt_svc_helper._invoke_optimizer_driver(
            self.ctx, FAKE_FW, 'delete_optimizer')
        self.opt_svc_helper.acl_driver.delete_optimizer.assert_called_with(
            None, None, FAKE_FW)
        self.optimizer_plugin_api.optimizer_deleted.assert_called_with(
            self.ctx, FAKE_FW['id'])

        self.opt_svc_helper.acl_driver.delete_optimizer.return_value = False
        self.opt_svc_helper._invoke_optimizer_driver(
            self.ctx, FAKE_FW, 'delete_optimizer')
        self.optimizer_plugin_api.set_optimizer_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)

    def test_invoke_optimizer_driver_for_create(self):
        self.opt_svc_helper.acl_driver.create_optimizer = mock.Mock()

        self.opt_svc_helper.acl_driver.create_optimizer.return_value = (
            True, FAKE_FW_STATUS)
        self.opt_svc_helper._invoke_optimizer_driver(
            self.ctx, FAKE_FW, 'create_optimizer')
        self.opt_svc_helper.acl_driver.create_optimizer.assert_called_with(
            None, None, FAKE_FW)
        self.optimizer_plugin_api.set_optimizer_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ACTIVE, FAKE_FW_STATUS)

        self.opt_svc_helper.acl_driver.create_optimizer.return_value = (
            False, {})
        self.opt_svc_helper._invoke_optimizer_driver(
            self.ctx, FAKE_FW, 'create_optimizer')
        self.optimizer_plugin_api.set_optimizer_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)

    def test_invoke_optimizer_driver_for_update(self):
        self.opt_svc_helper.acl_driver.update_optimizer = mock.Mock()

        self.opt_svc_helper.acl_driver.update_optimizer.return_value = (
            True, FAKE_FW_STATUS)
        self.opt_svc_helper._invoke_optimizer_driver(
            self.ctx, FAKE_FW, 'update_optimizer')
        self.opt_svc_helper.acl_driver.update_optimizer.assert_called_with(
            None, None, FAKE_FW)
        self.optimizer_plugin_api.set_optimizer_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ACTIVE, FAKE_FW_STATUS)

        self.opt_svc_helper.acl_driver.update_optimizer.return_value = (
            False, {})
        self.opt_svc_helper._invoke_optimizer_driver(
            self.ctx, FAKE_FW, 'update_optimizer')
        self.optimizer_plugin_api.set_optimizer_status.assert_called_with(
            self.ctx, FAKE_FW['id'], constants.ERROR)
