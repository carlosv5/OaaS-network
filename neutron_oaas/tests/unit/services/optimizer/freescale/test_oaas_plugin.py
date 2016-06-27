# Copyright 2015 Freescale, Inc.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import mock
from neutron import context
from neutron import manager
from webob import exc

from neutron.plugins.common import constants as const
from neutron_oaas.tests.unit.db.optimizer import (
    test_optimizer_db as test_db_optimizer)

"""Unit testing for Freescale OaaS Plugin."""

PLUGIN = ("neutron_oaas.services.optimizer.freescale"
          ".oaas_plugin.OptimizerPlugin")


class TestOptimizerCallbacks(test_db_optimizer.OptimizerPluginDbTestCase):

    def setUp(self):
        mock.patch('neutronclient.v2_0.client.Client').start()
        super(TestOptimizerCallbacks, self).setUp(opt_plugin=PLUGIN)
        n_mgr = manager.NeutronManager
        self.plugin = n_mgr.get_service_plugins()[const.OPTIMIZER]
        self.callbacks = self.plugin.endpoints[0]
        self.ctx = context.get_admin_context()

    def test_get_optimizers_for_tenant(self):
        tenant_id = 'test-tenant'
        with self.optimizer_rule(name='optr1', tenant_id=tenant_id,
                                do_delete=False) as fr:
            with self.optimizer_policy(tenant_id=tenant_id,
                                      do_delete=False) as optp:
                optp_id = optp['optimizer_policy']['id']
                opt_id = fr['optimizer_rule']['id']
                data = {'optimizer_policy':
                        {'optimizer_rules': [opt_id]}}
                self.plugin.update_optimizer_policy(self.ctx, optp_id, data)
                admin_state = test_db_optimizer.ADMIN_STATE_UP
                with self.optimizer(optimizer_policy_id=optp_id,
                                   tenant_id=tenant_id,
                                   do_delete=False,
                                   admin_state_up=admin_state) as opt:
                    self.callbacks.get_optimizers_for_tenant(self.ctx,
                                                            host='dummy')
                    opt_id = opt['optimizer']['id']
                    opt['optimizer']['config_mode'] = "NN"
                    self.plugin._client.show_optimizer.assert_called_once_with(
                        opt_id)
                    self.plugin.delete_optimizer(self.ctx, opt_id)
                self.callbacks.optimizer_deleted(self.ctx, opt_id)
            self.plugin.delete_optimizer_policy(self.ctx, optp_id)
        self.plugin.delete_optimizer_rule(self.ctx, fr['optimizer_rule']['id'])


class TestFreescaleOptimizerPlugin(test_db_optimizer.TestOptimizerDBPlugin):

    def setUp(self):
        mock.patch('neutronclient.v2_0.client.Client').start()
        super(TestFreescaleOptimizerPlugin, self).setUp(opt_plugin=PLUGIN)
        self.plugin = manager.NeutronManager.get_service_plugins()['OPTIMIZER']
        self.callbacks = self.plugin.endpoints[0]
        self.clnt = self.plugin._client
        self.ctx = context.get_admin_context()

    def test_create_optimizer_with_admin_and_optp_is_shared(self):
        opt_name = "opt_with_shared_optp"
        with self.optimizer_policy(do_delete=False, tenant_id="tenantX") as optp:
            optp_id = optp['optimizer_policy']['id']
            ctx = context.get_admin_context()
            target_tenant = 'tenant1'
            with self.optimizer(name=opt_name,
                               optimizer_policy_id=optp_id,
                               tenant_id=target_tenant,
                               context=ctx,
                               do_delete=False,
                               admin_state_up=True) as opt:
                self.assertEqual(opt['optimizer']['tenant_id'], target_tenant)
                opt_id = opt['optimizer']['id']
            self.plugin.delete_optimizer(self.ctx, opt_id)
            self.clnt.delete_optimizer.assert_called_once_with(opt_id)
            self.callbacks.optimizer_deleted(self.ctx, opt_id)

    def test_create_update_delete_optimizer_rule(self):
        """Testing create, update and delete optimizer rule."""
        ctx = context.get_admin_context()
        clnt = self.plugin._client
        with self.optimizer_rule(do_delete=False) as optr:
            optr_id = optr['optimizer_rule']['id']
            # Create Optimizer Rule
            crd_rule = {'optimizer_rule': optr}
            clnt.create_optimizer_rule.assert_called_once_with(optr)
            # Update Optimizer Rule
            data = {'optimizer_rule': {'name': 'new_rule_name',
                                      'source_port': '10:20',
                                      'destination_port': '30:40'}}
            opt_rule = self.plugin.update_optimizer_rule(ctx, optr_id, data)
            crd_rule = {'optimizer_rule': opt_rule}
            clnt.update_optimizer_rule.assert_called_once_with(optr_id, crd_rule)
            # Delete Optimizer Rule
            self.plugin.delete_optimizer_rule(ctx, optr_id)
            clnt.delete_optimizer_rule.assert_called_once_with(optr_id)

    def test_create_update_delete_optimizer_policy(self):
        """Testing create, update and delete optimizer policy."""
        with self.optimizer_policy(do_delete=False) as optp:
            optp_id = optp['optimizer_policy']['id']
            # Create Optimizer Policy
            crd_policy = {'optimizer_policy': optp}
            self.clnt.create_optimizer_policy.assert_called_once_with(optp)
            # Update Optimizer Policy
            data = {'optimizer_policy': {'name': 'updated-name'}}
            optp = self.plugin.update_optimizer_policy(self.ctx, optp_id, data)
            crd_policy = {'optimizer_policy': optp}
            self.clnt.update_optimizer_policy.assert_called_once_with(
                optp_id,
                crd_policy)
            # Delete Optimizer Policy
            self.plugin.delete_optimizer_policy(self.ctx, optp_id)
            self.clnt.delete_optimizer_policy.assert_called_once_with(optp_id)

    def test_create_optimizer(self):
        name = "optimizer-fake"
        expected_attrs = self._get_test_optimizer_attrs(name)
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            expected_attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(name=name,
                               optimizer_policy_id=optp_id,
                               admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                               do_delete=False) as actual_optimizer:
                opt_id = actual_optimizer['optimizer']['id']
                self.assertDictSupersetOf(expected_attrs,
                        actual_optimizer['optimizer'])
            self.plugin.delete_optimizer(self.ctx, opt_id)
            self.clnt.delete_optimizer.assert_called_once_with(opt_id)
            self.callbacks.optimizer_deleted(self.ctx, opt_id)

    def test_show_optimizer(self):
        name = "optimizer1"
        expected_attrs = self._get_test_optimizer_attrs(name)
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            expected_attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(name=name,
                               optimizer_policy_id=optp_id,
                               admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                               do_delete=False) as actual_optimizer:
                opt_id = actual_optimizer['optimizer']['id']
                req = self.new_show_request('optimizers', opt_id,
                                            fmt=self.fmt)
                actual_opt = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertDictSupersetOf(expected_attrs,
                        actual_opt['optimizer'])
            self.plugin.delete_optimizer(self.ctx, opt_id)
            self.clnt.delete_optimizer.assert_called_once_with(opt_id)
            self.callbacks.optimizer_deleted(self.ctx, opt_id)

    def test_update_optimizer(self):
        name = "new_optimizer1"
        expected_attrs = self._get_test_optimizer_attrs(name)
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            expected_attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(optimizer_policy_id=optp_id,
                               admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                               do_delete=False) as optimizer:
                opt_id = optimizer['optimizer']['id']
                self.callbacks.set_optimizer_status(self.ctx, opt_id,
                        const.ACTIVE)
                data = {'optimizer': {'name': name}}
                req = self.new_update_request('optimizers', data, opt_id)
                actual_opt = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                expected_attrs = self._replace_optimizer_status(expected_attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_UPDATE)
                self.assertDictSupersetOf(expected_attrs,
                        actual_opt['optimizer'])
            self.plugin.delete_optimizer(self.ctx, opt_id)
            self.clnt.delete_optimizer.assert_called_once_with(opt_id)
            self.callbacks.optimizer_deleted(self.ctx, opt_id)

    def test_update_optimizer_with_optp(self):
        with self.optimizer_policy() as optp1, \
                self.optimizer_policy(shared=False, do_delete=False) as optp2, \
                self.optimizer(optimizer_policy_id=optp1['optimizer_policy']['id'],
                              admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                              do_delete=False) as optimizer:
            opt_id = optimizer['optimizer']['id']
            optp2_id = optp2['optimizer_policy']['id']
            self.callbacks.set_optimizer_status(self.ctx, opt_id, const.ACTIVE)
            data = {'optimizer': {'optimizer_policy_id': optp2_id}}
            req = self.new_update_request('optimizers', data, opt_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_optimizer_with_shared_optp(self):
        with self.optimizer_policy() as optp1, \
                self.optimizer_policy(tenant_id='tenant2',
                                     do_delete=False) as optp2, \
                self.optimizer(optimizer_policy_id=optp1['optimizer_policy']['id'],
                              admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                              do_delete=False) as optimizer:
            opt_id = optimizer['optimizer']['id']
            optp2_id = optp2['optimizer_policy']['id']
            self.callbacks.set_optimizer_status(self.ctx, opt_id, const.ACTIVE)
            data = {'optimizer': {'optimizer_policy_id': optp2_id}}
            req = self.new_update_request('optimizers', data, opt_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_optimizer_with_admin_and_optp_different_tenant(self):
        with self.optimizer_policy(do_delete=False) as optp1, \
                self.optimizer_policy(tenant_id='tenant2', shared=False,
                                     do_delete=False) as optp2, \
                self.optimizer(optimizer_policy_id=optp1['optimizer_policy']['id'],
                              admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                              do_delete=False) as optimizer:
            opt_id = optimizer['optimizer']['id']
            optp2_id = optp2['optimizer_policy']['id']
            self.callbacks.set_optimizer_status(self.ctx, opt_id, const.ACTIVE)
            data = {'optimizer': {'optimizer_policy_id': optp2_id}}
            req = self.new_update_request('optimizers', data, opt_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(409, res.status_int)

    def test_list_optimizers(self):
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(name='opt1', optimizer_policy_id=optp_id,
                               description='opt') as opt1, \
                    self.optimizer(name='opt2', optimizer_policy_id=optp_id,
                                  description='opt') as opt2, \
                    self.optimizer(name='opt3', optimizer_policy_id=optp_id,
                                  description='opt') as opt3:

                optalls = [opt1, opt2, opt3]
                self._test_list_resources('optimizer', optalls,
                                          query_params='description=opt')
            for opt in optalls:
                opt_id = opt['optimizer']['id']
                self.plugin.delete_optimizer(self.ctx, opt_id)
                self.callbacks.optimizer_deleted(self.ctx, opt_id)

    def test_delete_optimizer_policy_with_optimizer_association(self):
        attrs = self._get_test_optimizer_attrs()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(optimizer_policy_id=optp_id,
                               admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                               do_delete=False)as opt:
                opt_id = opt['optimizer']['id']
                req = self.new_delete_request('optimizer_policies', optp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPConflict.code)
            self.plugin.delete_optimizer(self.ctx, opt_id)
            self.clnt.delete_optimizer.assert_called_once_with(opt_id)
            self.callbacks.optimizer_deleted(self.ctx, opt_id)

    def test_update_optimizer_policy_assoc_with_other_tenant_optimizer(self):
        with self.optimizer_policy(shared=True, tenant_id='tenant1') as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(optimizer_policy_id=optp_id,
                               do_delete=False) as opt:
                opt_id = opt['optimizer']['id']
                data = {'optimizer_policy': {'shared': False}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPConflict.code)
            self.plugin.delete_optimizer(self.ctx, opt_id)
            self.clnt.delete_optimizer.assert_called_once_with(opt_id)
            self.callbacks.optimizer_deleted(self.ctx, opt_id)

    def test_delete_optimizer(self):
        attrs = self._get_test_optimizer_attrs()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(optimizer_policy_id=optp_id,
                               admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                               do_delete=False) as optimizer:
                opt_id = optimizer['optimizer']['id']
                attrs = self._replace_optimizer_status(attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_DELETE)
                req = self.new_delete_request('optimizers', opt_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
            self.clnt.delete_optimizer.assert_called_once_with(opt_id)
            self.plugin.endpoints[0].optimizer_deleted(self.ctx, opt_id)

    def test_insert_remove_rule(self):
        """Testing Insert and Remove rule operations."""
        status_update = {"optimizer": {"status": 'PENDING_UPDATE'}}
        with self.optimizer_rule(name='fake_rule',
                                do_delete=False) as fr1:
            fr_id = fr1['optimizer_rule']['id']
            with self.optimizer_policy(do_delete=False) as optp:
                optp_id = optp['optimizer_policy']['id']
                with self.optimizer(optimizer_policy_id=optp_id,
                                   do_delete=False) as opt:
                    opt_id = opt['optimizer']['id']
                    # Insert Rule
                    rule_info = {'optimizer_rule_id': fr_id}
                    self.plugin.insert_rule(self.ctx, optp_id, rule_info)
                    fp_insert_rule = self.clnt.optimizer_policy_insert_rule
                    fp_insert_rule.assert_called_once_with(optp_id, rule_info)
                    self.clnt.update_optimizer.assert_called_once_with(
                        opt_id,
                        status_update)
                    # Remove Rule
                    rule_info = {'optimizer_rule_id': fr_id}
                    self.plugin.remove_rule(self.ctx, optp_id, rule_info)
                    fp_remove_rule = self.clnt.optimizer_policy_remove_rule
                    fp_remove_rule.assert_called_once_with(optp_id, rule_info)
                    self.clnt.update_optimizer.assert_called_with(opt_id,
                                                                 status_update)

    def test_create_optimizer_with_dvr(self):
        """Skip DVR Testing."""
        self.skipTest("DVR not supported")
