# Copyright 2013 Big Switch Networks, Inc.
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

from neutron.api.v2 import attributes as attr
from neutron import context
from neutron import manager
from neutron.plugins.common import constants as const
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from oslo_config import cfg
import six
from webob import exc

import neutron_oaas.extensions
from neutron_oaas.extensions import optimizer
from neutron_oaas.extensions import optimizerrouterinsertion
from neutron_oaas.services.optimizer import oaas_plugin
from neutron_oaas.tests import base
from neutron_oaas.tests.unit.db.optimizer import (
    test_optimizer_db as test_db_optimizer)

extensions_path = neutron_oaas.extensions.__path__[0]

FW_PLUGIN_KLASS = (
    "neutron_oaas.services.optimizer.oaas_plugin.OptimizerPlugin"
)


class OptimizerTestExtensionManager(test_l3_plugin.L3TestExtensionManager):

    def get_resources(self):
        res = super(OptimizerTestExtensionManager, self).get_resources()
        optimizer.RESOURCE_ATTRIBUTE_MAP['optimizers'].update(
            optimizerrouterinsertion.EXTENDED_ATTRIBUTES_2_0['optimizers'])
        return res + optimizer.Optimizer.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestOptimizerRouterInsertionBase(
        test_db_optimizer.OptimizerPluginDbTestCase):

    def setUp(self, core_plugin=None, opt_plugin=None, ext_mgr=None):
        self.agentapi_del_opt_p = mock.patch(test_db_optimizer.DELETEFW_PATH,
            create=True, new=test_db_optimizer.FakeAgentApi().delete_optimizer)
        self.agentapi_del_opt_p.start()

        plugin = None
        # the plugin without L3 support
        if not plugin:
            plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_l3.'
                     'TestL3NatServicePlugin')

        cfg.CONF.set_override('api_extensions_path', extensions_path)
        self.saved_attr_map = {}
        for resource, attrs in six.iteritems(attr.RESOURCE_ATTRIBUTE_MAP):
            self.saved_attr_map[resource] = attrs.copy()
        if not opt_plugin:
            opt_plugin = FW_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin,
            'opt_plugin_name': opt_plugin}

        if not ext_mgr:
            ext_mgr = OptimizerTestExtensionManager()
        super(test_db_optimizer.OptimizerPluginDbTestCase, self).setUp(
            plugin=plugin, service_plugins=service_plugins, ext_mgr=ext_mgr)

        self.setup_notification_driver()

        self.l3_plugin = manager.NeutronManager.get_service_plugins().get(
            const.L3_ROUTER_NAT)
        self.plugin = manager.NeutronManager.get_service_plugins().get(
            const.OPTIMIZER)
        self.callbacks = self.plugin.endpoints[0]

    def restore_attribute_map(self):
        # Remove the csroptimizerinsertion extension
        optimizer.RESOURCE_ATTRIBUTE_MAP['optimizers'].pop('router_ids')
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attr.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def tearDown(self):
        self.restore_attribute_map()
        super(TestOptimizerRouterInsertionBase, self).tearDown()

    def _create_optimizer(self, fmt, name, description, optimizer_policy_id=None,
                         admin_state_up=True, expected_res_status=None,
                         **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        router_ids = kwargs.get('router_ids')
        if optimizer_policy_id is None:
            res = self._create_optimizer_policy(fmt, 'optp',
                                               description="optimizer_policy",
                                               shared=True,
                                               optimizer_rules=[],
                                               audited=True)
            optimizer_policy = self.deserialize(fmt or self.fmt, res)
            optimizer_policy_id = optimizer_policy["optimizer_policy"]["id"]
        data = {'optimizer': {'name': name,
                             'description': description,
                             'optimizer_policy_id': optimizer_policy_id,
                             'admin_state_up': admin_state_up,
                             'tenant_id': tenant_id}}
        if router_ids is not None:
            data['optimizer']['router_ids'] = router_ids
        optimizer_req = self.new_create_request('optimizers', data, fmt)
        optimizer_res = optimizer_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, optimizer_res.status_int)
        return optimizer_res


class TestOptimizerCallbacks(TestOptimizerRouterInsertionBase):

    def setUp(self):
        super(TestOptimizerCallbacks,
              self).setUp(opt_plugin=FW_PLUGIN_KLASS)
        self.callbacks = self.plugin.endpoints[0]

    def test_set_optimizer_status(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(
                optimizer_policy_id=optp_id,
                admin_state_up=test_db_optimizer.ADMIN_STATE_UP
            ) as opt:
                opt_id = opt['optimizer']['id']
                res = self.callbacks.set_optimizer_status(ctx, opt_id,
                                                         const.ACTIVE,
                                                         host='dummy')
                opt_db = self.plugin.get_optimizer(ctx, opt_id)
                self.assertEqual(opt_db['status'], const.ACTIVE)
                self.assertTrue(res)
                res = self.callbacks.set_optimizer_status(ctx, opt_id,
                                                         const.ERROR)
                opt_db = self.plugin.get_optimizer(ctx, opt_id)
                self.assertEqual(opt_db['status'], const.ERROR)
                self.assertFalse(res)

    def test_set_optimizer_status_pending_delete(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(
                optimizer_policy_id=optp_id,
                admin_state_up=test_db_optimizer.ADMIN_STATE_UP
            ) as opt:
                opt_id = opt['optimizer']['id']
                opt_db = self.plugin._get_optimizer(ctx, opt_id)
                opt_db['status'] = const.PENDING_DELETE
                ctx.session.flush()
                res = self.callbacks.set_optimizer_status(ctx, opt_id,
                                                         const.ACTIVE,
                                                         host='dummy')
                opt_db = self.plugin.get_optimizer(ctx, opt_id)
                self.assertEqual(opt_db['status'], const.PENDING_DELETE)
                self.assertFalse(res)

    def test_optimizer_deleted(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(optimizer_policy_id=optp_id,
                               admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                               do_delete=False) as opt:
                opt_id = opt['optimizer']['id']
                with ctx.session.begin(subtransactions=True):
                    opt_db = self.plugin._get_optimizer(ctx, opt_id)
                    opt_db['status'] = const.PENDING_DELETE
                    ctx.session.flush()
                    res = self.callbacks.optimizer_deleted(ctx, opt_id,
                                                          host='dummy')
                    self.assertTrue(res)
                    self.assertRaises(optimizer.OptimizerNotFound,
                                      self.plugin.get_optimizer,
                                      ctx, opt_id)

    def test_optimizer_deleted_error(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(
                optimizer_policy_id=optp_id,
                admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
            ) as opt:
                opt_id = opt['optimizer']['id']
                res = self.callbacks.optimizer_deleted(ctx, opt_id,
                                                      host='dummy')
                self.assertFalse(res)
                opt_db = self.plugin._get_optimizer(ctx, opt_id)
                self.assertEqual(opt_db['status'], const.ERROR)

    def test_get_optimizer_for_tenant(self):
        tenant_id = 'test-tenant'
        ctx = context.Context('', tenant_id)
        with self.optimizer_rule(name='optr1', tenant_id=tenant_id) as optr1, \
                self.optimizer_rule(name='optr2', tenant_id=tenant_id) as optr2, \
                self.optimizer_rule(name='optr3', tenant_id=tenant_id) as optr3:
            with self.optimizer_policy(tenant_id=tenant_id) as optp:
                optp_id = optp['optimizer_policy']['id']
                fr = [optr1, optr2, optr3]
                opt_rule_ids = [r['optimizer_rule']['id'] for r in fr]
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp_id)
                res = req.get_response(self.ext_api)
                attrs = self._get_test_optimizer_attrs()
                attrs['optimizer_policy_id'] = optp_id
                with self.optimizer(
                        optimizer_policy_id=optp_id,
                        tenant_id=tenant_id,
                        admin_state_up=test_db_optimizer.ADMIN_STATE_UP) as opt:
                    opt_id = opt['optimizer']['id']
                    res = self.callbacks.get_optimizers_for_tenant(ctx,
                                                                  host='dummy')
                    opt_rules = (
                        self.plugin._make_optimizer_dict_with_rules(ctx,
                                                                   opt_id)
                    )
                    opt_rules['add-router-ids'] = []
                    opt_rules['del-router-ids'] = []
                    self.assertEqual(res[0], opt_rules)
                    self._compare_optimizer_rule_lists(
                        optp_id, fr, res[0]['optimizer_rule_list'])

    def test_get_optimizer_for_tenant_without_rules(self):
        tenant_id = 'test-tenant'
        ctx = context.Context('', tenant_id)
        with self.optimizer_policy(tenant_id=tenant_id) as optp:
            optp_id = optp['optimizer_policy']['id']
            attrs = self._get_test_optimizer_attrs()
            attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(optimizer_policy_id=optp_id, tenant_id=tenant_id,
                               admin_state_up=test_db_optimizer.ADMIN_STATE_UP
                               ) as opt:
                    # router_ids is not present in the optimizer db
                    # but is added in the get_optimizers override by plugin
                    opt_list = [opt['optimizer']]
                    f = self.callbacks.get_optimizers_for_tenant_without_rules
                    res = f(ctx, host='dummy')
                    for opt in res:
                        del opt['shared']
                    self.assertEqual(res, opt_list)


class TestOptimizerAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestOptimizerAgentApi, self).setUp()

        self.api = oaas_plugin.OptimizerAgentApi('topic', 'host')

    def test_init(self):
        self.assertEqual(self.api.client.target.topic, 'topic')
        self.assertEqual(self.api.host, 'host')

    def _call_test_helper(self, method_name):
        with mock.patch.object(self.api.client, 'cast') as rpc_mock, \
                mock.patch.object(self.api.client, 'prepare') as prepare_mock:
            prepare_mock.return_value = self.api.client
            getattr(self.api, method_name)(mock.sentinel.context, 'test')

        prepare_args = {'fanout': True}
        prepare_mock.assert_called_once_with(**prepare_args)

        rpc_mock.assert_called_once_with(mock.sentinel.context, method_name,
                                         optimizer='test', host='host')

    def test_create_optimizer(self):
        self._call_test_helper('create_optimizer')

    def test_update_optimizer(self):
        self._call_test_helper('update_optimizer')

    def test_delete_optimizer(self):
        self._call_test_helper('delete_optimizer')


class TestOptimizerPluginBase(TestOptimizerRouterInsertionBase,
                             test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self):
        super(TestOptimizerPluginBase, self).setUp(opt_plugin=FW_PLUGIN_KLASS)

    def tearDown(self):
        super(TestOptimizerPluginBase, self).tearDown()

    def test_create_optimizer_routers_not_specified(self):
        """neutron optimizer-create test-policy """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                with self.optimizer() as opt1:
                    self.assertEqual(const.PENDING_CREATE,
                        opt1['optimizer']['status'])

    def test_create_optimizer_routers_specified(self):
        """neutron optimizer-create test-policy --router-ids "r1 r2" """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id) as router2:
                router_ids = [router1['router']['id'], router2['router']['id']]
                with self.optimizer(router_ids=router_ids) as opt1:
                    self.assertEqual(const.PENDING_CREATE,
                        opt1['optimizer']['status'])

    def test_create_optimizer_routers_present_empty_list_specified(self):
        """neutron optimizer-create test-policy --router-ids "" """
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                router_ids = []
                with self.optimizer(router_ids=router_ids) as opt1:
                    self.assertEqual(const.INACTIVE,
                        opt1['optimizer']['status'])

    def test_create_optimizer_no_routers_empty_list_specified(self):
        """neutron optimizer-create test-policy --router-ids "" """
        router_ids = []
        with self.optimizer(router_ids=router_ids) as opt1:
            self.assertEqual(const.INACTIVE,
                opt1['optimizer']['status'])

    def test_create_second_optimizer_on_same_tenant(self):
        """opt1 created with default routers, opt2 no routers on same tenant."""
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.router(name='router2', admin_state_up=True,
                tenant_id=self._tenant_id):
                router_ids = []
                with self.optimizer() as opt1:
                    with self.optimizer(router_ids=router_ids) as opt2:
                        self.assertEqual(const.PENDING_CREATE,
                            opt1['optimizer']['status'])
                        self.assertEqual(const.INACTIVE,
                            opt2['optimizer']['status'])

    def test_create_optimizer_admin_not_affected_by_other_tenant(self):
        # Create opt with admin after creating opt with other tenant
        with self.optimizer(tenant_id='other-tenant') as opt1:
            with self.optimizer() as opt2:
                self.assertEqual('other-tenant', opt1['optimizer']['tenant_id'])
                self.assertEqual(self._tenant_id, opt2['optimizer']['tenant_id'])

    def test_update_optimizer(self):
        ctx = context.get_admin_context()
        name = "new_optimizer1"
        attrs = self._get_test_optimizer_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['optimizer_policy_id'] = optp_id
                with self.optimizer(
                    optimizer_policy_id=optp_id,
                    admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                    router_ids=[router1['router']['id']]
                ) as optimizer:
                    opt_id = optimizer['optimizer']['id']
                    res = self.callbacks.set_optimizer_status(ctx, opt_id,
                                                         const.ACTIVE)
                    data = {'optimizer': {'name': name}}
                    req = self.new_update_request('optimizers', data, opt_id)
                    res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                    attrs = self._replace_optimizer_status(attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_UPDATE)
                    for k, v in six.iteritems(attrs):
                        self.assertEqual(res['optimizer'][k], v)

    def test_update_optimizer_fails_when_optimizer_pending(self):
        name = "new_optimizer1"
        attrs = self._get_test_optimizer_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['optimizer_policy_id'] = optp_id
                with self.optimizer(
                    optimizer_policy_id=optp_id,
                    admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                    router_ids=[router1['router']['id']]
                ) as optimizer:
                    opt_id = optimizer['optimizer']['id']
                    data = {'optimizer': {'name': name}}
                    req = self.new_update_request('optimizers', data, opt_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_update_optimizer_with_router_when_optimizer_inactive(self):
        name = "optimizer1"
        attrs = self._get_test_optimizer_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['optimizer_policy_id'] = optp_id
                with self.optimizer(
                    name=name,
                    optimizer_policy_id=optp_id,
                    admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                    router_ids=[]
                ) as optimizer:
                    opt_id = optimizer['optimizer']['id']
                    data = {
                        'optimizer': {'router_ids': [router1['router']['id']]}}
                    req = self.new_update_request('optimizers', data, opt_id)
                    res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                    attrs = self._replace_optimizer_status(attrs,
                                                      const.PENDING_CREATE,
                                                      const.PENDING_UPDATE)
                    for k, v in six.iteritems(attrs):
                        self.assertEqual(res['optimizer'][k], v)

    def test_update_optimizer_shared_fails_for_non_admin(self):
        ctx = context.get_admin_context()
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id) as router1:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                with self.optimizer(
                    optimizer_policy_id=optp_id,
                    admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                    tenant_id='noadmin',
                    router_ids=[router1['router']['id']]
                ) as optimizer:
                    opt_id = optimizer['optimizer']['id']
                    self.callbacks.set_optimizer_status(ctx, opt_id,
                                                   const.ACTIVE)
                    data = {'optimizer': {'shared': True}}
                    req = self.new_update_request(
                        'optimizers', data, opt_id,
                        context=context.Context('', 'noadmin'))
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPForbidden.code, res.status_int)

    def test_update_optimizer_policy_fails_when_optimizer_pending(self):
        name = "new_optimizer1"
        attrs = self._get_test_optimizer_attrs(name)

        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['optimizer_policy_id'] = optp_id
                with self.optimizer(
                    optimizer_policy_id=optp_id,
                    admin_state_up=test_db_optimizer.ADMIN_STATE_UP
                ):
                    data = {'optimizer_policy': {'name': name}}
                    req = self.new_update_request('optimizer_policies',
                                              data, optp_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_update_optimizer_rule_fails_when_optimizer_pending(self):
        with self.router(name='router1', admin_state_up=True,
            tenant_id=self._tenant_id):
            with self.optimizer_rule(name='optr1') as fr:
                with self.optimizer_policy() as optp:
                    optp_id = optp['optimizer_policy']['id']
                    fr_id = fr['optimizer_rule']['id']
                    opt_rule_ids = [fr_id]
                    data = {'optimizer_policy':
                           {'optimizer_rules': opt_rule_ids}}
                    req = self.new_update_request('optimizer_policies', data,
                                              optp_id)
                    req.get_response(self.ext_api)
                    with self.optimizer(
                        optimizer_policy_id=optp_id,
                        admin_state_up=test_db_optimizer.ADMIN_STATE_UP
                    ):
                        data = {'optimizer_rule': {'protocol': 'udp'}}
                        req = self.new_update_request('optimizer_rules',
                                                  data, fr_id)
                        res = req.get_response(self.ext_api)
                        self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_delete_optimizer_with_no_routers(self):
        ctx = context.get_admin_context()
        # stop the AgentRPC patch for this one to test pending states
        self.agentapi_del_opt_p.stop()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(
                optimizer_policy_id=optp_id,
                admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                do_delete=False
            ) as opt:
                opt_id = opt['optimizer']['id']
                req = self.new_delete_request('optimizers', opt_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
                self.assertRaises(optimizer.OptimizerNotFound,
                                  self.plugin.get_optimizer,
                                  ctx, opt_id)

    def test_delete_optimizer_after_agent_delete(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(optimizer_policy_id=optp_id,
                               do_delete=False) as opt:
                opt_id = opt['optimizer']['id']
                req = self.new_delete_request('optimizers', opt_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, exc.HTTPNoContent.code)
                self.assertRaises(optimizer.OptimizerNotFound,
                                  self.plugin.get_optimizer,
                                  ctx, opt_id)

    def test_make_optimizer_dict_with_in_place_rules(self):
        ctx = context.get_admin_context()
        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3:
            with self.optimizer_policy() as optp:
                fr = [optr1, optr2, optr3]
                optp_id = optp['optimizer_policy']['id']
                opt_rule_ids = [r['optimizer_rule']['id'] for r in fr]
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp_id)
                req.get_response(self.ext_api)
                attrs = self._get_test_optimizer_attrs()
                attrs['optimizer_policy_id'] = optp_id
                with self.optimizer(
                    optimizer_policy_id=optp_id,
                    admin_state_up=test_db_optimizer.ADMIN_STATE_UP,
                    router_ids=[]
                ) as opt:
                    opt_id = opt['optimizer']['id']
                    opt_rules = (
                        self.plugin._make_optimizer_dict_with_rules(ctx,
                                                                   opt_id)
                    )
                    self.assertEqual(opt_rules['id'], opt_id)
                    self._compare_optimizer_rule_lists(
                        optp_id, fr, opt_rules['optimizer_rule_list'])

    def test_make_optimizer_dict_with_in_place_rules_no_policy(self):
        ctx = context.get_admin_context()
        with self.optimizer() as opt:
            opt_id = opt['optimizer']['id']
            opt_rules = self.plugin._make_optimizer_dict_with_rules(ctx, opt_id)
            self.assertEqual([], opt_rules['optimizer_rule_list'])

    def test_list_optimizers(self):
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(name='opt1', optimizer_policy_id=optp_id,
                               description='opt') as optalls:
                self._test_list_resources('optimizer', [optalls],
                                          query_params='description=opt')

    def test_insert_rule(self):
        ctx = context.get_admin_context()
        with self.optimizer_rule() as optr:
            fr_id = optr['optimizer_rule']['id']
            rule_info = {'optimizer_rule_id': fr_id}
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                with self.optimizer(optimizer_policy_id=optp_id) as opt:
                    opt_id = opt['optimizer']['id']
                    self.plugin.insert_rule(ctx, optp_id, rule_info)
                    opt_rules = self.plugin._make_optimizer_dict_with_rules(
                        ctx, opt_id)
                    self.assertEqual(1, len(opt_rules['optimizer_rule_list']))
                    self.assertEqual(fr_id,
                                     opt_rules['optimizer_rule_list'][0]['id'])

    def test_remove_rule(self):
        ctx = context.get_admin_context()
        with self.optimizer_rule() as optr:
            fr_id = optr['optimizer_rule']['id']
            rule_info = {'optimizer_rule_id': fr_id}
            with self.optimizer_policy(optimizer_rules=[fr_id]) as optp:
                optp_id = optp['optimizer_policy']['id']
                with self.optimizer(optimizer_policy_id=optp_id) as opt:
                    opt_id = opt['optimizer']['id']
                    self.plugin.remove_rule(ctx, optp_id, rule_info)
                    opt_rules = self.plugin._make_optimizer_dict_with_rules(
                        ctx, opt_id)
                    self.assertEqual([], opt_rules['optimizer_rule_list'])
