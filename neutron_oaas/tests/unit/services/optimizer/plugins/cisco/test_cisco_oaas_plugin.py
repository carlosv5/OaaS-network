# Copyright 2015 Cisco Systems, Inc.  All rights reserved.
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
#

import mock

from neutron.api.v2 import attributes as attr
from neutron import context
from neutron import manager
from neutron.plugins.common import constants as const
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
import six

import neutron_oaas
from neutron_oaas.db.cisco import cisco_oaas_db as csropt_db
from neutron_oaas.extensions.cisco import csr_optimizer_insertion
from neutron_oaas.extensions import optimizer
from neutron_oaas.services.optimizer.plugins.cisco import cisco_oaas_plugin
from neutron_oaas.tests.unit.db.optimizer import (
    test_optimizer_db as test_db_optimizer)
from oslo_config import cfg

# We need the test_l3_plugin to ensure we have a valid port_id corresponding
# to a router interface.
CORE_PLUGIN_KLASS = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
L3_PLUGIN_KLASS = (
    'neutron.tests.unit.extensions.test_l3.TestL3NatServicePlugin')
# the plugin under test
CSR_FW_PLUGIN_KLASS = (
    "neutron_oaas.services.optimizer.plugins.cisco.cisco_oaas_plugin."
    "CSROptimizerPlugin"
)
extensions_path = neutron_oaas.extensions.__path__[0] + '/cisco'


class CSR1kvOptimizerTestExtensionManager(
    test_l3_plugin.L3TestExtensionManager):

    def get_resources(self):
        res = super(CSR1kvOptimizerTestExtensionManager, self).get_resources()
        optimizer.RESOURCE_ATTRIBUTE_MAP['optimizers'].update(
            csr_optimizer_insertion.EXTENDED_ATTRIBUTES_2_0['optimizers'])
        return res + optimizer.Optimizer.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class CSR1kvOptimizerTestCaseBase(test_db_optimizer.OptimizerPluginDbTestCase,
        test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self, core_plugin=None, l3_plugin=None, opt_plugin=None,
            ext_mgr=None):
        self.agentapi_delf_p = mock.patch(test_db_optimizer.DELETEFW_PATH,
            create=True, new=test_db_optimizer.FakeAgentApi().delete_optimizer)
        self.agentapi_delf_p.start()
        cfg.CONF.set_override('api_extensions_path', extensions_path)
        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        self.saved_attr_map = {}
        for resource, attrs in six.iteritems(attr.RESOURCE_ATTRIBUTE_MAP):
            self.saved_attr_map[resource] = attrs.copy()
        if not core_plugin:
            core_plugin = CORE_PLUGIN_KLASS
        if l3_plugin is None:
            l3_plugin = L3_PLUGIN_KLASS
        if not opt_plugin:
            opt_plugin = CSR_FW_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin,
            'opt_plugin_name': opt_plugin}
        if not ext_mgr:
            ext_mgr = CSR1kvOptimizerTestExtensionManager()
        super(test_db_optimizer.OptimizerPluginDbTestCase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins,
            ext_mgr=ext_mgr)

        self.core_plugin = manager.NeutronManager.get_plugin()
        self.l3_plugin = manager.NeutronManager.get_service_plugins().get(
            const.L3_ROUTER_NAT)
        self.plugin = manager.NeutronManager.get_service_plugins().get(
            const.OPTIMIZER)
        self.callbacks = self.plugin.endpoints[0]

        self.setup_notification_driver()

    def restore_attribute_map(self):
        # Remove the csroptimizerinsertion extension
        optimizer.RESOURCE_ATTRIBUTE_MAP['optimizers'].pop('port_id')
        optimizer.RESOURCE_ATTRIBUTE_MAP['optimizers'].pop('direction')
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attr.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def tearDown(self):
        self.restore_attribute_map()
        super(CSR1kvOptimizerTestCaseBase, self).tearDown()

    def _create_optimizer(self, fmt, name, description, optimizer_policy_id=None,
                         admin_state_up=True, expected_res_status=None,
                         **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        port_id = kwargs.get('port_id')
        direction = kwargs.get('direction')
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
        if port_id:
            data['optimizer']['port_id'] = port_id
        if direction:
            data['optimizer']['direction'] = direction
        optimizer_req = self.new_create_request('optimizers', data, fmt)
        optimizer_res = optimizer_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, optimizer_res.status_int)
        return optimizer_res


class TestCiscoOptimizerCallbacks(test_db_optimizer.OptimizerPluginDbTestCase):

    def setUp(self):
        super(TestCiscoOptimizerCallbacks, self).setUp()
        self.plugin = cisco_oaas_plugin.CSROptimizerPlugin()
        self.callbacks = self.plugin.endpoints[0]

    def test_optimizer_deleted(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy(do_delete=False) as optp:
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


class TestCiscoOptimizerPlugin(CSR1kvOptimizerTestCaseBase,
                              csropt_db.CiscoOptimizer_db_mixin):

    def setUp(self):
        super(TestCiscoOptimizerPlugin, self).setUp()
        self.fake_vendor_ext = {
            'host_mngt_ip': '1.2.3.4',
            'host_usr_nm': 'admin',
            'host_usr_pw': 'cisco',
            'if_list': {'port': {'id': 0, 'hosting_info': 'csr'},
                        'direction': 'default'}
        }
        self.mock_get_hosting_info = mock.patch.object(
            self.plugin, '_get_hosting_info').start()

    def test_create_csr_optimizer(self):

        with self.router(tenant_id=self._tenant_id) as r,\
                self.subnet() as s:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s['subnet']['id'],
                None)
            port_id = body['port_id']

            self.fake_vendor_ext['if_list']['port']['id'] = port_id
            self.fake_vendor_ext['if_list']['direction'] = 'inside'
            self.mock_get_hosting_info.return_value = self.fake_vendor_ext

            with self.optimizer(port_id=body['port_id'],
                direction='inside') as opt:
                ctx = context.get_admin_context()
                opt_id = opt['optimizer']['id']
                csropt = self.lookup_optimizer_csr_association(
                    ctx, opt_id)
                # cant be in PENDING_XXX state for delete clean up
                with ctx.session.begin(subtransactions=True):
                    opt_db = self.plugin._get_optimizer(ctx, opt_id)
                    opt_db['status'] = const.ACTIVE
                    ctx.session.flush()
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s['subnet']['id'],
                None)

            self.assertEqual('optimizer_1', opt['optimizer']['name'])
            self.assertEqual(port_id, csropt['port_id'])
            self.assertEqual('inside', csropt['direction'])

    def test_create_csr_optimizer_only_port_id_specified(self):

        with self.router(tenant_id=self._tenant_id) as r, \
                self.subnet() as s:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s['subnet']['id'],
                None)
            port_id = body['port_id']

            self.fake_vendor_ext['if_list']['port']['id'] = port_id
            self.fake_vendor_ext['if_list']['direction'] = None
            self.mock_get_hosting_info.return_value = self.fake_vendor_ext

            with self.optimizer(port_id=body['port_id']) as opt:
                ctx = context.get_admin_context()
                opt_id = opt['optimizer']['id']
                csropt = self.lookup_optimizer_csr_association(
                    ctx, opt_id)
                # cant be in PENDING_XXX state for delete clean up
                with ctx.session.begin(subtransactions=True):
                    opt_db = self.plugin._get_optimizer(ctx, opt_id)
                    opt_db['status'] = const.ACTIVE
                    ctx.session.flush()
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s['subnet']['id'],
                None)

            self.assertEqual('optimizer_1', opt['optimizer']['name'])
            self.assertEqual(port_id, csropt['port_id'])
            self.assertEqual(None, csropt['direction'])

    def test_create_csr_optimizer_no_port_id_no_direction_specified(self):

        with self.optimizer() as opt:
            ctx = context.get_admin_context()
            opt_id = opt['optimizer']['id']
            csropt = self.lookup_optimizer_csr_association(
                ctx, opt_id)
            # cant be in PENDING_XXX state for delete clean up
            with ctx.session.begin(subtransactions=True):
                opt_db = self.plugin._get_optimizer(ctx, opt_id)
                opt_db['status'] = const.ACTIVE
                ctx.session.flush()

            self.assertEqual('optimizer_1', opt['optimizer']['name'])
            self.assertEqual(None, csropt)

    def test_update_csr_optimizer(self):

        with self.router(tenant_id=self._tenant_id) as r, \
                self.subnet() as s:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s['subnet']['id'],
                None)
            port_id = body['port_id']

            self.fake_vendor_ext['if_list']['port']['id'] = port_id
            self.fake_vendor_ext['if_list']['direction'] = 'inside'
            self.mock_get_hosting_info.return_value = self.fake_vendor_ext

            with self.optimizer(port_id=body['port_id'],
                 direction='both') as opt:
                ctx = context.get_admin_context()
                opt_id = opt['optimizer']['id']
                csropt = self.lookup_optimizer_csr_association(
                    ctx, opt_id)
                status_data = {'acl_id': 100}

                res = self.callbacks.set_optimizer_status(ctx, opt_id,
                    const.ACTIVE, status_data)

                # update direction on same port
                data = {'optimizer': {'name': 'optimizer_2',
                    'direction': 'both', 'port_id': port_id}}
                req = self.new_update_request('optimizers', data,
                    opt['optimizer']['id'])
                req.environ['neutron.context'] = context.Context(
                    '', 'test-tenant')
                res = self.deserialize(self.fmt,
                req.get_response(self.ext_api))

                csropt = self.lookup_optimizer_csr_association(ctx,
                    opt['optimizer']['id'])

                self.assertEqual('optimizer_2', res['optimizer']['name'])
                self.assertEqual(port_id, csropt['port_id'])
                self.assertEqual('both', csropt['direction'])

                # cant be in PENDING_XXX state for delete clean up
                with ctx.session.begin(subtransactions=True):
                    opt_db = self.plugin._get_optimizer(ctx, opt_id)
                    opt_db['status'] = const.ACTIVE
                    ctx.session.flush()
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s['subnet']['id'],
                None)

    def test_update_csr_optimizer_port_id(self):

        with self.router(tenant_id=self._tenant_id) as r, \
                self.subnet() as s1, \
                self.subnet(cidr='20.0.0.0/24') as s2:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            port_id1 = body['port_id']

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s2['subnet']['id'],
                None)
            port_id2 = body['port_id']

            self.fake_vendor_ext['if_list']['port']['id'] = port_id1
            self.fake_vendor_ext['if_list']['direction'] = 'inside'
            self.mock_get_hosting_info.return_value = self.fake_vendor_ext

            with self.optimizer(port_id=port_id1,
                 direction='both') as opt:
                ctx = context.get_admin_context()
                opt_id = opt['optimizer']['id']
                status_data = {'acl_id': 100}

                res = self.callbacks.set_optimizer_status(ctx, opt_id,
                    const.ACTIVE, status_data)

                # update direction on same port
                data = {'optimizer': {'name': 'optimizer_2',
                    'direction': 'both', 'port_id': port_id2}}
                req = self.new_update_request('optimizers', data,
                    opt['optimizer']['id'])
                req.environ['neutron.context'] = context.Context(
                    '', 'test-tenant')
                res = self.deserialize(self.fmt,
                req.get_response(self.ext_api))

                csropt = self.lookup_optimizer_csr_association(ctx,
                    opt['optimizer']['id'])

                self.assertEqual('optimizer_2', res['optimizer']['name'])
                self.assertEqual(port_id2, csropt['port_id'])
                self.assertEqual('both', csropt['direction'])

                # cant be in PENDING_XXX state for delete clean up
                with ctx.session.begin(subtransactions=True):
                    opt_db = self.plugin._get_optimizer(ctx, opt_id)
                    opt_db['status'] = const.ACTIVE
                    ctx.session.flush()
            self._router_interface_action('remove',
                r['router']['id'],
                s1['subnet']['id'],
                None)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s2['subnet']['id'],
                None)

    def test_delete_csr_optimizer(self):

        with self.router(tenant_id=self._tenant_id) as r, \
                self.subnet() as s:

            body = self._router_interface_action(
                'add',
                r['router']['id'],
                s['subnet']['id'],
                None)
            port_id = body['port_id']

            self.fake_vendor_ext['if_list']['port']['id'] = port_id
            self.fake_vendor_ext['if_list']['direction'] = 'inside'
            self.mock_get_hosting_info.return_value = self.fake_vendor_ext

            with self.optimizer(port_id=port_id,
                direction='inside', do_delete=False) as opt:
                opt_id = opt['optimizer']['id']
                ctx = context.get_admin_context()
                csropt = self.lookup_optimizer_csr_association(ctx,
                    opt_id)
                self.assertNotEqual(None, csropt)
                req = self.new_delete_request('optimizers', opt_id)
                req.get_response(self.ext_api)
                with ctx.session.begin(subtransactions=True):
                    opt_db = self.plugin._get_optimizer(ctx, opt_id)
                    opt_db['status'] = const.PENDING_DELETE
                    ctx.session.flush()
                self.callbacks.optimizer_deleted(ctx, opt_id)
                csropt = self.lookup_optimizer_csr_association(ctx,
                    opt_id)
                self.assertEqual(None, csropt)
            self._router_interface_action(
                'remove',
                r['router']['id'],
                s['subnet']['id'],
                None)
