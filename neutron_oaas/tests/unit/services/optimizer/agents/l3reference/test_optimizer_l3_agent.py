# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
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

import uuid

import mock
from oslo_config import cfg

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import config as l3_config
from neutron.agent.l3 import ha
from neutron.agent.l3 import router_info
from neutron.agent.linux import ip_lib
from neutron.common import config as base_config
from neutron import context
from neutron.plugins.common import constants
from neutron_oaas.services.optimizer.agents import optimizer_agent_api
from neutron_oaas.services.optimizer.agents.l3reference \
    import optimizer_l3_agent
from neutron_oaas.tests import base
from neutron_oaas.tests.unit.services.optimizer.agents \
    import test_optimizer_agent_api


class FWaasHelper(object):
    def __init__(self, host):
        pass


class FWaasAgent(optimizer_l3_agent.OaaSL3AgentRpcCallback, FWaasHelper):
    neutron_service_plugins = []


def _setup_test_agent_class(service_plugins):
    class FWaasTestAgent(optimizer_l3_agent.OaaSL3AgentRpcCallback,
                         FWaasHelper):
        neutron_service_plugins = service_plugins

        def __init__(self, conf):
            self.event_observers = mock.Mock()
            self.conf = conf
            super(FWaasTestAgent, self).__init__(conf)

    return FWaasTestAgent


class TestOaasL3AgentRpcCallback(base.BaseTestCase):
    def setUp(self):
        super(TestOaasL3AgentRpcCallback, self).setUp()

        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(l3_config.OPTS)
        self.conf.register_opts(ha.OPTS)
        agent_config.register_use_namespaces_opts_helper(self.conf)
        self.conf.register_opts(optimizer_agent_api.OaaSOpts, 'oaas')
        self.api = FWaasAgent(self.conf)
        self.api.oaas_driver = test_optimizer_agent_api.NoopOaasDriver()
        self.adminContext = context.get_admin_context()
        self.router_id = str(uuid.uuid4())
        self.agent_conf = mock.Mock()
        self.agent_conf.use_namespaces = True
        self.ri_kwargs = {'router': {'id': self.router_id,
                                     'tenant_id': str(uuid.uuid4())},
                          'agent_conf': self.agent_conf,
                          'interface_driver': mock.ANY,
                          'use_ipv6': mock.ANY,
                          }

    def test_opt_config_match(self):
        test_agent_class = _setup_test_agent_class([constants.OPTIMIZER])
        cfg.CONF.set_override('enabled', True, 'oaas')
        with mock.patch('oslo_utils.importutils.import_object'):
            test_agent_class(cfg.CONF)

    def test_opt_config_mismatch_plugin_enabled_agent_disabled(self):
        test_agent_class = _setup_test_agent_class([constants.OPTIMIZER])
        cfg.CONF.set_override('enabled', False, 'oaas')
        self.assertRaises(SystemExit, test_agent_class, cfg.CONF)

    def test_opt_plugin_list_unavailable(self):
        test_agent_class = _setup_test_agent_class(None)
        cfg.CONF.set_override('enabled', False, 'oaas')
        with mock.patch('oslo_utils.importutils.import_object'):
            test_agent_class(cfg.CONF)

    def test_create_optimizer(self):
        fake_optimizer = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [1, 2]}
        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.oaas_driver, 'create_optimizer'
                                  ) as mock_driver_create_optimizer, \
                mock.patch.object(self.api.optplugin_rpc, 'set_optimizer_status'
                                  ) as mock_set_optimizer_status:
            mock_driver_create_optimizer.return_value = True
            self.api.create_optimizer(
                context=mock.sentinel.context,
                optimizer=fake_optimizer, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_optimizer['add-router-ids'], fake_optimizer['tenant_id'])

            mock_set_optimizer_status.assert_called_once_with(
                mock.sentinel.context,
                fake_optimizer['id'],
                'ACTIVE')

    def test_update_optimizer_with_routers_added_and_deleted(self):
        fake_optimizer = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [1, 2],
                         'del-router-ids': [3, 4],
                         'router_ids': [],
                         'last-router': False}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.oaas_driver, 'update_optimizer'
                                  ) as mock_driver_delete_optimizer, \
                mock.patch.object(self.api.oaas_driver, 'delete_optimizer'
                                  ) as mock_driver_update_optimizer, \
                mock.patch.object(self.api.optplugin_rpc, 'set_optimizer_status'
                                  ) as mock_set_optimizer_status:

            mock_driver_delete_optimizer.return_value = True
            mock_driver_update_optimizer.return_value = True

            calls = [mock.call(fake_optimizer['del-router-ids'],
                      fake_optimizer['tenant_id']),
                     mock.call(fake_optimizer['add-router-ids'],
                      fake_optimizer['tenant_id'])]

            self.api.update_optimizer(
                context=mock.sentinel.context,
                optimizer=fake_optimizer, host='host')

            self.assertEqual(
                mock_get_router_info_list_for_tenant.call_args_list,
                calls)

            mock_set_optimizer_status.assert_called_once_with(
                mock.sentinel.context,
                fake_optimizer['id'],
                'ACTIVE')

    def test_update_optimizer_with_routers_added_and_admin_state_down(self):
        fake_optimizer = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': False,
                         'add-router-ids': [1, 2],
                         'del-router-ids': [],
                         'router_ids': [],
                         'last-router': False}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.oaas_driver, 'update_optimizer'
                                  ) as mock_driver_update_optimizer, \
                mock.patch.object(self.api.optplugin_rpc, 'set_optimizer_status'
                                  ) as mock_set_optimizer_status:

            mock_driver_update_optimizer.return_value = True

            self.api.update_optimizer(
                context=mock.sentinel.context,
                optimizer=fake_optimizer, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_optimizer['add-router-ids'], fake_optimizer['tenant_id'])

            mock_set_optimizer_status.assert_called_once_with(
                mock.sentinel.context,
                fake_optimizer['id'],
                'DOWN')

    def test_update_optimizer_with_all_routers_deleted(self):
        fake_optimizer = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [],
                         'del-router-ids': [3, 4],
                         'last-router': True}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.oaas_driver, 'delete_optimizer'
                                  ) as mock_driver_delete_optimizer, \
                mock.patch.object(self.api.optplugin_rpc, 'set_optimizer_status'
                                  ) as mock_set_optimizer_status:

            mock_driver_delete_optimizer.return_value = True

            self.api.update_optimizer(
                context=mock.sentinel.context,
                optimizer=fake_optimizer, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_optimizer['del-router-ids'], fake_optimizer['tenant_id'])

            mock_set_optimizer_status.assert_called_once_with(
                mock.sentinel.context,
                fake_optimizer['id'],
                'INACTIVE')

    def test_update_optimizer_with_rtrs_and_no_rtrs_added_nor_deleted(self):
        fake_optimizer = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [],
                         'del-router-ids': [],
                         'router_ids': [1, 2]}
        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api.oaas_driver, 'update_optimizer'
                               ) as mock_driver_update_optimizer, \
                mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                                  ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.optplugin_rpc, 'set_optimizer_status'
                                  ) as mock_set_optimizer_status:

            mock_driver_update_optimizer.return_value = True

            self.api.update_optimizer(
                context=mock.sentinel.context,
                optimizer=fake_optimizer, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_optimizer['router_ids'], fake_optimizer['tenant_id'])

            mock_set_optimizer_status.assert_called_once_with(
                mock.sentinel.context,
                fake_optimizer['id'],
                'ACTIVE')

    def test_update_optimizer_with_no_rtrs_and_no_rtrs_added_nor_deleted(self):
        fake_optimizer = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [],
                         'del-router-ids': [],
                         'router_ids': []}
        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api.oaas_driver, 'update_optimizer'
                               ) as mock_driver_update_optimizer, \
                mock.patch.object(self.api.optplugin_rpc, 'set_optimizer_status'
                                  ) as mock_set_optimizer_status:

            mock_driver_update_optimizer.return_value = True

            self.api.update_optimizer(
                context=mock.sentinel.context,
                optimizer=fake_optimizer, host='host')

            mock_set_optimizer_status.assert_called_once_with(
                mock.sentinel.context,
                fake_optimizer['id'],
                'INACTIVE')

    def test_delete_optimizer(self):
        fake_optimizer = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True,
                         'add-router-ids': [],
                         'del-router-ids': [3, 4],
                         'last-router': True}

        self.api.plugin_rpc = mock.Mock()
        with mock.patch.object(self.api, '_get_router_info_list_for_tenant'
                               ) as mock_get_router_info_list_for_tenant, \
                mock.patch.object(self.api.oaas_driver, 'delete_optimizer'
                                  ) as mock_driver_delete_optimizer, \
                mock.patch.object(self.api.optplugin_rpc, 'optimizer_deleted'
                                  ) as mock_optimizer_deleted:

            mock_driver_delete_optimizer.return_value = True
            self.api.delete_optimizer(
                context=mock.sentinel.context,
                optimizer=fake_optimizer, host='host')

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                fake_optimizer['del-router-ids'], fake_optimizer['tenant_id'])

            mock_optimizer_deleted.assert_called_once_with(
                mock.sentinel.context,
                fake_optimizer['id'])

    def _prepare_router_data(self):
        return router_info.RouterInfo(self.router_id,
                                      **self.ri_kwargs)

    def _get_router_info_list_helper(self, use_namespaces):
        self.conf.set_override('use_namespaces', use_namespaces)
        ri = self._prepare_router_data()
        routers = [ri.router]
        router_ids = [router['id'] for router in routers]
        self.api.router_info = {ri.router_id: ri}
        with mock.patch.object(ip_lib.IPWrapper,
                               'get_namespaces') as mock_get_namespaces:
            mock_get_namespaces.return_value = []
            router_info_list = self.api._get_router_info_list_for_tenant(
                router_ids,
                ri.router['tenant_id'])
        if use_namespaces:
            mock_get_namespaces.assert_called_once_with()
            self.assertFalse(router_info_list)
        else:
            self.assertEqual([ri], router_info_list)

    def test_get_router_info_list_for_tenant_for_namespaces_disabled(self):
        self._get_router_info_list_helper(use_namespaces=False)

    def test_get_router_info_list_for_tenant(self):
        self._get_router_info_list_helper(use_namespaces=True)

    def _get_router_info_list_router_without_router_info_helper(self,
                                                                rtr_with_ri):
        self.conf.set_override('use_namespaces', True)
        # ri.router with associated router_info (ri)
        # rtr2 has no router_info
        ri = self._prepare_router_data()
        rtr2 = {'id': str(uuid.uuid4()), 'tenant_id': ri.router['tenant_id']}
        routers = [rtr2]
        self.api.router_info = {}
        ri_expected = []
        if rtr_with_ri:
            self.api.router_info[ri.router_id] = ri
            routers.append(ri.router)
            ri_expected.append(ri)
        router_ids = [router['id'] for router in routers]
        with mock.patch.object(ip_lib.IPWrapper,
                               'get_namespaces') as mock_get_namespaces:
            mock_get_namespaces.return_value = ri.ns_name
            router_info_list = self.api._get_router_info_list_for_tenant(
                router_ids,
                ri.router['tenant_id'])
            self.assertEqual(ri_expected, router_info_list)

    def test_get_router_info_list_router_without_router_info(self):
        self._get_router_info_list_router_without_router_info_helper(
            rtr_with_ri=False)

    def test_get_router_info_list_two_routers_one_without_router_info(self):
        self._get_router_info_list_router_without_router_info_helper(
            rtr_with_ri=True)
