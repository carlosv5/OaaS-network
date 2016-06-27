# Copyright (c) 2013 OpenStack Foundation
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

import mock

from neutron_oaas.services.optimizer.agents import optimizer_agent_api as api
from neutron_oaas.services.optimizer.drivers import oaas_base as base_driver
from neutron_oaas.tests import base


class NoopOaasDriver(base_driver.OaasDriverBase):
    """Noop Oaas Driver.

    Optimizer driver which does nothing.
    This driver is for disabling Oaas functionality.
    """

    def create_optimizer(self, agent_mode, apply_list, optimizer):
        pass

    def delete_optimizer(self, agent_mode, apply_list, optimizer):
        pass

    def update_optimizer(self, agent_mode, apply_list, optimizer):
        pass

    def apply_default_policy(self, agent_mode, apply_list, optimizer):
        pass


class TestOaaSAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestOaaSAgentApi, self).setUp()

        self.api = api.OaaSPluginApiMixin(
            'topic',
            'host')

    def test_init(self):
        self.assertEqual(self.api.host, 'host')

    def _test_optimizer_method(self, method_name, **kwargs):
        with mock.patch.object(self.api.client, 'call') as rpc_mock, \
                mock.patch.object(self.api.client, 'prepare') as prepare_mock:

            prepare_mock.return_value = self.api.client
            getattr(self.api, method_name)(mock.sentinel.context, 'test',
                                           **kwargs)

        prepare_args = {}
        prepare_mock.assert_called_once_with(**prepare_args)

        rpc_mock.assert_called_once_with(mock.sentinel.context, method_name,
                                         optimizer_id='test', host='host',
                                         **kwargs)

    def test_set_optimizer_status(self):
        self._test_optimizer_method('set_optimizer_status', status='fake_status')

    def test_optimizer_deleted(self):
        self._test_optimizer_method('optimizer_deleted')
