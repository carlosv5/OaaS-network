# Copyright 2015 OpenStack Foundation.
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

import sys

import mock

from neutron.tests import base
from oslo_utils import uuidutils
from six.moves.urllib import parse

# Mocking imports of 3rd party vyatta library in unit tests and all modules
# that depends on this library. Import will fail if not mocked and 3rd party
# vyatta library is not installed.
with mock.patch.dict(sys.modules, {
    'networking_brocade': mock.Mock(),
    'networking_brocade.vyatta': mock.Mock(),
    'networking_brocade.vyatta.common': mock.Mock(),
    'networking_brocade.vyatta.vrouter': mock.Mock(),
}):
    from networking_brocade.vyatta.vrouter import client as vyatta_client
    from neutron_oaas.services.optimizer.agents.vyatta import vyatta_utils
    from neutron_oaas.services.optimizer.drivers.vyatta import vyatta_oaas

_uuid = uuidutils.generate_uuid

FAKE_FW_UUID = _uuid()


def fake_cmd(*args, **kwargs):
    return (args, kwargs)


class VyattaOaasTestCase(base.BaseTestCase):
    def setUp(self):
        super(VyattaOaasTestCase, self).setUp()

        mock.patch.object(vyatta_client, 'SetCmd', fake_cmd).start()
        mock.patch.object(vyatta_client, 'DeleteCmd', fake_cmd).start()

        self.oaas_driver = vyatta_oaas.VyattaOptimizerDriver()

        self.fake_rules = [self._make_fake_opt_rule()]
        self.fake_optimizer = self._make_fake_optimizer(self.fake_rules)
        self.fake_optimizer_name = vyatta_utils.get_optimizer_name(
            None, self.fake_optimizer)
        self.fake_apply_list = [self._make_fake_router_info()]
        self.fake_agent_mode = None

    def test_create_optimizer(self):

        with mock.patch.object(
                self.oaas_driver, 'update_optimizer') as opt_update:
            self.oaas_driver.create_optimizer(
                self.fake_agent_mode, self.fake_apply_list, self.fake_optimizer)

            opt_update.assert_called_once_with(
                self.fake_agent_mode, self.fake_apply_list, self.fake_optimizer)

    def test_update_optimizer(self):
        with mock.patch.object(
                self.oaas_driver, '_update_optimizer') as opt_update:
            self.fake_optimizer['admin_state_up'] = True
            self.oaas_driver.create_optimizer(
                self.fake_agent_mode, self.fake_apply_list, self.fake_optimizer)

            opt_update.assert_called_once_with(
                self.fake_apply_list, self.fake_optimizer)

        with mock.patch.object(
                self.oaas_driver, 'apply_default_policy') as opt_apply_policy:
            self.fake_optimizer['admin_state_up'] = False
            self.oaas_driver.create_optimizer(
                self.fake_agent_mode, self.fake_apply_list, self.fake_optimizer)

            opt_apply_policy.assert_called_once_with(
                self.fake_agent_mode, self.fake_apply_list, self.fake_optimizer)

    def test_delete_optimizer(self):
        with mock.patch.object(
                self.oaas_driver, 'apply_default_policy') as opt_apply_policy:
            self.oaas_driver.delete_optimizer(
                self.fake_agent_mode, self.fake_apply_list, self.fake_optimizer)

            opt_apply_policy.assert_called_once_with(
                self.fake_agent_mode, self.fake_apply_list, self.fake_optimizer)

    def test_apply_default_policy(self):
        with mock.patch.object(
                self.oaas_driver, '_delete_optimizer') as opt_delete:
            self.oaas_driver.apply_default_policy(
                self.fake_agent_mode, self.fake_apply_list, self.fake_optimizer)

            calls = [mock.call(x, self.fake_optimizer)
                     for x in self.fake_apply_list]
            opt_delete.assert_has_calls(calls)

    def test_update_optimizer_internal(self):
        with mock.patch.object(
                self.oaas_driver, '_delete_optimizer'
        ) as opt_delete, mock.patch.object(
                self.oaas_driver, '_setup_optimizer') as opt_setup:
            self.oaas_driver._update_optimizer(
                self.fake_apply_list, self.fake_optimizer)

            calls = [mock.call(x, self.fake_optimizer)
                     for x in self.fake_apply_list]

            opt_delete.assert_has_calls(calls)
            opt_setup.assert_has_calls(calls)

    def test_setup_optimizer_internal(self):
        fake_rule = self._make_fake_opt_rule()
        fake_router_info = self._make_fake_router_info()
        fake_rule_cmd = 'fake-opt-rule0'
        fake_zone_configure_rules = ['fake-config-rule0']

        mock_api = mock.Mock()
        mock_api_gen = mock.Mock(return_value=mock_api)
        mock_get_optimizer_rule = mock.Mock(return_value=[fake_rule_cmd])
        mock_get_zone_cmds = mock.Mock(return_value=fake_zone_configure_rules)
        with mock.patch.object(self.oaas_driver, '_get_vyatta_client',
                               mock_api_gen), \
                mock.patch.object(vyatta_oaas.vyatta_utils, 'get_zone_cmds',
                                  mock_get_zone_cmds), \
                mock.patch.object(self.oaas_driver, '_set_optimizer_rule',
                                  mock_get_optimizer_rule):
            self.oaas_driver._setup_optimizer(
                fake_router_info, self.fake_optimizer)

            mock_api_gen.assert_called_once_with(
                fake_router_info.router)
            mock_get_optimizer_rule.assert_called_once_with(
                self.fake_optimizer_name, 1, fake_rule)
            mock_get_zone_cmds.assert_called_once_with(
                mock_api, fake_router_info, self.fake_optimizer_name)

            cmds = [
                vyatta_client.SetCmd(
                    vyatta_oaas.FW_NAME.format(
                        self.fake_optimizer_name)),
                vyatta_client.SetCmd(
                    vyatta_oaas.FW_DESCRIPTION.format(
                        self.fake_optimizer_name,
                        parse.quote_plus(self.fake_optimizer['description']))),
                vyatta_client.SetCmd(
                    vyatta_oaas.FW_ESTABLISHED_ACCEPT),
                vyatta_client.SetCmd(
                    vyatta_oaas.FW_RELATED_ACCEPT),
                fake_rule_cmd,
            ] + fake_zone_configure_rules
            mock_api.exec_cmd_batch.assert_called_once_with(cmds)

    def test_delete_optimizer_internal(self):
        fake_router_info = self._make_fake_router_info()

        with mock.patch.object(
                self.oaas_driver,
                '_get_vyatta_client') as mock_client_factory:
            mock_api = mock_client_factory.return_value

            self.oaas_driver._delete_optimizer(
                fake_router_info, self.fake_optimizer)

            cmds = [
                vyatta_client.DeleteCmd("zone-policy"),
                vyatta_client.DeleteCmd(vyatta_oaas.FW_NAME.format(
                    self.fake_optimizer_name)),
                vyatta_client.DeleteCmd("optimizer/state-policy"),
            ]
            mock_api.exec_cmd_batch.assert_called_once_with(cmds)

    def test_set_optimizer_rule_internal(self):
        fake_rule = self._make_fake_opt_rule()
        fake_optimizer_name = 'fake-opt-name'

        fake_rule.update({
            'description': 'rule description',
            'source_port': '2080',
            'destination_ip_address': '172.16.1.1'
        })
        action_map = {
            'allow': 'accept',
        }

        cmds_actual = self.oaas_driver._set_optimizer_rule(
            fake_optimizer_name, 1, fake_rule)
        cmds_expect = [
            vyatta_client.SetCmd(
                vyatta_oaas.FW_RULE_DESCRIPTION.format(
                    parse.quote_plus(fake_optimizer_name), 1,
                    parse.quote_plus(fake_rule['description'])))
        ]

        rules = [
            ('protocol', vyatta_oaas.FW_RULE_PROTOCOL),
            ('source_port', vyatta_oaas.FW_RULE_SRC_PORT),
            ('destination_port', vyatta_oaas.FW_RULE_DEST_PORT),
            ('source_ip_address', vyatta_oaas.FW_RULE_SRC_ADDR),
            ('destination_ip_address', vyatta_oaas.FW_RULE_DEST_ADDR),
        ]

        for key, url in rules:
            cmds_expect.append(vyatta_client.SetCmd(
                url.format(
                    parse.quote_plus(fake_optimizer_name), 1,
                    parse.quote_plus(fake_rule[key]))))

        cmds_expect.append(vyatta_client.SetCmd(
            vyatta_oaas.FW_RULE_ACTION.format(
                parse.quote_plus(fake_optimizer_name), 1,
                action_map.get(fake_rule['action'], 'drop'))))

        self.assertEqual(cmds_expect, cmds_actual)

    def _make_fake_router_info(self):
        info = mock.Mock()
        info.router = {
            'id': 'fake-router-id',
            'tenant_id': 'tenant-uuid',
        }
        return info

    def _make_fake_opt_rule(self):
        return {
            'enabled': True,
            'action': 'allow',
            'ip_version': 4,
            'protocol': 'tcp',
            'destination_port': '80',
            'source_ip_address': '10.24.4.2'}

    def _make_fake_optimizer(self, rules):
        return {'id': FAKE_FW_UUID,
                'admin_state_up': True,
                'name': 'test-optimizer',
                'tenant_id': 'tenant-uuid',
                'description': 'Fake optimizer',
                'optimizer_rule_list': rules}
