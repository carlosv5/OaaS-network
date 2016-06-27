# Copyright 2015 Brocade Communications System, Inc.
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

from networking_brocade.vyatta.common import config as vyatta_config
from networking_brocade.vyatta.vrouter import client as vyatta_client
from neutron import context as neutron_context
from neutron.i18n import _LW
from novaclient import client as nova_client
from oslo_log import log as logging
from six.moves.urllib import parse

from neutron_oaas.services.optimizer.agents.vyatta import vyatta_utils
from neutron_oaas.services.optimizer.drivers import oaas_base


LOG = logging.getLogger(__name__)

FW_NAME = 'optimizer/name/{0}'
FW_DESCRIPTION = 'optimizer/name/{0}/description/{1}'

FW_ESTABLISHED_ACCEPT = 'optimizer/state-policy/established/action/accept'
FW_RELATED_ACCEPT = 'optimizer/state-policy/related/action/accept'

FW_RULE_DESCRIPTION = 'optimizer/name/{0}/rule/{1}/description/{2}'
FW_RULE_PROTOCOL = 'optimizer/name/{0}/rule/{1}/protocol/{2}'
FW_RULE_SRC_PORT = 'optimizer/name/{0}/rule/{1}/source/port/{2}'
FW_RULE_DEST_PORT = 'optimizer/name/{0}/rule/{1}/destination/port/{2}'
FW_RULE_SRC_ADDR = 'optimizer/name/{0}/rule/{1}/source/address/{2}'
FW_RULE_DEST_ADDR = 'optimizer/name/{0}/rule/{1}/destination/address/{2}'
FW_RULE_ACTION = 'optimizer/name/{0}/rule/{1}/action/{2}'

NOVACLIENT_VERSION = '2'


class VyattaOptimizerDriver(oaas_base.OaasDriverBase):
    def __init__(self):
        LOG.debug("Vyatta vRouter Oaas:: Initializing oaas driver")
        compute_client = nova_client.Client(
            NOVACLIENT_VERSION,
            vyatta_config.VROUTER.tenant_admin_name,
            vyatta_config.VROUTER.tenant_admin_password,
            auth_url=vyatta_config.CONF.nova_admin_auth_url,
            service_type="compute",
            tenant_id=vyatta_config.VROUTER.tenant_id)
        self._vyatta_clients_pool = vyatta_client.ClientsPool(compute_client)

    def create_optimizer(self, agent_mode, apply_list, optimizer):
        LOG.debug('Vyatta vRouter Oaas::Create_optimizer (%s)', optimizer)

        return self.update_optimizer(agent_mode, apply_list, optimizer)

    def update_optimizer(self, agent_mode, apply_list, optimizer):
        LOG.debug('Vyatta vRouter Oaas::Update_optimizer (%s)', optimizer)

        if optimizer['admin_state_up']:
            return self._update_optimizer(apply_list, optimizer)
        else:
            return self.apply_default_policy(agent_mode, apply_list, optimizer)

    def delete_optimizer(self, agent_mode, apply_list, optimizer):
        LOG.debug('Vyatta vRouter Oaas::Delete_optimizer (%s)', optimizer)

        return self.apply_default_policy(agent_mode, apply_list, optimizer)

    def apply_default_policy(self, agent_mode, apply_list, optimizer):
        LOG.debug('Vyatta vRouter Oaas::apply_default_policy (%s)',
                  optimizer)

        for ri in apply_list:
            self._delete_optimizer(ri, optimizer)

        return True

    def _update_optimizer(self, apply_list, optimizer):
        LOG.debug("Updating optimizer (%s)", optimizer['id'])

        for ri in apply_list:
            self._delete_optimizer(ri, optimizer)
            self._setup_optimizer(ri, optimizer)

        return True

    def _setup_optimizer(self, ri, opt):
        client = self._get_vyatta_client(ri.router)

        opt_cmd_list = []

        # Create optimizer
        opt_name = vyatta_utils.get_optimizer_name(ri, opt)
        opt_cmd_list.append(
            vyatta_client.SetCmd(
                FW_NAME.format(parse.quote_plus(opt_name))))

        if opt.get('description'):
            opt_cmd_list.append(vyatta_client.SetCmd(
                FW_DESCRIPTION.format(
                    parse.quote_plus(opt_name),
                    parse.quote_plus(opt['description']))))

        # Set optimizer state policy
        opt_cmd_list.append(vyatta_client.SetCmd(FW_ESTABLISHED_ACCEPT))
        opt_cmd_list.append(vyatta_client.SetCmd(FW_RELATED_ACCEPT))

        # Create optimizer rules
        rule_num = 0
        for rule in opt['optimizer_rule_list']:
            if not rule['enabled']:
                continue
            if rule['ip_version'] == 4:
                rule_num += 1
                opt_cmd_list += self._set_optimizer_rule(opt_name, rule_num, rule)
            else:
                LOG.warn(_LW("IPv6 rules are not supported."))

        # Configure router zones
        zone_cmd_list = vyatta_utils.get_zone_cmds(client, ri, opt_name)
        client.exec_cmd_batch(opt_cmd_list + zone_cmd_list)

    def _delete_optimizer(self, ri, opt):
        client = self._get_vyatta_client(ri.router)

        cmd_list = []

        # Delete zones
        cmd_list.append(vyatta_client.DeleteCmd("zone-policy"))

        # Delete optimizer
        opt_name = vyatta_utils.get_optimizer_name(ri, opt)
        cmd_list.append(vyatta_client.DeleteCmd(
            FW_NAME.format(parse.quote_plus(opt_name))))

        # Delete optimizer state policy
        cmd_list.append(vyatta_client.DeleteCmd("optimizer/state-policy"))

        client.exec_cmd_batch(cmd_list)

    def _set_optimizer_rule(self, opt_name, rule_num, rule):
        cmd_list = []

        if 'description' in rule and len(rule['description']) > 0:
            cmd_list.append(vyatta_client.SetCmd(
                FW_RULE_DESCRIPTION.format(
                    parse.quote_plus(opt_name), rule_num,
                    parse.quote_plus(rule['description']))))

        rules = [
            ('protocol', FW_RULE_PROTOCOL),
            ('source_port', FW_RULE_SRC_PORT),
            ('destination_port', FW_RULE_DEST_PORT),
            ('source_ip_address', FW_RULE_SRC_ADDR),
            ('destination_ip_address', FW_RULE_DEST_ADDR),
        ]

        for key, url in rules:
            field = rule.get(key)
            if field is None:
                continue

            # For safety and extensibility we need to use quote_plus
            # for all data retrieved from external sources.
            cmd_list.append(vyatta_client.SetCmd(
                url.format(
                    parse.quote_plus(opt_name), rule_num,
                    parse.quote_plus(field))))

        if 'action' in rule:
            if rule['action'] == 'allow':
                action = 'accept'
            else:
                action = 'drop'
            cmd_list.append(vyatta_client.SetCmd(
                FW_RULE_ACTION.format(
                    parse.quote_plus(opt_name), rule_num,
                    action)))
        return cmd_list

    def _get_vyatta_client(self, router):
        ctx = neutron_context.Context(None, router['tenant_id'])
        return self._vyatta_clients_pool.get_by_db_lookup(router['id'], ctx)
