# Copyright 2013 Big Switch Networks, Inc.
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

from neutron.api.v2 import attributes as attr
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as neutron_context
from neutron.i18n import _LW
from neutron import manager
from neutron.plugins.common import constants as const
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron_oaas.db.optimizer import optimizer_db
from neutron_oaas.db.optimizer import optimizer_router_insertion_db
from neutron_oaas.extensions import optimizer as opt_ext


LOG = logging.getLogger(__name__)


class OptimizerCallbacks(object):
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        super(OptimizerCallbacks, self).__init__()
        self.plugin = plugin

    def set_optimizer_status(self, context, optimizer_id, status, **kwargs):
        """Agent uses this to set a optimizer's status."""
        LOG.debug("Setting optimizer %s to status: %s" % (optimizer_id, status))
        # Sanitize status first
        if status in (const.ACTIVE, const.DOWN, const.INACTIVE):
            to_update = status
        else:
            to_update = const.ERROR
        # ignore changing status if optimizer expects to be deleted
        # That case means that while some pending operation has been
        # performed on the backend, neutron server received delete request
        # and changed optimizer status to PENDING_DELETE
        updated = self.plugin.update_optimizer_status(
            context, optimizer_id, to_update, not_in=(const.PENDING_DELETE,))
        if updated:
            LOG.debug("optimizer %s status set: %s" % (optimizer_id, to_update))
        return updated and to_update != const.ERROR

    def optimizer_deleted(self, context, optimizer_id, **kwargs):
        """Agent uses this to indicate optimizer is deleted."""
        LOG.debug("optimizer_deleted() called")
        with context.session.begin(subtransactions=True):
            opt_db = self.plugin._get_optimizer(context, optimizer_id)
            # allow to delete optimizers in ERROR state
            if opt_db.status in (const.PENDING_DELETE, const.ERROR):
                self.plugin.delete_db_optimizer_object(context, optimizer_id)
                return True
            else:
                LOG.warn(_LW('Optimizer %(opt)s unexpectedly deleted by agent, '
                             'status was %(status)s'),
                         {'opt': optimizer_id, 'status': opt_db.status})
                opt_db.update({"status": const.ERROR})
                return False

    def get_optimizers_for_tenant(self, context, **kwargs):
        """Agent uses this to get all optimizers and rules for a tenant."""
        LOG.debug("get_optimizers_for_tenant() called")
        opt_list = []
        for opt in self.plugin.get_optimizers(context):
            opt_with_rules = self.plugin._make_optimizer_dict_with_rules(
                context, opt['id'])
            if opt['status'] == const.PENDING_DELETE:
                opt_with_rules['add-router-ids'] = []
                opt_with_rules['del-router-ids'] = (
                    self.plugin.get_optimizer_routers(context, opt['id']))
            else:
                opt_with_rules['add-router-ids'] = (
                    self.plugin.get_optimizer_routers(context, opt['id']))
                opt_with_rules['del-router-ids'] = []
            opt_list.append(opt_with_rules)
        return opt_list

    def get_optimizers_for_tenant_without_rules(self, context, **kwargs):
        """Agent uses this to get all optimizers for a tenant."""
        LOG.debug("get_optimizers_for_tenant_without_rules() called")
        opt_list = [opt for opt in self.plugin.get_optimizers(context)]
        return opt_list

    def get_tenants_with_optimizers(self, context, **kwargs):
        """Agent uses this to get all tenants that have optimizers."""
        LOG.debug("get_tenants_with_optimizers() called")
        ctx = neutron_context.get_admin_context()
        opt_list = self.plugin.get_optimizers(ctx)
        opt_tenant_list = list(set(opt['tenant_id'] for opt in opt_list))
        return opt_tenant_list


class OptimizerAgentApi(object):
    """Plugin side of plugin to agent RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def create_optimizer(self, context, optimizer):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'create_optimizer', optimizer=optimizer,
                   host=self.host)

    def update_optimizer(self, context, optimizer):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'update_optimizer', optimizer=optimizer,
                   host=self.host)

    def delete_optimizer(self, context, optimizer):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'delete_optimizer', optimizer=optimizer,
                   host=self.host)


class OptimizerPlugin(
    optimizer_db.Optimizer_db_mixin,
    optimizer_router_insertion_db.OptimizerRouterInsertionDbMixin):

    """Implementation of the Neutron Optimizer Service Plugin.

    This class manages the workflow of OaaS request/response.
    Most DB related works are implemented in class
    optimizer_db.Optimizer_db_mixin.
    """
    supported_extension_aliases = ["oaas", "oaasrouterinsertion"]
    path_prefix = opt_ext.OPTIMIZER_PREFIX

    def __init__(self):
        """Do the initialization for the optimizer service plugin here."""
        self.endpoints = [OptimizerCallbacks(self)]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.OPTIMIZER_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

        self.agent_rpc = OptimizerAgentApi(
            topics.L3_AGENT,
            cfg.CONF.host
        )
        optimizer_db.subscribe()

    def _rpc_update_optimizer(self, context, optimizer_id):
        status_update = {"optimizer": {"status": const.PENDING_UPDATE}}
        super(OptimizerPlugin, self).update_optimizer(context, optimizer_id,
                                                    status_update)
        opt_with_rules = self._make_optimizer_dict_with_rules(context,
                                                            optimizer_id)
        # this is triggered on an update to opt rule or policy, no
        # change in associated routers.
        opt_with_rules['add-router-ids'] = self.get_optimizer_routers(
                context, optimizer_id)
        opt_with_rules['del-router-ids'] = []
        self.agent_rpc.update_optimizer(context, opt_with_rules)

    def _rpc_update_optimizer_policy(self, context, optimizer_policy_id):
        optimizer_policy = self.get_optimizer_policy(context, optimizer_policy_id)
        if optimizer_policy:
            for optimizer_id in optimizer_policy['optimizer_list']:
                self._rpc_update_optimizer(context, optimizer_id)

    def _ensure_update_optimizer(self, context, optimizer_id):
        optall = self.get_optimizer(context, optimizer_id)
        if optall['status'] in [const.PENDING_CREATE,
                               const.PENDING_UPDATE,
                               const.PENDING_DELETE]:
            raise opt_ext.OptimizerInPendingState(optimizer_id=optimizer_id,
                                                pending_state=optall['status'])

    def _ensure_update_optimizer_policy(self, context, optimizer_policy_id):
        optimizer_policy = self.get_optimizer_policy(context, optimizer_policy_id)
        if optimizer_policy and 'optimizer_list' in optimizer_policy:
            for optimizer_id in optimizer_policy['optimizer_list']:
                self._ensure_update_optimizer(context, optimizer_id)

    def _ensure_update_optimizer_rule(self, context, optimizer_rule_id):
        opt_rule = self.get_optimizer_rule(context, optimizer_rule_id)
        if 'optimizer_policy_id' in opt_rule and opt_rule['optimizer_policy_id']:
            self._ensure_update_optimizer_policy(context,
                                                opt_rule['optimizer_policy_id'])

    def _get_routers_for_create_optimizer(self, tenant_id, context, optimizer):

        # pop router_id as this goes in the router association db
        # and not optimizer db
        router_ids = optimizer['optimizer'].pop('router_ids', None)
        if router_ids == attr.ATTR_NOT_SPECIFIED:
            # old semantics router-ids keyword not specified pick up
            # all routers on tenant.
            l3_plugin = manager.NeutronManager.get_service_plugins().get(
                const.L3_ROUTER_NAT)
            ctx = neutron_context.get_admin_context()
            routers = l3_plugin.get_routers(ctx)
            router_ids = [
                router['id']
                for router in routers
                if router['tenant_id'] == tenant_id]
            # validation can still fail this if there is another opt
            # which is associated with one of these routers.
            self.validate_optimizer_routers_not_in_use(context, router_ids)
            return router_ids
        else:
            if not router_ids:
                # This indicates that user specifies no routers.
                return []
            else:
                # some router(s) provided.
                self.validate_optimizer_routers_not_in_use(context, router_ids)
                return router_ids

    def create_optimizer(self, context, optimizer):
        LOG.debug("create_optimizer() called")
        tenant_id = self._get_tenant_id_for_create(context,
            optimizer['optimizer'])

        opt_new_rtrs = self._get_routers_for_create_optimizer(
            tenant_id, context, optimizer)

        if not opt_new_rtrs:
            # no messaging to agent needed, and opt needs to go
            # to INACTIVE(no associated rtrs) state.
            status = const.INACTIVE
            opt = super(OptimizerPlugin, self).create_optimizer(
                context, optimizer, status)
            opt['router_ids'] = []
            return opt
        else:
            opt = super(OptimizerPlugin, self).create_optimizer(
                context, optimizer)
            opt['router_ids'] = opt_new_rtrs

        opt_with_rules = (
            self._make_optimizer_dict_with_rules(context, opt['id']))

        opt_with_rtrs = {'opt_id': opt['id'],
                        'router_ids': opt_new_rtrs}
        self.set_routers_for_optimizer(context, opt_with_rtrs)
        opt_with_rules['add-router-ids'] = opt_new_rtrs
        opt_with_rules['del-router-ids'] = []

        self.agent_rpc.create_optimizer(context, opt_with_rules)

        return opt

    def update_optimizer(self, context, id, optimizer):
        LOG.debug("update_optimizer() called on optimizer %s", id)

        self._ensure_update_optimizer(context, id)
        # pop router_id as this goes in the router association db
        # and not optimizer db
        router_ids = optimizer['optimizer'].pop('router_ids', None)
        opt_current_rtrs = self.get_optimizer_routers(context, id)
        if router_ids is not None:
            if router_ids == []:
                # This indicates that user is indicating no routers.
                opt_new_rtrs = []
            else:
                self.validate_optimizer_routers_not_in_use(
                    context, router_ids, id)
                opt_new_rtrs = router_ids
            self.update_optimizer_routers(context, {'opt_id': id,
                'router_ids': opt_new_rtrs})
        else:
            # router-ids keyword not specified for update pick up
            # existing routers.
            opt_new_rtrs = self.get_optimizer_routers(context, id)

        if not opt_new_rtrs and not opt_current_rtrs:
            # no messaging to agent needed, and we need to continue
            # in INACTIVE state
            optimizer['optimizer']['status'] = const.INACTIVE
            opt = super(OptimizerPlugin, self).update_optimizer(
                context, id, optimizer)
            opt['router_ids'] = []
            return opt
        else:
            optimizer['optimizer']['status'] = const.PENDING_UPDATE
            opt = super(OptimizerPlugin, self).update_optimizer(
                context, id, optimizer)
            opt['router_ids'] = opt_new_rtrs

        opt_with_rules = (
            self._make_optimizer_dict_with_rules(context, opt['id']))

        # determine rtrs to add opt to and del from
        opt_with_rules['add-router-ids'] = opt_new_rtrs
        opt_with_rules['del-router-ids'] = list(
            set(opt_current_rtrs).difference(set(opt_new_rtrs)))

        # last-router drives agent to ack with status to set state to INACTIVE
        opt_with_rules['last-router'] = not opt_new_rtrs

        LOG.debug("update_optimizer %s: Add Routers: %s, Del Routers: %s",
            opt['id'],
            opt_with_rules['add-router-ids'],
            opt_with_rules['del-router-ids'])

        self.agent_rpc.update_optimizer(context, opt_with_rules)

        return opt

    def delete_db_optimizer_object(self, context, id):
        super(OptimizerPlugin, self).delete_optimizer(context, id)

    def delete_optimizer(self, context, id):
        LOG.debug("delete_optimizer() called on optimizer %s", id)
        opt_with_rules = (
            self._make_optimizer_dict_with_rules(context, id))
        opt_with_rules['del-router-ids'] = self.get_optimizer_routers(
            context, id)
        opt_with_rules['add-router-ids'] = []
        if not opt_with_rules['del-router-ids']:
            # no routers to delete on the agent side
            self.delete_db_optimizer_object(context, id)
        else:
            status = {"optimizer": {"status": const.PENDING_DELETE}}
            super(OptimizerPlugin, self).update_optimizer(context, id, status)
            # Reflect state change in opt_with_rules
            opt_with_rules['status'] = status['optimizer']['status']
            self.agent_rpc.delete_optimizer(context, opt_with_rules)

    def update_optimizer_policy(self, context, id, optimizer_policy):
        LOG.debug("update_optimizer_policy() called")
        self._ensure_update_optimizer_policy(context, id)
        optp = super(OptimizerPlugin,
                    self).update_optimizer_policy(context, id, optimizer_policy)
        self._rpc_update_optimizer_policy(context, id)
        return optp

    def update_optimizer_rule(self, context, id, optimizer_rule):
        LOG.debug("update_optimizer_rule() called")
        self._ensure_update_optimizer_rule(context, id)
        optr = super(OptimizerPlugin,
                    self).update_optimizer_rule(context, id, optimizer_rule)
        optimizer_policy_id = optr['optimizer_policy_id']
        if optimizer_policy_id:
            self._rpc_update_optimizer_policy(context, optimizer_policy_id)
        return optr

    def insert_rule(self, context, id, rule_info):
        LOG.debug("insert_rule() called")
        self._ensure_update_optimizer_policy(context, id)
        optp = super(OptimizerPlugin,
                    self).insert_rule(context, id, rule_info)
        self._rpc_update_optimizer_policy(context, id)
        return optp

    def remove_rule(self, context, id, rule_info):
        LOG.debug("remove_rule() called")
        self._ensure_update_optimizer_policy(context, id)
        optp = super(OptimizerPlugin,
                    self).remove_rule(context, id, rule_info)
        self._rpc_update_optimizer_policy(context, id)
        return optp

    def get_optimizers(self, context, filters=None, fields=None):
        LOG.debug("oaas get_optimizers() called")
        opt_list = super(OptimizerPlugin, self).get_optimizers(
                        context, filters, fields)
        for opt in opt_list:
            opt_current_rtrs = self.get_optimizer_routers(context, opt['id'])
            opt['router_ids'] = opt_current_rtrs
        return opt_list

    def get_optimizer(self, context, id, fields=None):
        LOG.debug("oaas get_optimizer() called")
        res = super(OptimizerPlugin, self).get_optimizer(
                        context, id, fields)
        opt_current_rtrs = self.get_optimizer_routers(context, id)
        res['router_ids'] = opt_current_rtrs
        return res
