# Copyright (c) 2013 OpenStack Foundation.
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

from neutron.agent.linux import ip_lib
from neutron.common import topics
from neutron import context
from neutron.i18n import _LE
from neutron.plugins.common import constants
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_oaas.extensions import optimizer as opt_ext
from neutron_oaas.services.optimizer.agents import optimizer_agent_api as api
from neutron_oaas.services.optimizer.agents import optimizer_service

LOG = logging.getLogger(__name__)


class OaaSL3PluginApi(api.OaaSPluginApiMixin):
    """Agent side of the OaaS agent to OaaS Plugin RPC API."""
    def __init__(self, topic, host):
        super(OaaSL3PluginApi, self).__init__(topic, host)

    def get_optimizers_for_tenant(self, context, **kwargs):
        """Get the Optimizers with rules from the Plugin to send to driver."""
        LOG.debug("Retrieve Optimizer with rules from Plugin")
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_optimizers_for_tenant', host=self.host)

    def get_tenants_with_optimizers(self, context, **kwargs):
        """Get all Tenants that have Optimizers configured from plugin."""
        LOG.debug("Retrieve Tenants with Optimizers configured from Plugin")
        cctxt = self.client.prepare()
        return cctxt.call(context,
                          'get_tenants_with_optimizers', host=self.host)


class OaaSL3AgentRpcCallback(api.OaaSAgentRpcCallbackMixin):
    """OaaS Agent support to be used by Neutron L3 agent."""

    def __init__(self, conf):
        LOG.debug("Initializing optimizer agent")
        self.conf = conf
        self.oaas_enabled = cfg.CONF.oaas.enabled

        # None means l3-agent has no information on the server
        # configuration due to the lack of RPC support.
        if self.neutron_service_plugins is not None:
            oaas_plugin_configured = (constants.OPTIMIZER
                                       in self.neutron_service_plugins)
            if oaas_plugin_configured and not self.oaas_enabled:
                msg = _("OaaS plugin is configured in the server side, but "
                        "OaaS is disabled in L3-agent.")
                LOG.error(msg)
                raise SystemExit(1)
            self.oaas_enabled = self.oaas_enabled and oaas_plugin_configured

        if self.oaas_enabled:
            # NOTE: Temp location for creating service and loading driver
            self.opt_service = optimizer_service.OptimizerService()
            self.oaas_driver = self.opt_service.load_device_drivers()
        self.services_sync_needed = False
        # setup RPC to msg oaas plugin
        self.optplugin_rpc = OaaSL3PluginApi(topics.OPTIMIZER_PLUGIN,
                                             conf.host)
        super(OaaSL3AgentRpcCallback, self).__init__(host=conf.host)

    def _has_router_insertion_fields(self, opt):
        return 'add-router-ids' in opt

    def _get_router_ids_for_opt(self, context, opt, to_delete=False):
        """Return the router_ids either from opt dict or tenant routers."""
        if self._has_router_insertion_fields(opt):
            # it is a new version of plugin
            return (opt['del-router-ids'] if to_delete
                    else opt['add-router-ids'])
        else:
            # we are in a upgrade and msg from older version of plugin
            try:
                routers = self.plugin_rpc.get_routers(context)
            except Exception:
                LOG.exception(
                    _LE("OaaS RPC failure in _get_router_ids_for_opt "
                        "for optimizer: %(optid)s"),
                    {'optid': opt['id']})
                self.services_sync_needed = True
            return [
                router['id']
                for router in routers
                if router['tenant_id'] == opt['tenant_id']]

    def _get_router_info_list_for_tenant(self, router_ids, tenant_id):
        """Returns the list of router info objects on which to apply the opt."""
        root_ip = ip_lib.IPWrapper()
        local_ns_list = (root_ip.get_namespaces()
                         if self.conf.use_namespaces else [])

        router_info_list = []
        # Pick up namespaces for Tenant Routers
        for rid in router_ids:
            # for routers without an interface - get_routers returns
            # the router - but this is not yet populated in router_info
            if rid not in self.router_info:
                continue
            if self.conf.use_namespaces:
                router_ns = self.router_info[rid].ns_name
                if router_ns in local_ns_list:
                    router_info_list.append(self.router_info[rid])
            else:
                router_info_list.append(self.router_info[rid])
        return router_info_list

    def _invoke_driver_for_sync_from_plugin(self, ctx, router_info_list, opt):
        """Invoke the delete driver method for status of PENDING_DELETE and
        update method for all other status to (re)apply on driver which is
        Idempotent.
        """
        if opt['status'] == constants.PENDING_DELETE:
            try:
                self.oaas_driver.delete_optimizer(
                    self.conf.agent_mode,
                    router_info_list,
                    opt)
                self.optplugin_rpc.optimizer_deleted(
                    ctx,
                    opt['id'])
            except opt_ext.OptimizerInternalDriverError:
                LOG.error(_LE("Optimizer Driver Error on opt state %(optmsg)s "
                              "for opt: %(optid)s"),
                          {'optmsg': opt['status'], 'optid': opt['id']})
                self.optplugin_rpc.set_optimizer_status(
                    ctx,
                    opt['id'],
                    constants.ERROR)
        else:
            # PENDING_UPDATE, PENDING_CREATE, ...
            try:
                self.oaas_driver.update_optimizer(
                    self.conf.agent_mode,
                    router_info_list,
                    opt)
                if opt['admin_state_up']:
                    status = constants.ACTIVE
                else:
                    status = constants.DOWN
            except opt_ext.OptimizerInternalDriverError:
                LOG.error(_LE("Optimizer Driver Error on opt state %(optmsg)s "
                              "for opt: %(optid)s"),
                          {'optmsg': opt['status'], 'optid': opt['id']})
                status = constants.ERROR

            self.optplugin_rpc.set_optimizer_status(
                ctx,
                opt['id'],
                status)

    def _process_router_add(self, ri):
        """On router add, get opt with rules from plugin and update driver."""
        LOG.debug("Process router add, router_id: '%s'", ri.router['id'])
        router_ids = ri.router['id']
        router_info_list = self._get_router_info_list_for_tenant(
            [router_ids],
            ri.router['tenant_id'])
        if router_info_list:
            # Get the optimizer with rules
            # for the tenant the router is on.
            ctx = context.Context('', ri.router['tenant_id'])
            opt_list = self.optplugin_rpc.get_optimizers_for_tenant(ctx)
            for opt in opt_list:
                if self._has_router_insertion_fields(opt):
                    # if router extension present apply only if router in opt
                    if (not (router_ids in opt['add-router-ids']) and
                        not (router_ids in opt['del-router-ids'])):
                        continue
                self._invoke_driver_for_sync_from_plugin(
                    ctx,
                    router_info_list,
                    opt)
                # router can be present only on one opt
                return

    def process_router_add(self, ri):
        """On router add, get opt with rules from plugin and update driver.

        Handles agent restart, when a router is added, query the plugin to
        check if this router is in the router list for any optimizer. If so
        install optimizer rules on this router.
        """
        # avoid msg to plugin when oaas is not configured
        if not self.oaas_enabled:
            return
        try:
            # TODO(sridar): as per discussion with pc_m, we may want to hook
            # this up to the l3 agent observer notification
            self._process_router_add(ri)
        except Exception:
            LOG.exception(
                _LE("OaaS RPC info call failed for '%s'."),
                ri.router['id'])
            self.services_sync_needed = True

    def process_services_sync(self, ctx):
        if not self.services_sync_needed:
            return

        """On RPC issues sync with plugin and apply the sync data."""
        # avoid msg to plugin when oaas is not configured
        if not self.oaas_enabled:
            return
        try:
            # get the list of tenants with optimizers configured
            # from the plugin
            tenant_ids = self.optplugin_rpc.get_tenants_with_optimizers(ctx)
            LOG.debug("Tenants with Optimizers: '%s'", tenant_ids)
            for tenant_id in tenant_ids:
                ctx = context.Context('', tenant_id)
                opt_list = self.optplugin_rpc.get_optimizers_for_tenant(ctx)
                for opt in opt_list:
                    if opt['status'] == constants.PENDING_DELETE:
                        self.delete_optimizer(ctx, opt, self.host)
                    # no need to apply sync data for ACTIVE opt
                    elif opt['status'] != constants.ACTIVE:
                        self.update_optimizer(ctx, opt, self.host)
            self.services_sync_needed = False
        except Exception:
            LOG.exception(_LE("Failed oaas process services sync"))
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def create_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to create a optimizer."""

        router_ids = self._get_router_ids_for_opt(context, optimizer)
        if not router_ids:
            return
        router_info_list = self._get_router_info_list_for_tenant(
            router_ids,
            optimizer['tenant_id'])
        LOG.debug("Create: Add optimizer on Router List: '%s'",
            [ri.router['id'] for ri in router_info_list])
        # call into the driver
        try:
            self.oaas_driver.create_optimizer(
                self.conf.agent_mode,
                router_info_list,
                optimizer)
            if optimizer['admin_state_up']:
                status = constants.ACTIVE
            else:
                status = constants.DOWN
        except opt_ext.OptimizerInternalDriverError:
            LOG.error(_LE("Optimizer Driver Error for create_optimizer "
                          "for optimizer: %(optid)s"),
                {'optid': optimizer['id']})
            status = constants.ERROR

        try:
            # send status back to plugin
            self.optplugin_rpc.set_optimizer_status(
                context,
                optimizer['id'],
                status)
        except Exception:
            LOG.exception(
                _LE("OaaS RPC failure in create_optimizer "
                    "for optimizer: %(optid)s"),
                {'optid': optimizer['id']})
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def update_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to update a optimizer."""

        status = ""
        if self._has_router_insertion_fields(optimizer):
            # with the router_ids extension, we may need to delete and add
            # based on the list of routers. On the older version, we just
            # update (add) all routers on the tenant - delete not needed.
            router_ids = self._get_router_ids_for_opt(
                context, optimizer, to_delete=True)
            if router_ids:
                router_info_list = self._get_router_info_list_for_tenant(
                    router_ids,
                    optimizer['tenant_id'])
                # remove the optimizer from this set of routers
                # but no ack sent yet, check if we need to add
                LOG.debug("Update: Delete optimizer on Router List: '%s'",
                    [ri.router['id'] for ri in router_info_list])
                try:
                    self.oaas_driver.delete_optimizer(
                        self.conf.agent_mode,
                        router_info_list,
                        optimizer)
                    if optimizer['last-router']:
                        status = constants.INACTIVE
                    elif optimizer['admin_state_up']:
                        status = constants.ACTIVE
                    else:
                        status = constants.DOWN
                except opt_ext.OptimizerInternalDriverError:
                    LOG.error(_LE("Optimizer Driver Error for "
                                  "update_optimizer for optimizer: "
                                  "%(optid)s"),
                        {'optid': optimizer['id']})
                    status = constants.ERROR

        # handle the add router and/or rule, policy, optimizer
        # attribute updates
        if status not in (constants.ERROR, constants.INACTIVE):
            router_ids = self._get_router_ids_for_opt(context, optimizer)
            if router_ids or optimizer['router_ids']:
                router_info_list = self._get_router_info_list_for_tenant(
                    router_ids + optimizer['router_ids'],
                    optimizer['tenant_id'])
                LOG.debug("Update: Add optimizer on Router List: '%s'",
                    [ri.router['id'] for ri in router_info_list])
                # call into the driver
                try:
                    self.oaas_driver.update_optimizer(
                        self.conf.agent_mode,
                        router_info_list,
                        optimizer)
                    if optimizer['admin_state_up']:
                        status = constants.ACTIVE
                    else:
                        status = constants.DOWN
                except opt_ext.OptimizerInternalDriverError:
                    LOG.error(_LE("Optimizer Driver Error for "
                                  "update_optimizer for optimizer: "
                                  "%(optid)s"),
                        {'optid': optimizer['id']})
                    status = constants.ERROR
            else:
                status = constants.INACTIVE
        try:
            # send status back to plugin
            self.optplugin_rpc.set_optimizer_status(
                context,
                optimizer['id'],
                status)
        except Exception:
            LOG.exception(
                _LE("OaaS RPC failure in update_optimizer "
                    "for optimizer: %(optid)s"),
                {'optid': optimizer['id']})
            self.services_sync_needed = True

    @log_helpers.log_method_call
    def delete_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to delete a optimizer."""

        router_ids = self._get_router_ids_for_opt(
            context, optimizer, to_delete=True)
        if router_ids:
            router_info_list = self._get_router_info_list_for_tenant(
                router_ids,
                optimizer['tenant_id'])
            LOG.debug(
                "Delete optimizer %(opt)s on routers: '%(routers)s'"
                % {'opt': optimizer['id'],
                   'routers': [ri.router['id'] for ri in router_info_list]})
            # call into the driver
            try:
                self.oaas_driver.delete_optimizer(
                    self.conf.agent_mode,
                    router_info_list,
                    optimizer)
                if optimizer['admin_state_up']:
                    status = constants.ACTIVE
                else:
                    status = constants.DOWN
            except opt_ext.OptimizerInternalDriverError:
                LOG.error(_LE("Optimizer Driver Error for delete_optimizer "
                              "for optimizer: %(optid)s"),
                    {'optid': optimizer['id']})
                status = constants.ERROR

            try:
                # send status back to plugin
                if status in [constants.ACTIVE, constants.DOWN]:
                    self.optplugin_rpc.optimizer_deleted(context, optimizer['id'])
                else:
                    self.optplugin_rpc.set_optimizer_status(
                        context,
                        optimizer['id'],
                        status)
            except Exception:
                LOG.exception(
                    _LE("OaaS RPC failure in delete_optimizer "
                        "for optimizer: %(optid)s"),
                    {'optid': optimizer['id']})
                self.services_sync_needed = True
