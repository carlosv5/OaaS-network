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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.agent.linux import ip_lib
from neutron.common import exceptions as nexception
from neutron.common import topics
from neutron import context
from neutron.i18n import _LE
from neutron.plugins.common import constants
from neutron.services.optimizer.agents import optimizer_agent_api as api
from neutron.services import provider_configuration as provconf

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
        oaas_driver_class_path = provconf.get_provider_driver_class(
            cfg.CONF.oaas.driver)
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
            try:
                self.oaas_driver = importutils.import_object(
                    oaas_driver_class_path)
                LOG.debug("OaaS Driver Loaded: '%s'", oaas_driver_class_path)
            except ImportError:
                msg = _('Error importing OaaS device driver: %s')
                raise ImportError(msg % oaas_driver_class_path)
        self.services_sync = False
        # setup RPC to msg oaas plugin
        self.optplugin_rpc = OaaSL3PluginApi(topics.OPTIMIZER_PLUGIN,
                                             conf.host)
        super(OaaSL3AgentRpcCallback, self).__init__(host=conf.host)

    def _get_router_info_list_for_tenant(self, routers, tenant_id):
        """Returns the list of router info objects on which to apply the opt."""
        root_ip = ip_lib.IPWrapper()
        # Get the routers for the tenant
        router_ids = [
            router['id']
            for router in routers
            if router['tenant_id'] == tenant_id]
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

    def _invoke_driver_for_plugin_api(self, context, opt, func_name):
        """Invoke driver method for plugin API and provide status back."""
        LOG.debug("%(func_name)s from agent for opt: %(optid)s",
                  {'func_name': func_name, 'optid': opt['id']})
        try:
            routers = self.plugin_rpc.get_routers(context)
            router_info_list = self._get_router_info_list_for_tenant(
                routers,
                opt['tenant_id'])
            if not router_info_list:
                LOG.debug('No Routers on tenant: %s', opt['tenant_id'])
                # opt was created before any routers were added, and if a
                # delete is sent then we need to ack so that plugin can
                # cleanup.
                if func_name == 'delete_optimizer':
                    self.optplugin_rpc.optimizer_deleted(context, opt['id'])
                return
            LOG.debug("Apply opt on Router List: '%s'",
                      [ri.router['id'] for ri in router_info_list])
            # call into the driver
            try:
                self.oaas_driver.__getattribute__(func_name)(
                    self.conf.agent_mode,
                    router_info_list,
                    opt)
                if opt['admin_state_up']:
                    status = constants.ACTIVE
                else:
                    status = constants.DOWN
            except nexception.OptimizerInternalDriverError:
                LOG.error(_LE("Optimizer Driver Error for %(func_name)s "
                              "for opt: %(optid)s"),
                          {'func_name': func_name, 'optid': opt['id']})
                status = constants.ERROR
            # delete needs different handling
            if func_name == 'delete_optimizer':
                if status in [constants.ACTIVE, constants.DOWN]:
                    self.optplugin_rpc.optimizer_deleted(context, opt['id'])
            else:
                self.optplugin_rpc.set_optimizer_status(
                    context,
                    opt['id'],
                    status)
        except Exception:
            LOG.exception(
                _LE("OaaS RPC failure in %(func_name)s for opt: %(optid)s"),
                {'func_name': func_name, 'optid': opt['id']})
            self.services_sync = True
        return

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
            except nexception.OptimizerInternalDriverError:
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
            except nexception.OptimizerInternalDriverError:
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
        routers = []
        routers.append(ri.router)
        router_info_list = self._get_router_info_list_for_tenant(
            routers,
            ri.router['tenant_id'])
        if router_info_list:
            # Get the optimizer with rules
            # for the tenant the router is on.
            ctx = context.Context('', ri.router['tenant_id'])
            opt_list = self.optplugin_rpc.get_optimizers_for_tenant(ctx)
            LOG.debug("Process router add, opt_list: '%s'",
                      [opt['id'] for opt in opt_list])
            for opt in opt_list:
                self._invoke_driver_for_sync_from_plugin(
                    ctx,
                    router_info_list,
                    opt)

    def process_router_add(self, ri):
        """On router add, get opt with rules from plugin and update driver."""
        # avoid msg to plugin when oaas is not configured
        if not self.oaas_enabled:
            return
        try:
            self._process_router_add(ri)
        except Exception:
            LOG.exception(
                _LE("OaaS RPC info call failed for '%s'."),
                ri.router['id'])
            self.services_sync = True

    def process_services_sync(self, ctx):
        """On RPC issues sync with plugin and apply the sync data."""
        # avoid msg to plugin when oaas is not configured
        if not self.oaas_enabled:
            return
        try:
            # get all routers
            routers = self.plugin_rpc.get_routers(ctx)
            # get the list of tenants with optimizers configured
            # from the plugin
            tenant_ids = self.optplugin_rpc.get_tenants_with_optimizers(ctx)
            LOG.debug("Tenants with Optimizers: '%s'", tenant_ids)
            for tenant_id in tenant_ids:
                ctx = context.Context('', tenant_id)
                opt_list = self.optplugin_rpc.get_optimizers_for_tenant(ctx)
                if opt_list:
                    # if opt present on tenant
                    router_info_list = self._get_router_info_list_for_tenant(
                        routers,
                        tenant_id)
                    if router_info_list:
                        LOG.debug("Router List: '%s'",
                                  [ri.router['id'] for ri in router_info_list])
                        LOG.debug("opt_list: '%s'",
                                  [opt['id'] for opt in opt_list])
                        # apply sync data on opt for this tenant
                        for opt in opt_list:
                            # opt, routers present on this host for tenant
                            # install
                            LOG.debug("Apply opt on Router List: '%s'",
                                      [ri.router['id']
                                          for ri in router_info_list])
                            # no need to apply sync data for ACTIVE opt
                            if opt['status'] != constants.ACTIVE:
                                self._invoke_driver_for_sync_from_plugin(
                                    ctx,
                                    router_info_list,
                                    opt)
            self.services_sync = False
        except Exception:
            LOG.exception(_LE("Failed oaas process services sync"))
            self.services_sync = True

    def create_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to create a optimizer."""
        return self._invoke_driver_for_plugin_api(
            context,
            optimizer,
            'create_optimizer')

    def update_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to update a optimizer."""
        return self._invoke_driver_for_plugin_api(
            context,
            optimizer,
            'update_optimizer')

    def delete_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to delete a optimizer."""
        return self._invoke_driver_for_plugin_api(
            context,
            optimizer,
            'delete_optimizer')
