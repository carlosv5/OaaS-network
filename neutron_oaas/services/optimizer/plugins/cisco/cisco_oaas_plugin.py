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

from neutron.api.v2 import attributes as attr
from neutron.common import constants as l3_const
from neutron.common import rpc as n_rpc
from neutron import context as neutron_context
from neutron.i18n import _LW
from neutron import manager
from neutron.plugins.common import constants as const
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging

from neutron_oaas.db.cisco import cisco_oaas_db as csropt_db
import neutron_oaas.extensions
from neutron_oaas.extensions.cisco import csr_optimizer_insertion as csr_ext
from neutron_oaas.services.optimizer import oaas_plugin as ref_opt_plugin

LOG = logging.getLogger(__name__)


class OptimizerCallbacks(object):

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        super(OptimizerCallbacks, self).__init__()
        self.plugin = plugin

    @log_helpers.log_method_call
    def set_optimizer_status(self, context, optimizer_id, status,
                            status_data=None, **kwargs):
        """Agent uses this to set a optimizer's status."""
        with context.session.begin(subtransactions=True):
            opt_db = self.plugin._get_optimizer(context, optimizer_id)
            # ignore changing status if optimizer expects to be deleted
            # That case means that while some pending operation has been
            # performed on the backend, neutron server received delete request
            # and changed optimizer status to const.PENDING_DELETE
            if status == const.ERROR:
                opt_db.status = const.ERROR
                return False
            if opt_db.status == const.PENDING_DELETE:
                LOG.debug("Optimizer %(opt_id)s in PENDING_DELETE state, "
                          "not changing to %(status)s",
                          {'opt_id': optimizer_id, 'status': status})
                return False
            if status in (const.ACTIVE, const.INACTIVE):
                opt_db.status = status
                csropt = self.plugin.lookup_optimizer_csr_association(context,
                    optimizer_id)
                _opt = {'id': csropt['opt_id'], 'port_id': csropt['port_id'],
                       'direction': csropt['direction'],
                       'acl_id': status_data['acl_id']}
                self.plugin.update_optimizer_csr_association(context,
                    optimizer_id, _opt)
            else:
                opt_db.status = const.ERROR

    @log_helpers.log_method_call
    def optimizer_deleted(self, context, optimizer_id, **kwargs):
        """Agent uses this to indicate optimizer is deleted."""
        with context.session.begin(subtransactions=True):
            opt_db = self.plugin._get_optimizer(context, optimizer_id)
            # allow to delete optimizers in ERROR state
            if opt_db.status in (const.PENDING_DELETE, const.ERROR):
                self.plugin.delete_db_optimizer_object(context, optimizer_id)
                return True
            LOG.warn(_LW('Optimizer %(opt)s unexpectedly deleted by agent, '
                         'status was %(status)s'),
                {'opt': optimizer_id, 'status': opt_db.status})
            opt_db.status = const.ERROR
        return False

    @log_helpers.log_method_call
    def get_optimizers_for_tenant(self, context, **kwargs):
        """Agent uses this to get all optimizers and rules for a tenant."""
        opt_list = []
        for opt in self.plugin.get_optimizers(context):
            opt_with_rules = (
                self.plugin._make_optimizer_dict_with_rules(context, opt['id']))
            csropt = self.plugin.lookup_optimizer_csr_association(context,
                opt['id'])
            router_id = csropt['router_id']
            opt_with_rules['vendor_ext'] = self.plugin._get_hosting_info(
                context, csropt['port_id'], router_id, csropt['direction'])
            opt_with_rules['vendor_ext']['acl_id'] = csropt['acl_id']
            opt_list.append(opt_with_rules)
        return opt_list

    @log_helpers.log_method_call
    def get_optimizers_for_tenant_without_rules(self, context, **kwargs):
        """Agent uses this to get all optimizers for a tenant."""
        return [opt for opt in self.plugin.get_optimizers(context)]

    @log_helpers.log_method_call
    def get_tenants_with_optimizers(self, context, **kwargs):
        """Agent uses this to get all tenants that have optimizers."""
        ctx = neutron_context.get_admin_context()
        opt_list = self.plugin.get_optimizers(ctx)
        return list(set(opt['tenant_id'] for opt in opt_list))


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


class CSROptimizerPlugin(ref_opt_plugin.OptimizerPlugin,
                        csropt_db.CiscoOptimizer_db_mixin):

    """Implementation of the Neutron Optimizer Service Plugin.

    This class implements the Cisco CSR OaaS Service Plugin,
    inherits from the oaas ref plugin as no changes are made
    to handling oaas policy and rules. The CRUD methods are
    overridden to provide for the specific implementation. The
    basic oaas db is managed thru the optimizer_db.Optimizer_db_mixin.
    The backend specific associations are captured in the new table,
    csropt_db.CiscoOptimizer_db_mixin.
    """
    supported_extension_aliases = ["oaas", "csroptimizerinsertion"]

    def __init__(self):
        """Do the initialization for the optimizer service plugin here."""

        ext_path = neutron_oaas.extensions.__path__[0] + '/cisco'
        if ext_path not in cfg.CONF.api_extensions_path.split(':'):
            cfg.CONF.set_override('api_extensions_path',
                              cfg.CONF.api_extensions_path + ':' + ext_path)

        self.endpoints = [OptimizerCallbacks(self)]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            'CISCO_FW_PLUGIN', self.endpoints, fanout=False)
        self.conn.consume_in_threads()

        self.agent_rpc = OptimizerAgentApi(
            'CISCO_FW',
            cfg.CONF.host
        )

    def _rpc_update_optimizer(self, context, optimizer_id):
        status_update = {"optimizer": {"status": const.PENDING_UPDATE}}
        opt = super(ref_opt_plugin.OptimizerPlugin, self).update_optimizer(
            context, optimizer_id, status_update)
        if opt:
            opt_with_rules = (
                self._make_optimizer_dict_with_rules(context,
                                                    optimizer_id))
            csropt = self.lookup_optimizer_csr_association(context, optimizer_id)
            opt_with_rules['vendor_ext'] = self._get_hosting_info(context,
                csropt['port_id'], csropt['router_id'], csropt['direction'])
            opt_with_rules['vendor_ext']['acl_id'] = csropt['acl_id']
            LOG.debug("Update of Rule or policy: opt_with_rules: %s",
                opt_with_rules)
            self.agent_rpc.update_optimizer(context, opt_with_rules)

    @log_helpers.log_method_call
    def _validate_opt_port_and_get_router_id(self, context, tenant_id, port_id):
        # port validation with router plugin
        l3_plugin = manager.NeutronManager.get_service_plugins().get(
            const.L3_ROUTER_NAT)
        ctx = neutron_context.get_admin_context()
        routers = l3_plugin.get_routers(ctx)
        router_ids = [
            router['id']
            for router in routers
            if router['tenant_id'] == tenant_id]
        port_db = self._core_plugin._get_port(context, port_id)
        if not (port_db['device_id'] in router_ids and
                port_db['device_owner'] == l3_const.DEVICE_OWNER_ROUTER_INTF):
            raise csr_ext.InvalidInterfaceForCSRFW(port_id=port_id)
        return port_db['device_id']

    def _map_csr_device_info_for_agent(self, hosting_device):
        return {'host_mngt_ip': hosting_device['management_ip_address'],
                'host_usr_nm': hosting_device['credentials']['username'],
                'host_usr_pw': hosting_device['credentials']['password']}

    def _get_service_insertion_points(self, context, interfaces, port_id,
            direction):
        insertion_point = dict()
        hosting_info = dict()
        for interface in interfaces:
            if interface['id'] == port_id:
                hosting_info = interface['hosting_info']
        if not hosting_info:
            raise csr_ext.InvalidRouterHostingInfoForCSRFW(port_id=port_id)
        insertion_point['port'] = {'id': port_id,
            'hosting_info': hosting_info}
        insertion_point['direction'] = direction
        return [insertion_point]

    def _get_hosting_info(self, context, port_id, router_id, direction):
        l3_plugin = manager.NeutronManager.get_service_plugins().get(
            const.L3_ROUTER_NAT)
        ctx = neutron_context.get_admin_context()
        routers = l3_plugin.get_sync_data_ext(ctx)
        for router in routers:
            if router['id'] == router_id:
                vendor_ext = self._map_csr_device_info_for_agent(
                    router['hosting_device'])
                vendor_ext['if_list'] = self._get_service_insertion_points(
                    context, router['_interfaces'], port_id, direction)
                return vendor_ext
        # TODO(sridar): we may need to raise an excp - check backlogging

    @log_helpers.log_method_call
    def create_optimizer(self, context, optimizer):
        tenant_id = self._get_tenant_id_for_create(context,
                                                   optimizer['optimizer'])
        port_id = optimizer['optimizer'].pop('port_id', None)
        direction = optimizer['optimizer'].pop('direction', None)

        if port_id == attr.ATTR_NOT_SPECIFIED:
            LOG.debug("create_optimizer() called")
            port_id = None
            router_id = None
        else:
            # TODO(sridar): add check to see if the new port-id does not have
            # any associated optimizer.
            router_id = self._validate_opt_port_and_get_router_id(context,
                tenant_id, port_id)

        if direction == attr.ATTR_NOT_SPECIFIED:
            direction = None

        optimizer['optimizer']['status'] = const.PENDING_CREATE
        opt = super(ref_opt_plugin.OptimizerPlugin, self).create_optimizer(
            context, optimizer)
        opt_with_rules = (
            self._make_optimizer_dict_with_rules(context, opt['id']))

        if not port_id and not direction:
            return opt

        # Add entry into optimizer associations table
        _opt = {'id': opt['id'], 'port_id': port_id,
            'direction': direction, 'router_id': router_id, 'acl_id': None}
        self.add_optimizer_csr_association(context, _opt)

        if port_id and direction:
            opt_with_rules['vendor_ext'] = self._get_hosting_info(context,
                port_id, router_id, direction)
            opt_with_rules['vendor_ext']['acl_id'] = None

            self.agent_rpc.create_optimizer(context, opt_with_rules)
        return opt

    @log_helpers.log_method_call
    def update_optimizer(self, context, optid, optimizer):
        self._ensure_update_optimizer(context, optid)
        tenant_id = self._get_tenant_id_for_create(context,
                                                   optimizer['optimizer'])
        csropt = self.lookup_optimizer_csr_association(context, optid)

        port_id = optimizer['optimizer'].pop('port_id', None)
        direction = optimizer['optimizer'].pop('direction', None)

        _opt = {'id': optid}

        if port_id:
            router_id = self._validate_opt_port_and_get_router_id(context,
                tenant_id, port_id)
            if csropt and csropt['port_id']:
                # TODO(sridar): add check to see if the new port_id does not
                # have any associated optimizer.

                # we only support a different port if associated
                # with the same router
                if router_id != csropt['router_id']:
                    raise csr_ext.InvalidRouterAssociationForCSRFW(
                        port_id=port_id)
            _opt['port_id'] = port_id
            _opt['router_id'] = router_id
        else:
            _opt['port_id'] = csropt['port_id'] if csropt else None
            _opt['router_id'] = csropt['router_id'] if csropt else None

        if direction:
            _opt['direction'] = direction
        else:
            _opt['direction'] = csropt['direction'] if csropt else None

        _opt['acl_id'] = csropt['acl_id'] if csropt else None

        self.update_optimizer_csr_association(context, optid, _opt)

        optimizer['optimizer']['status'] = const.PENDING_UPDATE

        opt = super(ref_opt_plugin.OptimizerPlugin, self).update_optimizer(
            context, optid, optimizer)
        opt_with_rules = (
            self._make_optimizer_dict_with_rules(context, opt['id']))

        if _opt['port_id'] and _opt['direction']:

            opt_with_rules['vendor_ext'] = self._get_hosting_info(context,
                port_id, csropt['router_id'], direction)
            opt_with_rules['vendor_ext']['acl_id'] = csropt['acl_id']
            LOG.debug("CSR Plugin update: opt_with_rules: %s", opt_with_rules)
            self.agent_rpc.update_optimizer(context, opt_with_rules)
        return opt

    @log_helpers.log_method_call
    def delete_optimizer(self, context, optid):
        self._ensure_update_optimizer(context, optid)

        status_update = {"optimizer": {"status": const.PENDING_DELETE}}
        opt = super(ref_opt_plugin.OptimizerPlugin, self).update_optimizer(
            context, optid, status_update)

        # given that we are not in a PENDING_CREATE we should have
        # an acl_id - since it is not present something bad has happened
        # on the backend and no sense in sending a msg to the agent.
        # Clean up ...
        csropt = self.lookup_optimizer_csr_association(context, optid)
        if not csropt or not csropt['acl_id']:
            self.delete_db_optimizer_object(context, optid)
            return

        opt_with_rules = (
            self._make_optimizer_dict_with_rules(context, opt['id']))

        opt_with_rules['vendor_ext'] = self._get_hosting_info(context,
            csropt['port_id'], csropt['router_id'], csropt['direction'])
        opt_with_rules['vendor_ext']['acl_id'] = csropt['acl_id']

        self.agent_rpc.delete_optimizer(context, opt_with_rules)

    @log_helpers.log_method_call
    def get_optimizer(self, context, optid, fields=None):
        res = super(ref_opt_plugin.OptimizerPlugin, self).get_optimizer(
                        context, optid, fields)
        csropt = self.lookup_optimizer_csr_association(context, res['id'])
        if not csropt:
            return res
        res['port_id'] = csropt['port_id']
        res['direction'] = csropt['direction']
        res['router_id'] = csropt['router_id']
        return res
