# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

from networking_cisco.plugins.cisco.cfg_agent.service_helpers import (
    service_helper)
from neutron.common import rpc as n_rpc
from neutron import context as n_context
from neutron.i18n import _LE
from neutron.plugins.common import constants
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging

from neutron_oaas.services.optimizer.drivers.cisco import csr_acl_driver

LOG = logging.getLogger(__name__)

CSR_FW_EVENT_Q_NAME = 'csr_opt_event_q'
CSR_FW_EVENT_CREATE = 'FW_EVENT_CREATE'
CSR_FW_EVENT_UPDATE = 'FW_EVENT_UPDATE'
CSR_FW_EVENT_DELETE = 'FW_EVENT_DELETE'


class CsrOptimizerlPluginApi(object):
    """CsrOptimizerServiceHelper (Agent) side of the ACL RPC API."""

    @log_helpers.log_method_call
    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    @log_helpers.log_method_call
    def get_optimizers_for_device(self, context, **kwargs):
        """Get Optimizers with rules for a device from Plugin."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_optimizers_for_device', host=self.host)

    @log_helpers.log_method_call
    def get_optimizers_for_tenant(self, context, **kwargs):
        """Get Optimizers with rules for a tenant from the Plugin."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_optimizers_for_tenant', host=self.host)

    @log_helpers.log_method_call
    def get_tenants_with_optimizers(self, context, **kwargs):
        """Get Tenants that have Optimizers configured from plugin."""
        cctxt = self.client.prepare()
        return cctxt.call(context,
                         'get_tenants_with_optimizers', host=self.host)

    @log_helpers.log_method_call
    def set_optimizer_status(self, context, opt_id, status, status_data=None):
        """Make a RPC to set the status of a optimizer."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'set_optimizer_status', host=self.host,
                         optimizer_id=opt_id, status=status,
                         status_data=status_data)

    def optimizer_deleted(self, context, optimizer_id):
        """Make a RPC to indicate that the optimizer resources are deleted."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'optimizer_deleted', host=self.host,
                         optimizer_id=optimizer_id)


class CsrOptimizerServiceHelper(object):

    @log_helpers.log_method_call
    def __init__(self, host, conf, cfg_agent):
        super(CsrOptimizerServiceHelper, self).__init__()
        self.conf = conf
        self.cfg_agent = cfg_agent
        self.fullsync = True
        self.event_q = service_helper.QueueMixin()
        self.opt_plugin_rpc = CsrOptimizerlPluginApi(
            'CISCO_FW_PLUGIN', conf.host)
        self.topic = 'CISCO_FW'
        self._setup_rpc()

        self.acl_driver = csr_acl_driver.CsrAclDriver()

    def _setup_rpc(self):
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [self]
        self.conn.create_consumer(self.topic,
                                  self.endpoints, fanout=True)
        self.conn.consume_in_threads()

    ### Notifications from Plugin ####

    def create_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to create a optimizer."""
        LOG.debug("create_optimizer: optimizer %s", optimizer)
        event_data = {'event': CSR_FW_EVENT_CREATE,
                      'context': context,
                      'optimizer': optimizer,
                      'host': host}
        self.event_q.enqueue(CSR_FW_EVENT_Q_NAME, event_data)

    def update_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to update a optimizer."""
        LOG.debug("update_optimizer: optimizer %s", optimizer)
        event_data = {'event': CSR_FW_EVENT_UPDATE,
                      'context': context,
                      'optimizer': optimizer,
                      'host': host}
        self.event_q.enqueue(CSR_FW_EVENT_Q_NAME, event_data)

    def delete_optimizer(self, context, optimizer, host):
        """Handle Rpc from plugin to delete a optimizer."""
        LOG.debug("delete_optimizer: optimizer %s", optimizer)
        event_data = {'event': CSR_FW_EVENT_DELETE,
                      'context': context,
                      'optimizer': optimizer,
                      'host': host}
        self.event_q.enqueue(CSR_FW_EVENT_Q_NAME, event_data)

    def _invoke_optimizer_driver(self, context, optimizer, func_name):
        LOG.debug("_invoke_optimizer_driver: %s", func_name)
        try:
            if func_name == 'delete_optimizer':
                return_code = self.acl_driver.__getattribute__(func_name)(
                    None, None, optimizer)
                if not return_code:
                    LOG.debug("optimizer %s", optimizer['id'])
                    self.opt_plugin_rpc.set_optimizer_status(
                        context, optimizer['id'], constants.ERROR)
                else:
                    self.opt_plugin_rpc.optimizer_deleted(
                        context, optimizer['id'])
            else:
                return_code, status = self.acl_driver.__getattribute__(
                    func_name)(None, None, optimizer)
                if not return_code:
                    LOG.debug("optimizer %s", optimizer['id'])
                    self.opt_plugin_rpc.set_optimizer_status(
                        context, optimizer['id'], constants.ERROR)
                else:
                    LOG.debug("status %s", status)
                    self.opt_plugin_rpc.set_optimizer_status(
                        context, optimizer['id'], constants.ACTIVE, status)
        except Exception:
            LOG.debug("_invoke_optimizer_driver: PRC failure")
            self.fullsync = True

    def _process_optimizer_pending_op(self, context, optimizer_list):
        for optimizer in optimizer_list:
            optimizer_status = optimizer['status']
            if optimizer_status == 'PENDING_CREATE':
                self._invoke_optimizer_driver(
                    context, optimizer, 'create_optimizer')
            elif optimizer_status == 'PENDING_UPDATE':
                self._invoke_optimizer_driver(
                    context, optimizer, 'update_optimizer')
            elif optimizer_status == 'PENDING_DELETE':
                self._invoke_optimizer_driver(
                    context, optimizer, 'delete_optimizer')

    def _process_fullsync(self):
        LOG.debug("_process_fullsync")
        try:
            context = n_context.get_admin_context()
            tenants = self.opt_plugin_rpc.get_tenants_with_optimizers(
                context)
            LOG.debug("tenants with optimizer: %s", tenants)
            for tenant_id in tenants:
                ctx = n_context.Context('', tenant_id)
                optimizer_list = self.opt_plugin_rpc.get_optimizers_for_tenant(
                    ctx)
                self._process_optimizer_pending_op(ctx, optimizer_list)

        except Exception:
            LOG.debug("_process_fullsync: RPC failure")
            self.fullsync = True

    def _process_devices(self, device_ids):
        LOG.debug("_process_devices: device_ids %s", device_ids)
        try:
            for device_id in device_ids:
                ctx = n_context.Context('', device_id)
                optimizer_list = self.opt_plugin_rpc.get_optimizers_for_device(
                    ctx)
                self._process_optimizer_pending_op(ctx, optimizer_list)

        except Exception:
            LOG.debug("_process_devices: RPC failure")
            self.fullsync = True

    def _process_event_q(self):
        while True:
            try:
                event_data = self.event_q.dequeue(CSR_FW_EVENT_Q_NAME)
                if not event_data:
                    return
            except ValueError:
                LOG.debug("_process_event_q: no queue yet")
                return

            LOG.debug("_process_event_q: event_data %s", event_data)
            event = event_data['event']
            context = event_data['context']
            optimizer = event_data['optimizer']
            if event == CSR_FW_EVENT_CREATE:
                self._invoke_optimizer_driver(
                    context, optimizer, 'create_optimizer')
            elif event == CSR_FW_EVENT_UPDATE:
                self._invoke_optimizer_driver(
                    context, optimizer, 'update_optimizer')
            elif event == CSR_FW_EVENT_DELETE:
                self._invoke_optimizer_driver(
                    context, optimizer, 'delete_optimizer')
            else:
                LOG.error(_LE("invalid event %s"), event)

    def process_service(self, device_ids=None, removed_devices_info=None):
        try:
            if self.fullsync:
                self.fullsync = False
                self._process_fullsync()

            else:
                if device_ids:
                    self._process_devices(device_ids)

                if removed_devices_info:
                    LOG.debug("process_service: removed_devices_info %s",
                              removed_devices_info)
                    # do nothing for now
                else:
                    self._process_event_q()

        except Exception:
            LOG.exception(_LE('process_service exception ERROR'))
