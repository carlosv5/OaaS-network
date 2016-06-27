# Copyright 2015 Freescale, Inc.
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
#

from neutron.common import rpc
from neutron.common import topics
from neutron.i18n import _LE
from neutron.plugins.common import constants as const
from neutron.plugins.ml2.drivers.freescale import config
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy.orm import exc

from neutron_oaas.db.optimizer import optimizer_db
from neutron_oaas.services.optimizer import oaas_plugin

LOG = logging.getLogger(__name__)


class OptimizerCallbacks(oaas_plugin.OptimizerCallbacks):

    """Callbacks to handle CRD notifications to amqp."""

    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        self.plugin = plugin
        self._client = self.plugin._client

    def get_optimizers_for_tenant(self, context, **kwargs):
        """Get all Optimizers and rules for a tenant from CRD.

        For all the optimizers created, check CRD for config_mode.
        If it is Network Node, prepare the list.
        Other config modes are handled by CRD internally.
        """

        opt_list = []
        for opt in self.plugin.get_optimizers(context):
            opt_id = opt['id']
            # get the optimizer details from CRD service.
            crd_opt_details = self._client.show_optimizer(opt_id)
            config_mode = crd_opt_details['optimizer']['config_mode']
            # get those FWs with config mode NetworkNode (NN) or None
            if config_mode in ('NN', None):
                opt_list.append(self.plugin._make_optimizer_dict_with_rules(
                    context, opt_id))
        return opt_list


class OptimizerPlugin(optimizer_db.Optimizer_db_mixin):

    """Implementation of the Freescale Optimizer Service Plugin.

    This class manages the workflow of OaaS request/response.
    Existing Optimizer database is used.
    """
    supported_extension_aliases = ["oaas"]

    def __init__(self):
        """Do the initialization for the optimizer service plugin here."""

        self._client = config.get_crdclient()
        self.endpoints = [OptimizerCallbacks(self)]

        self.conn = rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.OPTIMIZER_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

    def _update_optimizer_status(self, context, optimizer_id):
        status_update = {"optimizer": {"status": const.PENDING_UPDATE}}
        super(OptimizerPlugin, self).update_optimizer(context, optimizer_id,
                                                    status_update)
        try:
            self._client.update_optimizer(optimizer_id, status_update)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update optimizer status (%s)."),
                          optimizer_id)

    def _update_optimizer_policy(self, context, optimizer_policy_id):
        optimizer_policy = self.get_optimizer_policy(context, optimizer_policy_id)
        if optimizer_policy:
            for optimizer_id in optimizer_policy['optimizer_list']:
                self._update_optimizer_status(context, optimizer_id)

    # Optimizer Management
    def create_optimizer(self, context, optimizer):
        """Create Optimizer.

        'PENDING' status updates are handled by CRD by posting messages
        to AMQP (topics.OPTIMIZER_PLUGIN) that Optimizer consumes to
        update its status.
        """
        optimizer['optimizer']['status'] = const.PENDING_CREATE
        opt = super(OptimizerPlugin, self).create_optimizer(context, optimizer)
        try:
            crd_optimizer = {'optimizer': opt}
            self._client.create_optimizer(crd_optimizer)
        except Exception:
            with excutils.save_and_reraise_exception():
                opt_id = opt['optimizer']['id']
                LOG.error(_LE("Failed to create optimizer (%s)."),
                          opt_id)
                super(OptimizerPlugin, self).delete_optimizer(context, opt_id)
        return opt

    def update_optimizer(self, context, opt_id, optimizer=None):
        optimizer['optimizer']['status'] = const.PENDING_UPDATE
        opt = super(OptimizerPlugin,
                   self).update_optimizer(context, opt_id, optimizer)
        try:
            crd_optimizer = {'optimizer': opt}
            self._client.update_optimizer(opt_id, crd_optimizer)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to update optimizer (%s)."), opt_id)
                # TODO(trinaths):do rollback on error
        return opt

    def delete_db_optimizer_object(self, context, opt_id):
        optimizer = self.get_optimizer(context, opt_id)
        if optimizer['status'] in [const.PENDING_DELETE]:
            try:
                super(OptimizerPlugin, self).delete_optimizer(context, opt_id)
            except exc.NoResultFound:
                LOG.error(_LE("Delete Optimizer (%s) DB object failed."),
                          opt_id)

    def delete_optimizer(self, context, opt_id):
        status_update = {"optimizer": {"status": const.PENDING_DELETE}}
        super(OptimizerPlugin, self).update_optimizer(context, opt_id,
                                                    status_update)
        try:
            self._client.delete_optimizer(opt_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to delete optimizer (%s)."), opt_id)
                # TODO(trinaths):do rollback on error

    # Optimizer Policy Management
    def create_optimizer_policy(self, context, optimizer_policy):
        opt_policy = super(OptimizerPlugin, self).create_optimizer_policy(
            context,
            optimizer_policy)
        opt_policy.pop('optimizer_list')
        try:
            crd_optimizer_policy = {'optimizer_policy': opt_policy}
            self._client.create_optimizer_policy(crd_optimizer_policy)
        except Exception:
            with excutils.save_and_reraise_exception():
                optp_id = opt_policy['optimizer_policy']['id']
                LOG.error(_LE("Failed to create optimizer policy (%s)."),
                          optp_id)
                super(OptimizerPlugin, self).delete_optimizer_policy(context,
                                                                   optp_id)
        return opt_policy

    def update_optimizer_policy(self, context, fp_id, optimizer_policy):
        opt_policy = super(OptimizerPlugin,
                          self).update_optimizer_policy(context, fp_id,
                                                       optimizer_policy)
        self._update_optimizer_policy(context, fp_id)
        opt_policy.pop('optimizer_list')
        try:
            crd_optimizer_policy = {'optimizer_policy': opt_policy}
            self._client.update_optimizer_policy(fp_id, crd_optimizer_policy)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Update optimizer policy failed (%s)."), fp_id)
                # TODO(trinaths):do rollback on error
        return opt_policy

    def delete_optimizer_policy(self, context, fp_id):
        super(OptimizerPlugin, self).delete_optimizer_policy(context, fp_id)
        try:
            self._client.delete_optimizer_policy(fp_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Delete Optimizer Policy (%s) failed."),
                          fp_id)
                # TODO(trinaths):do rollback on error

    # Optimizer Rule management
    def create_optimizer_rule(self, context, optimizer_rule):
        opt_rule = super(OptimizerPlugin,
                        self).create_optimizer_rule(context, optimizer_rule)
        try:
            crd_optimizer_rule = {'optimizer_rule': opt_rule}
            self._client.create_optimizer_rule(crd_optimizer_rule)
        except Exception:
            with excutils.save_and_reraise_exception():
                optr_id = opt_rule['optimizer_rule']['id']
                LOG.error(_LE("Failed to create optimizer rule (%s)."),
                          optr_id)
                super(OptimizerPlugin, self).delete_optimizer_rule(context,
                                                                 optr_id)
        return opt_rule

    def update_optimizer_rule(self, context, fr_id, optimizer_rule):
        opt_rule = super(OptimizerPlugin,
                        self).update_optimizer_rule(context, fr_id,
                                                   optimizer_rule)
        if opt_rule['optimizer_policy_id']:
            self._update_optimizer_policy(
                context,
                opt_rule['optimizer_policy_id'])
        try:
            crd_optimizer_rule = {'optimizer_rule': opt_rule}
            self._client.update_optimizer_rule(fr_id, crd_optimizer_rule)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to update optimizer rule (%s)."), fr_id)
                # TODO(trinaths):do rollback on error
        return opt_rule

    def delete_optimizer_rule(self, context, fr_id):
        opt_rule = self.get_optimizer_rule(context, fr_id)
        super(OptimizerPlugin, self).delete_optimizer_rule(context, fr_id)
        if opt_rule['optimizer_policy_id']:
            self._update_optimizer_policy(context,
                                         opt_rule['optimizer_policy_id'])
        try:
            self._client.delete_optimizer_rule(fr_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to delete optimizer rule (%s)."),
                          fr_id)
                # TODO(trinaths):do rollback on error

    def insert_rule(self, context, rid, rule_info):
        rule = super(OptimizerPlugin,
                     self).insert_rule(context, rid, rule_info)
        try:
            self._client.optimizer_policy_insert_rule(rid, rule_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to insert rule %(rule)s into "
                              "optimizer policy %(optpid)s."),
                          {'rule': rule_info,
                           'optpid': rid})
                super(OptimizerPlugin, self).remove_rule(context, rid,
                                                        rule_info)
        self._update_optimizer_policy(context, rid)
        return rule

    def remove_rule(self, context, rid, rule_info):
        rule = super(OptimizerPlugin,
                     self).remove_rule(context, rid, rule_info)
        try:
            self._client.optimizer_policy_remove_rule(rid, rule_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to remove rule %(rule)s from "
                              "optimizer policy %(optpid)s."),
                          {'rule': rule_info,
                           'optpid': rid})
        self._update_optimizer_policy(context, rid)
        return rule
