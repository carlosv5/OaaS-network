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

from neutron.common import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging


LOG = logging.getLogger(__name__)

OaaSOpts = [
    cfg.StrOpt(
        'driver',
        default='',
        help=_("Name of the OaaS Driver")),
    cfg.BoolOpt(
        'enabled',
        default=False,
        help=_("Enable OaaS")),
]
cfg.CONF.register_opts(OaaSOpts, 'oaas')


class OaaSPluginApiMixin(object):
    """Agent side of the OaaS agent to OaaS Plugin RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def set_optimizer_status(self, context, optimizer_id, status):
        """Make a RPC to set the status of a optimizer."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'set_optimizer_status', host=self.host,
                          optimizer_id=optimizer_id, status=status)

    def optimizer_deleted(self, context, optimizer_id):
        """Make a RPC to indicate that the optimizer resources are deleted."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'optimizer_deleted', host=self.host,
                          optimizer_id=optimizer_id)


class OaaSAgentRpcCallbackMixin(object):
    """Mixin for OaaS agent Implementations."""

    def __init__(self, host):

        super(OaaSAgentRpcCallbackMixin, self).__init__(host)

    def create_optimizer(self, context, optimizer, host):
        """Handle RPC cast from plugin to create a optimizer."""
        pass

    def update_optimizer(self, context, optimizer, host):
        """Handle RPC cast from plugin to update a optimizer."""
        pass

    def delete_optimizer(self, context, optimizer, host):
        """Handle RPC cast from plugin to delete a optimizer."""
        pass
