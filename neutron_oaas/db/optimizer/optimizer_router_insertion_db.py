# Copyright 2015 Cisco Systems Inc.
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

from neutron.db import model_base
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import sqlalchemy as sa

from neutron_oaas.extensions import optimizerrouterinsertion as optrtrins

LOG = logging.getLogger(__name__)


class OptimizerRouterAssociation(model_base.BASEV2):

    """Tracks FW Router Association"""

    __tablename__ = 'optimizer_router_associations'

    opt_id = sa.Column(sa.String(36),
        sa.ForeignKey('optimizers.id', ondelete="CASCADE"),
        primary_key=True)
    router_id = sa.Column(sa.String(36),
        sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)


class OptimizerRouterInsertionDbMixin(object):

    """Access methods for the optimizer_router_associations table."""

    @log_helpers.log_method_call
    def set_routers_for_optimizer(self, context, opt):
        """Sets the routers associated with the opt."""
        with context.session.begin(subtransactions=True):
            for r_id in opt['router_ids']:
                opt_rtr_db = OptimizerRouterAssociation(opt_id=opt['opt_id'],
                                   router_id=r_id)
                context.session.add(opt_rtr_db)

    @log_helpers.log_method_call
    def get_optimizer_routers(self, context, optid):
        """Gets all routers associated with a optimizer."""
        with context.session.begin(subtransactions=True):
            opt_rtr_qry = context.session.query(
                OptimizerRouterAssociation.router_id)
            opt_rtr_rows = opt_rtr_qry.filter_by(opt_id=optid)
            opt_rtrs = [entry.router_id for entry in opt_rtr_rows]
        LOG.debug("get_optimizer_routers(): opt_rtrs: %s", opt_rtrs)
        return opt_rtrs

    @log_helpers.log_method_call
    def validate_optimizer_routers_not_in_use(
            self, context, router_ids, optid=None):
        """Validate if router-ids not associated with any optimizer.

        If any of the router-ids in the list is already associated with
        a optimizer, raise an exception else just return.
        """
        opt_rtr_qry = context.session.query(OptimizerRouterAssociation.router_id)
        opt_rtrs = opt_rtr_qry.filter(
            OptimizerRouterAssociation.router_id.in_(router_ids),
            OptimizerRouterAssociation.opt_id != optid).all()
        if opt_rtrs:
            router_ids = [entry.router_id for entry in opt_rtrs]
            raise optrtrins.OptimizerRouterInUse(router_ids=router_ids)

    @log_helpers.log_method_call
    def update_optimizer_routers(self, context, opt):
        """Update the optimizer with new routers.

        This involves removing existing router associations and replacing
        it with the new router associations provided in the update method.
        """
        with context.session.begin(subtransactions=True):
            opt_rtr_qry = context.session.query(OptimizerRouterAssociation)
            opt_rtr_qry.filter_by(opt_id=opt['opt_id']).delete()
            if opt['router_ids']:
                self.set_routers_for_optimizer(context, opt)

            # TODO(sridar): Investigate potential corner case if rpc failure
            # happens on PENDING_UPDATE and agent did not restart. Evaluate
            # complexity vs benefit of holding on to old entries until ack
            # from agent.

        return opt
