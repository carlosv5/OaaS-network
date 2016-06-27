# Copyright 2015 Cisco Systems, Inc.
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

LOG = logging.getLogger(__name__)


class CiscoOptimizerAssociation(model_base.BASEV2):

    """Represents FW association with CSR interface and attributes"""
    __tablename__ = 'cisco_optimizer_associations'

    opt_id = sa.Column(sa.String(36),
                      sa.ForeignKey('optimizers.id', ondelete="CASCADE"),
                      primary_key=True)
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"))
    direction = sa.Column(sa.String(16))
    acl_id = sa.Column(sa.String(36))
    router_id = sa.Column(sa.String(36))


class CiscoOptimizer_db_mixin(object):

    @log_helpers.log_method_call
    def add_optimizer_csr_association(self, context, opt):
        with context.session.begin(subtransactions=True):
            optimizer_db = CiscoOptimizerAssociation(opt_id=opt['id'],
                                   port_id=opt['port_id'],
                                   direction=opt['direction'],
                                   acl_id=opt['acl_id'],
                                   router_id=opt['router_id'])
            context.session.add(optimizer_db)

    @log_helpers.log_method_call
    def lookup_optimizer_csr_association(self, context, optid):
        with context.session.begin(subtransactions=True):
            csr_opt_qry = context.session.query(CiscoOptimizerAssociation)
            csr_opt = csr_opt_qry.filter_by(opt_id=optid).first()
        return csr_opt

    @log_helpers.log_method_call
    def update_optimizer_csr_association(self, context, optid, optimizer):
        with context.session.begin(subtransactions=True):
            csr_opt_qry = context.session.query(CiscoOptimizerAssociation)
            csr_opt = csr_opt_qry.filter_by(opt_id=optid).first()
            csr_opt.update(optimizer)
        return optimizer
