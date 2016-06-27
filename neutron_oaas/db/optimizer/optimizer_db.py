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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants
from neutron.db import common_db_mixin as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.common import constants as p_const
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron_oaas.extensions import optimizer as opt_ext
#OaaS
import math

LOG = logging.getLogger(__name__)


class OptimizerRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Optimizer rule."""
    __tablename__ = 'optimizer_rules'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    optimizer_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('optimizer_policies.id'),
                                   nullable=True)
    shared = sa.Column(sa.Boolean)
    protocol = sa.Column(sa.String(40))
    ip_version = sa.Column(sa.Integer, nullable=False)
    source_ip_address = sa.Column(sa.String(46))
    destination_ip_address = sa.Column(sa.String(46))
    source_port_range_min = sa.Column(sa.Integer)
    source_port_range_max = sa.Column(sa.Integer)
    destination_port_range_min = sa.Column(sa.Integer)
    destination_port_range_max = sa.Column(sa.Integer)
#OaaS
    action = sa.Column(sa.Enum('allow', 'deny', 'reject','optimize',
                               name='optimizerrules_action'))
    enabled = sa.Column(sa.Boolean)
    position = sa.Column(sa.Integer)


class Optimizer(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Optimizer resource."""
    __tablename__ = 'optimizers'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    admin_state_up = sa.Column(sa.Boolean)
    status = sa.Column(sa.String(16))
#OaaS
    solowan = sa.Column(sa.Boolean)
    local_id = sa.Column(sa.String(20))
    action = sa.Column(sa.String(30))
    num_pkt_cache_size = sa.Column(sa.Integer)


    optimizer_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('optimizer_policies.id'),
                                   nullable=True)


class OptimizerPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Optimizer Policy resource."""
    __tablename__ = 'optimizer_policies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    optimizer_rules = orm.relationship(
        OptimizerRule,
        backref=orm.backref('optimizer_policies', cascade='all, delete'),
        order_by='OptimizerRule.position',
        collection_class=ordering_list('position', count_from=1))
    audited = sa.Column(sa.Boolean)
    optimizers = orm.relationship(Optimizer, backref='optimizer_policies')


class Optimizer_db_mixin(opt_ext.OptimizerPluginBase, base_db.CommonDbMixin):
    """Mixin class for Optimizer DB implementation."""

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_optimizer(self, context, id):
        try:
            return self._get_by_id(context, Optimizer, id)
        except exc.NoResultFound:
            raise opt_ext.OptimizerNotFound(optimizer_id=id)

    def _get_optimizer_policy(self, context, id):
        try:
            return self._get_by_id(context, OptimizerPolicy, id)
        except exc.NoResultFound:
            raise opt_ext.OptimizerPolicyNotFound(optimizer_policy_id=id)

    def _get_optimizer_rule(self, context, id):
        try:
            return self._get_by_id(context, OptimizerRule, id)
        except exc.NoResultFound:
            raise opt_ext.OptimizerRuleNotFound(optimizer_rule_id=id)

    def _make_optimizer_dict(self, opt, fields=None):
        #OaaS PKT log 
        if(opt['num_pkt_cache_size'] != None):
            exp = math.log(opt['num_pkt_cache_size'],2)
            exp = round(exp)
            opt['num_pkt_cache_size'] = int (math.pow(2,exp))


        res = {'id': opt['id'],
               'tenant_id': opt['tenant_id'],
               'name': opt['name'],
               'description': opt['description'],
               'shared': opt['shared'],
               'admin_state_up': opt['admin_state_up'],
#OaaS
               'solowan': opt['solowan'],
               'local_id': opt['local_id'],
               'action': opt['action'],
               'num_pkt_cache_size': opt['num_pkt_cache_size'],


               'status': opt['status'],
               'optimizer_policy_id': opt['optimizer_policy_id']}
        return self._fields(res, fields)

    def _make_optimizer_policy_dict(self, optimizer_policy, fields=None):
        opt_rules = [rule['id'] for rule in optimizer_policy['optimizer_rules']]
        optimizers = [opt['id'] for opt in optimizer_policy['optimizers']]
        res = {'id': optimizer_policy['id'],
               'tenant_id': optimizer_policy['tenant_id'],
               'name': optimizer_policy['name'],
               'description': optimizer_policy['description'],
               'shared': optimizer_policy['shared'],
               'audited': optimizer_policy['audited'],
               'optimizer_rules': opt_rules,
               'optimizer_list': optimizers}
        return self._fields(res, fields)

    def _make_optimizer_rule_dict(self, optimizer_rule, fields=None):
        position = None
        # We return the position only if the optimizer_rule is bound to a
        # optimizer_policy.
        if optimizer_rule['optimizer_policy_id']:
            position = optimizer_rule['position']
        src_port_range = self._get_port_range_from_min_max_ports(
            optimizer_rule['source_port_range_min'],
            optimizer_rule['source_port_range_max'])
        dst_port_range = self._get_port_range_from_min_max_ports(
            optimizer_rule['destination_port_range_min'],
            optimizer_rule['destination_port_range_max'])
        res = {'id': optimizer_rule['id'],
               'tenant_id': optimizer_rule['tenant_id'],
               'name': optimizer_rule['name'],
               'description': optimizer_rule['description'],
               'optimizer_policy_id': optimizer_rule['optimizer_policy_id'],
               'shared': optimizer_rule['shared'],
               'protocol': optimizer_rule['protocol'],
               'ip_version': optimizer_rule['ip_version'],
               'source_ip_address': optimizer_rule['source_ip_address'],
               'destination_ip_address':
               optimizer_rule['destination_ip_address'],
               'source_port': src_port_range,
               'destination_port': dst_port_range,
               'action': optimizer_rule['action'],
               'position': position,
               'enabled': optimizer_rule['enabled']}
        return self._fields(res, fields)

    def _make_optimizer_dict_with_rules(self, context, optimizer_id):
        optimizer = self.get_optimizer(context, optimizer_id)
        opt_policy_id = optimizer['optimizer_policy_id']
        if opt_policy_id:
            opt_policy = self.get_optimizer_policy(context, opt_policy_id)
            opt_rules_list = [self.get_optimizer_rule(
                context, rule_id) for rule_id in opt_policy['optimizer_rules']]
            optimizer['optimizer_rule_list'] = opt_rules_list
        else:
            optimizer['optimizer_rule_list'] = []
        # FIXME(Sumit): If the size of the optimizer object we are creating
        # here exceeds the largest message size supported by rabbit/qpid
        # then we will have a problem.
        return optimizer

    def _check_optimizer_rule_conflict(self, optr_db, optp_db):
        if not optr_db['shared']:
            if optr_db['tenant_id'] != optp_db['tenant_id']:
                raise opt_ext.OptimizerRuleConflict(
                    optimizer_rule_id=optr_db['id'],
                    tenant_id=optr_db['tenant_id'])

    def _set_rules_for_policy(self, context, optimizer_policy_db, optp):
        rule_id_list = optp['optimizer_rules']
        optp_db = optimizer_policy_db
        with context.session.begin(subtransactions=True):
            if not rule_id_list:
                optp_db.optimizer_rules = []
                optp_db.audited = False
                return
            # We will first check if the new list of rules is valid
            filters = {'id': [r_id for r_id in rule_id_list]}
            rules_in_db = self._get_collection_query(context, OptimizerRule,
                                                     filters=filters)
            rules_dict = dict((optr_db['id'], optr_db) for optr_db in rules_in_db)
            for optrule_id in rule_id_list:
                if optrule_id not in rules_dict:
                    # If we find an invalid rule in the list we
                    # do not perform the update since this breaks
                    # the integrity of this list.
                    raise opt_ext.OptimizerRuleNotFound(
                        optimizer_rule_id=optrule_id)
                elif rules_dict[optrule_id]['optimizer_policy_id']:
                    if (rules_dict[optrule_id]['optimizer_policy_id'] !=
                            optp_db['id']):
                        raise opt_ext.OptimizerRuleInUse(
                            optimizer_rule_id=optrule_id)
                if 'shared' in optp:
                    if optp['shared'] and not rules_dict[optrule_id]['shared']:
                        raise opt_ext.OptimizerRuleSharingConflict(
                            optimizer_rule_id=optrule_id,
                            optimizer_policy_id=optp_db['id'])
                elif optp_db['shared'] and not rules_dict[optrule_id]['shared']:
                    raise opt_ext.OptimizerRuleSharingConflict(
                        optimizer_rule_id=optrule_id,
                        optimizer_policy_id=optp_db['id'])
            for optr_db in rules_in_db:
                self._check_optimizer_rule_conflict(optr_db, optp_db)
            # New list of rules is valid so we will first reset the existing
            # list and then add each rule in order.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing rules.
            optp_db.optimizer_rules = []
            for optrule_id in rule_id_list:
                optp_db.optimizer_rules.append(rules_dict[optrule_id])
            optp_db.optimizer_rules.reorder()
            optp_db.audited = False

    def _check_unshared_rules_for_policy(self, optp_db, optp):
        if optp['shared']:
            rules_in_db = optp_db['optimizer_rules']
            for optr_db in rules_in_db:
                if not optr_db['shared']:
                    raise opt_ext.OptimizerPolicySharingConflict(
                        optimizer_rule_id=optr_db['id'],
                        optimizer_policy_id=optp_db['id'])

    def _process_rule_for_policy(self, context, optimizer_policy_id,
                                 optimizer_rule_db, position):
        with context.session.begin(subtransactions=True):
            optp_query = context.session.query(
                OptimizerPolicy).with_lockmode('update')
            optp_db = optp_query.filter_by(id=optimizer_policy_id).one()
            if position:
                # Note that although position numbering starts at 1,
                # internal ordering of the list starts at 0, so we compensate.
                optp_db.optimizer_rules.insert(position - 1, optimizer_rule_db)
            else:
                optp_db.optimizer_rules.remove(optimizer_rule_db)
            optp_db.optimizer_rules.reorder()
            optp_db.audited = False
        return self._make_optimizer_policy_dict(optp_db)

    def _get_min_max_ports_from_range(self, port_range):
        if not port_range:
            return [None, None]
        min_port, sep, max_port = port_range.partition(":")
        if not max_port:
            max_port = min_port
        self._validate_optr_port_range(min_port, max_port)
        return [int(min_port), int(max_port)]

    def _get_port_range_from_min_max_ports(self, min_port, max_port):
        if not min_port:
            return None
        if min_port == max_port:
            return str(min_port)
        self._validate_optr_port_range(min_port, max_port)
        return '%s:%s' % (min_port, max_port)

    def _validate_opt_parameters(self, context, opt, opt_tenant_id):
        if 'optimizer_policy_id' not in opt:
            return
        optp_id = opt['optimizer_policy_id']
        optp = self._get_optimizer_policy(context, optp_id)
        if opt_tenant_id != optp['tenant_id'] and not optp['shared']:
            raise opt_ext.OptimizerPolicyConflict(optimizer_policy_id=optp_id)

    def _validate_optr_port_range(self, min_port, max_port):
        if int(min_port) > int(max_port):
            port_range = '%s:%s' % (min_port, max_port)
            raise opt_ext.OptimizerRuleInvalidPortValue(port=port_range)

    def _validate_optr_protocol_parameters(self, optr):
        protocol = optr['protocol']
        if protocol not in (constants.PROTO_NAME_TCP,
                            constants.PROTO_NAME_UDP):
            if optr['source_port'] or optr['destination_port']:
                raise opt_ext.OptimizerRuleInvalidICMPParameter(
                    param="Source, destination port")

    def create_optimizer(self, context, optimizer, status=None):
        LOG.debug("create_optimizer() called")
        opt = optimizer['optimizer']
        tenant_id = self._get_tenant_id_for_create(context, opt)
        # distributed routers may required a more complex state machine;
        # the introduction of a new 'CREATED' state allows this, whilst
        # keeping a backward compatible behavior of the logical resource.
        if not status:
            status = (p_const.CREATED if cfg.CONF.router_distributed
                      else p_const.PENDING_CREATE)
        with context.session.begin(subtransactions=True):
            self._validate_opt_parameters(context, opt, tenant_id)
            optimizer_db = Optimizer(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=opt['name'],
                description=opt['description'],
                optimizer_policy_id=opt['optimizer_policy_id'],
                admin_state_up=opt['admin_state_up'],
                status=status)
            context.session.add(optimizer_db)
        return self._make_optimizer_dict(optimizer_db)

    def update_optimizer(self, context, id, optimizer):
        LOG.debug("update_optimizer() called")
        opt = optimizer['optimizer']
        with context.session.begin(subtransactions=True):
            opt_db = self.get_optimizer(context, id)
            self._validate_opt_parameters(context, opt, opt_db['tenant_id'])
            count = context.session.query(Optimizer).filter_by(id=id).update(opt)
            if not count:
                raise opt_ext.OptimizerNotFound(optimizer_id=id)
        return self.get_optimizer(context, id)

    def update_optimizer_status(self, context, id, status, not_in=None):
        """Conditionally update optimizer status.

        Status transition is performed only if optimizer is not in the specified
        states as defined by 'not_in' list.
        """
        # filter in_ wants iterable objects, None isn't.
        not_in = not_in or []
        with context.session.begin(subtransactions=True):
            return (context.session.query(Optimizer).
                    filter(Optimizer.id == id).
                    filter(~Optimizer.status.in_(not_in)).
                    update({'status': status}, synchronize_session=False))

    def delete_optimizer(self, context, id):
        LOG.debug("delete_optimizer() called")
        with context.session.begin(subtransactions=True):
            # Note: Plugin should ensure that it's okay to delete if the
            # optimizer is active
            count = context.session.query(Optimizer).filter_by(id=id).delete()
            if not count:
                raise opt_ext.OptimizerNotFound(optimizer_id=id)

    def get_optimizer(self, context, id, fields=None):
        LOG.debug("get_optimizer() called")
        opt = self._get_optimizer(context, id)
        return self._make_optimizer_dict(opt, fields)

    def get_optimizers(self, context, filters=None, fields=None):
        LOG.debug("get_optimizers() called")
        return self._get_collection(context, Optimizer,
                                    self._make_optimizer_dict,
                                    filters=filters, fields=fields)

    def get_optimizers_count(self, context, filters=None):
        LOG.debug("get_optimizers_count() called")
        return self._get_collection_count(context, Optimizer,
                                          filters=filters)

    def create_optimizer_policy(self, context, optimizer_policy):
        LOG.debug("create_optimizer_policy() called")
        optp = optimizer_policy['optimizer_policy']
        tenant_id = self._get_tenant_id_for_create(context, optp)
        with context.session.begin(subtransactions=True):
            optp_db = OptimizerPolicy(id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    name=optp['name'],
                                    description=optp['description'],
                                    shared=optp['shared'])
            context.session.add(optp_db)
            self._set_rules_for_policy(context, optp_db, optp)
            optp_db.audited = optp['audited']
        return self._make_optimizer_policy_dict(optp_db)

    def update_optimizer_policy(self, context, id, optimizer_policy):
        LOG.debug("update_optimizer_policy() called")
        optp = optimizer_policy['optimizer_policy']
        with context.session.begin(subtransactions=True):
            optp_db = self._get_optimizer_policy(context, id)
            # check tenant ids are same for opt and optp or not
            if not optp.get('shared', True) and optp_db.optimizers:
                for opt in optp_db['optimizers']:
                    if optp_db['tenant_id'] != opt['tenant_id']:
                        raise opt_ext.OptimizerPolicyInUse(
                            optimizer_policy_id=id)
            # check any existing rules are not shared
            if 'shared' in optp and 'optimizer_rules' not in optp:
                self._check_unshared_rules_for_policy(optp_db, optp)
            elif 'optimizer_rules' in optp:
                self._set_rules_for_policy(context, optp_db, optp)
                del optp['optimizer_rules']
            if 'audited' not in optp:
                optp['audited'] = False
            optp_db.update(optp)
        return self._make_optimizer_policy_dict(optp_db)

    def delete_optimizer_policy(self, context, id):
        LOG.debug("delete_optimizer_policy() called")
        with context.session.begin(subtransactions=True):
            optp = self._get_optimizer_policy(context, id)
            # Ensure that the optimizer_policy  is not
            # being used
            qry = context.session.query(Optimizer)
            if qry.filter_by(optimizer_policy_id=id).first():
                raise opt_ext.OptimizerPolicyInUse(optimizer_policy_id=id)
            else:
                context.session.delete(optp)

    def get_optimizer_policy(self, context, id, fields=None):
        LOG.debug("get_optimizer_policy() called")
        optp = self._get_optimizer_policy(context, id)
        return self._make_optimizer_policy_dict(optp, fields)

    def get_optimizer_policies(self, context, filters=None, fields=None):
        LOG.debug("get_optimizer_policies() called")
        return self._get_collection(context, OptimizerPolicy,
                                    self._make_optimizer_policy_dict,
                                    filters=filters, fields=fields)

    def get_optimizers_policies_count(self, context, filters=None):
        LOG.debug("get_optimizer_policies_count() called")
        return self._get_collection_count(context, OptimizerPolicy,
                                          filters=filters)

    def create_optimizer_rule(self, context, optimizer_rule):
        LOG.debug("create_optimizer_rule() called")
        optr = optimizer_rule['optimizer_rule']
        self._validate_optr_protocol_parameters(optr)
        tenant_id = self._get_tenant_id_for_create(context, optr)
        if not optr['protocol'] and (optr['source_port'] or
           optr['destination_port']):
            raise opt_ext.OptimizerRuleWithPortWithoutProtocolInvalid()
        src_port_min, src_port_max = self._get_min_max_ports_from_range(
            optr['source_port'])
        dst_port_min, dst_port_max = self._get_min_max_ports_from_range(
            optr['destination_port'])
        with context.session.begin(subtransactions=True):
            optr_db = OptimizerRule(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=optr['name'],
                description=optr['description'],
                shared=optr['shared'],
                protocol=optr['protocol'],
                ip_version=optr['ip_version'],
                source_ip_address=optr['source_ip_address'],
                destination_ip_address=optr['destination_ip_address'],
                source_port_range_min=src_port_min,
                source_port_range_max=src_port_max,
                destination_port_range_min=dst_port_min,
                destination_port_range_max=dst_port_max,
                action=optr['action'],
                enabled=optr['enabled'])
            context.session.add(optr_db)
        return self._make_optimizer_rule_dict(optr_db)

    def update_optimizer_rule(self, context, id, optimizer_rule):
        LOG.debug("update_optimizer_rule() called")
        optr = optimizer_rule['optimizer_rule']
        optr_db = self._get_optimizer_rule(context, id)
        if optr_db.optimizer_policy_id:
            optp_db = self._get_optimizer_policy(context,
                                               optr_db.optimizer_policy_id)
            if 'shared' in optr and not optr['shared']:
                if optr_db['tenant_id'] != optp_db['tenant_id']:
                    raise opt_ext.OptimizerRuleInUse(optimizer_rule_id=id)
        if 'source_port' in optr:
            src_port_min, src_port_max = self._get_min_max_ports_from_range(
                optr['source_port'])
            optr['source_port_range_min'] = src_port_min
            optr['source_port_range_max'] = src_port_max
            del optr['source_port']
        if 'destination_port' in optr:
            dst_port_min, dst_port_max = self._get_min_max_ports_from_range(
                optr['destination_port'])
            optr['destination_port_range_min'] = dst_port_min
            optr['destination_port_range_max'] = dst_port_max
            del optr['destination_port']
        with context.session.begin(subtransactions=True):
            protocol = optr.get('protocol', optr_db['protocol'])
            if not protocol:
                sport = optr.get('source_port_range_min',
                                optr_db['source_port_range_min'])
                dport = optr.get('destination_port_range_min',
                                optr_db['destination_port_range_min'])
                if sport or dport:
                    raise opt_ext.OptimizerRuleWithPortWithoutProtocolInvalid()
            optr_db.update(optr)
            if optr_db.optimizer_policy_id:
                optp_db.audited = False
        return self._make_optimizer_rule_dict(optr_db)

    def delete_optimizer_rule(self, context, id):
        LOG.debug("delete_optimizer_rule() called")
        with context.session.begin(subtransactions=True):
            optr = self._get_optimizer_rule(context, id)
            if optr.optimizer_policy_id:
                raise opt_ext.OptimizerRuleInUse(optimizer_rule_id=id)
            context.session.delete(optr)

    def get_optimizer_rule(self, context, id, fields=None):
        LOG.debug("get_optimizer_rule() called")
        optr = self._get_optimizer_rule(context, id)
        return self._make_optimizer_rule_dict(optr, fields)

    def get_optimizer_rules(self, context, filters=None, fields=None):
        LOG.debug("get_optimizer_rules() called")
        return self._get_collection(context, OptimizerRule,
                                    self._make_optimizer_rule_dict,
                                    filters=filters, fields=fields)

    def get_optimizers_rules_count(self, context, filters=None):
        LOG.debug("get_optimizer_rules_count() called")
        return self._get_collection_count(context, OptimizerRule,
                                          filters=filters)

    def _validate_insert_remove_rule_request(self, id, rule_info):
        if not rule_info or 'optimizer_rule_id' not in rule_info:
            raise opt_ext.OptimizerRuleInfoMissing()

    def insert_rule(self, context, id, rule_info):
        LOG.debug("insert_rule() called")
        self._validate_insert_remove_rule_request(id, rule_info)
        optimizer_rule_id = rule_info['optimizer_rule_id']
        insert_before = True
        ref_optimizer_rule_id = None
        if not optimizer_rule_id:
            raise opt_ext.OptimizerRuleNotFound(optimizer_rule_id=None)
        if 'insert_before' in rule_info:
            ref_optimizer_rule_id = rule_info['insert_before']
        if not ref_optimizer_rule_id and 'insert_after' in rule_info:
            # If insert_before is set, we will ignore insert_after.
            ref_optimizer_rule_id = rule_info['insert_after']
            insert_before = False
        with context.session.begin(subtransactions=True):
            optr_db = self._get_optimizer_rule(context, optimizer_rule_id)
            optp_db = self._get_optimizer_policy(context, id)
            if optr_db.optimizer_policy_id:
                raise opt_ext.OptimizerRuleInUse(optimizer_rule_id=optr_db['id'])
            self._check_optimizer_rule_conflict(optr_db, optp_db)
            if ref_optimizer_rule_id:
                # If reference_optimizer_rule_id is set, the new rule
                # is inserted depending on the value of insert_before.
                # If insert_before is set, the new rule is inserted before
                # reference_optimizer_rule_id, and if it is not set the new
                # rule is inserted after reference_optimizer_rule_id.
                ref_optr_db = self._get_optimizer_rule(
                    context, ref_optimizer_rule_id)
                if ref_optr_db.optimizer_policy_id != id:
                    raise opt_ext.OptimizerRuleNotAssociatedWithPolicy(
                        optimizer_rule_id=ref_optr_db['id'],
                        optimizer_policy_id=id)
                if insert_before:
                    position = ref_optr_db.position
                else:
                    position = ref_optr_db.position + 1
            else:
                # If reference_optimizer_rule_id is not set, it is assumed
                # that the new rule needs to be inserted at the top.
                # insert_before field is ignored.
                # So default insertion is always at the top.
                # Also note that position numbering starts at 1.
                position = 1
            return self._process_rule_for_policy(context, id, optr_db,
                                                 position)

    def remove_rule(self, context, id, rule_info):
        LOG.debug("remove_rule() called")
        self._validate_insert_remove_rule_request(id, rule_info)
        optimizer_rule_id = rule_info['optimizer_rule_id']
        if not optimizer_rule_id:
            raise opt_ext.OptimizerRuleNotFound(optimizer_rule_id=None)
        with context.session.begin(subtransactions=True):
            optr_db = self._get_optimizer_rule(context, optimizer_rule_id)
            if optr_db.optimizer_policy_id != id:
                raise opt_ext.OptimizerRuleNotAssociatedWithPolicy(
                    optimizer_rule_id=optr_db['id'],
                    optimizer_policy_id=id)
            return self._process_rule_for_policy(context, id, optr_db, None)


def migration_callback(resource, event, trigger, **kwargs):
    context = kwargs['context']
    router = kwargs['router']
    opt_plugin = manager.NeutronManager.get_service_plugins().get(
        p_const.OPTIMIZER)
    if opt_plugin:
        tenant_optimizers = opt_plugin.get_optimizers(
            context, filters={'tenant_id': [router['tenant_id']]})
        if tenant_optimizers:
            raise l3.RouterInUse(router_id=router['id'])


def subscribe():
    registry.subscribe(
        migration_callback, resources.ROUTER, events.BEFORE_UPDATE)

# NOTE(armax): multiple FW service plugins (potentially out of tree) may
# inherit from optimizer_db and may need the callbacks to be processed. Having
# an implicit subscription (through the module import) preserves the existing
# behavior, and at the same time it avoids fixing it manually in each and
# every opt plugin out there. That said, The subscription is also made
# explicitly in the reference opt plugin. The subscription operation is
# idempotent so there is no harm in registering the same callback multiple
# times.
subscribe()
