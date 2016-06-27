#    Copyright 2013, Big Switch Networks, Inc.
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

from __future__ import absolute_import

from collections import OrderedDict

from horizon.utils import memoized

from openstack_dashboard.api import neutron

neutronclient = neutron.neutronclient


class Rule(neutron.NeutronAPIDictWrapper):
    """Wrapper for neutron optimizer rule."""

    def get_dict(self):
        rule_dict = self._apidict
        rule_dict['rule_id'] = rule_dict['id']
        return rule_dict


class Policy(neutron.NeutronAPIDictWrapper):
    """Wrapper for neutron optimizer policy."""

    def get_dict(self):
        policy_dict = self._apidict
        policy_dict['policy_id'] = policy_dict['id']
        return policy_dict


class Optimizer(neutron.NeutronAPIDictWrapper):
    """Wrapper for neutron optimizer."""

    def __init__(self, apiresource):
        apiresource['admin_state'] = \
            'UP' if apiresource['admin_state_up'] else 'DOWN'
        super(Optimizer, self).__init__(apiresource)

    def get_dict(self):
        optimizer_dict = self._apidict
        optimizer_dict['optimizer_id'] = optimizer_dict['id']
        return optimizer_dict


def rule_create(request, **kwargs):
    """Create a optimizer rule

    :param request: request context
    :param name: name for rule
    :param description: description for rule
    :param protocol: protocol for rule
    :param action: action for rule
    :param source_ip_address: source IP address or subnet
    :param source_port: integer in [1, 65535] or range in a:b
    :param destination_ip_address: destination IP address or subnet
    :param destination_port: integer in [1, 65535] or range in a:b
    :param shared: boolean (default false)
    :param enabled: boolean (default true)
    :return: Rule object
    """
    body = {'optimizer_rule': kwargs}
    rule = neutronclient(request).create_optimizer_rule(
        body).get('optimizer_rule')
    return Rule(rule)


def rule_list(request, **kwargs):
    return _rule_list(request, expand_policy=True, **kwargs)


def rule_list_for_tenant(request, tenant_id, **kwargs):
    """Return a rule list available for the tenant.

    The list contains rules owned by the tenant and shared rules.
    This is required because Neutron returns all resources including
    all tenants if a user has admin role.
    """
    rules = rule_list(request, tenant_id=tenant_id, shared=False, **kwargs)
    shared_rules = rule_list(request, shared=True, **kwargs)
    return rules + shared_rules


def _rule_list(request, expand_policy, **kwargs):
    rules = neutronclient(request).list_optimizer_rules(
        **kwargs).get('optimizer_rules')
    if expand_policy and rules:
        policies = _policy_list(request, expand_rule=False)
        policy_dict = OrderedDict((p.id, p) for p in policies)
        for rule in rules:
            rule['policy'] = policy_dict.get(rule['optimizer_policy_id'])
    return [Rule(r) for r in rules]


def rule_get(request, rule_id):
    return _rule_get(request, rule_id, expand_policy=True)


def _rule_get(request, rule_id, expand_policy):
    rule = neutronclient(request).show_optimizer_rule(
        rule_id).get('optimizer_rule')
    if expand_policy:
        if rule['optimizer_policy_id']:
            rule['policy'] = _policy_get(request, rule['optimizer_policy_id'],
                                         expand_rule=False)
        else:
            rule['policy'] = None
    return Rule(rule)


def rule_delete(request, rule_id):
    neutronclient(request).delete_optimizer_rule(rule_id)


def rule_update(request, rule_id, **kwargs):
    body = {'optimizer_rule': kwargs}
    rule = neutronclient(request).update_optimizer_rule(
        rule_id, body).get('optimizer_rule')
    return Rule(rule)


def policy_create(request, **kwargs):
    """Create a optimizer policy

    :param request: request context
    :param name: name for policy
    :param description: description for policy
    :param optimizer_rules: ordered list of rules in policy
    :param shared: boolean (default false)
    :param audited: boolean (default false)
    :return: Policy object
    """
    body = {'optimizer_policy': kwargs}
    policy = neutronclient(request).create_optimizer_policy(
        body).get('optimizer_policy')
    return Policy(policy)


def policy_list(request, **kwargs):
    return _policy_list(request, expand_rule=True, **kwargs)


def policy_list_for_tenant(request, tenant_id, **kwargs):
    """Return a policy list available for the tenant.

    The list contains policies owned by the tenant and shared policies.
    This is required because Neutron returns all resources including
    all tenants if a user has admin role.
    """
    policies = policy_list(request, tenant_id=tenant_id,
                           shared=False, **kwargs)
    shared_policies = policy_list(request, shared=True, **kwargs)
    return policies + shared_policies


def _policy_list(request, expand_rule, **kwargs):
    policies = neutronclient(request).list_optimizer_policies(
        **kwargs).get('optimizer_policies')
    if expand_rule and policies:
        rules = _rule_list(request, expand_policy=False)
        rule_dict = OrderedDict((rule.id, rule) for rule in rules)
        for p in policies:
            p['rules'] = [rule_dict.get(rule) for rule in p['optimizer_rules']]
    return [Policy(p) for p in policies]


def policy_get(request, policy_id):
    return _policy_get(request, policy_id, expand_rule=True)


def _policy_get(request, policy_id, expand_rule):
    policy = neutronclient(request).show_optimizer_policy(
        policy_id).get('optimizer_policy')
    if expand_rule:
        policy_rules = policy['optimizer_rules']
        if policy_rules:
            rules = _rule_list(request, expand_policy=False,
                               optimizer_policy_id=policy_id)
            rule_dict = OrderedDict((rule.id, rule) for rule in rules)
            policy['rules'] = [rule_dict.get(rule) for rule in policy_rules]
        else:
            policy['rules'] = []
    return Policy(policy)


def policy_delete(request, policy_id):
    neutronclient(request).delete_optimizer_policy(policy_id)


def policy_update(request, policy_id, **kwargs):
    body = {'optimizer_policy': kwargs}
    policy = neutronclient(request).update_optimizer_policy(
        policy_id, body).get('optimizer_policy')
    return Policy(policy)


def policy_insert_rule(request, policy_id, **kwargs):
    policy = neutronclient(request).optimizer_policy_insert_rule(
        policy_id, kwargs)
    return Policy(policy)


def policy_remove_rule(request, policy_id, **kwargs):
    policy = neutronclient(request).optimizer_policy_remove_rule(
        policy_id, kwargs)
    return Policy(policy)


def optimizer_create(request, **kwargs):
    """Create a optimizer for specified policy

    :param request: request context
    :param name: name for optimizer
    :param description: description for optimizer
    :param optimizer_policy_id: policy id used by optimizer
    :param shared: boolean (default false)
    :param admin_state_up: boolean (default true)
    :return: Optimizer object
    """
    body = {'optimizer': kwargs}
    optimizer = neutronclient(request).create_optimizer(body).get('optimizer')
    return Optimizer(optimizer)


def optimizer_list(request, **kwargs):
    return _optimizer_list(request, expand_policy=True, **kwargs)


def optimizer_list_for_tenant(request, tenant_id, **kwargs):
    """Return a optimizer list available for the tenant.

    The list contains optimizers owned by the tenant and shared optimizers.
    This is required because Neutron returns all resources including
    all tenants if a user has admin role.
    """
    # NOTE(amotoki): At now 'shared' attribute is not visible in Neutron
    # and there is no way to query shared optimizers explicitly.
    # Thus this method returns the same as when tenant_id is specified,
    # but I would like to have this method for symmetry to optimizer
    # rules and policies to avoid unnecessary confusion.
    return optimizer_list(request, tenant_id=tenant_id, **kwargs)


def _optimizer_list(request, expand_policy, **kwargs):
    optimizers = neutronclient(request).list_optimizers(
        **kwargs).get('optimizers')
    if expand_policy and optimizers:
        policies = _policy_list(request, expand_rule=False)
        policy_dict = OrderedDict((p.id, p) for p in policies)
        for opt in optimizers:
            opt['policy'] = policy_dict.get(opt['optimizer_policy_id'])
    return [Optimizer(f) for f in optimizers]


def optimizer_get(request, optimizer_id):
    return _optimizer_get(request, optimizer_id, expand_policy=True)


def _optimizer_get(request, optimizer_id, expand_policy):
    optimizer = neutronclient(request).show_optimizer(
        optimizer_id).get('optimizer')
    if expand_policy:
        policy_id = optimizer['optimizer_policy_id']
        if policy_id:
            optimizer['policy'] = _policy_get(request, policy_id,
                                             expand_rule=False)
        else:
            optimizer['policy'] = None
    return Optimizer(optimizer)


def optimizer_delete(request, optimizer_id):
    neutronclient(request).delete_optimizer(optimizer_id)


def optimizer_update(request, optimizer_id, **kwargs):
    body = {'optimizer': kwargs}
    optimizer = neutronclient(request).update_optimizer(
        optimizer_id, body).get('optimizer')
    return Optimizer(optimizer)


@memoized.memoized
def optimizer_unassociated_routers_list(request, tenant_id):
    all_routers = neutron.router_list(request, tenant_id=tenant_id)
    tenant_optimizers = optimizer_list_for_tenant(request, tenant_id=tenant_id)
    optimizer_router_ids = [rid
                           for opt in tenant_optimizers
                           for rid in getattr(opt, 'router_ids', [])]

    available_routers = [r for r in all_routers
                         if r.id not in optimizer_router_ids]
    available_routers = sorted(available_routers,
                               key=lambda router: router.name_or_id)
    return available_routers
