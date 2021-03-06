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

import logging

from django.core.urlresolvers import reverse
from django.template import defaultfilters as filters
from django.utils.translation import pgettext_lazy
from django.utils.translation import ugettext_lazy as _
from django.utils.translation import ungettext_lazy

from horizon import exceptions
from horizon import tables
from openstack_dashboard import api
from openstack_dashboard import policy

LOG = logging.getLogger(__name__)


class AddRuleLink(tables.LinkAction):
    name = "addrule"
    verbose_name = _("Add Rule")
    url = "horizon:project:optimizers:addrule"
    classes = ("ajax-modal",)
    icon = "plus"
    policy_rules = (("network", "create_optimizer_rule"),)


class AddPolicyLink(tables.LinkAction):
    name = "addpolicy"
    verbose_name = _("Add Policy")
    url = "horizon:project:optimizers:addpolicy"
    classes = ("ajax-modal", "btn-addpolicy",)
    icon = "plus"
    policy_rules = (("network", "create_optimizer_policy"),)


class AddOptimizerLink(tables.LinkAction):
    name = "addoptimizer"
#OaaS
    verbose_name = _("Create Optimizer")
    url = "horizon:project:optimizers:addoptimizer"
    classes = ("ajax-modal",)
    icon = "plus"
    policy_rules = (("network", "create_optimizer"),)


class DeleteRuleLink(policy.PolicyTargetMixin, tables.DeleteAction):
    name = "deleterule"
    policy_rules = (("network", "delete_optimizer_rule"),)

    @staticmethod
    def action_present(count):
        return ungettext_lazy(
            u"Delete Rule",
            u"Delete Rules",
            count
        )

    @staticmethod
    def action_past(count):
        return ungettext_lazy(
            u"Scheduled deletion of Rule",
            u"Scheduled deletion of Rules",
            count
        )

    def allowed(self, request, datum=None):
        if datum and datum.policy:
            return False
        return True

    def delete(self, request, obj_id):
        try:
            api.oaas.rule_delete(request, obj_id)
        except Exception as e:
            exceptions.handle(request, _('Unable to delete rule. %s') % e)


class DeletePolicyLink(policy.PolicyTargetMixin, tables.DeleteAction):
    name = "deletepolicy"
    policy_rules = (("network", "delete_optimizer_policy"),)

    @staticmethod
    def action_present(count):
        return ungettext_lazy(
            u"Delete Policy",
            u"Delete Policies",
            count
        )

    @staticmethod
    def action_past(count):
        return ungettext_lazy(
            u"Scheduled deletion of Policy",
            u"Scheduled deletion of Policies",
            count
        )

    def delete(self, request, obj_id):
        try:
            api.oaas.policy_delete(request, obj_id)
        except Exception as e:
            exceptions.handle(request, _('Unable to delete policy. %s') % e)


class DeleteOptimizerLink(policy.PolicyTargetMixin,
                         tables.DeleteAction):
    name = "deleteoptimizer"
    policy_rules = (("network", "delete_optimizer"),)

    @staticmethod
    def action_present(count):
        return ungettext_lazy(
#OaaS
            u"Delete Optimizer",
            u"Delete Optimizers",
            count
        )

    @staticmethod
    def action_past(count):
        return ungettext_lazy(
            u"Scheduled deletion of Optimizer",
            u"Scheduled deletion of Optimizers",
            count
        )

    def delete(self, request, obj_id):
        try:
            api.oaas.optimizer_delete(request, obj_id)
        except Exception as e:
            exceptions.handle(request, _('Unable to delete optimizer. %s') % e)


class UpdateRuleLink(policy.PolicyTargetMixin, tables.LinkAction):
    name = "updaterule"
    verbose_name = _("Edit Rule")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("network", "update_optimizer_rule"),)

    def get_link_url(self, rule):
        base_url = reverse("horizon:project:optimizers:updaterule",
                           kwargs={'rule_id': rule.id})
        return base_url


class UpdatePolicyLink(policy.PolicyTargetMixin, tables.LinkAction):
    name = "updatepolicy"
    verbose_name = _("Edit Policy")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("network", "update_optimizer_policy"),)

    def get_link_url(self, policy):
        base_url = reverse("horizon:project:optimizers:updatepolicy",
                           kwargs={'policy_id': policy.id})
        return base_url


class UpdateOptimizerLink(policy.PolicyTargetMixin, tables.LinkAction):
    name = "updateoptimizer"
#OaaS
    verbose_name = _("Edit Optimizer")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("network", "update_optimizer"),)

    def get_link_url(self, optimizer):
        base_url = reverse("horizon:project:optimizers:updateoptimizer",
                           kwargs={'optimizer_id': optimizer.id})
        return base_url

    def allowed(self, request, optimizer):
        if optimizer.status in ("PENDING_CREATE",
                               "PENDING_UPDATE",
                               "PENDING_DELETE"):
            return False
        return True


class InsertRuleToPolicyLink(policy.PolicyTargetMixin,
                             tables.LinkAction):
    name = "insertrule"
    verbose_name = _("Insert Rule")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("network", "get_optimizer_policy"),
                    ("network", "insert_rule"),)

    def get_link_url(self, policy):
        base_url = reverse("horizon:project:optimizers:insertrule",
                           kwargs={'policy_id': policy.id})
        return base_url


class RemoveRuleFromPolicyLink(policy.PolicyTargetMixin,
                               tables.LinkAction):
    name = "removerule"
    verbose_name = _("Remove Rule")
    classes = ("ajax-modal", "btn-danger",)
    policy_rules = (("network", "get_optimizer_policy"),
                    ("network", "remove_rule"),)

    def get_link_url(self, policy):
        base_url = reverse("horizon:project:optimizers:removerule",
                           kwargs={'policy_id': policy.id})
        return base_url

    def allowed(self, request, policy):
        if len(policy.rules) > 0:
            return True
        return False


class AddRouterToOptimizerLink(policy.PolicyTargetMixin,
                              tables.LinkAction):
    name = "addrouter"
    verbose_name = _("Add Router")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("network", "get_optimizer"),
                    ("network", "add_router"),)

    def get_link_url(self, optimizer):
        base_url = reverse("horizon:project:optimizers:addrouter",
                           kwargs={'optimizer_id': optimizer.id})
        return base_url

    def allowed(self, request, optimizer):
        if not api.neutron.is_extension_supported(request,
                                                  'oaasrouterinsertion'):
            return False
        tenant_id = optimizer['tenant_id']
        available_routers = api.oaas.optimizer_unassociated_routers_list(
            request, tenant_id)
        return bool(available_routers)


class RemoveRouterFromOptimizerLink(policy.PolicyTargetMixin,
                                   tables.LinkAction):
    name = "removerouter"
    verbose_name = _("Remove Router")
    classes = ("ajax-modal", "btn-update",)
    policy_rules = (("network", "get_optimizer"),
                    ("network", "remove_router"),)

    def get_link_url(self, optimizer):
        base_url = reverse("horizon:project:optimizers:removerouter",
                           kwargs={'optimizer_id': optimizer.id})
        return base_url

    def allowed(self, request, optimizer):
        if not api.neutron.is_extension_supported(request,
                                                  'oaasrouterinsertion'):
            return False
        return bool(optimizer['router_ids'])


def get_rules_name(datum):
    return ', '.join([rule.name or rule.id[:13]
                      for rule in datum.rules])


def get_routers_name(optimizer):
    if optimizer.routers:
        return ', '.join(router.name_or_id for router in optimizer.routers)


def get_policy_name(datum):
    if datum.policy:
        return datum.policy.name or datum.policy.id


def get_policy_link(datum):
    if datum.policy:
        return reverse('horizon:project:optimizers:policydetails',
                       kwargs={'policy_id': datum.policy.id})


class RulesTable(tables.DataTable):
#OaaS
    ACTION_DISPLAY_CHOICES = (
        ("Allow", pgettext_lazy("Action Name of a Optimizer Rule", u"ALLOW")),
        ("Deny", pgettext_lazy("Action Name of a Optimizer Rule", u"DENY")),
        ("Reject", pgettext_lazy("Action Name of a Optimizer Rule", u"REJECT")),
        ("Optimize", pgettext_lazy("Action Name of a Optimizer Rule", u"OPTIMIZE")),
    )
    name = tables.Column("name_or_id",
                         verbose_name=_("Name"),
                         link="horizon:project:optimizers:ruledetails")
    description = tables.Column('description', verbose_name=_('Description'))
    protocol = tables.Column("protocol",
                             filters=(lambda v: filters.default(v, _("ANY")),
                                      filters.upper,),
                             verbose_name=_("Protocol"))
    source_ip_address = tables.Column("source_ip_address",
                                      verbose_name=_("Source IP"))
    source_port = tables.Column("source_port",
                                verbose_name=_("Source Port"))
    destination_ip_address = tables.Column("destination_ip_address",
                                           verbose_name=_("Destination IP"))
    destination_port = tables.Column("destination_port",
                                     verbose_name=_("Destination Port"))
    action = tables.Column("action",
                           display_choices=ACTION_DISPLAY_CHOICES,
                           verbose_name=_("Action"))
    shared = tables.Column("shared",
                           verbose_name=_("Shared"),
                           filters=(filters.yesno, filters.capfirst))
    enabled = tables.Column("enabled",
                            verbose_name=_("Enabled"),
                            filters=(filters.yesno, filters.capfirst))
    optimizer_policy_id = tables.Column(get_policy_name,
                                       link=get_policy_link,
                                       verbose_name=_("In Policy"))

    class Meta(object):
        name = "rulestable"
        verbose_name = _("Rules")
        table_actions = (AddRuleLink, DeleteRuleLink)
        row_actions = (UpdateRuleLink, DeleteRuleLink)


class PoliciesTable(tables.DataTable):
    name = tables.Column("name_or_id",
                         verbose_name=_("Name"),
                         link="horizon:project:optimizers:policydetails")
    description = tables.Column('description', verbose_name=_('Description'))
    optimizer_rules = tables.Column(get_rules_name,
                                   verbose_name=_("Rules"))
    shared = tables.Column("shared",
                           verbose_name=_("Shared"),
                           filters=(filters.yesno, filters.capfirst))
    audited = tables.Column("audited",
                            verbose_name=_("Audited"),
                            filters=(filters.yesno, filters.capfirst))

    class Meta(object):
        name = "policiestable"
        verbose_name = _("Policies")
        table_actions = (AddPolicyLink, DeletePolicyLink)
        row_actions = (UpdatePolicyLink, InsertRuleToPolicyLink,
                       RemoveRuleFromPolicyLink, DeletePolicyLink)


class OptimizersTable(tables.DataTable):
    STATUS_DISPLAY_CHOICES = (
        ("Active", pgettext_lazy("Current status of a Optimizer",
                                 u"Active")),
        ("Down", pgettext_lazy("Current status of a Optimizer",
                               u"Down")),
        ("Error", pgettext_lazy("Current status of a Optimizer",
                                u"Error")),
        ("Created", pgettext_lazy("Current status of a Optimizer",
                                  u"Created")),
        ("Pending_Create", pgettext_lazy("Current status of a Optimizer",
                                         u"Pending Create")),
        ("Pending_Update", pgettext_lazy("Current status of a Optimizer",
                                         u"Pending Update")),
        ("Pending_Delete", pgettext_lazy("Current status of a Optimizer",
                                         u"Pending Delete")),
        ("Inactive", pgettext_lazy("Current status of a Optimizer",
                                   u"Inactive")),
    )
    ADMIN_STATE_DISPLAY_CHOICES = (
        ("UP", pgettext_lazy("Admin state of a Optimizer", u"UP")),
        ("DOWN", pgettext_lazy("Admin state of a Optimizer", u"DOWN")),
    )

    name = tables.Column("name_or_id",
                         verbose_name=_("Name"),
                         link="horizon:project:optimizers:optimizerdetails")
    description = tables.Column('description', verbose_name=_('Description'))
    optimizer_policy_id = tables.Column(get_policy_name,
                                       link=get_policy_link,
                                       verbose_name=_("Policy"))
    router_ids = tables.Column(get_routers_name,
                               verbose_name=_("Associated Routers"))
#OaaS
    solowan = tables.Column('solowan', verbose_name=_('SoloWan'))
    local_id = tables.Column('local_id', verbose_name=_('Optimizer_id'))
    action = tables.Column('action', verbose_name=_('Action'))
    num_pkt_cache_size = tables.Column('num_pkt_cache_size', verbose_name=_('Number packets cache size'))



    status = tables.Column("status",
                           verbose_name=_("Status"),
                           display_choices=STATUS_DISPLAY_CHOICES)
    admin_state = tables.Column("admin_state",
                                verbose_name=_("Admin State"),
                                display_choices=ADMIN_STATE_DISPLAY_CHOICES)

    class Meta(object):
        name = "optimizerstable"
        verbose_name = _("Optimizers")
        table_actions = (AddOptimizerLink, DeleteOptimizerLink)
        row_actions = (UpdateOptimizerLink, DeleteOptimizerLink,
                       AddRouterToOptimizerLink, RemoveRouterFromOptimizerLink)

    def __init__(self, request, data=None, needs_form_wrapper=None, **kwargs):
        super(OptimizersTable, self).__init__(
            request, data=data,
            needs_form_wrapper=needs_form_wrapper, **kwargs)
        try:
            if not api.neutron.is_extension_supported(request,
                                                      'oaasrouterinsertion'):
                del self.columns['router_ids']
        except Exception as e:
            msg = _('Failed to verify extension support %(reason)s') % {
                'reason': e}
            LOG.error(msg)
            exceptions.handle(request, msg)
