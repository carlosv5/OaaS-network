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

from django.core.urlresolvers import reverse_lazy
from django.utils.translation import ugettext_lazy as _

from horizon import exceptions
from horizon import tabs

from openstack_dashboard import api
from openstack_dashboard.dashboards.project.optimizers import tables

OptimizersTable = tables.OptimizersTable
PoliciesTable = tables.PoliciesTable
RulesTable = tables.RulesTable


class RulesTab(tabs.TableTab):
    table_classes = (RulesTable,)
#OaaS
    name = _("Optimizer Rules")
    slug = "rules"
    template_name = "horizon/common/_detail_table.html"

    def get_rulestable_data(self):
        try:
            tenant_id = self.request.user.tenant_id
            request = self.tab_group.request
            rules = api.oaas.rule_list_for_tenant(request, tenant_id)
        except Exception:
            rules = []
            exceptions.handle(self.tab_group.request,
                              _('Unable to retrieve rules list.'))

        return rules


class PoliciesTab(tabs.TableTab):
    table_classes = (PoliciesTable,)
#OaaS
    name = _("Optimizer Policies")
    slug = "policies"
    template_name = "horizon/common/_detail_table.html"

    def get_policiestable_data(self):
        try:
            tenant_id = self.request.user.tenant_id
            request = self.tab_group.request
            policies = api.oaas.policy_list_for_tenant(request, tenant_id)
        except Exception:
            policies = []
            exceptions.handle(self.tab_group.request,
                              _('Unable to retrieve policies list.'))

        return policies


class OptimizersTab(tabs.TableTab):
    table_classes = (OptimizersTable,)
#OaaS
    name = _("Optimizers")
    slug = "optimizers"
    template_name = "horizon/common/_detail_table.html"

    def get_optimizerstable_data(self):
        try:
            tenant_id = self.request.user.tenant_id
            request = self.tab_group.request
            optimizers = api.oaas.optimizer_list_for_tenant(request, tenant_id)

            if api.neutron.is_extension_supported(request,
                                                  'oaasrouterinsertion'):
                routers = api.neutron.router_list(request, tenant_id=tenant_id)

                for opt in optimizers:
                    router_list = [r for r in routers
                                   if r['id'] in opt['router_ids']]
                    opt.get_dict()['routers'] = router_list

        except Exception:
            optimizers = []
            exceptions.handle(self.tab_group.request,
                              _('Unable to retrieve optimizer list.'))

        return optimizers


class RuleDetailsTab(tabs.Tab):
#OaaS
    name = _("Optimizer Rule Details")
    slug = "ruledetails"
    template_name = "project/optimizers/_rule_details.html"
    failure_url = reverse_lazy('horizon:project:optimizers:index')

    def get_context_data(self, request):
        rid = self.tab_group.kwargs['rule_id']
        try:
            rule = api.oaas.rule_get(request, rid)
        except Exception:
            exceptions.handle(request,
                              _('Unable to retrieve rule details.'),
                              redirect=self.failure_url)
        return {'rule': rule}


class PolicyDetailsTab(tabs.Tab):
#OaaS
    name = _("Optimizer Policy Details")
    slug = "policydetails"
    template_name = "project/optimizers/_policy_details.html"
    failure_url = reverse_lazy('horizon:project:optimizers:index')

    def get_context_data(self, request):
        pid = self.tab_group.kwargs['policy_id']
        try:
            policy = api.oaas.policy_get(request, pid)
        except Exception:
            exceptions.handle(request,
                              _('Unable to retrieve policy details.'),
                              redirect=self.failure_url)
        return {'policy': policy}


class OptimizerDetailsTab(tabs.Tab):
#OaaS
    name = _("Optimizer Details")
    slug = "optimizerdetails"
    template_name = "project/optimizers/_optimizer_details.html"
    failure_url = reverse_lazy('horizon:project:optimizers:index')

    def get_context_data(self, request):
        fid = self.tab_group.kwargs['optimizer_id']
        try:
            optimizer = api.oaas.optimizer_get(request, fid)
            body = {'optimizer': optimizer}
            if api.neutron.is_extension_supported(request,
                                                  'oaasrouterinsertion'):
                tenant_id = self.request.user.tenant_id
                tenant_routers = api.neutron.router_list(request,
                                                         tenant_id=tenant_id)
                router_ids = optimizer.get_dict()['router_ids']
                routers = [r for r in tenant_routers
                           if r['id'] in router_ids]
                body['routers'] = routers
        except Exception:
            exceptions.handle(request,
                              _('Unable to retrieve optimizer details.'),
                              redirect=self.failure_url)
        return body


class OptimizerTabs(tabs.TabGroup):
    slug = "opttabs"
    tabs = (OptimizersTab, PoliciesTab, RulesTab)
    sticky = True


class RuleDetailsTabs(tabs.TabGroup):
    slug = "ruletabs"
    tabs = (RuleDetailsTab,)


class PolicyDetailsTabs(tabs.TabGroup):
    slug = "policytabs"
    tabs = (PolicyDetailsTab,)


class OptimizerDetailsTabs(tabs.TabGroup):
    slug = "optimizertabs"
    tabs = (OptimizerDetailsTab,)
