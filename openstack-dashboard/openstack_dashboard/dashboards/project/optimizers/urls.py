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

from django.conf.urls import patterns
from django.conf.urls import url

from openstack_dashboard.dashboards.project.optimizers import views

urlpatterns = patterns(
    'openstack_dashboard.dashboards.project.optimizers.views',
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^addrule$', views.AddRuleView.as_view(), name='addrule'),
    url(r'^addpolicy$', views.AddPolicyView.as_view(), name='addpolicy'),
    url(r'^addoptimizer/(?P<policy_id>[^/]+)/$',
        views.AddOptimizerView.as_view(), name='addoptimizer'),
    url(r'^addoptimizer$', views.AddOptimizerView.as_view(), name='addoptimizer'),
    url(r'^insertrule/(?P<policy_id>[^/]+)/$',
        views.InsertRuleToPolicyView.as_view(), name='insertrule'),
    url(r'^removerule/(?P<policy_id>[^/]+)/$',
        views.RemoveRuleFromPolicyView.as_view(), name='removerule'),
    url(r'^updaterule/(?P<rule_id>[^/]+)/$',
        views.UpdateRuleView.as_view(), name='updaterule'),
    url(r'^updatepolicy/(?P<policy_id>[^/]+)/$',
        views.UpdatePolicyView.as_view(), name='updatepolicy'),
    url(r'^updateoptimizer/(?P<optimizer_id>[^/]+)/$',
        views.UpdateOptimizerView.as_view(), name='updateoptimizer'),
    url(r'^rule/(?P<rule_id>[^/]+)/$',
        views.RuleDetailsView.as_view(), name='ruledetails'),
    url(r'^policy/(?P<policy_id>[^/]+)/$',
        views.PolicyDetailsView.as_view(), name='policydetails'),
    url(r'^addrouter/(?P<optimizer_id>[^/]+)/$',
        views.AddRouterToOptimizerView.as_view(), name='addrouter'),
    url(r'^removerouter/(?P<optimizer_id>[^/]+)/$',
        views.RemoveRouterFromOptimizerView.as_view(), name='removerouter'),
    url(r'^optimizer/(?P<optimizer_id>[^/]+)/$',
        views.OptimizerDetailsView.as_view(), name='optimizerdetails'))
