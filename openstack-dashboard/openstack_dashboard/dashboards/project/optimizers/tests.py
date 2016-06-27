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

from mox3.mox import IsA  # noqa

from django.core.urlresolvers import reverse
from django.core.urlresolvers import reverse_lazy
from django import http

from openstack_dashboard import api
from openstack_dashboard.api import oaas
from openstack_dashboard.test import helpers as test


class OptimizerTests(test.TestCase):
    class AttributeDict(dict):
        def __getattr__(self, attr):
            return self[attr]

        def __setattr__(self, attr, value):
            self[attr] = value

    DASHBOARD = 'project'
    INDEX_URL = reverse_lazy('horizon:%s:optimizers:index' % DASHBOARD)

    ADDRULE_PATH = 'horizon:%s:optimizers:addrule' % DASHBOARD
    ADDPOLICY_PATH = 'horizon:%s:optimizers:addpolicy' % DASHBOARD
    ADDOPTIMIZER_PATH = 'horizon:%s:optimizers:addoptimizer' % DASHBOARD

    RULE_DETAIL_PATH = 'horizon:%s:optimizers:ruledetails' % DASHBOARD
    POLICY_DETAIL_PATH = 'horizon:%s:optimizers:policydetails' % DASHBOARD
    OPTIMIZER_DETAIL_PATH = 'horizon:%s:optimizers:optimizerdetails' % DASHBOARD

    UPDATERULE_PATH = 'horizon:%s:optimizers:updaterule' % DASHBOARD
    UPDATEPOLICY_PATH = 'horizon:%s:optimizers:updatepolicy' % DASHBOARD
    UPDATEOPTIMIZER_PATH = 'horizon:%s:optimizers:updateoptimizer' % DASHBOARD

    INSERTRULE_PATH = 'horizon:%s:optimizers:insertrule' % DASHBOARD
    REMOVERULE_PATH = 'horizon:%s:optimizers:removerule' % DASHBOARD

    ADDROUTER_PATH = 'horizon:%s:optimizers:addrouter' % DASHBOARD
    REMOVEROUTER_PATH = 'horizon:%s:optimizers:removerouter' % DASHBOARD

    def set_up_expect(self, oaas_router_extension=True):
        # retrieve rules
        tenant_id = self.tenant.id

        api.neutron.is_extension_supported(
            IsA(http.HttpRequest), 'oaasrouterinsertion'
        ).MultipleTimes().AndReturn(oaas_router_extension)

        api.oaas.rule_list_for_tenant(
            IsA(http.HttpRequest),
            tenant_id).AndReturn(self.opt_rules.list())

        # retrieves policies
        policies = self.opt_policies.list()
        api.oaas.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)

        # retrieves optimizers
        optimizers = self.optimizers.list()
        api.oaas.optimizer_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(optimizers)

        routers = self.routers.list()
        api.neutron.router_list(
            IsA(http.HttpRequest), tenant_id=tenant_id).AndReturn(routers)
        api.oaas.optimizer_unassociated_routers_list(
            IsA(http.HttpRequest), tenant_id).\
            MultipleTimes().AndReturn(routers)

    def set_up_expect_with_exception(self):
        tenant_id = self.tenant.id

        api.neutron.is_extension_supported(
            IsA(http.HttpRequest), 'oaasrouterinsertion').AndReturn(True)

        api.oaas.rule_list_for_tenant(
            IsA(http.HttpRequest),
            tenant_id).AndRaise(self.exceptions.neutron)
        api.oaas.policy_list_for_tenant(
            IsA(http.HttpRequest),
            tenant_id).AndRaise(self.exceptions.neutron)
        api.oaas.optimizer_list_for_tenant(
            IsA(http.HttpRequest),
            tenant_id).AndRaise(self.exceptions.neutron)

    @test.create_stubs({api.oaas: ('optimizer_list_for_tenant',
                                    'policy_list_for_tenant',
                                    'rule_list_for_tenant',
                                    'optimizer_unassociated_routers_list',),
                        api.neutron: ('is_extension_supported',
                                      'router_list',), })
    def test_index_optimizers(self):
        self.set_up_expect()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL, tenant_id=tenant_id)

        self.assertTemplateUsed(res, '%s/optimizers/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['table'].data),
                         len(self.optimizers.list()))

    # TODO(absubram): Change test_index_optimizers for with and without
    #                 router extensions.

    @test.create_stubs({api.oaas: ('optimizer_list_for_tenant',
                                    'policy_list_for_tenant',
                                    'rule_list_for_tenant',
                                    'optimizer_unassociated_routers_list',),
                        api.neutron: ('is_extension_supported',
                                      'router_list',), })
    def test_index_policies(self):
        self.set_up_expect()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=opttabs__policies',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, '%s/optimizers/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['policiestable_table'].data),
                         len(self.opt_policies.list()))

    @test.create_stubs({api.oaas: ('optimizer_list_for_tenant',
                                    'policy_list_for_tenant',
                                    'rule_list_for_tenant',
                                    'optimizer_unassociated_routers_list',),
                        api.neutron: ('is_extension_supported',
                                      'router_list',), })
    def test_index_rules(self):
        self.set_up_expect()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=opttabs__rules',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res, '%s/optimizers/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res, 'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['rulestable_table'].data),
                         len(self.opt_rules.list()))

    @test.create_stubs({api.oaas: ('optimizer_list_for_tenant',
                                    'policy_list_for_tenant',
                                    'rule_list_for_tenant'),
                        api.neutron: ('is_extension_supported',), })
    def test_index_exception_optimizers(self):
        self.set_up_expect_with_exception()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL, tenant_id=tenant_id)

        self.assertTemplateUsed(res,
                                '%s/optimizers/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res,
                                'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['table'].data), 0)

    @test.create_stubs({api.oaas: ('optimizer_list_for_tenant',
                                    'policy_list_for_tenant',
                                    'rule_list_for_tenant'),
                        api.neutron: ('is_extension_supported',), })
    def test_index_exception_policies(self):
        self.set_up_expect_with_exception()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=opttabs__policies',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res,
                                '%s/optimizers/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res,
                                'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['policiestable_table'].data), 0)

    @test.create_stubs({api.oaas: ('optimizer_list_for_tenant',
                                    'policy_list_for_tenant',
                                    'rule_list_for_tenant'),
                        api.neutron: ('is_extension_supported',), })
    def test_index_exception_rules(self):
        self.set_up_expect_with_exception()

        self.mox.ReplayAll()

        tenant_id = self.tenant.id

        res = self.client.get(self.INDEX_URL + '?tab=opttabs__rules',
                              tenant_id=tenant_id)

        self.assertTemplateUsed(res,
                                '%s/optimizers/details_tabs.html'
                                % self.DASHBOARD)
        self.assertTemplateUsed(res,
                                'horizon/common/_detail_table.html')
        self.assertEqual(len(res.context['rulestable_table'].data), 0)

    @test.create_stubs({api.oaas: ('rule_create',), })
    def test_add_rule_post(self):
        rule1 = self.opt_rules.first()

        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': rule1.protocol,
                     'action': rule1.action,
                     'source_ip_address': rule1.source_ip_address,
                     'source_port': rule1.source_port,
                     'destination_ip_address': rule1.destination_ip_address,
                     'destination_port': rule1.destination_port,
                     'shared': rule1.shared,
                     'enabled': rule1.enabled
                     }

        api.oaas.rule_create(
            IsA(http.HttpRequest), **form_data).AndReturn(rule1)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    def test_add_rule_post_with_error(self):
        rule1 = self.opt_rules.first()

        form_data = {'name': rule1.name,
                     'description': rule1.description,
                     'protocol': 'abc',
                     'action': 'pass',
                     'source_ip_address': rule1.source_ip_address,
                     'source_port': rule1.source_port,
                     'destination_ip_address': rule1.destination_ip_address,
                     'destination_port': rule1.destination_port,
                     'shared': rule1.shared,
                     'enabled': rule1.enabled
                     }

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDRULE_PATH), form_data)

        self.assertFormErrors(res, 2)

    @test.create_stubs({api.oaas: ('policy_create',
                                    'rule_list_for_tenant'), })
    def test_add_policy_post(self):
        policy = self.opt_policies.first()
        rules = self.opt_rules.list()
        tenant_id = self.tenant.id
        form_data = {'name': policy.name,
                     'description': policy.description,
                     'optimizer_rules': policy.optimizer_rules,
                     'shared': policy.shared,
                     'audited': policy.audited
                     }
        post_data = {'name': policy.name,
                     'description': policy.description,
                     'rule': policy.optimizer_rules,
                     'shared': policy.shared,
                     'audited': policy.audited
                     }

        # NOTE: SelectRulesAction.populate_rule_choices() lists rule not
        # associated with any policy. We need to ensure that rules specified
        # in policy.optimizer_rules in post_data (above) are not associated
        # with any policy. Test data in neutron_data is data in a stable state,
        # so we need to modify here.
        for rule in rules:
            if rule.id in policy.optimizer_rules:
                rule.optimizer_policy_id = rule.policy = None
        api.oaas.rule_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(rules)
        api.oaas.policy_create(
            IsA(http.HttpRequest), **form_data).AndReturn(policy)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDPOLICY_PATH), post_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('policy_create',
                                    'rule_list_for_tenant'), })
    def test_add_policy_post_with_error(self):
        policy = self.opt_policies.first()
        rules = self.opt_rules.list()
        tenant_id = self.tenant.id
        form_data = {'description': policy.description,
                     'optimizer_rules': None,
                     'shared': policy.shared,
                     'audited': policy.audited
                     }
        api.oaas.rule_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(rules)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDPOLICY_PATH), form_data)

        self.assertFormErrors(res, 1)

    def _test_add_optimizer_post(self, router_extension=False):
        optimizer = self.optimizers.first()
        policies = self.opt_policies.list()
        tenant_id = self.tenant.id
        if router_extension:
            routers = self.routers.list()
            optimizers = self.optimizers.list()

        form_data = {'name': optimizer.name,
                     'description': optimizer.description,
                     'optimizer_policy_id': optimizer.optimizer_policy_id,
                     'admin_state_up': optimizer.admin_state_up
                     }
        if router_extension:
            form_data['router_ids'] = optimizer.router_ids
            api.neutron.router_list(
                IsA(http.HttpRequest), tenant_id=tenant_id).AndReturn(routers)
            api.oaas.optimizer_list_for_tenant(
                IsA(http.HttpRequest),
                tenant_id=tenant_id).AndReturn(optimizers)

        api.neutron.is_extension_supported(
            IsA(http.HttpRequest),
            'oaasrouterinsertion').AndReturn(router_extension)
        api.oaas.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)
        api.oaas.optimizer_create(
            IsA(http.HttpRequest), **form_data).AndReturn(optimizer)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDOPTIMIZER_PATH), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('optimizer_create',
                                    'policy_list_for_tenant',),
                        api.neutron: ('is_extension_supported',), })
    def test_add_optimizer_post(self):
        self._test_add_optimizer_post()

    # @test.create_stubs({api.oaas: ('optimizer_create',
    #                                'policy_list_for_tenant',
    #                                'optimizer_list_for_tenant',),
    #                    api.neutron: ('is_extension_supported',
    #                                  'router_list'), })
    # def test_add_optimizer_post_with_router_extension(self):
    #    self._test_add_optimizer_post(router_extension=True)
    # TODO(absubram): Fix test_add_optimizer_post_with_router_extension
    #                 It currently fails because views.py is not
    #                 initializing the AddRouter workflow?

    @test.create_stubs({api.oaas: ('optimizer_create',
                                    'policy_list_for_tenant',),
                        api.neutron: ('is_extension_supported',), })
    def test_add_optimizer_post_with_error(self):
        optimizer = self.optimizers.first()
        policies = self.opt_policies.list()
        tenant_id = self.tenant.id
        form_data = {'name': optimizer.name,
                     'description': optimizer.description,
                     'optimizer_policy_id': None,
                     'admin_state_up': optimizer.admin_state_up
                     }
        api.neutron.is_extension_supported(
            IsA(http.HttpRequest),
            'oaasrouterinsertion').AndReturn(False)
        api.oaas.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)

        self.mox.ReplayAll()

        res = self.client.post(reverse(self.ADDOPTIMIZER_PATH), form_data)

        self.assertFormErrors(res, 1)

    @test.create_stubs({api.oaas: ('rule_get',)})
    def test_update_rule_get(self):
        rule = self.opt_rules.first()

        api.oaas.rule_get(IsA(http.HttpRequest), rule.id).AndReturn(rule)

        self.mox.ReplayAll()

        res = self.client.get(reverse(self.UPDATERULE_PATH, args=(rule.id,)))

        self.assertTemplateUsed(res, 'project/optimizers/updaterule.html')

    @test.create_stubs({api.oaas: ('rule_get', 'rule_update')})
    def test_update_rule_post(self):
        rule = self.opt_rules.first()

        api.oaas.rule_get(IsA(http.HttpRequest), rule.id).AndReturn(rule)

        data = {'name': 'new name',
                'description': 'new desc',
                'protocol': 'ICMP',
                'action': 'ALLOW',
                'shared': False,
                'enabled': True,
                'source_ip_address': rule.source_ip_address,
                'destination_ip_address': None,
                'source_port': None,
                'destination_port': rule.destination_port,
                }

        api.oaas.rule_update(IsA(http.HttpRequest), rule.id, **data)\
            .AndReturn(rule)

        self.mox.ReplayAll()

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('rule_get', 'rule_update')})
    def test_update_protocol_any_rule_post(self):
        # protocol any means protocol == None in neutron context.
        rule = self.opt_rules.get(protocol=None)

        api.oaas.rule_get(IsA(http.HttpRequest), rule.id).AndReturn(rule)

        data = {'name': 'new name',
                'description': 'new desc',
                'protocol': 'ICMP',
                'action': 'ALLOW',
                'shared': False,
                'enabled': True,
                'source_ip_address': rule.source_ip_address,
                'destination_ip_address': None,
                'source_port': None,
                'destination_port': rule.destination_port,
                }

        api.oaas.rule_update(IsA(http.HttpRequest), rule.id, **data)\
            .AndReturn(rule)

        self.mox.ReplayAll()

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('rule_get', 'rule_update')})
    def test_update_rule_protocol_to_ANY_post(self):
        rule = self.opt_rules.first()

        api.oaas.rule_get(IsA(http.HttpRequest), rule.id).AndReturn(rule)

        data = {'name': 'new name',
                'description': 'new desc',
                'protocol': None,
                'action': 'ALLOW',
                'shared': False,
                'enabled': True,
                'source_ip_address': rule.source_ip_address,
                'destination_ip_address': None,
                'source_port': None,
                'destination_port': rule.destination_port,
                }
        api.oaas.rule_update(IsA(http.HttpRequest), rule.id, **data)\
            .AndReturn(rule)

        self.mox.ReplayAll()

        form_data = data.copy()
        form_data['destination_ip_address'] = ''
        form_data['source_port'] = ''
        form_data['protocol'] = 'ANY'

        res = self.client.post(
            reverse(self.UPDATERULE_PATH, args=(rule.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('policy_get',)})
    def test_update_policy_get(self):
        policy = self.opt_policies.first()

        api.oaas.policy_get(IsA(http.HttpRequest),
                             policy.id).AndReturn(policy)

        self.mox.ReplayAll()

        res = self.client.get(
            reverse(self.UPDATEPOLICY_PATH, args=(policy.id,)))

        self.assertTemplateUsed(res, 'project/optimizers/updatepolicy.html')

    @test.create_stubs({api.oaas: ('policy_get', 'policy_update',
                                    'rule_list_for_tenant')})
    def test_update_policy_post(self):
        policy = self.opt_policies.first()

        api.oaas.policy_get(IsA(http.HttpRequest),
                             policy.id).AndReturn(policy)

        data = {'name': 'new name',
                'description': 'new desc',
                'shared': True,
                'audited': False
                }

        api.oaas.policy_update(IsA(http.HttpRequest), policy.id, **data)\
            .AndReturn(policy)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.UPDATEPOLICY_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('optimizer_get', 'policy_list_for_tenant')})
    def test_update_optimizer_get(self):
        optimizer = self.optimizers.first()
        policies = self.opt_policies.list()
        tenant_id = self.tenant.id

        api.oaas.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)

        api.oaas.optimizer_get(IsA(http.HttpRequest),
                               optimizer.id).AndReturn(optimizer)

        self.mox.ReplayAll()

        res = self.client.get(
            reverse(self.UPDATEOPTIMIZER_PATH, args=(optimizer.id,)))

        self.assertTemplateUsed(res, 'project/optimizers/updateoptimizer.html')

    @test.create_stubs({api.oaas: ('optimizer_get', 'policy_list_for_tenant',
                                    'optimizer_update')})
    def test_update_optimizer_post(self):
        optimizer = self.optimizers.first()
        tenant_id = self.tenant.id
        api.oaas.optimizer_get(IsA(http.HttpRequest),
                               optimizer.id).AndReturn(optimizer)

        data = {'name': 'new name',
                'description': 'new desc',
                'optimizer_policy_id': optimizer.optimizer_policy_id,
                'admin_state_up': False
                }

        policies = self.opt_policies.list()
        api.oaas.policy_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(policies)

        api.oaas.optimizer_update(IsA(http.HttpRequest), optimizer.id, **data)\
            .AndReturn(optimizer)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.UPDATEOPTIMIZER_PATH, args=(optimizer.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('policy_get', 'policy_insert_rule',
                                    'rule_list_for_tenant', 'rule_get')})
    def test_policy_insert_rule(self):
        policy = self.opt_policies.first()
        tenant_id = self.tenant.id
        rules = self.opt_rules.list()

        new_rule_id = rules[2].id

        data = {'optimizer_rule_id': new_rule_id,
                'insert_before': rules[1].id,
                'insert_after': rules[0].id}

        api.oaas.policy_get(IsA(http.HttpRequest),
                             policy.id).AndReturn(policy)

        policy.optimizer_rules = [rules[0].id,
                                 new_rule_id,
                                 rules[1].id]

        api.oaas.rule_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(rules)
        api.oaas.rule_get(
            IsA(http.HttpRequest), new_rule_id).AndReturn(rules[2])
        api.oaas.policy_insert_rule(IsA(http.HttpRequest), policy.id, **data)\
            .AndReturn(policy)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.INSERTRULE_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('policy_get', 'policy_remove_rule',
                                    'rule_list_for_tenant', 'rule_get')})
    def test_policy_remove_rule(self):
        policy = self.opt_policies.first()
        tenant_id = self.tenant.id
        rules = self.opt_rules.list()

        remove_rule_id = policy.optimizer_rules[0]
        left_rule_id = policy.optimizer_rules[1]

        data = {'optimizer_rule_id': remove_rule_id}

        after_remove_policy_dict = {'id': 'abcdef-c3eb-4fee-9763-12de3338041e',
                                    'tenant_id': '1',
                                    'name': 'policy1',
                                    'description': 'policy description',
                                    'optimizer_rules': [left_rule_id],
                                    'audited': True,
                                    'shared': True}
        after_remove_policy = oaas.Policy(after_remove_policy_dict)

        api.oaas.policy_get(IsA(http.HttpRequest),
                             policy.id).AndReturn(policy)
        api.oaas.rule_list_for_tenant(
            IsA(http.HttpRequest), tenant_id).AndReturn(rules)
        api.oaas.rule_get(
            IsA(http.HttpRequest), remove_rule_id).AndReturn(rules[0])
        api.oaas.policy_remove_rule(IsA(http.HttpRequest), policy.id, **data)\
            .AndReturn(after_remove_policy)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.REMOVERULE_PATH, args=(policy.id,)), data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('optimizer_get',
                                    'optimizer_list_for_tenant',
                                    'optimizer_update',
                                    'optimizer_unassociated_routers_list')})
    def test_optimizer_add_router(self):
        tenant_id = self.tenant.id
        optimizer = self.optimizers.first()
        routers = self.routers.list()

        existing_router_ids = optimizer.router_ids
        add_router_ids = [routers[1].id]

        form_data = {'router_ids': add_router_ids}
        post_data = {'router_ids': add_router_ids + existing_router_ids}

        api.oaas.optimizer_get(
            IsA(http.HttpRequest), optimizer.id).AndReturn(optimizer)
        api.oaas.optimizer_unassociated_routers_list(
            IsA(http.HttpRequest), tenant_id).AndReturn(routers)

        optimizer.router_ids = [add_router_ids, existing_router_ids]

        api.oaas.optimizer_update(
            IsA(http.HttpRequest),
            optimizer.id, **post_data).AndReturn(optimizer)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.ADDROUTER_PATH, args=(optimizer.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('optimizer_get',
                                    'optimizer_update'),
                        api.neutron: ('router_list',), })
    def test_optimizer_remove_router(self):
        optimizer = self.optimizers.first()
        tenant_id = self.tenant.id
        routers = self.routers.list()
        existing_router_ids = optimizer.router_ids

        form_data = {'router_ids': existing_router_ids}

        api.oaas.optimizer_get(
            IsA(http.HttpRequest), optimizer.id).AndReturn(optimizer)
        api.neutron.router_list(
            IsA(http.HttpRequest), tenant_id=tenant_id).AndReturn(routers)
        optimizer.router_ids = []
        api.oaas.optimizer_update(
            IsA(http.HttpRequest),
            optimizer.id, **form_data).AndReturn(optimizer)

        self.mox.ReplayAll()

        res = self.client.post(
            reverse(self.REMOVEROUTER_PATH, args=(optimizer.id,)), form_data)

        self.assertNoFormErrors(res)
        self.assertRedirectsNoFollow(res, str(self.INDEX_URL))

    @test.create_stubs({api.oaas: ('rule_list_for_tenant',
                                    'rule_delete'),
                        api.neutron: ('is_extension_supported',)})
    def test_delete_rule(self):
        api.neutron.is_extension_supported(
            IsA(http.HttpRequest), 'oaasrouterinsertion').AndReturn(True)

        rule = self.opt_rules.list()[2]
        api.oaas.rule_list_for_tenant(
            IsA(http.HttpRequest),
            self.tenant.id).AndReturn(self.opt_rules.list())
        api.oaas.rule_delete(IsA(http.HttpRequest), rule.id)
        self.mox.ReplayAll()

        form_data = {"action": "rulestable__deleterule__%s" % rule.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)

    @test.create_stubs({api.oaas: ('policy_list_for_tenant',
                                    'policy_delete'),
                        api.neutron: ('is_extension_supported',)})
    def test_delete_policy(self):
        api.neutron.is_extension_supported(
            IsA(http.HttpRequest), 'oaasrouterinsertion').AndReturn(True)

        policy = self.opt_policies.first()
        api.oaas.policy_list_for_tenant(
            IsA(http.HttpRequest),
            self.tenant.id).AndReturn(self.opt_policies.list())
        api.oaas.policy_delete(IsA(http.HttpRequest), policy.id)
        self.mox.ReplayAll()

        form_data = {"action": "policiestable__deletepolicy__%s" % policy.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)

    @test.create_stubs({api.oaas: ('optimizer_list_for_tenant',
                                    'optimizer_delete'),
                        api.neutron: ('is_extension_supported',
                                      'router_list',)})
    def test_delete_optimizer(self):
        api.neutron.is_extension_supported(
            IsA(http.HttpRequest), 'oaasrouterinsertion'
        ).MultipleTimes().AndReturn(True)

        routers = self.routers.list()
        api.neutron.router_list(
            IsA(http.HttpRequest), tenant_id=self.tenant.id).AndReturn(routers)

        optl = self.optimizers.first()
        api.oaas.optimizer_list_for_tenant(
            IsA(http.HttpRequest), self.tenant.id).AndReturn([optl])
        api.oaas.optimizer_delete(IsA(http.HttpRequest), optl.id)
        self.mox.ReplayAll()

        form_data = {"action": "optimizerstable__deleteoptimizer__%s" % optl.id}
        res = self.client.post(self.INDEX_URL, form_data)

        self.assertNoFormErrors(res)
