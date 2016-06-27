# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import contextlib

import mock
from neutron.api import extensions as api_ext
from neutron.common import config
from neutron import context
import neutron.extensions as nextensions
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.common import constants
from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import uuidutils
import six
import webob.exc

from neutron_oaas.db.optimizer import optimizer_db as fdb
from neutron_oaas import extensions
from neutron_oaas.extensions import optimizer
from neutron_oaas.services.optimizer import oaas_plugin
from neutron_oaas.tests import base

DB_FW_PLUGIN_KLASS = (
    "neutron_oaas.db.optimizer.optimizer_db.Optimizer_db_mixin"
)
OAAS_PLUGIN = 'neutron_oaas.services.optimizer.oaas_plugin'
DELETEFW_PATH = OAAS_PLUGIN + '.OptimizerAgentApi.delete_optimizer'
extensions_path = ':'.join(extensions.__path__ + nextensions.__path__)
DESCRIPTION = 'default description'
SHARED = True
PROTOCOL = 'tcp'
IP_VERSION = 4
SOURCE_IP_ADDRESS_RAW = '1.1.1.1'
DESTINATION_IP_ADDRESS_RAW = '2.2.2.2'
SOURCE_PORT = '55000:56000'
DESTINATION_PORT = '56000:57000'
ACTION = 'allow'
AUDITED = True
ENABLED = True
ADMIN_STATE_UP = True


class FakeAgentApi(oaas_plugin.OptimizerCallbacks):
    """
    This class used to mock the AgentAPI delete method inherits from
    OptimizerCallbacks because it needs access to the optimizer_deleted method.
    The delete_optimizer method belongs to the OptimizerAgentApi, which has
    no access to the optimizer_deleted method normally because it's not
    responsible for deleting the optimizer from the DB. However, it needs
    to in the unit tests since there is no agent to call back.
    """
    def __init__(self):
        pass

    def delete_optimizer(self, context, optimizer, **kwargs):
        self.plugin = manager.NeutronManager.get_service_plugins()['OPTIMIZER']
        self.optimizer_deleted(context, optimizer['id'], **kwargs)


class OptimizerPluginDbTestCase(base.NeutronDbPluginV2TestCase):
    resource_prefix_map = dict(
        (k, optimizer.OPTIMIZER_PREFIX)
        for k in optimizer.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def setUp(self, core_plugin=None, opt_plugin=None, ext_mgr=None):
        self.agentapi_delf_p = mock.patch(DELETEFW_PATH, create=True,
                                          new=FakeAgentApi().delete_optimizer)
        self.agentapi_delf_p.start()
        if not opt_plugin:
            opt_plugin = DB_FW_PLUGIN_KLASS
        service_plugins = {'opt_plugin_name': opt_plugin}

        fdb.Optimizer_db_mixin.supported_extension_aliases = ["oaas"]
        fdb.Optimizer_db_mixin.path_prefix = optimizer.OPTIMIZER_PREFIX
        super(OptimizerPluginDbTestCase, self).setUp(
            ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )

        if not ext_mgr:
            self.plugin = importutils.import_object(opt_plugin)
            ext_mgr = api_ext.PluginAwareExtensionManager(
                extensions_path,
                {constants.OPTIMIZER: self.plugin}
            )
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)

    def _test_list_resources(self, resource, items,
                             neutron_context=None,
                             query_params=None):
        if resource.endswith('y'):
            resource_plural = resource.replace('y', 'ies')
        else:
            resource_plural = resource + 's'

        res = self._list(resource_plural,
                         neutron_context=neutron_context,
                         query_params=query_params)
        resource = resource.replace('-', '_')
        self.assertEqual(sorted([i['id'] for i in res[resource_plural]]),
                         sorted([i[resource]['id'] for i in items]))

    def _get_test_optimizer_rule_attrs(self, name='optimizer_rule1'):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'shared': SHARED,
                 'protocol': PROTOCOL,
                 'ip_version': IP_VERSION,
                 'source_ip_address': SOURCE_IP_ADDRESS_RAW,
                 'destination_ip_address': DESTINATION_IP_ADDRESS_RAW,
                 'source_port': SOURCE_PORT,
                 'destination_port': DESTINATION_PORT,
                 'action': ACTION,
                 'enabled': ENABLED}
        return attrs

    def _get_test_optimizer_policy_attrs(self, name='optimizer_policy1',
                                        audited=AUDITED):
        attrs = {'name': name,
                 'description': DESCRIPTION,
                 'tenant_id': self._tenant_id,
                 'shared': SHARED,
                 'optimizer_rules': [],
                 'audited': audited}
        return attrs

    def _get_test_optimizer_attrs(self, name='optimizer_1',
                                 status='PENDING_CREATE'):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'admin_state_up': ADMIN_STATE_UP,
                 'status': status}

        return attrs

    def _create_optimizer_policy(self, fmt, name, description, shared,
                                optimizer_rules, audited,
                                expected_res_status=None, **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'optimizer_policy': {'name': name,
                                    'description': description,
                                    'tenant_id': tenant_id,
                                    'shared': shared,
                                    'optimizer_rules': optimizer_rules,
                                    'audited': audited}}

        opt_policy_req = self.new_create_request('optimizer_policies', data, fmt)
        opt_policy_res = opt_policy_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(opt_policy_res.status_int, expected_res_status)

        return opt_policy_res

    def _replace_optimizer_status(self, attrs, old_status, new_status):
        if attrs['status'] is old_status:
            attrs['status'] = new_status
        return attrs

    @contextlib.contextmanager
    def optimizer_policy(self, fmt=None, name='optimizer_policy1',
                        description=DESCRIPTION, shared=True,
                        optimizer_rules=None, audited=True,
                        do_delete=True, **kwargs):
        if optimizer_rules is None:
            optimizer_rules = []
        if not fmt:
            fmt = self.fmt
        res = self._create_optimizer_policy(fmt, name, description, shared,
                                           optimizer_rules, audited,
                                           **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        optimizer_policy = self.deserialize(fmt or self.fmt, res)
        yield optimizer_policy
        if do_delete:
            self._delete('optimizer_policies',
                         optimizer_policy['optimizer_policy']['id'])

    def _create_optimizer_rule(self, fmt, name, shared, protocol,
                              ip_version, source_ip_address,
                              destination_ip_address, source_port,
                              destination_port, action, enabled,
                              expected_res_status=None, **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'optimizer_rule': {'name': name,
                                  'tenant_id': tenant_id,
                                  'shared': shared,
                                  'protocol': protocol,
                                  'ip_version': ip_version,
                                  'source_ip_address': source_ip_address,
                                  'destination_ip_address':
                                  destination_ip_address,
                                  'source_port': source_port,
                                  'destination_port': destination_port,
                                  'action': action,
                                  'enabled': enabled}}

        opt_rule_req = self.new_create_request('optimizer_rules', data, fmt)
        opt_rule_res = opt_rule_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(opt_rule_res.status_int, expected_res_status)

        return opt_rule_res

    @contextlib.contextmanager
    def optimizer_rule(self, fmt=None, name='optimizer_rule1',
                      shared=SHARED, protocol=PROTOCOL, ip_version=IP_VERSION,
                      source_ip_address=SOURCE_IP_ADDRESS_RAW,
                      destination_ip_address=DESTINATION_IP_ADDRESS_RAW,
                      source_port=SOURCE_PORT,
                      destination_port=DESTINATION_PORT,
                      action=ACTION, enabled=ENABLED,
                      do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_optimizer_rule(fmt, name, shared, protocol,
                                         ip_version, source_ip_address,
                                         destination_ip_address,
                                         source_port, destination_port,
                                         action, enabled, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        optimizer_rule = self.deserialize(fmt or self.fmt, res)
        yield optimizer_rule
        if do_delete:
            self._delete('optimizer_rules',
                         optimizer_rule['optimizer_rule']['id'])

    def _create_optimizer(self, fmt, name, description, optimizer_policy_id,
                         admin_state_up=True, expected_res_status=None,
                         **kwargs):
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        if optimizer_policy_id is None:
            res = self._create_optimizer_policy(fmt, 'optp',
                                               description=DESCRIPTION,
                                               shared=True,
                                               optimizer_rules=[],
                                               tenant_id=tenant_id,
                                               audited=AUDITED)
            optimizer_policy = self.deserialize(fmt or self.fmt, res)
            optimizer_policy_id = optimizer_policy["optimizer_policy"]["id"]
        data = {'optimizer': {'name': name,
                             'description': description,
                             'optimizer_policy_id': optimizer_policy_id,
                             'admin_state_up': admin_state_up}}
        ctx = kwargs.get('context', None)
        if ctx is None or ctx.is_admin:
            data['optimizer'].update({'tenant_id': tenant_id})

        optimizer_req = self.new_create_request('optimizers', data, fmt,
                                               context=ctx)
        optimizer_res = optimizer_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(optimizer_res.status_int, expected_res_status)

        return optimizer_res

    @contextlib.contextmanager
    def optimizer(self, fmt=None, name='optimizer_1', description=DESCRIPTION,
                 optimizer_policy_id=None, admin_state_up=True,
                 do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_optimizer(fmt, name, description, optimizer_policy_id,
                                    admin_state_up, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        optimizer = self.deserialize(fmt or self.fmt, res)
        yield optimizer
        if do_delete:
            self._delete('optimizers', optimizer['optimizer']['id'])

    def _rule_action(self, action, id, optimizer_rule_id, insert_before=None,
                     insert_after=None, expected_code=webob.exc.HTTPOk.code,
                     expected_body=None, body_data=None):
        # We intentionally do this check for None since we want to distinguish
        # from empty dictionary
        if body_data is None:
            if action == 'insert':
                body_data = {'optimizer_rule_id': optimizer_rule_id,
                             'insert_before': insert_before,
                             'insert_after': insert_after}
            else:
                body_data = {'optimizer_rule_id': optimizer_rule_id}

        req = self.new_action_request('optimizer_policies',
                                      body_data, id,
                                      "%s_rule" % action)
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_code)
        response = self.deserialize(self.fmt, res)
        if expected_body:
            self.assertEqual(response, expected_body)
        return response

    def _compare_optimizer_rule_lists(self, optimizer_policy_id,
                                     list1, list2):
        position = 0
        for r1, r2 in zip(list1, list2):
            rule = r1['optimizer_rule']
            rule['optimizer_policy_id'] = optimizer_policy_id
            position += 1
            rule['position'] = position
            for k in rule:
                self.assertEqual(rule[k], r2[k])


class TestOptimizerDBPlugin(OptimizerPluginDbTestCase):

    def test_create_optimizer_policy(self):
        name = "optimizer_policy1"
        attrs = self._get_test_optimizer_policy_attrs(name)

        with self.optimizer_policy(name=name, shared=SHARED,
                                  optimizer_rules=None,
                                  audited=AUDITED) as optimizer_policy:
            for k, v in six.iteritems(attrs):
                self.assertEqual(optimizer_policy['optimizer_policy'][k], v)

    def test_create_optimizer_policy_with_rules(self):
        name = "optimizer_policy1"
        attrs = self._get_test_optimizer_policy_attrs(name)

        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3:
            fr = [optr1, optr2, optr3]
            opt_rule_ids = [r['optimizer_rule']['id'] for r in fr]
            attrs['optimizer_rules'] = opt_rule_ids
            with self.optimizer_policy(name=name, shared=SHARED,
                                      optimizer_rules=opt_rule_ids,
                                      audited=AUDITED) as optp:
                for k, v in six.iteritems(attrs):
                    self.assertEqual(optp['optimizer_policy'][k], v)

    def test_create_admin_optimizer_policy_with_other_tenant_rules(self):
        with self.optimizer_rule(shared=False) as fr:
            opt_rule_ids = [fr['optimizer_rule']['id']]
            res = self._create_optimizer_policy(None, 'optimizer_policy1',
                                               description=DESCRIPTION,
                                               shared=SHARED,
                                               optimizer_rules=opt_rule_ids,
                                               audited=AUDITED,
                                               tenant_id='admin-tenant')
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_optimizer_policy_with_previously_associated_rule(self):
        with self.optimizer_rule() as optr:
            opt_rule_ids = [optr['optimizer_rule']['id']]
            with self.optimizer_policy(optimizer_rules=opt_rule_ids):
                res = self._create_optimizer_policy(
                    None, 'optimizer_policy2', description=DESCRIPTION,
                    shared=SHARED, optimizer_rules=opt_rule_ids,
                    audited=AUDITED)
                self.assertEqual(res.status_int, 409)

    def test_create_shared_optimizer_policy_with_unshared_rule(self):
        with self.optimizer_rule(shared=False) as optr:
            opt_rule_ids = [optr['optimizer_rule']['id']]
            res = self._create_optimizer_policy(
                None, 'optimizer_policy1', description=DESCRIPTION, shared=True,
                optimizer_rules=opt_rule_ids, audited=AUDITED)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_show_optimizer_policy(self):
        name = "optimizer_policy1"
        attrs = self._get_test_optimizer_policy_attrs(name)

        with self.optimizer_policy(name=name, shared=SHARED,
                                  optimizer_rules=None,
                                  audited=AUDITED) as optp:
            req = self.new_show_request('optimizer_policies',
                                        optp['optimizer_policy']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(res['optimizer_policy'][k], v)

    def test_list_optimizer_policies(self):
        with self.optimizer_policy(name='optp1', description='optp') as optp1, \
                self.optimizer_policy(name='optp2', description='optp') as optp2, \
                self.optimizer_policy(name='optp3', description='optp') as optp3:
            opt_policies = [optp1, optp2, optp3]
            self._test_list_resources('optimizer_policy',
                                      opt_policies,
                                      query_params='description=optp')

    def test_update_optimizer_policy(self):
        name = "new_optimizer_policy1"
        attrs = self._get_test_optimizer_policy_attrs(name, audited=False)

        with self.optimizer_policy(shared=SHARED,
                                  optimizer_rules=None,
                                  audited=AUDITED) as optp:
            data = {'optimizer_policy': {'name': name}}
            req = self.new_update_request('optimizer_policies', data,
                                          optp['optimizer_policy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(res['optimizer_policy'][k], v)

    def _test_update_optimizer_policy(self, with_audited):
        with self.optimizer_policy(name='optimizer_policy1',
                                  description='optp',
                                  audited=AUDITED) as optp:
            attrs = self._get_test_optimizer_policy_attrs(audited=with_audited)
            data = {'optimizer_policy':
                    {'description': 'opt_p1'}}
            if with_audited:
                data['optimizer_policy']['audited'] = 'True'

            req = self.new_update_request('optimizer_policies', data,
                                          optp['optimizer_policy']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            attrs['description'] = 'opt_p1'
            for k, v in six.iteritems(attrs):
                self.assertEqual(res['optimizer_policy'][k], v)

    def test_update_optimizer_policy_set_audited_false(self):
        self._test_update_optimizer_policy(with_audited=False)

    def test_update_optimizer_policy_with_audited_set_true(self):
        self._test_update_optimizer_policy(with_audited=True)

    def test_update_optimizer_policy_with_rules(self):
        attrs = self._get_test_optimizer_policy_attrs()

        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3:
            with self.optimizer_policy() as optp:
                fr = [optr1, optr2, optr3]
                opt_rule_ids = [r['optimizer_rule']['id'] for r in fr]
                attrs['optimizer_rules'] = opt_rule_ids
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs['audited'] = False
                for k, v in six.iteritems(attrs):
                    self.assertEqual(res['optimizer_policy'][k], v)

    def test_update_optimizer_policy_replace_rules(self):
        attrs = self._get_test_optimizer_policy_attrs()

        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3, \
                self.optimizer_rule(name='optr4') as optr4:
            frs = [optr1, optr2, optr3, optr4]
            fr1 = frs[0:2]
            fr2 = frs[2:4]
            with self.optimizer_policy() as optp:
                opt_rule_ids = [r['optimizer_rule']['id'] for r in fr1]
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                req.get_response(self.ext_api)

                opt_rule_ids = [r['optimizer_rule']['id'] for r in fr2]
                attrs['optimizer_rules'] = opt_rule_ids
                new_data = {'optimizer_policy':
                            {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', new_data,
                                              optp['optimizer_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs['audited'] = False
                for k, v in six.iteritems(attrs):
                    self.assertEqual(res['optimizer_policy'][k], v)

    def test_update_optimizer_policy_reorder_rules(self):
        attrs = self._get_test_optimizer_policy_attrs()

        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3, \
                self.optimizer_rule(name='optr4') as optr4:
            fr = [optr1, optr2, optr3, optr4]
            with self.optimizer_policy() as optp:
                opt_rule_ids = [fr[2]['optimizer_rule']['id'],
                               fr[3]['optimizer_rule']['id']]
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                req.get_response(self.ext_api)
                # shuffle the rules, add more rules
                opt_rule_ids = [fr[1]['optimizer_rule']['id'],
                               fr[3]['optimizer_rule']['id'],
                               fr[2]['optimizer_rule']['id'],
                               fr[0]['optimizer_rule']['id']]
                attrs['optimizer_rules'] = opt_rule_ids
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                rules = []
                for rule_id in opt_rule_ids:
                    req = self.new_show_request('optimizer_rules',
                                                rule_id,
                                                fmt=self.fmt)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.ext_api))
                    rules.append(res['optimizer_rule'])
                self.assertEqual(rules[0]['position'], 1)
                self.assertEqual(rules[0]['id'], fr[1]['optimizer_rule']['id'])
                self.assertEqual(rules[1]['position'], 2)
                self.assertEqual(rules[1]['id'], fr[3]['optimizer_rule']['id'])
                self.assertEqual(rules[2]['position'], 3)
                self.assertEqual(rules[2]['id'], fr[2]['optimizer_rule']['id'])
                self.assertEqual(rules[3]['position'], 4)
                self.assertEqual(rules[3]['id'], fr[0]['optimizer_rule']['id'])

    def test_update_optimizer_policy_with_non_existing_rule(self):
        attrs = self._get_test_optimizer_policy_attrs()

        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2:
            fr = [optr1, optr2]
            with self.optimizer_policy() as optp:
                opt_rule_ids = [r['optimizer_rule']['id'] for r in fr]
                # appending non-existent rule
                opt_rule_ids.append(uuidutils.generate_uuid())
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                res = req.get_response(self.ext_api)
                # check that the optimizer_rule was not found
                self.assertEqual(res.status_int, 404)
                # check if none of the rules got added to the policy
                req = self.new_show_request('optimizer_policies',
                                            optp['optimizer_policy']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in six.iteritems(attrs):
                    self.assertEqual(res['optimizer_policy'][k], v)

    def test_update_shared_optimizer_policy_with_unshared_rule(self):
        with self.optimizer_rule(name='optr1', shared=False) as fr:
            with self.optimizer_policy() as optp:
                opt_rule_ids = [fr['optimizer_rule']['id']]
                # update shared policy with unshared rule
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_optimizer_policy_with_shared_attr_unshared_rule(self):
        with self.optimizer_rule(name='optr1', shared=False) as fr:
            with self.optimizer_policy(shared=False) as optp:
                opt_rule_ids = [fr['optimizer_rule']['id']]
                # update shared policy with shared attr and unshared rule
                data = {'optimizer_policy': {'shared': True,
                                            'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_optimizer_policy_with_shared_attr_exist_unshare_rule(self):
        with self.optimizer_rule(name='optr1', shared=False) as fr:
            opt_rule_ids = [fr['optimizer_rule']['id']]
            with self.optimizer_policy(shared=False,
                                      optimizer_rules=opt_rule_ids) as optp:
                # update policy with shared attr
                data = {'optimizer_policy': {'shared': True}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_optimizer_policy_assoc_with_other_tenant_optimizer(self):
        with self.optimizer_policy(shared=True, tenant_id='tenant1') as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(optimizer_policy_id=optp_id):
                data = {'optimizer_policy': {'shared': False}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_delete_optimizer_policy(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy(do_delete=False) as optp:
            optp_id = optp['optimizer_policy']['id']
            req = self.new_delete_request('optimizer_policies', optp_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)
            self.assertRaises(optimizer.OptimizerPolicyNotFound,
                              self.plugin.get_optimizer_policy,
                              ctx, optp_id)

    def test_delete_optimizer_policy_with_rule(self):
        ctx = context.get_admin_context()
        attrs = self._get_test_optimizer_policy_attrs()
        with self.optimizer_policy(do_delete=False) as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer_rule(name='optr1') as fr:
                fr_id = fr['optimizer_rule']['id']
                opt_rule_ids = [fr_id]
                attrs['optimizer_rules'] = opt_rule_ids
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                req.get_response(self.ext_api)
                opt_rule = self.plugin.get_optimizer_rule(ctx, fr_id)
                self.assertEqual(opt_rule['optimizer_policy_id'], optp_id)
                req = self.new_delete_request('optimizer_policies', optp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)
                self.assertRaises(optimizer.OptimizerPolicyNotFound,
                                  self.plugin.get_optimizer_policy,
                                  ctx, optp_id)
                opt_rule = self.plugin.get_optimizer_rule(ctx, fr_id)
                self.assertIsNone(opt_rule['optimizer_policy_id'])

    def test_delete_optimizer_policy_with_optimizer_association(self):
        attrs = self._get_test_optimizer_attrs()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(
                    optimizer_policy_id=optp_id,
                    admin_state_up=ADMIN_STATE_UP):
                req = self.new_delete_request('optimizer_policies', optp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 409)

    def test_create_optimizer_rule(self):
        attrs = self._get_test_optimizer_rule_attrs()

        with self.optimizer_rule() as optimizer_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(optimizer_rule['optimizer_rule'][k], v)

        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.optimizer_rule(source_port=None,
                                destination_port=None) as optimizer_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(optimizer_rule['optimizer_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.optimizer_rule(source_port=10000,
                                destination_port=80) as optimizer_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(optimizer_rule['optimizer_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.optimizer_rule(source_port='10000',
                                destination_port='80') as optimizer_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(optimizer_rule['optimizer_rule'][k], v)

    def test_create_optimizer_src_port_illegal_range(self):
        attrs = self._get_test_optimizer_rule_attrs()
        attrs['source_port'] = '65535:1024'
        res = self._create_optimizer_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_create_optimizer_dest_port_illegal_range(self):
        attrs = self._get_test_optimizer_rule_attrs()
        attrs['destination_port'] = '65535:1024'
        res = self._create_optimizer_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_create_optimizer_rule_icmp_with_port(self):
        attrs = self._get_test_optimizer_rule_attrs()
        attrs['protocol'] = 'icmp'
        res = self._create_optimizer_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_create_optimizer_rule_icmp_without_port(self):
        attrs = self._get_test_optimizer_rule_attrs()

        attrs['protocol'] = 'icmp'
        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.optimizer_rule(source_port=None,
                                destination_port=None,
                                protocol='icmp') as optimizer_rule:
            for k, v in six.iteritems(attrs):
                self.assertEqual(optimizer_rule['optimizer_rule'][k], v)

    def test_create_optimizer_rule_without_protocol_with_dport(self):
        attrs = self._get_test_optimizer_rule_attrs()
        attrs['protocol'] = None
        attrs['source_port'] = None
        res = self._create_optimizer_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_create_optimizer_rule_without_protocol_with_sport(self):
        attrs = self._get_test_optimizer_rule_attrs()
        attrs['protocol'] = None
        attrs['destination_port'] = None
        res = self._create_optimizer_rule(self.fmt, **attrs)
        self.assertEqual(400, res.status_int)

    def test_show_optimizer_rule_with_opt_policy_not_associated(self):
        attrs = self._get_test_optimizer_rule_attrs()
        with self.optimizer_rule() as opt_rule:
            req = self.new_show_request('optimizer_rules',
                                        opt_rule['optimizer_rule']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(res['optimizer_rule'][k], v)

    def test_show_optimizer_rule_with_opt_policy_associated(self):
        attrs = self._get_test_optimizer_rule_attrs()
        with self.optimizer_rule() as opt_rule:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['optimizer_policy_id'] = optp_id
                data = {'optimizer_policy':
                        {'optimizer_rules':
                         [opt_rule['optimizer_rule']['id']]}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                req.get_response(self.ext_api)
                req = self.new_show_request('optimizer_rules',
                                            opt_rule['optimizer_rule']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in six.iteritems(attrs):
                    self.assertEqual(res['optimizer_rule'][k], v)

    def test_list_optimizer_rules(self):
        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3:
            fr = [optr1, optr2, optr3]
            query_params = 'protocol=tcp'
            self._test_list_resources('optimizer_rule', fr,
                                      query_params=query_params)

    def test_update_optimizer_rule(self):
        name = "new_optimizer_rule1"
        attrs = self._get_test_optimizer_rule_attrs(name)

        attrs['source_port'] = '10:20'
        attrs['destination_port'] = '30:40'
        with self.optimizer_rule() as optr:
            data = {'optimizer_rule': {'name': name,
                                      'source_port': '10:20',
                                      'destination_port': '30:40'}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(res['optimizer_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.optimizer_rule() as optr:
            data = {'optimizer_rule': {'name': name,
                                      'source_port': 10000,
                                      'destination_port': 80}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(res['optimizer_rule'][k], v)

        attrs['source_port'] = '10000'
        attrs['destination_port'] = '80'
        with self.optimizer_rule() as optr:
            data = {'optimizer_rule': {'name': name,
                                      'source_port': '10000',
                                      'destination_port': '80'}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(res['optimizer_rule'][k], v)

        attrs['source_port'] = None
        attrs['destination_port'] = None
        with self.optimizer_rule() as optr:
            data = {'optimizer_rule': {'name': name,
                                      'source_port': None,
                                      'destination_port': None}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in six.iteritems(attrs):
                self.assertEqual(res['optimizer_rule'][k], v)

    def test_update_optimizer_rule_with_port_and_no_proto(self):
        with self.optimizer_rule() as optr:
            data = {'optimizer_rule': {'protocol': None,
                                      'destination_port': 80}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(400, res.status_int)

    def test_update_optimizer_rule_without_ports_and_no_proto(self):
        with self.optimizer_rule() as optr:
            data = {'optimizer_rule': {'protocol': None,
                                      'destination_port': None,
                                      'source_port': None}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_optimizer_rule_with_port(self):
        with self.optimizer_rule(source_port=None,
                                destination_port=None,
                                protocol=None) as optr:
            data = {'optimizer_rule': {'destination_port': 80}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(400, res.status_int)

    def test_update_optimizer_rule_with_port_illegal_range(self):
        with self.optimizer_rule() as optr:
            data = {'optimizer_rule': {'destination_port': '65535:1024'}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(400, res.status_int)

    def test_update_optimizer_rule_with_port_and_protocol(self):
        with self.optimizer_rule(source_port=None,
                                destination_port=None,
                                protocol=None) as optr:
            data = {'optimizer_rule': {'destination_port': 80,
                                      'protocol': 'tcp'}}
            req = self.new_update_request('optimizer_rules', data,
                                          optr['optimizer_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_optimizer_rule_with_policy_associated(self):
        name = "new_optimizer_rule1"
        attrs = self._get_test_optimizer_rule_attrs(name)
        with self.optimizer_rule() as optr:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['optimizer_policy_id'] = optp_id
                optr_id = optr['optimizer_rule']['id']
                data = {'optimizer_policy': {'optimizer_rules': [optr_id]}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                req.get_response(self.ext_api)
                data = {'optimizer_rule': {'name': name}}
                req = self.new_update_request('optimizer_rules', data,
                                              optr['optimizer_rule']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                attrs['optimizer_policy_id'] = optp_id
                for k, v in six.iteritems(attrs):
                    self.assertEqual(res['optimizer_rule'][k], v)
                req = self.new_show_request('optimizer_policies',
                                            optp['optimizer_policy']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                self.assertEqual(res['optimizer_policy']['optimizer_rules'],
                                 [optr_id])
                self.assertEqual(res['optimizer_policy']['audited'], False)

    def test_update_optimizer_rule_associated_with_other_tenant_policy(self):
        with self.optimizer_rule(shared=True, tenant_id='tenant1') as optr:
            optr_id = [optr['optimizer_rule']['id']]
            with self.optimizer_policy(shared=False,
                                      optimizer_rules=optr_id):
                data = {'optimizer_rule': {'shared': False}}
                req = self.new_update_request('optimizer_rules', data,
                                              optr['optimizer_rule']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_delete_optimizer_rule(self):
        ctx = context.get_admin_context()
        with self.optimizer_rule(do_delete=False) as optr:
            optr_id = optr['optimizer_rule']['id']
            req = self.new_delete_request('optimizer_rules', optr_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)
            self.assertRaises(optimizer.OptimizerRuleNotFound,
                              self.plugin.get_optimizer_rule,
                              ctx, optr_id)

    def test_delete_optimizer_rule_with_policy_associated(self):
        attrs = self._get_test_optimizer_rule_attrs()
        with self.optimizer_rule() as optr:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['optimizer_policy_id'] = optp_id
                optr_id = optr['optimizer_rule']['id']
                data = {'optimizer_policy': {'optimizer_rules': [optr_id]}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp['optimizer_policy']['id'])
                req.get_response(self.ext_api)
                req = self.new_delete_request('optimizer_rules', optr_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 409)

    def _test_create_optimizer(self, attrs):
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(
                name=attrs['name'],
                optimizer_policy_id=optp_id,
                admin_state_up=ADMIN_STATE_UP
            ) as optimizer:
                for k, v in six.iteritems(attrs):
                    self.assertEqual(optimizer['optimizer'][k], v)

    def test_create_optimizer(self):
        attrs = self._get_test_optimizer_attrs("optimizer1")
        self._test_create_optimizer(attrs)

    def test_create_optimizer_with_dvr(self):
        cfg.CONF.set_override('router_distributed', True)
        attrs = self._get_test_optimizer_attrs("optimizer1", "CREATED")
        self._test_create_optimizer(attrs)

    def test_create_optimizer_with_optp_does_not_exist(self):
        fmt = self.fmt
        opt_name = "optimizer1"
        description = "my_optimizer1"
        not_found_optp_id = uuidutils.generate_uuid()
        self._create_optimizer(fmt, opt_name,
                              description, not_found_optp_id,
                              ADMIN_STATE_UP,
                              expected_res_status=404)

    def test_create_optimizer_with_optp_not_found_on_different_tenant(self):
        fmt = self.fmt
        opt_name = "optimizer1"
        description = "my_optimizer1"
        with self.optimizer_policy(shared=False, tenant_id='tenant2') as optp:
            optp_id = optp['optimizer_policy']['id']
            ctx = context.Context('not_admin', 'tenant1')
            self._create_optimizer(fmt, opt_name,
                                  description, optp_id,
                                  context=ctx,
                                  expected_res_status=404)

    def test_create_optimizer_with_admin_and_optp_different_tenant(self):
        fmt = self.fmt
        opt_name = "optimizer1"
        description = "my_optimizer1"
        with self.optimizer_policy(shared=False, tenant_id='tenant2') as optp:
            optp_id = optp['optimizer_policy']['id']
            ctx = context.get_admin_context()
            self._create_optimizer(fmt, opt_name,
                                  description, optp_id,
                                  tenant_id="admin-tenant",
                                  context=ctx,
                                  expected_res_status=409)

    def test_create_optimizer_with_admin_and_optp_is_shared(self):
        opt_name = "opt_with_shared_optp"
        with self.optimizer_policy(tenant_id="tenantX") as optp:
            optp_id = optp['optimizer_policy']['id']
            ctx = context.get_admin_context()
            target_tenant = 'tenant1'
            with self.optimizer(name=opt_name, optimizer_policy_id=optp_id,
                               tenant_id=target_tenant, context=ctx,
                               admin_state_up=ADMIN_STATE_UP) as opt:
                self.assertEqual(opt['optimizer']['tenant_id'], target_tenant)

    def test_show_optimizer(self):
        name = "optimizer1"
        attrs = self._get_test_optimizer_attrs(name)

        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(
                    name=name,
                    optimizer_policy_id=optp_id,
                    admin_state_up=ADMIN_STATE_UP) as optimizer:
                req = self.new_show_request('optimizers',
                                            optimizer['optimizer']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in six.iteritems(attrs):
                    self.assertEqual(res['optimizer'][k], v)

    def test_list_optimizers(self):
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(name='opt1', tenant_id='tenant1',
                               optimizer_policy_id=optp_id,
                               description='opt') as opt1, \
                    self.optimizer(name='opt2', tenant_id='tenant2',
                                  optimizer_policy_id=optp_id,
                                  description='opt') as opt2, \
                    self.optimizer(name='opt3', tenant_id='tenant3',
                                  optimizer_policy_id=optp_id,
                                  description='opt') as opt3:
                optalls = [opt1, opt2, opt3]
                self._test_list_resources('optimizer', optalls,
                                          query_params='description=opt')

    def test_update_optimizer(self):
        name = "new_optimizer1"
        attrs = self._get_test_optimizer_attrs(name)

        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            attrs['optimizer_policy_id'] = optp_id
            with self.optimizer(
                    optimizer_policy_id=optp_id,
                    admin_state_up=ADMIN_STATE_UP) as optimizer:
                data = {'optimizer': {'name': name}}
                req = self.new_update_request('optimizers', data,
                                              optimizer['optimizer']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in six.iteritems(attrs):
                    self.assertEqual(res['optimizer'][k], v)

    def test_update_optimizer_with_optp(self):
        ctx = context.Context('not_admin', 'tenant1')
        with self.optimizer_policy() as optp1, \
                self.optimizer_policy(
                    tenant_id='tenant1', shared=False) as optp2, \
                self.optimizer(optimizer_policy_id=optp1['optimizer_policy']['id'],
                              context=ctx) as opt:
            opt_id = opt['optimizer']['id']
            optp2_id = optp2['optimizer_policy']['id']
            data = {'optimizer': {'optimizer_policy_id': optp2_id}}
            req = self.new_update_request('optimizers', data, opt_id,
                                          context=ctx)
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_optimizer_with_shared_optp(self):
        ctx = context.Context('not_admin', 'tenant1')
        with self.optimizer_policy() as optp1, \
                self.optimizer_policy(tenant_id='tenant2') as optp2, \
                self.optimizer(optimizer_policy_id=optp1['optimizer_policy']['id'],
                              context=ctx) as opt:
            opt_id = opt['optimizer']['id']
            optp2_id = optp2['optimizer_policy']['id']
            data = {'optimizer': {'optimizer_policy_id': optp2_id}}
            req = self.new_update_request('optimizers', data, opt_id,
                                          context=ctx)
            res = req.get_response(self.ext_api)
            self.assertEqual(200, res.status_int)

    def test_update_optimizer_with_admin_and_optp_different_tenant(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy() as optp1, \
                self.optimizer_policy(
                    tenant_id='tenant2', shared=False) as optp2, \
                self.optimizer(optimizer_policy_id=optp1['optimizer_policy']['id'],
                              context=ctx) as opt:
            opt_id = opt['optimizer']['id']
            optp2_id = optp2['optimizer_policy']['id']
            data = {'optimizer': {'optimizer_policy_id': optp2_id}}
            req = self.new_update_request('optimizers', data, opt_id,
                                          context=ctx)
            res = req.get_response(self.ext_api)
            self.assertEqual(409, res.status_int)

    def test_update_optimizer_optp_not_found_on_different_tenant(self):
        with self.optimizer_policy(name='optp1', tenant_id='tenant1',
                                  do_delete=False) as optp1, \
                self.optimizer_policy(name='optp2', shared=False,
                                     tenant_id='tenant2') as optp2:

            optps = [optp1, optp2]
            # create optimizer using optp1 exists the same tenant.
            optp1_id = optps[0]['optimizer_policy']['id']
            optp2_id = optps[1]['optimizer_policy']['id']
            ctx = context.Context('not_admin', 'tenant1')
            with self.optimizer(optimizer_policy_id=optp1_id,
                               context=ctx) as optimizer:
                opt_id = optimizer['optimizer']['id']
                opt_db = self.plugin._get_optimizer(ctx, opt_id)
                opt_db['status'] = constants.ACTIVE
                # update optimizer from optp1 to optp2(different tenant)
                data = {'optimizer': {'optimizer_policy_id': optp2_id}}
                req = self.new_update_request('optimizers', data, opt_id,
                                              context=ctx)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 404)

    def test_delete_optimizer(self):
        ctx = context.get_admin_context()
        with self.optimizer_policy() as optp:
            optp_id = optp['optimizer_policy']['id']
            with self.optimizer(optimizer_policy_id=optp_id,
                               do_delete=False) as opt:
                opt_id = opt['optimizer']['id']
                req = self.new_delete_request('optimizers', opt_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)
                self.assertRaises(optimizer.OptimizerNotFound,
                                  self.plugin.get_optimizer,
                                  ctx, opt_id)

    def test_insert_rule_in_policy_with_prior_rules_added_via_update(self):
        attrs = self._get_test_optimizer_policy_attrs()
        attrs['audited'] = False
        attrs['optimizer_list'] = []
        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3:
            frs = [optr1, optr2, optr3]
            fr1 = frs[0:2]
            optr3 = frs[2]
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['id'] = optp_id
                opt_rule_ids = [r['optimizer_rule']['id'] for r in fr1]
                attrs['optimizer_rules'] = opt_rule_ids[:]
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp_id)
                req.get_response(self.ext_api)
                self._rule_action('insert', optp_id, opt_rule_ids[0],
                                  insert_before=opt_rule_ids[0],
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPConflict.code,
                                  expected_body=None)
                optr3_id = optr3['optimizer_rule']['id']
                attrs['optimizer_rules'].insert(0, optr3_id)
                self._rule_action('insert', optp_id, optr3_id,
                                  insert_before=opt_rule_ids[0],
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)

    def test_insert_rule_in_policy_failures(self):
        with self.optimizer_rule(name='optr1') as fr1:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                fr1_id = fr1['optimizer_rule']['id']
                opt_rule_ids = [fr1_id]
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp_id)
                req.get_response(self.ext_api)
                # test inserting with empty request body
                self._rule_action('insert', optp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None, body_data={})
                # test inserting when optimizer_rule_id is missing in
                # request body
                insert_data = {'insert_before': '123',
                               'insert_after': '456'}
                self._rule_action('insert', optp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None,
                                  body_data=insert_data)
                # test inserting when optimizer_rule_id is None
                insert_data = {'optimizer_rule_id': None,
                               'insert_before': '123',
                               'insert_after': '456'}
                self._rule_action('insert', optp_id, '123',
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None,
                                  body_data=insert_data)
                # test inserting when optimizer_policy_id is incorrect
                self._rule_action('insert', '123', fr1_id,
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test inserting when optimizer_policy_id is None
                self._rule_action('insert', None, fr1_id,
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)

    def test_insert_rule_for_previously_associated_rule(self):
        with self.optimizer_rule() as optr:
            optr_id = optr['optimizer_rule']['id']
            opt_rule_ids = [optr_id]
            with self.optimizer_policy(optimizer_rules=opt_rule_ids):
                with self.optimizer_policy(name='optimizer_policy2') as optp:
                    optp_id = optp['optimizer_policy']['id']
                    insert_data = {'optimizer_rule_id': optr_id}
                    self._rule_action(
                        'insert', optp_id, optr_id, insert_before=None,
                        insert_after=None,
                        expected_code=webob.exc.HTTPConflict.code,
                        expected_body=None, body_data=insert_data)

    def test_insert_rule_for_prev_associated_ref_rule(self):
        with self.optimizer_rule(name='optr0') as optr0, \
                self.optimizer_rule(name='optr1') as optr1:
            optr = [optr0, optr1]
            optr0_id = optr[0]['optimizer_rule']['id']
            optr1_id = optr[1]['optimizer_rule']['id']
            with self.optimizer_policy(name='optp0') as optp0, \
                    self.optimizer_policy(name='optp1',
                             optimizer_rules=[optr1_id]) as optp1:
                optp = [optp0, optp1]
                optp0_id = optp[0]['optimizer_policy']['id']
                # test inserting before a rule which
                # is associated with different policy
                self._rule_action('insert', optp0_id, optr0_id,
                        insert_before=optr1_id,
                        expected_code=webob.exc.HTTPBadRequest.code,
                        expected_body=None)
                # test inserting  after a rule which
                # is associated with different policy
                self._rule_action('insert', optp0_id, optr0_id,
                        insert_after=optr1_id,
                        expected_code=webob.exc.HTTPBadRequest.code,
                        expected_body=None)

    def test_insert_rule_for_policy_of_other_tenant(self):
        with self.optimizer_rule(tenant_id='tenant-2', shared=False) as optr:
            optr_id = optr['optimizer_rule']['id']
            with self.optimizer_policy(name='optimizer_policy') as optp:
                optp_id = optp['optimizer_policy']['id']
                insert_data = {'optimizer_rule_id': optr_id}
                self._rule_action(
                    'insert', optp_id, optr_id, insert_before=None,
                    insert_after=None,
                    expected_code=webob.exc.HTTPConflict.code,
                    expected_body=None, body_data=insert_data)

    def test_insert_rule_in_policy(self):
        attrs = self._get_test_optimizer_policy_attrs()
        attrs['audited'] = False
        attrs['optimizer_list'] = []
        with self.optimizer_rule(name='optr0') as optr0, \
                self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3, \
                self.optimizer_rule(name='optr4') as optr4, \
                self.optimizer_rule(name='optr5') as optr5, \
                self.optimizer_rule(name='optr6') as optr6:
            optr = [optr0, optr1, optr2, optr3, optr4, optr5, optr6]
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['id'] = optp_id
                # test insert when rule list is empty
                optr0_id = optr[0]['optimizer_rule']['id']
                attrs['optimizer_rules'].insert(0, optr0_id)
                self._rule_action('insert', optp_id, optr0_id,
                                  insert_before=None,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert at top of rule list, insert_before and
                # insert_after not provided
                optr1_id = optr[1]['optimizer_rule']['id']
                attrs['optimizer_rules'].insert(0, optr1_id)
                insert_data = {'optimizer_rule_id': optr1_id}
                self._rule_action('insert', optp_id, optr0_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs, body_data=insert_data)
                # test insert at top of list above existing rule
                optr2_id = optr[2]['optimizer_rule']['id']
                attrs['optimizer_rules'].insert(0, optr2_id)
                self._rule_action('insert', optp_id, optr2_id,
                                  insert_before=optr1_id,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert at bottom of list
                optr3_id = optr[3]['optimizer_rule']['id']
                attrs['optimizer_rules'].append(optr3_id)
                self._rule_action('insert', optp_id, optr3_id,
                                  insert_before=None,
                                  insert_after=optr0_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert in the middle of the list using
                # insert_before
                optr4_id = optr[4]['optimizer_rule']['id']
                attrs['optimizer_rules'].insert(1, optr4_id)
                self._rule_action('insert', optp_id, optr4_id,
                                  insert_before=optr1_id,
                                  insert_after=None,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert in the middle of the list using
                # insert_after
                optr5_id = optr[5]['optimizer_rule']['id']
                attrs['optimizer_rules'].insert(1, optr5_id)
                self._rule_action('insert', optp_id, optr5_id,
                                  insert_before=None,
                                  insert_after=optr2_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)
                # test insert when both insert_before and
                # insert_after are set
                optr6_id = optr[6]['optimizer_rule']['id']
                attrs['optimizer_rules'].insert(1, optr6_id)
                self._rule_action('insert', optp_id, optr6_id,
                                  insert_before=optr5_id,
                                  insert_after=optr5_id,
                                  expected_code=webob.exc.HTTPOk.code,
                                  expected_body=attrs)

    def test_remove_rule_from_policy(self):
        attrs = self._get_test_optimizer_policy_attrs()
        attrs['audited'] = False
        attrs['optimizer_list'] = []
        with self.optimizer_rule(name='optr1') as optr1, \
                self.optimizer_rule(name='optr2') as optr2, \
                self.optimizer_rule(name='optr3') as optr3:
            fr1 = [optr1, optr2, optr3]
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                attrs['id'] = optp_id
                opt_rule_ids = [r['optimizer_rule']['id'] for r in fr1]
                attrs['optimizer_rules'] = opt_rule_ids[:]
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp_id)
                req.get_response(self.ext_api)
                # test removing a rule from a policy that does not exist
                self._rule_action('remove', '123', opt_rule_ids[1],
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test removing a rule in the middle of the list
                attrs['optimizer_rules'].remove(opt_rule_ids[1])
                self._rule_action('remove', optp_id, opt_rule_ids[1],
                                  expected_body=attrs)
                # test removing a rule at the top of the list
                attrs['optimizer_rules'].remove(opt_rule_ids[0])
                self._rule_action('remove', optp_id, opt_rule_ids[0],
                                  expected_body=attrs)
                # test removing remaining rule in the list
                attrs['optimizer_rules'].remove(opt_rule_ids[2])
                self._rule_action('remove', optp_id, opt_rule_ids[2],
                                  expected_body=attrs)
                # test removing rule that is not associated with the policy
                self._rule_action('remove', optp_id, opt_rule_ids[2],
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None)

    def test_remove_rule_from_policy_failures(self):
        with self.optimizer_rule(name='optr1') as fr1:
            with self.optimizer_policy() as optp:
                optp_id = optp['optimizer_policy']['id']
                opt_rule_ids = [fr1['optimizer_rule']['id']]
                data = {'optimizer_policy':
                        {'optimizer_rules': opt_rule_ids}}
                req = self.new_update_request('optimizer_policies', data,
                                              optp_id)
                req.get_response(self.ext_api)
                # test removing rule that does not exist
                self._rule_action('remove', optp_id, '123',
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None)
                # test removing rule with bad request
                self._rule_action('remove', optp_id, '123',
                                  expected_code=webob.exc.HTTPBadRequest.code,
                                  expected_body=None, body_data={})
                # test removing rule with optimizer_rule_id set to None
                self._rule_action('remove', optp_id, '123',
                                  expected_code=webob.exc.HTTPNotFound.code,
                                  expected_body=None,
                                  body_data={'optimizer_rule_id': None})

    def test_check_router_has_no_optimizer_raises(self):
        with mock.patch.object(
            manager.NeutronManager, 'get_service_plugins') as sp:
            opt_plugin = mock.Mock()
            sp.return_value = {'OPTIMIZER': opt_plugin}
            opt_plugin.get_optimizers.return_value = [mock.ANY]
            kwargs = {
                'context': mock.ANY,
                'router': {'id': 'foo_id', 'tenant_id': 'foo_tenant'}
            }
            self.assertRaises(
                l3.RouterInUse,
                fdb.migration_callback,
                'router', 'before_event', mock.ANY,
                **kwargs)

    def test_check_router_has_no_optimizer_passes(self):
        with mock.patch.object(manager.NeutronManager,
                               'get_service_plugins',
                               return_value={}):
            kwargs = {'context': mock.ANY, 'router': mock.ANY}
            self.assertIsNone(fdb.migration_callback(
                mock.ANY, mock.ANY, mock.ANY, **kwargs))
