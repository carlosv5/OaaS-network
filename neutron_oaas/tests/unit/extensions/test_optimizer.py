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

import copy

import mock
from neutron.api.v2 import attributes as attr
from neutron.plugins.common import constants
from neutron.tests import base
from neutron.tests.unit.api.v2 import test_base as test_api_v2
from neutron.tests.unit.extensions import base as test_api_v2_extension
from oslo_utils import uuidutils
from webob import exc
import webtest

from neutron_oaas.extensions import optimizer

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path
_long_name = 'x' * (attr.NAME_MAX_LEN + 1)
_long_description = 'y' * (attr.DESCRIPTION_MAX_LEN + 1)


class OptimizerExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(OptimizerExtensionTestCase, self).setUp()
        plural_mappings = {'optimizer_policy': 'optimizer_policies'}
        self._setUpExtension(
            'neutron_oaas.extensions.optimizer.OptimizerPluginBase',
            constants.OPTIMIZER, optimizer.RESOURCE_ATTRIBUTE_MAP,
            optimizer.Optimizer, 'opt', plural_mappings=plural_mappings)

    def test_create_optimizer(self):
        opt_id = _uuid()
        data = {'optimizer': {'description': 'descr_optimizer1',
                             'name': 'optimizer1',
                             'admin_state_up': True,
                             'optimizer_policy_id': _uuid(),
                             'shared': False,
                             'tenant_id': _uuid()}}
        return_value = copy.copy(data['optimizer'])
        return_value.update({'id': opt_id})
        # since 'shared' is hidden
        del return_value['shared']

        instance = self.plugin.return_value
        instance.create_optimizer.return_value = return_value
        res = self.api.post(_get_path('opt/optimizers', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_optimizer.assert_called_with(mock.ANY,
                                                    optimizer=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('optimizer', res)
        self.assertEqual(res['optimizer'], return_value)

    def test_create_optimizer_invalid_long_name(self):
        data = {'optimizer': {'description': 'descr_optimizer1',
                             'name': _long_name,
                             'admin_state_up': True,
                             'optimizer_policy_id': _uuid(),
                             'shared': False,
                             'tenant_id': _uuid()}}
        res = self.api.post(_get_path('opt/optimizers', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertTrue('Invalid input for name' in res.body.decode('utf-8'))

    def test_create_optimizer_invalid_long_description(self):
        data = {'optimizer': {'description': _long_description,
                             'name': 'optimizer1',
                             'admin_state_up': True,
                             'optimizer_policy_id': _uuid(),
                             'shared': False,
                             'tenant_id': _uuid()}}
        res = self.api.post(_get_path('opt/optimizers', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertTrue('Invalid input '
                        'for description' in res.body.decode('utf-8'))

    def test_optimizer_list(self):
        opt_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': opt_id}]

        instance = self.plugin.return_value
        instance.get_optimizers.return_value = return_value

        res = self.api.get(_get_path('opt/optimizers', fmt=self.fmt))

        instance.get_optimizers.assert_called_with(mock.ANY,
                                                  fields=mock.ANY,
                                                  filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_optimizer_get(self):
        opt_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': opt_id}

        instance = self.plugin.return_value
        instance.get_optimizer.return_value = return_value

        res = self.api.get(_get_path('opt/optimizers',
                                     id=opt_id, fmt=self.fmt))

        instance.get_optimizer.assert_called_with(mock.ANY,
                                                 opt_id,
                                                 fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('optimizer', res)
        self.assertEqual(res['optimizer'], return_value)

    def test_optimizer_update(self):
        opt_id = _uuid()
        update_data = {'optimizer': {'name': 'new_name'}}
        return_value = {'tenant_id': _uuid(),
                        'id': opt_id}

        instance = self.plugin.return_value
        instance.update_optimizer.return_value = return_value

        res = self.api.put(_get_path('opt/optimizers', id=opt_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_optimizer.assert_called_with(mock.ANY, opt_id,
                                                    optimizer=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('optimizer', res)
        self.assertEqual(res['optimizer'], return_value)

    def test_optimizer_delete(self):
        self._test_entity_delete('optimizer')

    def _test_create_optimizer_rule(self, src_port, dst_port):
        rule_id = _uuid()
        data = {'optimizer_rule': {'description': 'descr_optimizer_rule1',
                                  'name': 'rule1',
                                  'shared': False,
                                  'protocol': 'tcp',
                                  'ip_version': 4,
                                  'source_ip_address': '192.168.0.1',
                                  'destination_ip_address': '127.0.0.1',
                                  'source_port': src_port,
                                  'destination_port': dst_port,
                                  'action': 'allow',
                                  'enabled': True,
                                  'tenant_id': _uuid()}}
        expected_ret_val = copy.copy(data['optimizer_rule'])
        expected_ret_val['source_port'] = str(src_port)
        expected_ret_val['destination_port'] = str(dst_port)
        expected_call_args = copy.copy(expected_ret_val)
        expected_ret_val['id'] = rule_id
        instance = self.plugin.return_value
        instance.create_optimizer_rule.return_value = expected_ret_val
        res = self.api.post(_get_path('opt/optimizer_rules', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_optimizer_rule.assert_called_with(
            mock.ANY,
            optimizer_rule={'optimizer_rule': expected_call_args})
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('optimizer_rule', res)
        self.assertEqual(res['optimizer_rule'], expected_ret_val)

    def test_create_optimizer_rule_with_integer_ports(self):
        self._test_create_optimizer_rule(1, 10)

    def test_create_optimizer_rule_with_string_ports(self):
        self._test_create_optimizer_rule('1', '10')

    def test_create_optimizer_rule_with_port_range(self):
        self._test_create_optimizer_rule('1:20', '30:40')

    def test_create_optimizer_rule_invalid_long_name(self):
        data = {'optimizer_rule': {'description': 'descr_optimizer_rule1',
                                  'name': _long_name,
                                  'shared': False,
                                  'protocol': 'tcp',
                                  'ip_version': 4,
                                  'source_ip_address': '192.168.0.1',
                                  'destination_ip_address': '127.0.0.1',
                                  'source_port': 1,
                                  'destination_port': 1,
                                  'action': 'allow',
                                  'enabled': True,
                                  'tenant_id': _uuid()}}
        res = self.api.post(_get_path('opt/optimizer_rules', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertTrue('Invalid input for name' in res.body.decode('utf-8'))

    def test_create_optimizer_rule_invalid_long_description(self):
        data = {'optimizer_rule': {'description': _long_description,
                                  'name': 'rule1',
                                  'shared': False,
                                  'protocol': 'tcp',
                                  'ip_version': 4,
                                  'source_ip_address': '192.168.0.1',
                                  'destination_ip_address': '127.0.0.1',
                                  'source_port': 1,
                                  'destination_port': 1,
                                  'action': 'allow',
                                  'enabled': True,
                                  'tenant_id': _uuid()}}
        res = self.api.post(_get_path('opt/optimizer_rules', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertTrue('Invalid input '
                        'for description' in res.body.decode('utf-8'))

    def test_optimizer_rule_list(self):
        rule_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': rule_id}]

        instance = self.plugin.return_value
        instance.get_optimizer_rules.return_value = return_value

        res = self.api.get(_get_path('opt/optimizer_rules', fmt=self.fmt))

        instance.get_optimizer_rules.assert_called_with(mock.ANY,
                                                       fields=mock.ANY,
                                                       filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_optimizer_rule_get(self):
        rule_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': rule_id}

        instance = self.plugin.return_value
        instance.get_optimizer_rule.return_value = return_value

        res = self.api.get(_get_path('opt/optimizer_rules',
                                     id=rule_id, fmt=self.fmt))

        instance.get_optimizer_rule.assert_called_with(mock.ANY,
                                                      rule_id,
                                                      fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('optimizer_rule', res)
        self.assertEqual(res['optimizer_rule'], return_value)

    def test_optimizer_rule_update(self):
        rule_id = _uuid()
        update_data = {'optimizer_rule': {'action': 'deny'}}
        return_value = {'tenant_id': _uuid(),
                        'id': rule_id}

        instance = self.plugin.return_value
        instance.update_optimizer_rule.return_value = return_value

        res = self.api.put(_get_path('opt/optimizer_rules', id=rule_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_optimizer_rule.assert_called_with(
            mock.ANY,
            rule_id,
            optimizer_rule=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('optimizer_rule', res)
        self.assertEqual(res['optimizer_rule'], return_value)

    def test_optimizer_rule_delete(self):
        self._test_entity_delete('optimizer_rule')

    def test_create_optimizer_policy(self):
        policy_id = _uuid()
        data = {'optimizer_policy': {'description': 'descr_optimizer_policy1',
                                    'name': 'new_opt_policy1',
                                    'shared': False,
                                    'optimizer_rules': [_uuid(), _uuid()],
                                    'audited': False,
                                    'tenant_id': _uuid()}}
        return_value = copy.copy(data['optimizer_policy'])
        return_value.update({'id': policy_id})

        instance = self.plugin.return_value
        instance.create_optimizer_policy.return_value = return_value
        res = self.api.post(_get_path('opt/optimizer_policies',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_optimizer_policy.assert_called_with(
            mock.ANY,
            optimizer_policy=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('optimizer_policy', res)
        self.assertEqual(res['optimizer_policy'], return_value)

    def test_create_optimizer_policy_invalid_long_name(self):
        data = {'optimizer_policy': {'description': 'descr_optimizer_policy1',
                                    'name': _long_name,
                                    'shared': False,
                                    'optimizer_rules': [_uuid(), _uuid()],
                                    'audited': False,
                                    'tenant_id': _uuid()}}
        res = self.api.post(_get_path('opt/optimizer_policies',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertTrue('Invalid input for name' in res.body.decode('utf-8'))

    def test_create_optimizer_policy_invalid_long_description(self):
        data = {'optimizer_policy': {'description': _long_description,
                                    'name': 'new_opt_policy1',
                                    'shared': False,
                                    'optimizer_rules': [_uuid(), _uuid()],
                                    'audited': False,
                                    'tenant_id': _uuid()}}
        res = self.api.post(_get_path('opt/optimizer_policies',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt,
                            status=exc.HTTPBadRequest.code)
        self.assertTrue('Invalid input '
                        'for description' in res.body.decode('utf-8'))

    def test_optimizer_policy_list(self):
        policy_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': policy_id}]

        instance = self.plugin.return_value
        instance.get_optimizer_policies.return_value = return_value

        res = self.api.get(_get_path('opt/optimizer_policies',
                                     fmt=self.fmt))

        instance.get_optimizer_policies.assert_called_with(mock.ANY,
                                                          fields=mock.ANY,
                                                          filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_optimizer_policy_get(self):
        policy_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': policy_id}

        instance = self.plugin.return_value
        instance.get_optimizer_policy.return_value = return_value

        res = self.api.get(_get_path('opt/optimizer_policies',
                                     id=policy_id, fmt=self.fmt))

        instance.get_optimizer_policy.assert_called_with(mock.ANY,
                                                        policy_id,
                                                        fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('optimizer_policy', res)
        self.assertEqual(res['optimizer_policy'], return_value)

    def test_optimizer_policy_update(self):
        policy_id = _uuid()
        update_data = {'optimizer_policy': {'audited': True}}
        return_value = {'tenant_id': _uuid(),
                        'id': policy_id}

        instance = self.plugin.return_value
        instance.update_optimizer_policy.return_value = return_value

        res = self.api.put(_get_path('opt/optimizer_policies',
                                     id=policy_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_optimizer_policy.assert_called_with(
            mock.ANY,
            policy_id,
            optimizer_policy=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('optimizer_policy', res)
        self.assertEqual(res['optimizer_policy'], return_value)

    def test_optimizer_policy_update_malformed_rules(self):
        # emulating client request when no rule uuids are provided for
        # --optimizer_rules parameter
        update_data = {'optimizer_policy': {'optimizer_rules': True}}
        # have to check for generic AppError
        self.assertRaises(
            webtest.AppError,
            self.api.put,
            _get_path('opt/optimizer_policies', id=_uuid(), fmt=self.fmt),
            self.serialize(update_data))

    def test_optimizer_policy_delete(self):
        self._test_entity_delete('optimizer_policy')

    def test_optimizer_policy_insert_rule(self):
        optimizer_policy_id = _uuid()
        optimizer_rule_id = _uuid()
        ref_optimizer_rule_id = _uuid()

        insert_data = {'optimizer_rule_id': optimizer_rule_id,
                       'insert_before': ref_optimizer_rule_id,
                       'insert_after': None}
        return_value = {'optimizer_policy':
                        {'tenant_id': _uuid(),
                         'id': optimizer_policy_id,
                         'optimizer_rules': [ref_optimizer_rule_id,
                                            optimizer_rule_id]}}

        instance = self.plugin.return_value
        instance.insert_rule.return_value = return_value

        path = _get_path('opt/optimizer_policies', id=optimizer_policy_id,
                         action="insert_rule",
                         fmt=self.fmt)
        res = self.api.put(path, self.serialize(insert_data))
        instance.insert_rule.assert_called_with(mock.ANY, optimizer_policy_id,
                                                insert_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertEqual(res, return_value)

    def test_optimizer_policy_remove_rule(self):
        optimizer_policy_id = _uuid()
        optimizer_rule_id = _uuid()

        remove_data = {'optimizer_rule_id': optimizer_rule_id}
        return_value = {'optimizer_policy':
                        {'tenant_id': _uuid(),
                         'id': optimizer_policy_id,
                         'optimizer_rules': []}}

        instance = self.plugin.return_value
        instance.remove_rule.return_value = return_value

        path = _get_path('opt/optimizer_policies', id=optimizer_policy_id,
                         action="remove_rule",
                         fmt=self.fmt)
        res = self.api.put(path, self.serialize(remove_data))
        instance.remove_rule.assert_called_with(mock.ANY, optimizer_policy_id,
                                                remove_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertEqual(res, return_value)


class TestOptimizerAttributeValidators(base.BaseTestCase):

    def test_validate_port_range(self):
        msg = optimizer._validate_port_range(None)
        self.assertIsNone(msg)

        msg = optimizer._validate_port_range('10')
        self.assertIsNone(msg)

        msg = optimizer._validate_port_range(10)
        self.assertIsNone(msg)

        msg = optimizer._validate_port_range(-1)
        self.assertEqual(msg, "Invalid port '-1'")

        msg = optimizer._validate_port_range('66000')
        self.assertEqual(msg, "Invalid port '66000'")

        msg = optimizer._validate_port_range('10:20')
        self.assertIsNone(msg)

        msg = optimizer._validate_port_range('1:65535')
        self.assertIsNone(msg)

        msg = optimizer._validate_port_range('0:65535')
        self.assertEqual(msg, "Invalid port '0'")

        msg = optimizer._validate_port_range('1:65536')
        self.assertEqual(msg, "Invalid port '65536'")

        msg = optimizer._validate_port_range('abc:efg')
        self.assertEqual(msg, "Port 'abc' is not a valid number")

        msg = optimizer._validate_port_range('1:efg')
        self.assertEqual(msg, "Port 'efg' is not a valid number")

        msg = optimizer._validate_port_range('-1:10')
        self.assertEqual(msg, "Invalid port '-1'")

        msg = optimizer._validate_port_range('66000:10')
        self.assertEqual(msg, "Invalid port '66000'")

        msg = optimizer._validate_port_range('10:66000')
        self.assertEqual(msg, "Invalid port '66000'")

        msg = optimizer._validate_port_range('1:-10')
        self.assertEqual(msg, "Invalid port '-10'")

    def test_validate_ip_or_subnet_or_none(self):
        msg = optimizer._validate_ip_or_subnet_or_none(None)
        self.assertIsNone(msg)

        msg = optimizer._validate_ip_or_subnet_or_none('1.1.1.1')
        self.assertIsNone(msg)

        msg = optimizer._validate_ip_or_subnet_or_none('1.1.1.0/24')
        self.assertIsNone(msg)

        ip_addr = '1111.1.1.1'
        msg = optimizer._validate_ip_or_subnet_or_none(ip_addr)
        self.assertEqual(msg, ("'%s' is not a valid IP address and "
                               "'%s' is not a valid IP subnet") % (ip_addr,
                                                                   ip_addr))

        ip_addr = '1.1.1.1 has whitespace'
        msg = optimizer._validate_ip_or_subnet_or_none(ip_addr)
        self.assertEqual(msg, ("'%s' is not a valid IP address and "
                               "'%s' is not a valid IP subnet") % (ip_addr,
                                                                   ip_addr))

        ip_addr = '111.1.1.1\twhitespace'
        msg = optimizer._validate_ip_or_subnet_or_none(ip_addr)
        self.assertEqual(msg, ("'%s' is not a valid IP address and "
                               "'%s' is not a valid IP subnet") % (ip_addr,
                                                                   ip_addr))

        ip_addr = '111.1.1.1\nwhitespace'
        msg = optimizer._validate_ip_or_subnet_or_none(ip_addr)
        self.assertEqual(msg, ("'%s' is not a valid IP address and "
                               "'%s' is not a valid IP subnet") % (ip_addr,
                                                                   ip_addr))

        # Valid - IPv4
        cidr = "10.0.2.0/24"
        msg = optimizer._validate_ip_or_subnet_or_none(cidr, None)
        self.assertIsNone(msg)

        # Valid - IPv6 without final octets
        cidr = "fe80::/24"
        msg = optimizer._validate_ip_or_subnet_or_none(cidr, None)
        self.assertIsNone(msg)

        # Valid - IPv6 with final octets
        cidr = "fe80::0/24"
        msg = optimizer._validate_ip_or_subnet_or_none(cidr, None)
        self.assertIsNone(msg)

        cidr = "fe80::"
        msg = optimizer._validate_ip_or_subnet_or_none(cidr, None)
        self.assertIsNone(msg)

        # Invalid - IPv6 with final octets, missing mask
        cidr = "fe80::0"
        msg = optimizer._validate_ip_or_subnet_or_none(cidr, None)
        self.assertIsNone(msg)

        # Invalid - Address format error
        cidr = 'invalid'
        msg = optimizer._validate_ip_or_subnet_or_none(cidr, None)
        self.assertEqual(msg, ("'%s' is not a valid IP address and "
                               "'%s' is not a valid IP subnet") % (cidr,
                                                                   cidr))
