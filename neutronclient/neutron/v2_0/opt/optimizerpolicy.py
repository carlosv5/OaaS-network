# Copyright 2013 Big Switch Networks
# All Rights Reserved
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
#

from __future__ import print_function

import argparse

from neutronclient.i18n import _
from neutronclient.neutron import v2_0 as neutronv20


def _format_optimizer_rules(optimizer_policy):
    try:
        output = '[' + ',\n '.join([rule for rule in
                                    optimizer_policy['optimizer_rules']]) + ']'
        return output
    except (TypeError, KeyError):
        return ''


def common_add_known_arguments(parser):
    parser.add_argument(
        '--optimizer-rules', type=lambda x: x.split(),
        help=_('Ordered list of whitespace-delimited optimizer rule '
               'names or IDs; e.g., --optimizer-rules \"rule1 rule2\"'))


def common_args2body(client, parsed_args):
    if parsed_args.optimizer_rules:
        _optimizer_rules = []
        for f in parsed_args.optimizer_rules:
            _optimizer_rules.append(
                neutronv20.find_resourceid_by_name_or_id(
                    client, 'optimizer_rule', f))
        body = {'optimizer_policy': {'optimizer_rules': _optimizer_rules}}
    else:
        body = {'optimizer_policy': {}}
    neutronv20.update_dict(parsed_args, body['optimizer_policy'],
                           ['name', 'description', 'shared',
                            'audited', 'tenant_id'])
    return body


class ListOptimizerPolicy(neutronv20.ListCommand):
    """List optimizer policies that belong to a given tenant."""

    resource = 'optimizer_policy'
    list_columns = ['id', 'name', 'optimizer_rules']
    _formatters = {'optimizer_rules': _format_optimizer_rules,
                   }
    pagination_support = True
    sorting_support = True


class ShowOptimizerPolicy(neutronv20.ShowCommand):
    """Show information of a given optimizer policy."""

    resource = 'optimizer_policy'


class CreateOptimizerPolicy(neutronv20.CreateCommand):
    """Create a optimizer policy."""

    resource = 'optimizer_policy'

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name',
            metavar='NAME',
            help=_('Name for the optimizer policy.'))
        parser.add_argument(
            '--description',
            help=_('Description for the optimizer policy.'))
        parser.add_argument(
            '--shared',
            dest='shared',
            action='store_true',
            help=_('Create a shared policy.'),
            default=argparse.SUPPRESS)
        common_add_known_arguments(parser)
        parser.add_argument(
            '--audited',
            action='store_true',
            help=_('Sets audited to True.'),
            default=argparse.SUPPRESS)

    def args2body(self, parsed_args):
        return common_args2body(self.get_client(), parsed_args)


class UpdateOptimizerPolicy(neutronv20.UpdateCommand):
    """Update a given optimizer policy."""

    resource = 'optimizer_policy'

    def add_known_arguments(self, parser):
        common_add_known_arguments(parser)

    def args2body(self, parsed_args):
        return common_args2body(self.get_client(), parsed_args)


class DeleteOptimizerPolicy(neutronv20.DeleteCommand):
    """Delete a given optimizer policy."""

    resource = 'optimizer_policy'


class OptimizerPolicyInsertRule(neutronv20.UpdateCommand):
    """Insert a rule into a given optimizer policy."""

    resource = 'optimizer_policy'

    def call_api(self, neutron_client, optimizer_policy_id, body):
        return neutron_client.optimizer_policy_insert_rule(optimizer_policy_id,
                                                          body)

    def args2body(self, parsed_args):
        _rule = ''
        if parsed_args.optimizer_rule_id:
            _rule = neutronv20.find_resourceid_by_name_or_id(
                self.get_client(), 'optimizer_rule',
                parsed_args.optimizer_rule_id)
        _insert_before = ''
        if 'insert_before' in parsed_args:
            if parsed_args.insert_before:
                _insert_before = neutronv20.find_resourceid_by_name_or_id(
                    self.get_client(), 'optimizer_rule',
                    parsed_args.insert_before)
        _insert_after = ''
        if 'insert_after' in parsed_args:
            if parsed_args.insert_after:
                _insert_after = neutronv20.find_resourceid_by_name_or_id(
                    self.get_client(), 'optimizer_rule',
                    parsed_args.insert_after)
        body = {'optimizer_rule_id': _rule,
                'insert_before': _insert_before,
                'insert_after': _insert_after}
        neutronv20.update_dict(parsed_args, body, [])
        return body

    def get_parser(self, prog_name):
        parser = super(OptimizerPolicyInsertRule, self).get_parser(prog_name)
        parser.add_argument(
            '--insert-before',
            metavar='OPTIMIZER_RULE',
            help=_('Insert before this rule.'))
        parser.add_argument(
            '--insert-after',
            metavar='OPTIMIZER_RULE',
            help=_('Insert after this rule.'))
        parser.add_argument(
            'optimizer_rule_id',
            metavar='OPTIMIZER_RULE',
            help=_('New rule to insert.'))
        self.add_known_arguments(parser)
        return parser

    def run(self, parsed_args):
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        body = self.args2body(parsed_args)
        _id = neutronv20.find_resourceid_by_name_or_id(neutron_client,
                                                       self.resource,
                                                       parsed_args.id)
        self.call_api(neutron_client, _id, body)
        print((_('Inserted optimizer rule in optimizer policy %(id)s') %
               {'id': parsed_args.id}), file=self.app.stdout)


class OptimizerPolicyRemoveRule(neutronv20.UpdateCommand):
    """Remove a rule from a given optimizer policy."""

    resource = 'optimizer_policy'

    def call_api(self, neutron_client, optimizer_policy_id, body):
        return neutron_client.optimizer_policy_remove_rule(optimizer_policy_id,
                                                          body)

    def args2body(self, parsed_args):
        _rule = ''
        if parsed_args.optimizer_rule_id:
            _rule = neutronv20.find_resourceid_by_name_or_id(
                self.get_client(), 'optimizer_rule',
                parsed_args.optimizer_rule_id)
        body = {'optimizer_rule_id': _rule}
        neutronv20.update_dict(parsed_args, body, [])
        return body

    def get_parser(self, prog_name):
        parser = super(OptimizerPolicyRemoveRule, self).get_parser(prog_name)
        parser.add_argument(
            'optimizer_rule_id',
            metavar='OPTIMIZER_RULE',
            help=_('Optimizer rule to remove from policy.'))
        self.add_known_arguments(parser)
        return parser

    def run(self, parsed_args):
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        body = self.args2body(parsed_args)
        _id = neutronv20.find_resourceid_by_name_or_id(neutron_client,
                                                       self.resource,
                                                       parsed_args.id)
        self.call_api(neutron_client, _id, body)
        print((_('Removed optimizer rule from optimizer policy %(id)s') %
               {'id': parsed_args.id}), file=self.app.stdout)
