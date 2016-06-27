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

from neutronclient.i18n import _
from neutronclient.neutron import v2_0 as neutronv20


class ListOptimizer(neutronv20.ListCommand):
    """List optimizers that belong to a given tenant."""

    resource = 'optimizer'
    list_columns = ['id', 'name', 'optimizer_policy_id']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowOptimizer(neutronv20.ShowCommand):
    """Show information of a given optimizer."""

    resource = 'optimizer'


class CreateOptimizer(neutronv20.CreateCommand):
    """Create a optimizer."""

    resource = 'optimizer'

    def add_known_arguments(self, parser):
        parser.add_argument(
            'optimizer_policy_id', metavar='POLICY',
            help=_('Optimizer policy name or ID.'))
        parser.add_argument(
            '--name',
            help=_('Name for the optimizer.'))
        parser.add_argument(
            '--description',
            help=_('Description for the optimizer rule.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state',
            action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--router',
            dest='routers',
            metavar='ROUTER',
            action='append',
            help=_('Optimizer associated router names or IDs (requires OaaS '
                   'router insertion extension, this option can be repeated)'))

    def args2body(self, parsed_args):
        client = self.get_client()
        _policy_id = neutronv20.find_resourceid_by_name_or_id(
            client, 'optimizer_policy',
            parsed_args.optimizer_policy_id)
        body = {
            self.resource: {
                'optimizer_policy_id': _policy_id,
                'admin_state_up': parsed_args.admin_state, }, }
        if parsed_args.routers:
            body[self.resource]['router_ids'] = [
                neutronv20.find_resourceid_by_name_or_id(client, 'router', r)
                for r in parsed_args.routers]
        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'tenant_id'])
        return body


class UpdateOptimizer(neutronv20.UpdateCommand):
    """Update a given optimizer."""

    resource = 'optimizer'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--policy', metavar='POLICY',
            help=_('Optimizer policy name or ID.'))
        #OaaS
        parser.add_argument(
            '--solowan',
            dest='solowan',
            metavar="service True| False",
            help=_("Set the state of solowan's service"))
        parser.add_argument(
            '--local_id',
            dest='local_id',
            metavar="local_id IP",
            help=_("Set the local_id IP of Optimizer"))
        parser.add_argument(
            '--action',
            dest='action',
            metavar="action OPTIMIZATION|DEDUPLICATION|'OPTIMIZATION DEDUPLICATION'",
            help=_("Set the action"))
        parser.add_argument(
            '--pkt',
            dest='num_pkt_cache_size',
            metavar="pkt integer'",
            help=_("Set the hash table max number of packets"))



        router_sg = parser.add_mutually_exclusive_group()
        router_sg.add_argument(
            '--router',
            dest='routers',
            metavar='ROUTER',
            action='append',
            help=_('Optimizer associated router names or IDs (requires OaaS '
                   'router insertion extension, this option can be repeated)'))
        router_sg.add_argument(
            '--no-routers',
            action='store_true',
            help=_('Associate no routers with the optimizer (requires OaaS '
                   'router insertion extension)'))

    def args2body(self, parsed_args):
        data = {}
        client = self.get_client()
        if parsed_args.policy:
            _policy_id = neutronv20.find_resourceid_by_name_or_id(
                client, 'optimizer_policy',
                parsed_args.policy)
            data['optimizer_policy_id'] = _policy_id
        if parsed_args.routers:
            data['router_ids'] = [
                neutronv20.find_resourceid_by_name_or_id(client, 'router', r)
                for r in parsed_args.routers]
        elif parsed_args.no_routers:
            data['router_ids'] = []
        #OaaS
        if parsed_args.solowan:
            data['solowan']= parsed_args.solowan
        if parsed_args.local_id:
            data['local_id']= parsed_args.local_id
        if parsed_args.action:
            data['action']= parsed_args.action
        if parsed_args.num_pkt_cache_size:
            data['num_pkt_cache_size']= parsed_args.num_pkt_cache_size


        return {self.resource: data}


class DeleteOptimizer(neutronv20.DeleteCommand):
    """Delete a given optimizer."""

    resource = 'optimizer'
