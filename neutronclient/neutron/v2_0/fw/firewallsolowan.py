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



#OaaS toda la clase
class CreateFirewallSolowan(neutronv20.CreateCommand):
    """Start solowan"""
    resource = 'firewall_solowan'

class UpdateFirewallSolowan(neutronv20.UpdateCommand):
    """Restart solowan"""
    resource = 'firewall_solowan'

class DeleteFirewallSolowan(neutronv20.DeleteCommand):
    """Stop solowan"""
    resource = 'firewall_solowan'

class ListFirewallSolowan(neutronv20.ListCommand):
    resource = 'firewall_solowan'

class ShowFirewallSolowan(neutronv20.ShowCommand):
    resource = 'firewall_solowan'

      
