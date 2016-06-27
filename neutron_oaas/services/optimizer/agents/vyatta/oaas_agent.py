# Copyright 2015 Brocade Communications System, Inc.
# All Rights Reserved.
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

from networking_brocade.vyatta.common import l3_agent as vyatta_l3
from neutron.agent import l3_agent

from neutron_oaas.services.optimizer.agents.vyatta import optimizer_service


class VyattaOptimizerAgent(vyatta_l3.L3AgentMiddleware):
    """Brocade Neutron Optimizer agent for Vyatta vRouter.

    The base class OaaSL3AgentRpcCallback of the VyattaOptimizerAgent creates
    the reference OptimizerService object that loads the VyattaOptimizerDriver
    class.The VyattaOptimizerService class registers callbacks and subscribes
    to router events.
    """
    def __init__(self, host, conf=None):
        super(VyattaOptimizerAgent, self).__init__(host, conf)
        self.service = optimizer_service.VyattaOptimizerService(self)


def main():
    l3_agent.main(
        manager='neutron_oaas.services.optimizer.agents.vyatta.'
                'oaas_agent.VyattaOptimizerAgent')
