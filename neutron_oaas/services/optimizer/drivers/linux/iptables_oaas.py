# Copyright 2013 Dell Inc.
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

from neutron.agent.linux import iptables_manager
from neutron.i18n import _LE
from oslo_log import log as logging

from neutron_oaas.extensions import optimizer as opt_ext
from neutron_oaas.services.optimizer.drivers import oaas_base
#OaaS
from neutron.agent.linux import utils as linux_utils
import subprocess
import os


LOG = logging.getLogger(__name__)
OAAS_DRIVER_NAME = 'Oaas iptables driver'
OAAS_DEFAULT_CHAIN = 'oaas-default-policy'

#OaaS
OAAS_TO_IPTABLE_ACTION_MAP = {'allow': 'ACCEPT',
                               'deny': 'DROP',
                               'reject': 'REJECT',
				'optimize': 'NFQUEUE --queue-num 0 --queue-bypass'}
INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'
CHAIN_NAME_PREFIX = {INGRESS_DIRECTION: 'i',
                     EGRESS_DIRECTION: 'o'}

""" Optimizer rules are applied on internal-interfaces of Neutron router.
    The packets ingressing tenant's network will be on the output
    direction on internal-interfaces.
"""
IPTABLES_DIR = {INGRESS_DIRECTION: '-o',
                EGRESS_DIRECTION: '-i'}
IPV4 = 'ipv4'
IPV6 = 'ipv6'
IP_VER_TAG = {IPV4: 'v4',
              IPV6: 'v6'}

INTERNAL_DEV_PREFIX = 'qr-'
SNAT_INT_DEV_PREFIX = 'sg-'
ROUTER_2_FIP_DEV_PREFIX = 'rfp-'


class IptablesOaasDriver(oaas_base.OaasDriverBase):
    """IPTables driver for Optimizer As A Service."""

    def __init__(self):
        LOG.debug("Initializing oaas iptables driver")

    def create_optimizer(self, agent_mode, apply_list, optimizer):
        LOG.debug('Creating optimizer %(opt_id)s for tenant %(tid)s)',
                  {'opt_id': optimizer['id'], 'tid': optimizer['tenant_id']})
#OaaS
        namespace = "qrouter-%s" % str(optimizer['add-router-ids']).strip("u['']")
        self.solowan_create_folder(namespace)
        try:
            if optimizer['admin_state_up']:
                self._setup_optimizer(agent_mode, apply_list, optimizer)
            else:
                self.apply_default_policy(agent_mode, apply_list, optimizer)
        except (LookupError, RuntimeError):
            # catch known library exceptions and raise Oaas generic exception
            LOG.exception(_LE("Failed to create optimizer: %s"), optimizer['id'])
            raise opt_ext.OptimizerInternalDriverError(driver=OAAS_DRIVER_NAME)

    def _get_ipt_mgrs_with_if_prefix(self, agent_mode, router_info):
        """Gets the iptables manager along with the if prefix to apply rules.

        With DVR we can have differing namespaces depending on which agent
        (on Network or Compute node). Also, there is an associated i/f for
        each namespace. The iptables on the relevant namespace and matching
        i/f are provided. On the Network node we could have both the snat
        namespace and a fip so this is provided back as a list - so in that
        scenario rules can be applied on both.
        """
        if not router_info.router.get('distributed'):
            return [{'ipt': router_info.iptables_manager,
                     'if_prefix': INTERNAL_DEV_PREFIX}]
        ipt_mgrs = []
        # TODO(sridar): refactor to get strings to a common location.
        if agent_mode == 'dvr_snat':
            if router_info.snat_iptables_manager:
                ipt_mgrs.append({'ipt': router_info.snat_iptables_manager,
                                 'if_prefix': SNAT_INT_DEV_PREFIX})
        if router_info.dist_fip_count:
            # handle the fip case on n/w or compute node.
            ipt_mgrs.append({'ipt': router_info.iptables_manager,
                             'if_prefix': ROUTER_2_FIP_DEV_PREFIX})
        return ipt_mgrs

    def delete_optimizer(self, agent_mode, apply_list, optimizer):
        LOG.debug('Deleting optimizer %(opt_id)s for tenant %(tid)s)',
                  {'opt_id': optimizer['id'], 'tid': optimizer['tenant_id']})
        optid = optimizer['id']
#OaaS
        namespace = "qrouter-%s" % str(optimizer['router_ids']).strip("u['']")
        self.solowan_delete_folder(optimizer['solowan'],namespace)

        try:
            for router_info in apply_list:
                ipt_if_prefix_list = self._get_ipt_mgrs_with_if_prefix(
                    agent_mode, router_info)
                for ipt_if_prefix in ipt_if_prefix_list:
                    ipt_mgr = ipt_if_prefix['ipt']
                    self._remove_chains(optid, ipt_mgr)
                    self._remove_default_chains(ipt_mgr)
                    # apply the changes immediately (no defer in optimizer path)
                    ipt_mgr.defer_apply_off()
        except (LookupError, RuntimeError):
            # catch known library exceptions and raise Oaas generic exception
            LOG.exception(_LE("Failed to delete optimizer: %s"), optid)
            raise opt_ext.OptimizerInternalDriverError(driver=OAAS_DRIVER_NAME)

    def update_optimizer(self, agent_mode, apply_list, optimizer):
        LOG.debug('Updating optimizer %(opt_id)s for tenant %(tid)s)',
                  {'opt_id': optimizer['id'], 'tid': optimizer['tenant_id']})
#OaaS
        namespace = "qrouter-%s" % str(optimizer['add-router-ids']).strip("u['']")
        local_id = optimizer['local_id'].split("/")[0]

        try:
            if optimizer['admin_state_up']:
                self._setup_optimizer(agent_mode, apply_list, optimizer)
		#OaaS
                self.solowan_localid(local_id,namespace)
                self.solowan_action(optimizer['action'],namespace)
                self.solowan_pkt(optimizer['num_pkt_cache_size'],namespace)
                self.solowan_service(optimizer['solowan'],namespace)



            else:
                self.apply_default_policy(agent_mode, apply_list, optimizer)
        except (LookupError, RuntimeError):
            # catch known library exceptions and raise Oaas generic exception
            LOG.exception(_LE("Failed to update optimizer: %s"), optimizer['id'])
            raise opt_ext.OptimizerInternalDriverError(driver=OAAS_DRIVER_NAME)

    def apply_default_policy(self, agent_mode, apply_list, optimizer):
        LOG.debug('Applying optimizer %(opt_id)s for tenant %(tid)s)',
                  {'opt_id': optimizer['id'], 'tid': optimizer['tenant_id']})
        optid = optimizer['id']
        try:
            for router_info in apply_list:
                ipt_if_prefix_list = self._get_ipt_mgrs_with_if_prefix(
                    agent_mode, router_info)
                for ipt_if_prefix in ipt_if_prefix_list:
                    # the following only updates local memory; no hole in FW
                    ipt_mgr = ipt_if_prefix['ipt']
                    self._remove_chains(optid, ipt_mgr)
                    self._remove_default_chains(ipt_mgr)

                    # create default 'DROP ALL' policy chain
                    self._add_default_policy_chain_v4v6(ipt_mgr)
                    self._enable_policy_chain(optid, ipt_if_prefix)

                    # apply the changes immediately (no defer in optimizer path)
                    ipt_mgr.defer_apply_off()
        except (LookupError, RuntimeError):
            # catch known library exceptions and raise Oaas generic exception
            LOG.exception(
                _LE("Failed to apply default policy on optimizer: %s"), optid)
            raise opt_ext.OptimizerInternalDriverError(driver=OAAS_DRIVER_NAME)

    def _setup_optimizer(self, agent_mode, apply_list, optimizer):
        optid = optimizer['id']
        for router_info in apply_list:
            ipt_if_prefix_list = self._get_ipt_mgrs_with_if_prefix(
                agent_mode, router_info)
            for ipt_if_prefix in ipt_if_prefix_list:
                ipt_mgr = ipt_if_prefix['ipt']
                # the following only updates local memory; no hole in FW
                self._remove_chains(optid, ipt_mgr)
                self._remove_default_chains(ipt_mgr)

                # create default 'DROP ALL' policy chain
                self._add_default_policy_chain_v4v6(ipt_mgr)
                #create chain based on configured policy
                self._setup_chains(optimizer, ipt_if_prefix)

                # apply the changes immediately (no defer in optimizer path)
                ipt_mgr.defer_apply_off()

    def _get_chain_name(self, optid, ver, direction):
        return '%s%s%s' % (CHAIN_NAME_PREFIX[direction],
                           IP_VER_TAG[ver],
                           optid)

    def _setup_chains(self, optimizer, ipt_if_prefix):
        """Create Oaas chain using the rules in the policy
        """
        opt_rules_list = optimizer['optimizer_rule_list']
        optid = optimizer['id']
        ipt_mgr = ipt_if_prefix['ipt']

        #default rules for invalid packets and established sessions
        invalid_rule = self._drop_invalid_packets_rule()
        est_rule = self._allow_established_rule()

        for ver in [IPV4, IPV6]:
            if ver == IPV4:
                table = ipt_mgr.ipv4['filter']
            else:
                table = ipt_mgr.ipv6['filter']
            ichain_name = self._get_chain_name(optid, ver, INGRESS_DIRECTION)
            ochain_name = self._get_chain_name(optid, ver, EGRESS_DIRECTION)
            for name in [ichain_name, ochain_name]:
                table.add_chain(name)
                table.add_rule(name, invalid_rule)
                table.add_rule(name, est_rule)

        for rule in opt_rules_list:
            if not rule['enabled']:
                continue
            iptbl_rule = self._convert_oaas_to_iptables_rule(rule)
            if rule['ip_version'] == 4:
                ver = IPV4
                table = ipt_mgr.ipv4['filter']
            else:
                ver = IPV6
                table = ipt_mgr.ipv6['filter']
	    ichain_name = self._get_chain_name(optid, ver, INGRESS_DIRECTION)
            ochain_name = self._get_chain_name(optid, ver, EGRESS_DIRECTION)

#OaaS
            if  rule.get('action') == 'optimize':
                table.add_rule(ichain_name, iptbl_rule,top=True)
                table.add_rule(ochain_name, iptbl_rule,top=True)
            else:
                table.add_rule(ichain_name, iptbl_rule)
                table.add_rule(ochain_name, iptbl_rule)

        self._enable_policy_chain(optid, ipt_if_prefix)

    def _remove_default_chains(self, nsid):
        """Remove oaas default policy chain."""
        self._remove_chain_by_name(IPV4, OAAS_DEFAULT_CHAIN, nsid)
        self._remove_chain_by_name(IPV6, OAAS_DEFAULT_CHAIN, nsid)

    def _remove_chains(self, optid, ipt_mgr):
        """Remove oaas policy chain."""
        for ver in [IPV4, IPV6]:
            for direction in [INGRESS_DIRECTION, EGRESS_DIRECTION]:
                chain_name = self._get_chain_name(optid, ver, direction)
                self._remove_chain_by_name(ver, chain_name, ipt_mgr)

    def _add_default_policy_chain_v4v6(self, ipt_mgr):
        ipt_mgr.ipv4['filter'].add_chain(OAAS_DEFAULT_CHAIN)
        ipt_mgr.ipv4['filter'].add_rule(OAAS_DEFAULT_CHAIN, '-j DROP')
        ipt_mgr.ipv6['filter'].add_chain(OAAS_DEFAULT_CHAIN)
        ipt_mgr.ipv6['filter'].add_rule(OAAS_DEFAULT_CHAIN, '-j DROP')

    def _remove_chain_by_name(self, ver, chain_name, ipt_mgr):
        if ver == IPV4:
            ipt_mgr.ipv4['filter'].remove_chain(chain_name)
        else:
            ipt_mgr.ipv6['filter'].remove_chain(chain_name)

    def _add_rules_to_chain(self, ipt_mgr, ver, chain_name, rules):
        if ver == IPV4:
            table = ipt_mgr.ipv4['filter']
        else:
            table = ipt_mgr.ipv6['filter']
        for rule in rules:
            table.add_rule(chain_name, rule)

    def _enable_policy_chain(self, optid, ipt_if_prefix):
        bname = iptables_manager.binary_name
        ipt_mgr = ipt_if_prefix['ipt']
        if_prefix = ipt_if_prefix['if_prefix']

        for (ver, tbl) in [(IPV4, ipt_mgr.ipv4['filter']),
                           (IPV6, ipt_mgr.ipv6['filter'])]:
            for direction in [INGRESS_DIRECTION, EGRESS_DIRECTION]:
                chain_name = self._get_chain_name(optid, ver, direction)
                chain_name = iptables_manager.get_chain_name(chain_name)
                if chain_name in tbl.chains:
                    jump_rule = ['%s %s+ -j %s-%s' % (IPTABLES_DIR[direction],
                        if_prefix, bname, chain_name)]
                    self._add_rules_to_chain(ipt_mgr,
                        ver, 'FORWARD', jump_rule)

        #jump to DROP_ALL policy
        chain_name = iptables_manager.get_chain_name(OAAS_DEFAULT_CHAIN)
        jump_rule = ['-o %s+ -j %s-%s' % (if_prefix, bname, chain_name)]
        self._add_rules_to_chain(ipt_mgr, IPV4, 'FORWARD', jump_rule)
        self._add_rules_to_chain(ipt_mgr, IPV6, 'FORWARD', jump_rule)

        #jump to DROP_ALL policy
        chain_name = iptables_manager.get_chain_name(OAAS_DEFAULT_CHAIN)
        jump_rule = ['-i %s+ -j %s-%s' % (if_prefix, bname, chain_name)]
        self._add_rules_to_chain(ipt_mgr, IPV4, 'FORWARD', jump_rule)
        self._add_rules_to_chain(ipt_mgr, IPV6, 'FORWARD', jump_rule)

    def _convert_oaas_to_iptables_rule(self, rule):
        action = OAAS_TO_IPTABLE_ACTION_MAP[rule.get('action')]

        args = [self._protocol_arg(rule.get('protocol')),
                self._port_arg('dport',
                               rule.get('protocol'),
                               rule.get('destination_port')),
                self._port_arg('sport',
                               rule.get('protocol'),
                               rule.get('source_port')),
                self._ip_prefix_arg('s', rule.get('source_ip_address')),
                self._ip_prefix_arg('d', rule.get('destination_ip_address')),
                self._action_arg(action)]

        iptables_rule = ' '.join(args)
        return iptables_rule

    def _drop_invalid_packets_rule(self):
        return '-m state --state INVALID -j DROP'

    def _allow_established_rule(self):
        return '-m state --state ESTABLISHED,RELATED -j ACCEPT'

    def _action_arg(self, action):
        if action:
            return '-j %s' % action
        return ''

    def _protocol_arg(self, protocol):
        if protocol:
            return '-p %s' % protocol
        return ''

    def _port_arg(self, direction, protocol, port):
        if not (protocol in ['udp', 'tcp'] and port):
            return ''
        return '--%s %s' % (direction, port)

    def _ip_prefix_arg(self, direction, ip_prefix):
        if ip_prefix:
            return '-%s %s' % (direction, ip_prefix)
        return ''


#OaaS

    def solowan_create_folder(self, namespace):
        subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf mkdir /etc/opennop/opennop-%s" %namespace, shell=True)
        subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf cp /etc/opennop/log4crc /etc/opennop/opennop-%s" %namespace, shell=True)
        subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf cp /etc/opennop/opennop.conf /etc/opennop/opennop-%s" %namespace, shell=True)
        subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf sed -i 's/solowan.log/solowan-%s.log/' /etc/opennop/opennop-%s/log4crc" %(namespace,namespace), shell=True)

    def solowan_delete_folder(self,solowan, namespace):
        subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf rmFile /etc/opennop/opennop-%s/log4crc" % namespace, shell=True)
        subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf rmFile /etc/opennop/opennop-%s/opennop.conf" % namespace, shell=True)
        subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf rmdir /etc/opennop/opennop-%s" % namespace, shell=True)
        if solowan == True:
            solowan = False
            self.solowan_service(solowan ,namespace)

    def solowan_service(self,solowan, namespace):
        if solowan == True and  not os.path.isfile('/var/run/opennop-%s.pid' % namespace):
            cmd = "LOG4C_RCPATH=/etc/opennop/opennop-%s ip netns exec %s  opennopd -c /etc/opennop/opennop-%s/opennop.conf -p /var/run/opennop-%s.pid" % (namespace,namespace, namespace,namespace )
            args = cmd.split()
            linux_utils.execute(args, run_as_root=True)

        if solowan == False and os.path.isfile('/var/run/opennop-%s.pid' % namespace):
            infile = open('/var/run/opennop-%s.pid' % namespace, 'r')
            PID = infile.readline()
            infile.close()
            subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf rm /var/run/opennop-%s.pid" % namespace,shell=True)
            subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf kill -9 %s" % PID, shell=True)

    def solowan_localid(self,local_id,namespace):
            subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf sed  -i  '/^localid/clocalid %s' /etc/opennop/opennop-%s/opennop.conf" %(local_id ,namespace), shell=True)
    def solowan_action(self,action,namespace):
            subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf sed  -i  '/^optimization/c%s' /etc/opennop/opennop-%s/opennop.conf" %(action ,namespace), shell=True)
            subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf sed  -i  '/^deduplication/c%s' /etc/opennop/opennop-%s/opennop.conf" %(action ,namespace), shell=True)
    def solowan_pkt(self,pkt,namespace):
            subprocess.call("sudo /usr/bin/neutron-rootwrap /etc/neutron/rootwrap.conf sed  -i  '/^num_pkt_cache_size/cnum_pkt_cache_size %s' /etc/opennop/opennop-%s/opennop.conf" %(pkt ,namespace), shell=True)

