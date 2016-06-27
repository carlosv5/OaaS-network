# Copyright 2015 Intel Corporation.
# Copyright 2015 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# Copyright 2015 Yalei Wang <yalei.wang at intel com>
#
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


import netaddr

from neutron.common import constants
from neutron_oaas.services.optimizer.drivers import oaas_base
import neutron_oaas.services.optimizer.drivers.mcafee.smc_api as smc_api
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_serialization import jsonutils


NGFWOpts = [
    cfg.StrOpt(
        'smc_url',
        default='',
        help=_("URL to contact SMC server")
    ),
    cfg.StrOpt(
        'smc_api_auth_key',
        default='',
        help=_("Authentication key to SMC API")
    ),
    cfg.StrOpt(
        'smc_api_version',
        default='',
        help=_("verion of SMC API")
    ),
]

cfg.CONF.register_opts(NGFWOpts, 'ngopt')

LOG = logging.getLogger(__name__)


class NgoptOaasDriver(oaas_base.OaasDriverBase):
    """Optimizer driver for NGFW Oaas of Mcafee """
    def __init__(self):
        LOG.debug("Initializing FWaas Mcafee NGFW driver")
        super(NgoptOaasDriver, self).__init__()
        self._host_list = []
        self._network_list = []
        self._smc_url = cfg.CONF.ngopt.smc_url
        self.opt_ips_template_ref = None
        self.opt_template_ref = None
        self.connection = smc_api.SMCAPIConnection(
            self._smc_url,
            cfg.CONF.ngopt.smc_api_version,
            cfg.CONF.ngopt.smc_api_auth_key)

    @log_helpers.log_method_call
    def create_optimizer(self, agent_mode, apply_list, optimizer):
        # call update_optimizer, because one tenant only support
        # one optimizer
        return self.update_optimizer(agent_mode, apply_list, optimizer)

    @log_helpers.log_method_call
    def delete_optimizer(self, agent_mode, apply_list, optimizer):
        # tell SMC server to remove the ngopt policy
        return self._delete_policy(apply_list, optimizer)

    @log_helpers.log_method_call
    def update_optimizer(self, agent_mode, apply_list, optimizer):
        for router_info in apply_list:
            rt = router_info.router

            # only update the policy when the router is active
            if (rt['tenant_id'] == optimizer['tenant_id'] and
                    rt['status'] == 'ACTIVE'):
                self._update_policy(rt, optimizer)

    def _delete_policy(self, apply_list, optimizer):
        for router_info in apply_list:
            rt = router_info.router

            self._clear_policy(rt, optimizer)

    @log_helpers.log_method_call
    def apply_default_policy(self, apply_list, optimizer):
        return self._delete_policy(apply_list, optimizer)

    def _update_policy(self, router, optimizer):
        # clear all the policy first
        self._clear_policy(router, optimizer)

        if optimizer['admin_state_up']:
            self._setup_policy(router, optimizer)

    def _is_ips_policy(self, policy_name):
        return policy_name[len(policy_name) - 4:].lower() == '-ips'

    def _get_policy_ref(self, policy_name):
        # get the template ref at the first time
        if not self.opt_ips_template_ref or not self.opt_template_ref:
            r = self.connection.get('elements/opt_template_policy')
            opt_template_list = r[0]['result']
            for tplt in opt_template_list:
                if tplt['name'] == "Optimizer Inspection Template":
                    self.opt_ips_template_ref = tplt['href'].replace(
                        self._smc_url +
                        "/%s/" % cfg.CONF.ngopt.smc_api_version,
                        '')
                elif tplt['name'] == "Optimizer Template":
                    self.opt_template_ref = tplt['href'].replace(
                        self._smc_url +
                        "/%s/" % cfg.CONF.ngopt.smc_api_version,
                        '')

        # use different template base on the policy name
        if self._is_ips_policy(policy_name):
            template = self.opt_ips_template_ref
        else:
            template = self.opt_template_ref

        # create the policy in SMC server
        opt_policy = {
            "name": policy_name,
            "template": template
        }

        ref = self._get_ref_from_service_data('opt_policy', opt_policy)

        return ref

    def _parse_port(self, source_port):
        min_port = ''
        max_port = ''

        if source_port is None:
            min_port = 0
            max_port = 65535
        elif ':' in source_port:
            ports = source_port.split(':')
            min_port = int(ports[0])
            max_port = int(ports[1])
        else:
            min_port = int(source_port)
            max_port = ''

        return min_port, max_port

    def _get_ref_from_addr(self, addr):
        if addr == 'None':
            return addr

        ip = netaddr.IPNetwork(addr)

        if str(ip.netmask) != "255.255.255.255":
            # create network objects
            ref = self._create_network(addr)
        else:
            # create host objects
            ref = self._create_host(str(ip.ip))

        return ref

    def _get_ref_from_service_data(self, service_path, service_data):
        json_data = jsonutils.dumps(service_data)
        r = self.connection.post_element(service_path, json_data)
        srv_ref = r.headers['location']
        return srv_ref

    def _convert_ipv4_to_ngopt_rule(self, rule):
        # convert the ipv4 rule into ngopt rules

        # create src/dst of hosts or networks
        src_ref = self._get_ref_from_addr(str(rule['source_ip_address']))
        dst_ref = self._get_ref_from_addr(str(rule['destination_ip_address']))

        # create service
        srv_ref = ''
        service_dict = {}

        service = "%s_service" % rule['protocol']
        if rule['protocol'] in (constants.PROTO_NAME_TCP,
                                constants.PROTO_NAME_UDP):

            source_port = rule['source_port']
            dest_port = rule['destination_port']

            min_src_port, max_src_port = self._parse_port(source_port)
            min_dst_port, max_dst_port = self._parse_port(dest_port)

            service_data = {
                "name": "service-%s" % rule['name'],
                "min_src_port": min_src_port,
                "max_src_port": (min_src_port if max_src_port == ''
                                 else max_src_port),
                "min_dst_port": min_dst_port,
                "max_dst_port": (min_dst_port if max_dst_port == ''
                                 else max_dst_port)
            }

            srv_ref = self._get_ref_from_service_data(service,
                    service_data)
            service_dict = {"service": [srv_ref]}

        elif rule['protocol'] == constants.PROTO_NAME_ICMP:
            # only ping is supported
            service_data = {
                "name": "service%s" % "22",
                "icmp_type": 0,
                "icmp_code": 0
            }

            srv_ref = self._get_ref_from_service_data(service,
                    service_data)
            service_dict = {"service": [srv_ref]}

        elif rule['protocol'] is None:
            # protocal "ANY" is translated to accept all, no service create
            # here
            # TODO(yalie): add rules for different protocol, not ignore the
            # other value like ports.
            service_dict = {"any": True}
        else:
            raise NotImplementedError(
                _("not support %s protocol now") % rule['protocol'])

        # create opt rule
        action = "discard" if rule["action"] == "deny" else "allow"

        payload = {
            "name": rule['name'],
            "action": {
                "action": action,
                "connection_tracking_options": {}
            },
            "destinations": {"dst": [dst_ref]},
            "services": service_dict,
            "sources": {"src": [src_ref]}
        }

        json_data = jsonutils.dumps(payload)

        return json_data

    def _get_policy_name(self, router, opt):
        # SMC server would bind the different NGFW policy with different
        # routers(sg-engine) in a tenant
        return "%s_%s_%s" % (
            opt['id'][0:7], opt['optimizer_policy_id'][0:7], router['id'][0:7])

    def _setup_policy(self, router, opt):
        # one tenant should use only one policy
        with self.connection.login_server():
            # create policy ref
            policy_name = self._get_policy_name(router, opt)
            policy_ref = self._get_policy_ref(policy_name)

            # post service
            for rule in opt['optimizer_rule_list']:
                if not rule['enabled']:
                    continue

                if rule['ip_version'] == 4:
                    json_data = self._convert_ipv4_to_ngopt_rule(rule)
                    self.connection.post(policy_ref +
                                         "/opt_ipv4_access_rule",
                                         json_data, raw=True)
                else:
                    msg = (_('Unsupported IP version rule. %(version)') %
                           {'version': rule['ip_version']})
                    raise ValueError(msg)

            # upload the policy
            self.connection.post(policy_ref + "/upload", '', raw=True)

    def _clear_policy(self, router, opt):
        # find the policy used by the tenant and optimizer
        policy_name = self._get_policy_name(router, opt)

        path_policy_filter = 'elements/opt_policy?filter=%s' % policy_name

        with self.connection.login_server():
            r = self.connection.get(path=path_policy_filter)

            opt_list = r[0]['result']
            for f in opt_list:
                if f['name'] == policy_name:
                    self.connection.delete(f['href'], raw=True)

            # Warning, find unused elements and delete them.
            r = self.connection.get(path='elements/search_unused')

            element_list = r[0]['result']

            for element in element_list:
                self.connection.delete(element['href'], raw=True)

    def _create_host(self, ip):
        ref = None
        host_json_def = {
            "name": "host-%s" % str(ip),
            "address": ip
        }

        with self.connection.login_server():
            ref = self._get_ref_from_service_data('host', host_json_def)

        return ref

    def _create_network(self, cidr):
        ref = None
        net_json_def = {
            "name": "network-%s" % str(cidr),
            "ipv4_network": cidr
        }

        with self.connection.login_server():
            # some network maybe pre-created by router-plugin
            r = self.connection.get("elements/network")
            networks = r[0]['result']
            for net in networks:
                if net['name'] == "network-%s" % cidr:
                    ref = net['href']
                    return ref

            ref = self._get_ref_from_service_data('network', net_json_def)

        return ref
