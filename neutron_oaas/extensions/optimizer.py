# Copyright 2013 Big Switch Networks, Inc.
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

import abc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.common import constants
from neutron.common import exceptions as nexception
from neutron.plugins.common import constants as p_const
from neutron.services import service_base
from oslo_config import cfg
from oslo_log import log as logging
import six


LOG = logging.getLogger(__name__)
#OaaS
# Optimizer rule action
OAAS_ALLOW = "allow"
OAAS_DENY = "deny"
OAAS_REJECT = "reject"
OAAS_OPTIMIZE = "optimize"
# Optimizer optimization action
COMPRESSION ="optimization compression"
DEDUPLICATION = "optimization deduplication"
BOTH = "optimization combined"

# Optimizer resource path prefix
OPTIMIZER_PREFIX = "/opt"


# Optimizer Exceptions
class OptimizerNotFound(nexception.NotFound):
    message = _("Optimizer %(optimizer_id)s could not be found.")


class OptimizerInUse(nexception.InUse):
    message = _("Optimizer %(optimizer_id)s is still active.")


class OptimizerInPendingState(nexception.Conflict):
    message = _("Operation cannot be performed since associated Optimizer "
                "%(optimizer_id)s is in %(pending_state)s.")


class OptimizerPolicyNotFound(nexception.NotFound):
    message = _("Optimizer Policy %(optimizer_policy_id)s could not be found.")


class OptimizerPolicyInUse(nexception.InUse):
    message = _("Optimizer Policy %(optimizer_policy_id)s is being used.")


class OptimizerPolicyConflict(nexception.Conflict):
    """OaaS exception for optimizer policy

    Occurs when admin policy tries to use another tenant's unshared
    policy.
    """
    message = _("Operation cannot be performed since Optimizer Policy "
                "%(optimizer_policy_id)s is not shared and does not belong to "
                "your tenant.")


class OptimizerRuleSharingConflict(nexception.Conflict):

    """OaaS exception for optimizer rules

    When a shared policy is created or updated with unshared rules,
    this exception will be raised.
    """
    message = _("Operation cannot be performed since Optimizer Policy "
                "%(optimizer_policy_id)s is shared but Optimizer Rule "
                "%(optimizer_rule_id)s is not shared")


class OptimizerPolicySharingConflict(nexception.Conflict):

    """OaaS exception for optimizer policy

    When a policy is shared without sharing its associated rules,
    this exception will be raised.
    """
    message = _("Operation cannot be performed. Before sharing Optimizer "
                "Policy %(optimizer_policy_id)s, share associated Optimizer "
                "Rule %(optimizer_rule_id)s")


class OptimizerRuleNotFound(nexception.NotFound):
    message = _("Optimizer Rule %(optimizer_rule_id)s could not be found.")


class OptimizerRuleInUse(nexception.InUse):
    message = _("Optimizer Rule %(optimizer_rule_id)s is being used.")


class OptimizerRuleNotAssociatedWithPolicy(nexception.InvalidInput):
    message = _("Optimizer Rule %(optimizer_rule_id)s is not associated "
                " with Optimizer Policy %(optimizer_policy_id)s.")


class OptimizerRuleInvalidProtocol(nexception.InvalidInput):
    message = _("Optimizer Rule protocol %(protocol)s is not supported. "
                "Only protocol values %(values)s and their integer "
                "representation (0 to 255) are supported.")


class OptimizerRuleInvalidAction(nexception.InvalidInput):
    message = _("Optimizer rule action %(action)s is not supported. "
                "Only action values %(values)s are supported.")


class OptimizerRuleInvalidICMPParameter(nexception.InvalidInput):
    message = _("%(param)s are not allowed when protocol "
                "is set to ICMP.")


class OptimizerRuleWithPortWithoutProtocolInvalid(nexception.InvalidInput):
    message = _("Source/destination port requires a protocol")


class OptimizerRuleInvalidPortValue(nexception.InvalidInput):
    message = _("Invalid value for port %(port)s.")


class OptimizerRuleInfoMissing(nexception.InvalidInput):
    message = _("Missing rule info argument for insert/remove "
                "rule operation.")


# TODO(dougwig) - once this exception is out of neutron, restore this
#class OptimizerInternalDriverError(nexception.NeutronException):
#    """Oaas exception for all driver errors.
#
#    On any failure or exception in the driver, driver should log it and
#    raise this exception to the agent
#    """
#    message = _("%(driver)s: Internal driver error.")
OptimizerInternalDriverError = nexception.FirewallInternalDriverError


class OptimizerRuleConflict(nexception.Conflict):

    """Optimizer rule conflict exception.

    Occurs when admin policy tries to use another tenant's unshared
    rule.
    """

    message = _("Operation cannot be performed since Optimizer Rule "
                "%(optimizer_rule_id)s is not shared and belongs to "
                "another tenant %(tenant_id)s")


opt_valid_protocol_values = [None, constants.PROTO_NAME_TCP,
                            constants.PROTO_NAME_UDP,
                            constants.PROTO_NAME_ICMP]
#OaaS
opt_valid_action_values = [OAAS_ALLOW, OAAS_DENY, OAAS_REJECT, OAAS_OPTIMIZE]
opt_valid_action_optimization_values = [COMPRESSION, DEDUPLICATION, BOTH]



def convert_protocol(value):
    if value is None:
        return
    if value.isdigit():
        val = int(value)
        if 0 <= val <= 255:
            return val
        else:
            raise OptimizerRuleInvalidProtocol(
                protocol=value,
                values=opt_valid_protocol_values)
    elif value.lower() in opt_valid_protocol_values:
        return value.lower()
    else:
        raise OptimizerRuleInvalidProtocol(
            protocol=value,
            values=opt_valid_protocol_values)


def convert_action_to_case_insensitive(value):
    if value is None:
        return
    else:
        return value.lower()


def convert_port_to_string(value):
    if value is None:
        return
    else:
        return str(value)


def _validate_port_range(data, key_specs=None):
    if data is None:
        return
    data = str(data)
    ports = data.split(':')
    for p in ports:
        try:
            val = int(p)
        except (ValueError, TypeError):
            msg = _("Port '%s' is not a valid number") % p
            LOG.debug(msg)
            return msg
        if val <= 0 or val > 65535:
            msg = _("Invalid port '%s'") % p
            LOG.debug(msg)
            return msg


def _validate_ip_or_subnet_or_none(data, valid_values=None):
    if data is None:
        return None
    msg_ip = attr._validate_ip_address(data, valid_values)
    if not msg_ip:
        return
    msg_subnet = attr._validate_subnet(data, valid_values)
    if not msg_subnet:
        return
    return _("%(msg_ip)s and %(msg_subnet)s") % {'msg_ip': msg_ip,
                                                 'msg_subnet': msg_subnet}


attr.validators['type:port_range'] = _validate_port_range
attr.validators['type:ip_or_subnet_or_none'] = _validate_ip_or_subnet_or_none


RESOURCE_ATTRIBUTE_MAP = {
    'optimizer_rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': attr.NAME_MAX_LEN},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                     attr.DESCRIPTION_MAX_LEN},
                        'is_visible': True, 'default': ''},
        'optimizer_policy_id': {'allow_post': False, 'allow_put': False,
                               'validate': {'type:uuid_or_none': None},
                               'is_visible': True},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol,
                     'validate': {'type:values': opt_valid_protocol_values}},
        'ip_version': {'allow_post': True, 'allow_put': True,
                       'default': 4, 'convert_to': attr.convert_to_int,
                       'validate': {'type:values': [4, 6]},
                       'is_visible': True},
        'source_ip_address': {'allow_post': True, 'allow_put': True,
                              'validate': {'type:ip_or_subnet_or_none': None},
                              'is_visible': True, 'default': None},
        'destination_ip_address': {'allow_post': True, 'allow_put': True,
                                   'validate': {'type:ip_or_subnet_or_none':
                                                None},
                                   'is_visible': True, 'default': None},
        'source_port': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:port_range': None},
                        'convert_to': convert_port_to_string,
                        'default': None, 'is_visible': True},
        'destination_port': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:port_range': None},
                             'convert_to': convert_port_to_string,
                             'default': None, 'is_visible': True},
        'position': {'allow_post': False, 'allow_put': False,
                     'default': None, 'is_visible': True},
        'action': {'allow_post': True, 'allow_put': True,
                   'convert_to': convert_action_to_case_insensitive,
                   'validate': {'type:values': opt_valid_action_values},
                   'is_visible': True, 'default': 'deny'},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'default': True, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
    },
    'optimizer_policies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': attr.NAME_MAX_LEN},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                     attr.DESCRIPTION_MAX_LEN},
                        'is_visible': True, 'default': ''},
        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': True, 'required_by_policy': True,
                   'enforce_policy': True},
        'optimizer_rules': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:uuid_list': None},
                           'convert_to': attr.convert_none_to_empty_list,
                           'default': None, 'is_visible': True},
        'audited': {'allow_post': True, 'allow_put': True,
                    'default': False, 'convert_to': attr.convert_to_boolean,
                    'is_visible': True},
    },
    'optimizers': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': attr.NAME_MAX_LEN},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string':
                                     attr.DESCRIPTION_MAX_LEN},
                        'is_visible': True, 'default': ''},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
#OaaS
        'solowan': {'allow_post': False, 'allow_put': True,
                   'is_visible': True, 'default': False, 'convert_to': attr.convert_to_boolean},
        'local_id': {'allow_post': False, 'allow_put': True,
                                   'validate': {'type:ip_or_subnet_or_none':
                                                None},
                                   'is_visible': True, 'default': None},
        'action': {'allow_post': False, 'allow_put': True,
                   'convert_to': convert_action_to_case_insensitive,
                   'validate': {'type:values': opt_valid_action_optimization_values},
                   'is_visible': True},
        'num_pkt_cache_size': {'allow_post': False, 'allow_put': True,
                             'convert_to': convert_port_to_string,
                             'default': 131072, 'is_visible': True},



        'shared': {'allow_post': True, 'allow_put': True,
                   'default': False, 'convert_to': attr.convert_to_boolean,
                   'is_visible': False, 'required_by_policy': True,
                   'enforce_policy': True},
        'optimizer_policy_id': {'allow_post': True, 'allow_put': True,
                               'validate': {'type:uuid_or_none': None},
                               'is_visible': True},
    },
}

optimizer_quota_opts = [
    cfg.IntOpt('quota_optimizer',
               default=1,
               help=_('Number of optimizers allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_optimizer_policy',
               default=1,
               help=_('Number of optimizer policies allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_optimizer_rule',
               default=100,
               help=_('Number of optimizer rules allowed per tenant. '
                      'A negative value means unlimited.')),
]
cfg.CONF.register_opts(optimizer_quota_opts, 'QUOTAS')


class Optimizer(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Optimizer service"

    @classmethod
    def get_alias(cls):
        return "oaas"

    @classmethod
    def get_description(cls):
        return "Extension for Optimizer service"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/Neutron/OaaS/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2013-02-25T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        special_mappings = {'optimizer_policies': 'optimizer_policy'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        action_map = {'optimizer_policy': {'insert_rule': 'PUT',
                                          'remove_rule': 'PUT'}}
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   p_const.OPTIMIZER,
                                                   action_map=action_map)

    @classmethod
    def get_plugin_interface(cls):
        return OptimizerPluginBase

    def update_attributes_map(self, attributes):
        super(Optimizer, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class OptimizerPluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return p_const.OPTIMIZER

    def get_plugin_type(self):
        return p_const.OPTIMIZER

    def get_plugin_description(self):
        return 'Optimizer service plugin'

    @abc.abstractmethod
    def get_optimizers(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_optimizer(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_optimizer(self, context, optimizer):
        pass

    @abc.abstractmethod
    def update_optimizer(self, context, id, optimizer):
        pass

    @abc.abstractmethod
    def delete_optimizer(self, context, id):
        pass

    @abc.abstractmethod
    def get_optimizer_rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_optimizer_rule(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_optimizer_rule(self, context, optimizer_rule):
        pass

    @abc.abstractmethod
    def update_optimizer_rule(self, context, id, optimizer_rule):
        pass

    @abc.abstractmethod
    def delete_optimizer_rule(self, context, id):
        pass

    @abc.abstractmethod
    def get_optimizer_policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_optimizer_policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_optimizer_policy(self, context, optimizer_policy):
        pass

    @abc.abstractmethod
    def update_optimizer_policy(self, context, id, optimizer_policy):
        pass

    @abc.abstractmethod
    def delete_optimizer_policy(self, context, id):
        pass

    @abc.abstractmethod
    def insert_rule(self, context, id, rule_info):
        pass

    @abc.abstractmethod
    def remove_rule(self, context, id, rule_info):
        pass
