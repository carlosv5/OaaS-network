# Copyright 2015 Cisco Systems, Inc.  All rights reserved.
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

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as excp

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class InvalidInterfaceForCSRFW(excp.NotFound):
    message = _("Interface id %(port_id)s provided "
                "not valid for Cisco CSR Optimizer")


class InvalidRouterAssociationForCSRFW(excp.InvalidInput):
    message = _("Port id %(port_id)s provided "
                "for Cisco CSR Optimizer associated with different Router")


class InvalidRouterHostingInfoForCSRFW(excp.NotFound):
    message = _("Interface id %(port_id)s provided "
                "does not have Hosting Info for Cisco CSR Optimizer")


csr_optimizer_direction = ['inside', 'outside', 'both']

EXTENDED_ATTRIBUTES_2_0 = {
    'optimizers': {
        'port_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid': None},
                    'is_visible': True, 'default': attr.ATTR_NOT_SPECIFIED},
        'direction': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:values': csr_optimizer_direction},
                      'is_visible': True, 'default': attr.ATTR_NOT_SPECIFIED},
    }
}


class Csr_optimizer_insertion(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "CSR Optimizer insertion"

    @classmethod
    def get_alias(cls):
        return "csroptimizerinsertion"

    @classmethod
    def get_description(cls):
        return "Optimizer insertion for Cisco CSR"

    @classmethod
    def get_namespace(cls):
        return ("http://docs.openstack.org/ext/neutron/"
                "csroptimizerinsertion/api/v1.0")

    @classmethod
    def get_updated(cls):
        return "2014-08-13T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
