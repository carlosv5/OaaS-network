# Copyright 2014 OpenStack Foundation.
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

from neutron.tests import base
from oslo_config import cfg

from neutron_oaas.services.optimizer.agents import optimizer_service

OAAS_NOP_DEVICE = ('neutron_oaas.tests.unit.services.optimizer.agents.'
                    'test_optimizer_agent_api.NoopOaasDriver')


class TestOptimizerDeviceDriverLoading(base.BaseTestCase):

    def setUp(self):
        super(TestOptimizerDeviceDriverLoading, self).setUp()
        self.service = optimizer_service.OptimizerService()

    def test_loading_optimizer_device_driver(self):
        """Get the sole device driver for OaaS."""
        cfg.CONF.set_override('driver',
                              OAAS_NOP_DEVICE,
                              'oaas')
        driver = self.service.load_device_drivers()
        self.assertIsNotNone(driver)
        self.assertIn(driver.__class__.__name__, OAAS_NOP_DEVICE)

    def test_fail_no_such_optimizer_device_driver(self):
        """Failure test of import error for OaaS device driver."""
        cfg.CONF.set_override('driver',
                              'no.such.class',
                              'oaas')
        self.assertRaises(ImportError,
                          self.service.load_device_drivers)

    def test_fail_optimizer_no_device_driver_specified(self):
        """Failure test when no OaaS device driver is specified.

        This is a configuration error, as the user must specify a device
        driver, when enabling the optimizer service (and there is no default
        configuration set. We'll simulate that by using an empty string.
        """
        cfg.CONF.set_override('driver',
                              '',
                              'oaas')
        self.assertRaises(ValueError,
                          self.service.load_device_drivers)
