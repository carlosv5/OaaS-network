# The presence of this file in /etc/openstack-dashboard/ and/or
# /usr/share/openstack-dashboard/openstack_dashboard/local/ will
# enable the Ubuntu theme for Horizon.  To disable, remove the
# openstack-dashboard-ubuntu-theme package, or remove this file.
import os

UBUNTU_THEME = "/usr/share/openstack-dashboard-ubuntu-theme/static/themes/ubuntu"

if os.path.exists(UBUNTU_THEME):
    CUSTOM_THEME_PATH = UBUNTU_THEME
