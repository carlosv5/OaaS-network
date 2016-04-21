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

"""
This file contains configuration for the locations of all the static file
libraries, such as JavaScript and CSS libraries. Packagers for individual
distributions can edit or replace this file, in order to change the paths
to match their distribution's standards.
"""

import os

import horizon.xstatic.main
import horizon.xstatic.pkg.angular
import horizon.xstatic.pkg.angular_bootstrap
import horizon.xstatic.pkg.angular_gettext
import horizon.xstatic.pkg.angular_lrdragndrop
import horizon.xstatic.pkg.angular_smart_table
import horizon.xstatic.pkg.bootstrap_datepicker
import horizon.xstatic.pkg.bootstrap_scss
import horizon.xstatic.pkg.bootswatch
import horizon.xstatic.pkg.d3
import horizon.xstatic.pkg.font_awesome
import horizon.xstatic.pkg.hogan
import horizon.xstatic.pkg.jasmine
import horizon.xstatic.pkg.jquery
import horizon.xstatic.pkg.jquery_migrate
import horizon.xstatic.pkg.jquery_quicksearch
import horizon.xstatic.pkg.jquery_tablesorter
import horizon.xstatic.pkg.jquery_ui
import horizon.xstatic.pkg.jsencrypt
import horizon.xstatic.pkg.magic_search
import horizon.xstatic.pkg.mdi
import horizon.xstatic.pkg.rickshaw
import horizon.xstatic.pkg.roboto_fontface
import horizon.xstatic.pkg.spin
import horizon.xstatic.pkg.termjs

from horizon.utils import file_discovery


def get_staticfiles_dirs(webroot='/'):
    STATICFILES_DIRS = [
        ('horizon/lib/angular',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.angular,
                                 root_url=webroot).base_dir),
        ('horizon/lib/angular',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.angular_bootstrap,
                                 root_url=webroot).base_dir),
        ('horizon/lib/angular',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.angular_gettext,
                                 root_url=webroot).base_dir),
        ('horizon/lib/angular',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.angular_lrdragndrop,
                                 root_url=webroot).base_dir),
        ('horizon/lib/angular',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.angular_smart_table,
                                 root_url=webroot).base_dir),
        ('horizon/lib/bootstrap_datepicker',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.bootstrap_datepicker,
                                 root_url=webroot).base_dir),
        ('bootstrap',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.bootstrap_scss,
                                 root_url=webroot).base_dir),
        ('horizon/lib/bootswatch',
         horizon.xstatic.main.XStatic(horizon.xstatic.pkg.bootswatch,
                              root_url=webroot).base_dir),
        ('horizon/lib',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.d3,
                                 root_url=webroot).base_dir),
        ('horizon/lib',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.hogan,
                                 root_url=webroot).base_dir),
        ('horizon/lib/font-awesome',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.font_awesome,
                                 root_url=webroot).base_dir),
        ('horizon/lib/jasmine',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jasmine,
                                 root_url=webroot).base_dir),
        ('horizon/lib/jquery',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jquery,
                                 root_url=webroot).base_dir),
        ('horizon/lib/jquery',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jquery_migrate,
                                 root_url=webroot).base_dir),
        ('horizon/lib/jquery',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jquery_quicksearch,
                                 root_url=webroot).base_dir),
        ('horizon/lib/jquery',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jquery_tablesorter,
                                 root_url=webroot).base_dir),
        ('horizon/lib/jsencrypt',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jsencrypt,
                                 root_url=webroot).base_dir),
        ('horizon/lib/magic_search',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.magic_search,
                                 root_url=webroot).base_dir),
        ('horizon/lib/mdi',
         horizon.xstatic.main.XStatic(horizon.xstatic.pkg.mdi,
                              root_url=webroot).base_dir),
        ('horizon/lib',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.rickshaw,
                                 root_url=webroot).base_dir),
        ('horizon/lib/roboto_fontface',
         horizon.xstatic.main.XStatic(horizon.xstatic.pkg.roboto_fontface,
                              root_url=webroot).base_dir),
        ('horizon/lib',
            horizon.xstatic.main.XStatic(horizon.xstatic.pkg.spin,
                                 root_url=webroot).base_dir),
        ('horizon/lib',
         horizon.xstatic.main.XStatic(horizon.xstatic.pkg.termjs,
                              root_url=webroot).base_dir),
    ]

    if horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jquery_ui,
                            root_url=webroot).version.startswith('1.10.'):
        # The 1.10.x versions already contain the 'ui' directory.
        STATICFILES_DIRS.append(
            ('horizon/lib/jquery-ui',
             horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jquery_ui,
                                  root_url=webroot).base_dir))
    else:
        # Newer versions dropped the directory, add it to keep the path the
        # same.
        STATICFILES_DIRS.append(
            ('horizon/lib/jquery-ui/ui',
             horizon.xstatic.main.XStatic(horizon.xstatic.pkg.jquery_ui,
                                  root_url=webroot).base_dir))

    return STATICFILES_DIRS


def find_static_files(HORIZON_CONFIG):
    import horizon
    import openstack_dashboard
    os_dashboard_home_dir = openstack_dashboard.__path__[0]
    horizon_home_dir = horizon.__path__[0]

    # note the path must end in a '/' or the resultant file paths will have a
    # leading "/"
    file_discovery.populate_horizon_config(
        HORIZON_CONFIG,
        os.path.join(horizon_home_dir, 'static/')
    )

    # filter out non-angular javascript code and lib
    HORIZON_CONFIG['js_files'] = ([f for f in HORIZON_CONFIG['js_files']
                                   if not f.startswith('horizon/')])

    # note the path must end in a '/' or the resultant file paths will have a
    # leading "/"
    file_discovery.populate_horizon_config(
        HORIZON_CONFIG,
        os.path.join(os_dashboard_home_dir, 'static/'),
        sub_path='app/'
    )
