# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
OpenSwitch Test for RBAC. Create a user with ops_admin role.
"""

from pytest import mark
from re import search

TOPOLOGY = """
#  +----------+
#  |  switch  |
#  +----------+

# Nodes
[type=openswitch name="OpenSwitch 1"] switch
"""


def test_rbac_create_ops_admin_account(topology, step):
    """
    Test that creates a user with ops_admin role.
    """
    sw = topology.get('switch')
    assert sw is not None

    ###
    # Running rbac_verify_admin_account test
    ###
    step("### Start: rbac_create_ops_admin_account test ###")
    read_switch_config = sw(
         'python -c \'import rbac; print rbac.READ_SWITCH_CONFIG\'',
         shell='bash')
    write_switch_config = sw(
         'python -c \'import rbac; print rbac.WRITE_SWITCH_CONFIG\'',
         shell='bash')
    sys_mgmt = sw(
         'python -c \'import rbac; print rbac.SYS_MGMT\'',
         shell='bash')

    role_admin = sw(
         'python -c \'import rbac; print rbac.ROLE_ADMIN\'',
         shell='bash')

    ##
    # Create and verify admin account is present.
    ##
    step("## Create and verify admin account is present ##")

    #
    # Create a user with ops_admin role.
    #
    step("# Create a user with ops_admin role #")
    result = sw('sudo /usr/sbin/useradd -g ops_admin -s /bin/bash\
                rbac_ct_admin', shell='bash')

    #
    # Verify that the rbac_ct_admin account is present.
    #
    step("# Verify the rbac_ct_admin account exists #")
    result = sw('id -u rbac_ct_admin', shell='bash')
    if "no such user" in result:
        assert False, 'rbac_ct_admin  account not created'

    #
    # Login to rbac_ct_admin account.
    #
    step("# login to rbac_ct_admin account #")
    result = sw('sudo su -c "id" rbac_ct_admin', shell='bash')
    if "rbac_ct_admin" not in result:
        assert False, 'su rbac_ct_admin command did not work'

    #
    # Verify rbac_ct_admin has sudo privileges.
    #
    step("# Check for sudo privilges #")
    result = sw('sudo su -c "sudo ls"', shell='bash')
    if "Permission denied" in result:
        assert False, 'su not working for admin'

    #
    # Verify that the rbac_ct_admin account has memberships to the
    # correct groups.
    #
    step("# Verify the rbac_ct_admin account has membership to the\
         right groups #")
    result = sw('groups rbac_ct_admin', shell='bash')
    if "ops_admin" not in result:
        assert False, 'rbac_ct_admin user is not a member of ops_admin group'
    if "ops_netop" in result:
        assert False, 'rbac_ct_admin user is a member of ops_admin group'
    if "ovsdb-client" in result:
        assert False, 'rbac_ct_admin is a member of the ovsdb-client group'

    #
    # Verify rbac_ct_admin's shell and home directory.
    #
    step("# Make sure admin is users bash startup shell #")
    result = sw('cat /etc/passwd | grep "rbac_ct_admin:"', shell='bash')
    if not result:
        assert False, 'could not find rbac_ct_admin in passwd file'
    if "/home/rbac_ct_admin" not in result:
        assert False, 'rbac_ct_admins home directory in in wrong location'
    if "/bin/bash" not in result:
        assert False, 'rbac_ct_admin start shell is not bash'

    ##
    # Verify admin's RBACs roles and permissions.
    ##
    step("## Verify RBAC is returning correct information for admin ##")

    ##
    # Verify admin's RBACs roles and permissions in RBAC python library.
    ##
    step("## Running RBAC Python library tests ##")

    #
    # rbac.get_user_role()
    # Role should be ops_admin
    #
    step("### Verify rbac.get_user_role(rbac_ct_admin) ###")
    result = sw('python -c \'import rbac;\
                rbac.get_user_role_p("rbac_ct_admin")\'', shell='bash')
    if role_admin not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be SYS_MGMT
    #
    step("### Verify rbac.get_user_permissions(rbac_ct_admin) ###")
    permissions = sw('python -c \'import rbac;\
                rbac.get_user_permissions_p("rbac_ct_admin")\'', shell='bash')

    if sys_mgmt not in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be SYS_MGMT
    #
    step("### Verify rbac.check_user_permission(rbac_ct_admin) ###")
    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("rbac_ct_admin",\
                 rbac.SYS_MGMT)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("rbac_ct_admin",\
                 rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("rbac_ct_admin",\
                 rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ##
    # Verify admin's RBACs roles and permissions in RBAC shared library.
    ##
    step("## Running RBAC shared library tests ##")

    #
    # We can only run these tests if our test program is in the target.
    #
    step("# Verify rbac_role executible exists #")
    result = sw('ls /usr/bin/rbac_role', shell='bash')
    if "cannot access" in result:
        step("# rbac_role does not exist #")
        step("# Skipping shared library tests #")

        ###
        # Finished rbac_verify_admin_account test
        ###
        step("### Finished: rbac_verify_admin_account test  ###")

        #
        # remove the rbac_ct_admin user.
        #
        step("### Remove the rbac_ct_admin user ###")
        result = sw('sudo /usr/sbin/userdel rbac_ct_admin', shell='bash')
        return

    #
    # rbac_get_user_role()
    # Role should be admin
    #
    step("# Verify rbac.get_user_role(rbac_ct_admin) #")

    result = sw('rbac_role rbac_ct_admin', shell='bash')
    if role_admin not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.get_user_permissions(rbac_ct_admin) ###")
    permissions = sw('rbac_role -p rbac_ct_admin', shell='bash')

    if sys_mgmt not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac_check_user_permission(admin) ###")

    result = sw('rbac_role -c SYS_MGMT rbac_ct_admin', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG rbac_ct_admin', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG rbac_ct_admin', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ###
    # Finished rbac_verify_admin_account test
    ###
    step("### Finished: rbac_verify_admin_account test  ###")

    #
    # remove the rbac_ct_admin user.
    #
    step("### Remove the rbac_ct_admin user ###")
    result = sw('sudo /usr/sbin/userdel rbac_ct_admin', shell='bash')
