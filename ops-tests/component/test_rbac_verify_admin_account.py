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
OpenSwitch Test for RBAC. Verify built-in admin user.
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


def test_rbac_verify_admin_account(topology, step):
    """
    Test that verifies that the admin account is created properly.
    """
    sw = topology.get('switch')
    assert sw is not None

    ###
    # Running rbac_verify_admin_account test
    ###
    step("### Start: rbac_verify_admin_account test ###")
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
    # Verifying admin account is present.
    ##
    step("## Verify admin account is present ##")

    #
    # Verify that the admin account is present.
    #
    step("# Verify the admin account exists #")
    result = sw('id -u admin', shell='bash')
    if "no such user" in result:
        assert False, 'user admin account not created'

    #
    # Login to admin account.
    #
    step("# login to admin account #")
    result = sw('sudo su -c "id" admin', shell='bash')
    if "admin" not in result:
        assert False, 'su admin command did not work'

    #
    # Verify admin has sudo privileges.
    #
    step("# Check for sudo privilges #")
    result = sw('sudo su -c "sudo ls"', shell='bash')
    if "Permission denied" in result:
        assert False, 'su not working for admin'

    #
    # Verify that the admin account has memberships to the correct groups.
    #
    step("# Verify the admin account has membership to the right groups #")
    result = sw('groups admin', shell='bash')
    if "ops_admin" not in result:
        assert False, 'admin is not a member of ops_admin group'
    if "ops_netop" in result:
        assert False, 'admin is a member of ops_netop group'
    if "ovsdb-client" in result:
        assert False, 'admin is a member of the ovsdb-client group'

    #
    # Verify admin's shell and home directory.
    #
    step("# Make sure admin is users bash startup shell #")
    result = sw('cat /etc/passwd | grep "admin:"', shell='bash')
    if not result:
        assert False, 'could not find admin in passwd file'
    if "/home/admin" not in result:
        assert False, 'admins home directory in in wrong location'
    if "/bin/bash" not in result:
        assert False, 'admin start shell is not bash'

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
    step("### Verify rbac.get_user_role(admin) ###")
    result = sw('python -c \'import rbac;\
                 rbac.get_user_role_p("admin")\'', shell='bash')
    if (role_admin not in result):
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be SYS_MGMT
    #
    step("### Verify rbac.get_user_permissions(admin) ###")
    permissions = sw('python -c \'import rbac;\
                 rbac.get_user_permissions_p("admin")\'', shell='bash')

    if (sys_mgmt not in permissions):
        assert False, 'rbac.get_user_role returning wrong permission'

    if (read_switch_config in permissions):
        assert False, 'rbac.get_user_role returning wrong permission'

    if (write_switch_config in permissions):
        assert False, 'rbac.get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be SYS_MGMT
    #
    step("# Verify rbac.check_user_permission(admin) #")
    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("admin",\
                 rbac.SYS_MGMT)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("admin",\
                 rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("admin",\
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
        return

    #
    # rbac.get_user_role()
    # Role should be admin
    #
    step("# Verify rbac.get_user_role(admin) #")
    result = sw('rbac_role admin', shell='bash')
    if role_admin not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.get_user_permissions(admin) ###")
    permissions = sw('rbac_role -p admin', shell='bash')

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

    result = sw('rbac_role -c SYS_MGMT admin', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG admin', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG admin', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ###
    # Finished rbac_verify_admin_account test
    ###
    step("### Finished: rbac_verify_admin_account test  ###")
