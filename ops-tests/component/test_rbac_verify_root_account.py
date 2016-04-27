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
OpenSwitch Test for RBAC. Verify built-in root user.
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


def test_rbac_verify_root_account(topology, step):
    """
    Test that verifies that the root account is created properly.
    """
    sw = topology.get('switch')
    assert sw is not None

    ###
    # Running rbac_verify_root_account test
    ###
    step("### Start: rbac_verify_root_account test ###")
    read_switch_config = sw(
         'python -c \'import rbac; print rbac.READ_SWITCH_CONFIG\'',
         shell='bash')
    write_switch_config = sw(
         'python -c \'import rbac; print rbac.WRITE_SWITCH_CONFIG\'',
         shell='bash')
    sys_mgmt = sw(
         'python -c \'import rbac; print rbac.SYS_MGMT\'',
         shell='bash')

    role_root = sw(
         'python -c \'import rbac; print rbac.ROLE_ROOT\'',
         shell='bash')

    ##
    # Verifying root account is present.
    ##
    step("## Verify root account is present ##")

    #
    # Verify that the root account is present.
    #
    step("# Verify the root account exists #")
    result = sw('id -u root', shell='bash')
    if "no such user" in result:
        assert False, 'user root account not created'

    #
    # Login to root account.
    #
    step("# login to root account #")
    result = sw('sudo su -c "id" root', shell='bash')
    if "root" not in result:
        assert False, 'su root command did not work'

    #
    # Verify that the root account has memberships to the correct groups.
    #
    step("# Verify the root account has membership to the right groups#")
    result = sw('groups root', shell='bash')
    if "root" not in result:
        assert False, 'root is not a member of root group'
    if "ops_admin" in result:
        assert False, 'root is a member of ops_admin group'
    if "ops_netop" in result:
        assert False, 'root is a member of ops_netop group'
    if "ovsdb-client" in result:
        assert False, 'root is a member of ovsdb-client group'

    #
    # Verify root's shell and home directory.
    #
    step("# Make sure root has a home directory #")
    result = sw('cat /etc/passwd | grep "root:"', shell='bash')
    if not result:
        assert False, 'could not find root in passwd file'
    if "/home/root" not in result:
        assert False, 'roots  home directory is in wrong location'

    ##
    # Verify root's RBACs roles and permissions.
    ##
    step("## Verify RBAC is returning correct information for root ##")

    ##
    # Verify root's RBACs roles and permissions in RBAC python library.
    ##
    step("## Running RBAC Python library tests ##")

    #
    # rbac.get_user_role()
    # Role should be root
    #
    step("### Verify rbac.get_user_role(root) ###")
    result = sw('python -c \'import rbac;\
                 rbac.get_user_role_p("root")\'', shell='bash')
    if role_root not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.get_user_permissions(root) ###")
    permissions = sw('python -c \'import rbac;\
                      rbac.get_user_permissions_p("root")\'', shell='bash')

    if (sys_mgmt not in permissions):
        assert False, 'rbac.get_user_role returning wrong permission'

    if (read_switch_config not in permissions):
        assert False, 'rbac.get_user_role returning wrong permission'

    if (write_switch_config not in permissions):
        assert False, 'rbac.get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.check_user_permission(root) ###")

    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("root", rbac.SYS_MGMT)\'',
                shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac; rbac.check_user_permission_p\
                ("root", rbac.READ_SWITCH_CONFIG)\'',
                shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac; rbac.check_user_permission_p\
                ("root", rbac.WRITE_SWITCH_CONFIG)\'',
                shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ##
    # Verify root's RBACs roles and permissions in RBAC shared library.
    ##
    step("## Running RBAC shared library tests ##")

    #
    # We can only run these tests if out test program is in the target.
    #
    step("### Verify rbac_role executible exists ###")
    result = sw('ls /usr/bin/rbac_role', shell='bash')
    if "cannot access" in result:
        step("### rbac_role does not exist ###")
        step("### Skipping shared library tests ###")
        return

    #
    # rbac.get_user_role()
    # Role should be root
    #
    step("### Verify rbac.get_user_role(root) ###")
    result = sw('rbac_role root', shell='bash')
    if role_root not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.get_user_permissions(root) ###")
    permissions = sw('rbac_role -p root', shell='bash')

    if sys_mgmt not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac_check_user_permission(root) ###")

    result = sw('rbac_role -c SYS_MGMT root', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG root', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG root', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ###
    # Finished rbac_verify_root_account test
    ###
    step("### Finished: rbac_verify_root_account test  ###")
