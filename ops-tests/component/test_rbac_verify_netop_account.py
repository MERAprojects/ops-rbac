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
OpenSwitch Test for RBAC. Verify built-in netop user.
"""

TOPOLOGY = """
#  +----------+
#  |  switch  |
#  +----------+

# Nodes
[type=openswitch name="OpenSwitch 1"] switch
"""


def test_rbac_verify_netop_account(topology, step):
    """
    Test that verifies that the netop account is created properly.
    """
    sw = topology.get('switch')
    assert sw is not None

    ###
    # Running rbac_verify_netop_account test
    ###
    step("### Start: rbac_verify_netop_account test ###")
    read_switch_config = sw(
         'python -c \'import rbac; print rbac.READ_SWITCH_CONFIG\'',
         shell='bash')
    write_switch_config = sw(
         'python -c \'import rbac; print rbac.WRITE_SWITCH_CONFIG\'',
         shell='bash')
    sys_mgmt = sw(
         'python -c \'import rbac; print rbac.SYS_MGMT\'',
         shell='bash')

    role_netop = sw(
         'python -c \'import rbac; print rbac.ROLE_NETOP\'',
         shell='bash')

    ##
    # Verifying netop account is present.
    ##
    step("## Verify netop account is present ##")

    #
    # Verify that the netop account is present.
    #
    step("# Verify the netop account exists #")
    result = sw('id -u netop', shell='bash')
    if "no such user" in result:
        assert False, 'User netop account not created'

    #
    # Login to netop account.
    #
    # step("# login to netop account #")
    # result = sw('su -c "id" netop', shell='bash')
    # if "netop" not in result:
    #    assert False, 'su netop command did not work'

    #
    # Verify that the netop account has memberships to the correct groups.
    #
    step("# Verify the netop account has membership to the right groups #")
    result = sw('groups netop', shell='bash')
    if "ops_admin" in result:
        assert False, 'netop is a member of ops_admin group'
    if "ops_netop" not in result:
        assert False, 'netop is not a member of ops_netop group'
    if "ovsdb-client" not in result:
        assert False, 'netop is not a member of the ovsdb-client group'

    ##
    # Verify netop's RBACs roles and permissions.
    ##
    step("## Verify RBAC is returning correct information for netop ##")

    ##
    # Verify netop's RBACs roles and permissions in RBAC python library.
    ##
    step("## Running RBAC Python library tests ##")

    #
    # rbac.get_user_role()
    # Role should be ops_netop
    #
    step("### Verify rbac.get_user_role(netop) ###")
    result = sw('python -c \'import rbac;\
                 rbac.get_user_role_p("netop")\'', shell='bash')
    if role_netop not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.get_user_permissions(netop) ###")
    permissions = sw('python -c \'import rbac;\
                      rbac.get_user_permissions_p("netop")\'', shell='bash')

    if sys_mgmt in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if read_switch_config not in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if write_switch_config not in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.check_user_permission(netop) ###")

    result = sw('python -c \'import rbac; rbac.check_user_permission_p\
                ("netop",rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.check_user_role returning wrong permission'

    result = sw('python -c \'import rbac; rbac.check_user_permission_p\
                ("netop",rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac; rbac.check_user_permission_p\
                ("netop",rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ##
    # Verify netop's RBACs roles and permissions in RBAC shared library.
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
    # Role should be netop
    #
    step("# Verify rbac.get_user_role(netop) #")
    result = sw('rbac_role netop', shell='bash')
    if role_netop not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.get_user_permissions(netop) ###")
    permissions = sw('rbac_role -p netop', shell='bash')

    if sys_mgmt in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac_check_user_permission(netop) ###")

    result = sw('rbac_role -c SYS_MGMT netop', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG netop', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG netop', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ###
    # Finished rbac_verify_netop_account test
    ###
    step("### Finished: rbac_verify_netop_account test  ###")
