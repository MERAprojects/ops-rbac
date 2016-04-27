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
OpenSwitch Test for RBAC. Verify nonexistent user has no permissions.
"""

TOPOLOGY = """
#  +----------+
#  |  switch  |
#  +----------+

# Nodes
[type=openswitch name="OpenSwitch 1"] switch
"""


def test_rbac_verify_nonexistent_account(topology, step):
    """
    Test that verifies that a non-existent user account has no permissions
    """
    sw = topology.get('switch')
    assert sw is not None

    ###
    # Running rbac_verify_nonexistent_account test
    ###
    step("### Start: rbac_verify_nonexistent_account test ###")
    read_switch_config = sw(
         'python -c \'import rbac; print rbac.READ_SWITCH_CONFIG\'',
         shell='bash')
    write_switch_config = sw(
         'python -c \'import rbac; print rbac.WRITE_SWITCH_CONFIG\'',
         shell='bash')
    sys_mgmt = sw(
         'python -c \'import rbac; print rbac.SYS_MGMT\'',
         shell='bash')

    role_none = sw(
         'python -c \'import rbac; print rbac.ROLE_NONE\'',
         shell='bash')

    ##
    # Verifying nonexistent account is not present.
    ##
    step("## Verify ne_user account is not present ##")

    #
    # Verify that the nonexistent user account is not present.
    #
    step("# Verify the ne_user user account does not exist #")
    result = sw('id -u ne_user', shell='bash')
    if "no such user" not in result:
        assert False, 'ne_user account is present'

    ##
    # Verify nonexistent user's RBACs roles and permissions.
    ##
    step("## Verify RBAC is returning correct information for ne_user ##")

    ##
    # Verify ne_user's RBACs roles and permissions in RBAC python library.
    ##
    step("## Running RBAC Python library tests ##")

    #
    # rbac.get_user_role()
    # Role should be "None"
    #
    step("### Verify rbac.get_user_role(ne_user) ###")
    result = sw('python -c \'import rbac;\
                 rbac.get_user_role_p("ne_user")\'', shell='bash')
    if role_none not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be []
    #
    step("### Verify rbac.get_user_permissions(ne_user) ###")
    permissions = sw('python -c \'import rbac;\
                     rbac.get_user_permissions_p("ne_user")\'',
                     shell='bash')

    if sys_mgmt in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be []
    #
    step("### Verify rbac.check_user_permission(ne_user) ###")

    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p\
                ("ne_user",rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.check_user_role returning wrong permission'

    result = sw('python -c \'import rbac; rbac.check_user_permission_p\
                ("ne_user",rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac; rbac.check_user_permission_p\
                ("ne_user",rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ##
    # Verify ne_user's RBACs roles and permissions in RBAC shared library.
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
    # Role should be "None"
    #
    step("# Verify rbac.get_user_role(ne_user) #")
    result = sw('rbac_role ne_user', shell='bash')
    if role_none not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be
    #
    step("# Verify rbac.get_user_permissions(ne_user) #")
    permissions = sw('rbac_role -p ne_user', shell='bash')

    if sys_mgmt in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be
    #
    step("# Verify rbac_check_user_permission(ne_user) #")

    result = sw('rbac_role -c SYS_MGMT ne_user', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG ne_user', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG ne_user', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ###
    # Finished rbac_verify_nonexistent_account test
    ###
    step("### Finished: rbac_verify_nonexistent_account test  ###")
