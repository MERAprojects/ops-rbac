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
OpenSwitch Test for RBAC. Create user with no RBAC role.
"""


TOPOLOGY = """
#  +----------+
#  |  switch  |
#  +----------+

# Nodes
[type=openswitch name="OpenSwitch 1"] switch
"""


def test_rbac_create_norole_account(topology, step):
    """
    Test that creates a user with no RBAC role.
    """
    sw = topology.get('switch')
    assert sw is not None

    ###
    # Running rbac_verify_netops_account test
    ###
    step("### Start: rbac_create_ops_norole_account test ###")
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
    # Create and verify norole account is present.
    ##
    step("## Create and verify norole account is present ##")

    #
    # Create a user with no RBAC role.
    #
    step("### Create a user with no RBAC role ###")
    result = sw('sudo /usr/sbin/useradd -g users\
                -s /bin/bash rbac_ct_norole', shell='bash')

    #
    # Verify that the rbac_ct_norole account is present.
    #
    step("### Verify the rbac_ct_norole account exists ###")
    result = sw('id -u rbac_ct_norole', shell='bash')
    if "no such user" in result:
        assert False, 'User rbac_ct_norole account not created'

    #
    # Login to rbac_ct_norole account.
    #
    step("### login to rbac_ct_norole account ###")
    result = sw('sudo su -c "id" rbac_ct_norole', shell='bash')
    if "rbac_ct_norole" not in result:
        assert False, 'su rbac_ct_norole command did not work'

    #
    # Verify that the rbac_ct_norole account has memberships to the
    # correct groups.
    #
    step("### Verify the rbac_ct_norole account has correctmembership")
    result = sw('groups rbac_ct_norole', shell='bash')
    if "user" not in result:
        assert False, 'rbac_ct_norole user is not a member of users group'
    if "ops_admin" in result:
        assert False, 'rbac_ct_norole user is member of ops_admin group'
    if "ops_netop" in result:
        assert False, 'rbac_ct_norole user is member of ops_netop group'
    if "ovsdb-client" in result:
        assert False, 'rbac_ct_norole user is a member of the ovsdb-client'

    #
    # Verify rbac_ct_norole's RBACs roles and permissions.
    #
    step("### Verify RBAC is returning correct info for rbac_ct_norole ###")

    #
    # rbac.get_user_role()
    # Should have role of "None"
    #
    step("### Verify rbac.get_user_role(rbac_ct_norole) ###")
    result = sw('python -c \'import rbac;\
                rbac.get_user_role_p("rbac_ct_norole")\'', shell='bash')

    if role_none not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Should have no permissions
    #
    step("### Verify rbac.get_user_permissions(rbac_ct_norole) ###")
    permissions = sw('python -c \'import rbac;\
                     rbac.get_user_permissions_p("rbac_ct_norole")\'',
                     shell='bash')

    if sys_mgmt in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Should have no permissions
    #
    step("### Verify rbac.check_user_permission(rbac_ct_norole) ###")
    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("rbac_ct_norole",\
                 rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.check_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("rbac_ct_norole",\
                 rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("rbac_ct_norole",\
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
        # Finished rbac_verify_norole_account test
        ###
        step("### Finished: rbac_verify_norole_account test  ###")

        #
        # Remove the rbac_ct_norole user.
        #
        step("### Remove the rbac_ct_norole user ###")
        result = sw('sudo /usr/sbin/userdel rbac_ct_norole', shell='bash')
        return

    #
    # rbac_get_user_role()
    # Role should be "None"
    #
    step("# Verify rbac.get_user_role(rbac_ct_norole) #")

    result = sw('rbac_role rbac_ct_norole', shell='bash')
    if role_none not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    #
    # rbac_get_user_permissions()
    # Permissions should be []
    #
    step("# Verify rbac_get_user_permissions(rbac_ct_norole #")

    permissions = sw('rbac_role -p rbac_ct_norole', shell='bash')
    if sys_mgmt in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be []
    #
    step("# Verify rbac_check_user_permission(rbac_ct_norole) #")

    result = sw('rbac_role -c SYS_MGMT rbac_ct_norole',
                shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG rbac_ct_norole',
                shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG rbac_ct_norole',
                shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ###
    # Finished rbac_verify_norole_account test
    ###
    step("### Finished: rbac_verify_norole_account test  ###")

    #
    # remove the rbac_ct_norole user.
    #
    step("### Remove the rbac_ct_norole user ###")
    result = sw('sudo /usr/sbin/userdel rbac_ct_norole', shell='bash')
