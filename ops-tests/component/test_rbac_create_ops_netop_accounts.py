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
OpenSwitch Test for RBAC. Create user with ops_netop role.
"""


TOPOLOGY = """
#  +----------+
#  |  switch  |
#  +----------+

# Nodes
[type=openswitch name="OpenSwitch 1"] switch
"""


def test_rbac_create_ops_netop_accounts(topology, step):
    """
    Test that creates a user with ops_netop role.
    """
    sw = topology.get('switch')
    assert sw is not None

    ###
    # Running rbac_verify_netops_account test
    ###
    step("### Start: rbac_create_ops_netop_accounts test ###")
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
    # Create and verify admin account is present.
    ##
    step("## Create and verify netop accounts is present ##")

    #
    # Create two users with ops_netop role.
    #
    # Note: Accounts with the ops_netop role should have vtysh
    # as there login shell. I am using bash here so I can
    # validate the account later in this script.
    #
    step("# Create a user with ops_netop role #")
    result = sw('sudo /usr/sbin/useradd -g ops_netop -G ovsdb-client \
                -s /bin/bash rbac_ct_netop1', shell='bash')
    result = sw('sudo /usr/sbin/useradd -g ovsdb-client -G ops_netop \
                -s /bin/bash rbac_ct_netop2', shell='bash')

    #
    # Verify that the netop accounts are present.
    #
    step("# Verify the netop account exists #")
    result = sw('id -u rbac_ct_netop1', shell='bash')
    if "no such user" in result:
        assert False, 'User rbac_ct_netop1 account not created'

    result = sw('id -u rbac_ct_netop2', shell='bash')
    if "no such user" in result:
        assert False, 'User rbac_ct_netop2 account not created'

    #
    # Login to rbac_ct_netop account.
    #
    step("# login to rbac_ct_netop accounts #")
    result = sw('sudo su -c "id" rbac_ct_netop1', shell='bash')
    if "rbac_ct_netop1" not in result:
        assert False, 'su rbac_ct_netop1 command did not work'

    result = sw('sudo su -c "id" rbac_ct_netop2', shell='bash')
    if "rbac_ct_netop2" not in result:
        assert False, 'su rbac_ct_netop2 command did not work'

    #
    # Verify that the rbac_ct_netop account has memberships to the
    # correct groups.
    #
    step("# Verify the rbac_ct_netop account membership #")
    result = sw('groups rbac_ct_netop1', shell='bash')
    if "ops_netop" not in result:
        assert False, 'rbac_ct_netop1 is not a member of ops_netop group'
    if "ovsdb-client" not in result:
        assert False, 'rbac_ct_netop1 is a member of the ovsdb-client group'

    result = sw('groups rbac_ct_netop2', shell='bash')
    if "ops_netop" not in result:
        assert False, 'rbac_ct_netop2 is not a member of ops_netop group'
    if "ovsdb-client" not in result:
        assert False, 'rbac_ct_netop2 is a member of the ovsdb-client group'

    ##
    # Verify rbac_ct_netop's RBACs roles and permissions.
    ##
    step("## Verify RBAC is returning correct information for\
         rbac_ct_netop ##")

    ##
    # Verify admin's RBACs roles and permissions in RBAC python library.
    ##
    step("## Running RBAC Python library tests ##")

    #
    # rbac.get_user_role()
    # Role should be ops_netop
    #
    step("### Verify rbac.get_user_role(rbac_ct_netop1) ###")
    result = sw('python -c \'import rbac;\
                rbac.get_user_role_p("rbac_ct_netop1")\'', shell='bash')
    if role_netop not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    step("### Verify rbac.get_user_role(rbac_ct_netop2) ###")
    result = sw('python -c \'import rbac;\
                rbac.get_user_role_p("rbac_ct_netop2")\'', shell='bash')
    if role_netop not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("### Verify rbac.get_user_permissions(rbac_ct_netop1) ###")
    permissions = sw('python -c \'import rbac;\
                     rbac.get_user_permissions_p("rbac_ct_netop1")\'',
                     shell='bash')

    if sys_mgmt in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if read_switch_config not in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if write_switch_config not in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    step("### Verify rbac.get_user_permissions(rbac_ct_netop2) ###")
    permissions = sw('python -c \'import rbac;\
                     rbac.get_user_permissions_p("rbac_ct_netop2")\'',
                     shell='bash')

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
    step("### Verify rbac.check_user_permission(rbac_ct_netop1) ###")
    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("rbac_ct_netop1",\
                 rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.check_user_role returning wrong permission'
    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_netop1",\
                rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'
    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_netop1",\
                rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    step("### Verify rbac.check_user_permission(rbac_ct_netop2) ###")
    result = sw('python -c \'import rbac;\
                 rbac.check_user_permission_p("rbac_ct_netop2",\
                 rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.check_user_role returning wrong permission'
    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_netop2",\
                rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'
    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_netop2",\
                rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "True" not in result:
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
        # Finished rbac_verify_netop_account test
        ###
        step("### Finished: rbac_verify_netop_account test  ###")

        #
        # remove the rbac_ct_admin user.
        #
        step("# Remove the user with ops_netop role #")
        result = sw('sudo /usr/sbin/userdel rbac_ct_netop1', shell='bash')
        result = sw('sudo /usr/sbin/userdel rbac_ct_netop2', shell='bash')
        return

    #
    # rbac_get_user_role()
    # Role should be ops_netop
    #
    step("# Verify rbac.get_user_role(admin) #")
    result = sw('rbac_role rbac_ct_netop1', shell='bash')
    if role_netop not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    result = sw('rbac_role rbac_ct_netop2', shell='bash')
    if role_netop not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    #
    # Finished rbac_verify_netop_accounts test
    # Permissions should be SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("# Verify rbac_get_user_permissions(netop) #")
    permissions = sw('rbac_role -p rbac_ct_netop1', shell='bash')
    if sys_mgmt in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    permissions = sw('rbac_role -p rbac_ct_netop2', shell='bash')
    if sys_mgmt in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG
    #
    step("# Verify rbac_check_user_permission(rbac_ct_netop1) #")
    result = sw('rbac_role -c SYS_MGMT rbac_ct_netop1', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG rbac_ct_netop1',
                shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG rbac_ct_netop1',
                shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    step("### Verify rbac_check_user_permission(rbac_ct_netop2) ###")
    result = sw('rbac_role -c SYS_MGMT rbac_ct_netop2', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG rbac_ct_netop2',
                shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG rbac_ct_netop2',
                shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ###
    # Finished rbac_verify_netop_accounts test
    ###
    step("### Finished: rbac_verify_netop_account test  ###")

    #
    # remove both rbac_ct_netop user.
    #
    step("# Remove the user with ops_netop role #")
    result = sw('sudo /usr/sbin/userdel rbac_ct_netop1', shell='bash')
    result = sw('sudo /usr/sbin/userdel rbac_ct_netop2', shell='bash')
