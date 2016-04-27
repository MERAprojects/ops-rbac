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
OpenSwitch Test for RBAC. Creates user with both ops_admin, ops_netop roles.
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


def test_rbac_create_multirole_accounts(topology, step):
    """
    RBAC test that creates a user with both ops_admin, ops_netop roles.
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
    # Create users with both ops_admin and ops_netop roles.
    #
    step("### Create users with ops_admin and ops_netop roles ###")
    result = sw('sudo /usr/sbin/useradd -g ops_admin -G ops_netop \
                -s /bin/bash rbac_ct_mr1', shell='bash')
    result = sw('sudo /usr/sbin/useradd -g ops_netop -G ops_admin \
                -s /bin/bash rbac_ct_mr2', shell='bash')

    #
    # Verify that both rbac_ct_mr user accounts are present.
    #
    step("### Verify the rbac_ct_mr1 account exists ###")
    result = sw('id -u rbac_ct_mr1', shell='bash')
    if "no such user" in result:
        assert False, 'rbac_ct_mr1 account not created'

    step("### Verify the rbac_ct_mr2 account exists ###")
    result = sw('id -u rbac_ct_mr2', shell='bash')
    if "no such user" in result:
        assert False, 'rbac_ct_mr2 account not created'

    #
    # Login to both rbac_ct_mr accounts.
    #
    step("### login to rbac_ct_mr1 account ###")
    result = sw('sudo su -c "id" rbac_ct_mr1', shell='bash')
    if "rbac_ct_mr1" not in result:
        assert False, 'su rbac_ct_mr1 command did not work'

    step("### login to rbac_ct_mr2 account ###")
    result = sw('sudo su -c "id" rbac_ct_mr2', shell='bash')
    if "rbac_ct_mr2" not in result:
        assert False, 'su rbac_ct_mr2 command did not work'

    #
    # Verify rbac_ct_mr accounts have sudo privileges.
    #
    step("### Check for sudo privilges ###")
    result = sw('sudo su rbac_ct_mr1 -c "sudo ls"', shell='bash')
    if "Permission denied" in result:
        assert False, 'sudo not working for rbac_ct_mr1'

    step("### Check for sudo privilges ###")
    result = sw('sudo su rbac_ct_mr2 -c "sudo ls"', shell='bash')
    if "Permission denied" in result:
        assert False, 'sudo not working for rbac_ct_mr2'

    #
    # Verify that both rbac_ct_mr accounts have memberships to the
    # correct groups.
    #
    step("### Verify the rbac_ct_mr1 account has membership to the \
         right groups")
    result = sw('groups rbac_ct_mr1', shell='bash')
    if "ops_admin" not in result:
        assert False, 'rbac_ct_mr1 user not a member of ops_admin group'
    if "ops_netop" not in result:
        assert False, 'rbac_ct_mr1 user not a member of ops_netop group'
    if "ovsdb-client" in result:
        assert False, 'rbac_ct_mr1 is a member of the ovsdb-client group'

    step("### Verify the rbac_ct_mr2 account has membership to the \
         right groups")
    result = sw('groups rbac_ct_mr2', shell='bash')
    if "ops_admin" not in result:
        assert False, 'rbac_ct_mr2 user not a member of ops_admin group'
    if "ops_netop" not in result:
        assert False, 'rbac_ct_mr2 user not a member of ops_admin group'
    if "ovsdb-client" in result:
        assert False, 'rbac_ct_mr2 is a member of the ovsdb-client group'

    #
    # Verify rbac_ct_admin's RBACs roles and permissions.
    #
    step("### Verify RBAC is returning correct information for \
          both rbac_ct_mr users ###")

    #
    # rbac.get_user_role()
    # Role should be ops_admin
    #
    step("### Verify rbac.get_user_role(rbac_ct_mr1) ###")
    result = sw('python -c \'import rbac;\
                 rbac.get_user_role_p("rbac_ct_mr1")\'', shell='bash')

    if role_admin not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    step("### Verify rbac.get_user_role(rbac_ct_mr2) ###")
    result = sw('python -c \'import rbac;\
                rbac.get_user_role_p("rbac_ct_mr2")\'', shell='bash')

    if role_admin not in result:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be SYS_MGMT
    #
    step("### Verify rbac.get_user_permissions(rbac_ct_mr1) ###")
    permissions = sw('python -c \'import rbac;\
                     rbac.get_user_permissions_p("rbac_ct_mr1")\'',
                     shell='bash')

    if sys_mgmt not in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac.get_user_role returning wrong permission'

    step("### Verify rbac.get_user_permissions(rbac_ct_mr2) ###")
    permissions = sw('python -c \'import rbac;\
                     rbac.get_user_permissions_p("rbac_ct_mr2")\'',
                     shell='bash')

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
    step("### Verify rbac.check_user_permission(rbac_ct_mr1) ###")
    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_mr1",\
                rbac.SYS_MGMT)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_mr1",\
                rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_mr1",\
                rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    step("### Verify rbac.check_user_permission(rbac_ct_mr2) ###")
    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_mr2",\
                rbac.SYS_MGMT)\'', shell='bash')
    if "True" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_mr2",\
                rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('python -c \'import rbac;\
                rbac.check_user_permission_p("rbac_ct_mr2",\
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
        # Finished rbac_verify_mr_account test
        ###
        step("### Finished: rbac_verify_mr_account test  ###")

        #
        # remove the rbac_ct_admin user.
        #
        step("# Remove the user with ops_netop role #")
        result = sw('sudo /usr/sbin/userdel rbac_ct_mr1', shell='bash')
        result = sw('sudo /usr/sbin/userdel rbac_ct_mr2', shell='bash')
        return

    #
    # rbac_get_user_role()
    # Role should be admin
    #
    step("# Verify rbac.get_user_role(rbac_ct_mr) #")
    result = sw('rbac_role rbac_ct_mr1', shell='bash')
    if role_admin not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    result = sw('rbac_role rbac_ct_mr2', shell='bash')
    if role_admin not in result:
        assert False, 'rbac_get_user_role returning wrong role'

    #
    # Finished rbac_verify_netop_accounts test
    # Permissions should be SYS_MGMT
    #
    step("# Verify rbac_get_user_permissions(rbac_cr_mr) #")
    permissions = sw('rbac_role -p rbac_ct_mr1', shell='bash')
    if sys_mgmt not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    permissions = sw('rbac_role -p rbac_ct_mr2', shell='bash')
    if sys_mgmt not in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if read_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    if write_switch_config in permissions:
        assert False, 'rbac_get_user_role returning wrong permission'

    #
    # rbac.check_user_permission()
    # Permissions should be SYS_MGMT
    #
    step("# Verify rbac_check_user_permission(rbac_ct_netop1) #")

    result = sw('rbac_role -c SYS_MGMT rbac_ct_mr1', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG rbac_ct_mr1', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG rbac_ct_mr1', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    step("### Verify rbac_check_user_permission(rbac_ct_mr2) ###")
    result = sw('rbac_role -c SYS_MGMT rbac_ct_mr2', shell='bash')
    if "true" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c READ_SWITCH_CONFIG rbac_ct_mr2', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    result = sw('rbac_role -c WRITE_SWITCH_CONFIG rbac_ct_mr2', shell='bash')
    if "false" not in result:
        assert False, 'rbac.get_user_role returning wrong permission'

    ###
    # Finished rbac_verify_multirole_accounts test
    ###
    step("### Finished: rbac_verify_multirole_account test  ###")

    #
    # remove the rbac_ct_mr users
    #
    step("### Remove the rbac_ct_rm users ###")
    result = sw('sudo /usr/sbin/userdel rbac_ct_mr1', shell='bash')
    result = sw('sudo /usr/sbin/userdel rbac_ct_mr2', shell='bash')
