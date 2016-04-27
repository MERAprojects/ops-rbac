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
OpenSwitch Test for RBAC. Range check RBAC APIs.
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


def test_rbac_range_check_api(topology, step):
    """
    Test that verifies the RBAC APIs.
    """
    sw = topology.get('switch')
    assert sw is not None

    #
    # Range check the RBAC API's
    #
    step("### Range check the RBAC API's ###")

    ##
    # Range check the RBAC Python interface.
    ##
    step("## Running RBAC Python tests ##")

    #
    # rbac.get_user_role()
    # Role should be none
    #
    step("### Range check rbac.get_user_role() ###")
    role_none = sw('python -c \'import rbac; print rbac.ROLE_NONE\'',
                   shell='bash')

    # User blank
    ret = sw('python -c \'import rbac; rbac.get_user_role_p("")\'',
             shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User junk
    ret = sw('python -c \'import rbac; rbac.get_user_role_p("KJSDKJDSKJ")\'',
             shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User "neto"
    ret = sw('python -c \'import rbac; rbac.get_user_role_p("neto")\'',
             shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User "netopp"
    ret = sw('python -c \'import rbac; rbac.get_user_role_p("netopp")\'',
             shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User "adm"
    ret = sw('python -c \'import rbac; rbac.get_user_role_p("adm")\'',
             shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User "adminn"
    ret = sw('python -c \'import rbac; rbac.get_user_role_p("adminn")\'',
             shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be none
    #
    step("### Verify rbac.get_user_permissions(admin) ###")

    # User blank
    ret = sw('python -c \'import rbac;\
             rbac.get_user_permissions_p("")\'', shell='bash')
    if "[]" not in ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User junk
    ret = sw('python -c \'import rbac;\
             rbac.get_user_permissions_p("KSDJFD")\'', shell='bash')
    if "[]" not in ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User "neto"
    ret = sw('python -c \'import rbac;\
             rbac.get_user_permissions_p("neto")\'', shell='bash')
    if "[]" not in ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User "netopp"
    ret = sw('python -c \'import rbac;\
             rbac.get_user_permissions_p("netopp")\'', shell='bash')
    if "[]" not in ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User "adm"
    ret = sw('python -c \'import rbac;\
             rbac.get_user_permissions_p("adm")\'', shell='bash')
    if "[]" not in ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User "adminn"
    ret = sw('python -c \'import rbac;\
             rbac.get_user_permissions_p("adminn")\'', shell='bash')
    if "[]" not in ret:
        assert False, 'rbac.get_user_permissions wrong value'

    #
    # rbac.check_user_permission()
    # Permissions should be none
    #
    # User blank
    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("","") \'',
             shell='bash')
    if "False" not in ret:
        assert False, 'rbac.check_user_permission  wrong value'

    # User junk
    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("DKJJDKF","JKDSJFL") \'',
             shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "neto"
    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("neto",\
             rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("neto",\
             rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("neto",\
             rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "netopp"
    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("netopp",\
             rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("netopp",\
             rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("netopp",\
             rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "adm"
    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("adm",\
             rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("adm",\
             rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("adm",\
             rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "adminn"
    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("adminn",\
             rbac.SYS_MGMT)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("adminn",\
             rbac.READ_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("adminn",\
             rbac.WRITE_SWITCH_CONFIG)\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "admin" or "netop" - invalid permissions
    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("admin",\
             "SYS_MGM")\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("admin",\
             "SYS_MGMTT")\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("netop",\
             "READ_SWITCH_CONFI")\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("netop",\
             "READ_SWITCH_CONFIGG")\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("netop",\
             "WRITE_SWITCH_CONFI")\'', shell='bash')
    if "False" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('python -c \'import rbac;\
             rbac.check_user_permission_p("netop",\
             "WRITE_SWITCH_CONFIGG")\'', shell='bash')
    if "False" not in ret:
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
        return

    #
    # rbac_get_user_role()
    # Role should be none
    #
    step("### Range check rbac.get_user_role() ###")

    # User junk
    ret = sw('rbac_role KJSDKJDSKJ', shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User "neto"
    ret = sw('rbac_role neto', shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User "netopp"
    ret = sw('rbac_role netopp', shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User "adm"
    ret = sw('rbac_role adm', shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    # User "adminn"
    ret = sw('rbac_role adminn', shell='bash')
    if ret not in role_none:
        assert False, 'rbac.get_user_role returning wrong role'

    #
    # rbac.get_user_permissions()
    # Permissions should be none
    #
    step("### Verify rbac.get_user_permissions() ###")

    # User junk
    ret = sw('rbac_role -p KSDJFD', shell='bash')
    if ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User "neto"
    ret = sw('rbac_role -p neto', shell='bash')
    if ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User "netopp"
    ret = sw('rbac_role -p netopp', shell='bash')
    if ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User "adm"
    ret = sw('rbac_role -p adm', shell='bash')
    if ret:
        assert False, 'rbac.get_user_permissions wrong value'

    # User "adminn"
    ret = sw('rbac_role -p adminn', shell='bash')
    if ret:
        assert False, 'rbac.get_user_permissions wrong value'

    #
    # rbac.check_user_permission()
    # Permissions should be none
    #

    # User junk
    ret = sw('rbac_role -c DKJJDKF JKDSJFL', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "neto"
    ret = sw('rbac_role -c SYS_MGMT neto', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c READ_SWITCH_CONFIG neto', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c WRITE_SWITCH_CONFIG neto', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "netopp"
    ret = sw('rbac_role -c SYS_MGMT netopp', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c READ_SWITCH_CONFIG netopp', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c WRITE_SWITCH_CONFIG netopp', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "adm"
    ret = sw('rbac_role -c SYS_MGMT adm', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c READ_SWITCH_CONFIG adm', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c WRITE_SWITCH_CONFIG adm', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "adminn"
    ret = sw('rbac_role -c SYS_MGMT adminn', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c READ_SWITCH_CONFIG adminn', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c WRITE_SWITCH_CONFIG adminn', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    # User "admin" or "netop" - invalid permissions
    ret = sw('rbac_role -c SYS_MGM admin', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c SYS_MGMTT admin', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c READ_SWITCH_CONFI netop', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c READ_SWITCH_CONFIGG netop', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c WRITE_SWITCH_CONFI netop', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'

    ret = sw('rbac_role -c WRITE_SWITCH_CONFIGG netop', shell='bash')
    if "false" not in ret:
        assert False, 'rbac.get_user_role returning wrong permission'
