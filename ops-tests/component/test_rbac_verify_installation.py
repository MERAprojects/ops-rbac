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
OpenSwitch Test for RBAC. Verify installation.
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


def test_rbac_verify_installation(topology, step):
    """
    Test that verifies the RBAC components are installed correctly.
    """
    sw = topology.get('switch')
    assert sw is not None

    #
    # The rbac.py script should be located at
    #    /usr/lib/python2.7/site-packages/rbac.py
    #    /usr/lib/python2.7/site-packages/rbac.pyc
    #
    step("### Verify the RBAC python scripts location and permissions ###")
    result = sw('ls -l /usr/lib/python2.7/site-packages/rbac.py', shell='bash')
    if "ls: cannot access" in result:
        assert False, 'Missing rbac.py file'
    if "No such file or directory" in result:
        assert False, 'Missing rbac.py file'
    if "-rw-r--r-- 1 root root" not in result:
        assert False, 'Incorrect permissions for rbac.py file'

    result = sw('ls -l /usr/lib/python2.7/site-packages/rbac.pyc',
                shell='bash')
    if "ls: cannot access" in result:
        assert False, 'Missing rbac.pyc file'
    if "No such file or directory" in result:
        assert False, 'Missing rbac.pyc file'
    if "-rw-r--r-- 1 root root" not in result:
        assert False, 'Incorrect permissions for rbac.py file'

    #
    # The rbac shared library should be located at
    #    /usr/lib//usr/lib/librbac.so.0.1.0
    #
    step("### Verify the rbac shared library location and permissions ###")
    result = sw('ls -l /usr/lib/librbac.so.0.1.0', shell='bash')
    if "ls: cannot access" in result:
        assert False, 'Missing librbac.so.0.1.0 file'
    if "No such file or directory" in result:
        assert False, 'Missing librbac.so.0.1.0 file'
    if "-rwxr-xr-x 1 root root" not in result:
        assert False, 'Incorrect permissions for librbac.so.0.1.0 file'
