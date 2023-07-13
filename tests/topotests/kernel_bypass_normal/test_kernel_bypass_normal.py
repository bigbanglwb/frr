#!/usr/bin/env python

#
# <template>.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
<template>.py: Test <template>.
"""

import os
import sys
import pytest
import json
import re
from functools import partial
import pdb
# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# # Required to instantiate the topology builder class.
# from mininet.topo import Topo
# from mininet.net import Mininet


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    
    switch = tgen.add_switch('s1')
    
    switch.add_link(tgen.gears['r1'])
    switch.add_link(tgen.gears['r2'])

    
def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()
    print("topology started")
    # This is a sample of configuration loading.
    router_list = tgen.routers()
    
    # For all registred routers, load the zebra configuration file
    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC,
            os.path.join(CWD, '{}/staticd.conf'.format(rname))
        )
    
    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()

    # Verify that we are using the proper version and that the BFD
    # daemon exists.
    for router in router_list.values():
        # Check for Version
        if router.has_version('<', '5.1'):
            tgen.set_error('Unsupported FRR version')
            break

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    # This function tears down the whole topology.
    tgen.stop_topology()


def test_ebgp_peers():
    "Assert that BGP peers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bgp peers to go up')

    for router in tgen.routers().values():
        ref_file = '{}/{}/peers.json'.format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show bgp neighbors json', expected)
        _, res = topotest.run_and_expect(test_func, None, count=1, wait=10.0)
        assertmsg = '{}: bgp did not established'.format(router.name)
        assert res is None, assertmsg

def test_ebgp_convergence():
    "Assert that BGP is converging."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bgp peers to go up')

    for router in tgen.routers().values():
        ref_file = '{}/{}/ip_route_summary.json'.format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(topotest.router_json_cmp,
                            router, 'show ip route summary json', expected)
        _, res = topotest.run_and_expect(test_func, None, count=1, wait=20.0)
        assertmsg = '{}: bgp did not converge'.format(router.name)
        assert res is None, assertmsg

def test_kernel_route():
    "Assert kernel route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('waiting for bgp peers to go up')
    r1 = tgen.gears['r1']
    test_func = partial(topotest.router_output_cmp,
                        r1, 'show running',"3")
    _, res = topotest.run_and_expect(test_func, None, count=1, wait=20.0)
    output = r1.cmd("route -n |wc -l")
    logger.info(r1.cmd("route -n"))
    assert int(output)==3 , 'normal test failed'

# # Memory leak test template
# def test_memory_leak():
#     "Run the memory leak test and report results."
#     tgen = get_topogen()
#     if not tgen.is_memleak_enabled():
#         pytest.skip('Memory leak test/report is disabled')

#     tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
