#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import

import sys
import os
from os.path import dirname, abspath
import socket

sys.path.insert(0, dirname(dirname(abspath(__file__))))
from support import settings, server

import pytest
import vagrant


@pytest.fixture(scope="module")
def dns_srv(request):
    overrides = getattr(request.module, "overrides", {})
    valgrind = getattr(request.module, "valgrind", False)

    srv = server.DNSServer(overrides, valgrind)
    if srv.cf["data_store"].lower() == "mongo":
        srv.mongo_clear()
        zone_init_str = getattr(request.module, "zone_init_str", None)
        if zone_init_str:
            srv.write_zone_to_mongo(zone_init_str)
    srv.start()

    yield srv
    srv.stop()


@pytest.fixture(scope="session", autouse=True)
def start_vagrant(request):
    print("starting vagrant...")
    vagrant_root = os.path.join(settings.REPO_ROOT, "vagrant")
    vgt = vagrant.Vagrant(root=vagrant_root)
    statuses = vgt.status()
    if len(statuses) >= 1 and statuses[0].state == "running":
        print("vm is in running state, skip `vagrant up`")
    else:
        res = vgt.up(provision=True, stream_output=True)
        if res is not None:
            for output in res:
                print(output, end='')
    print("vagrant is started...")

    # prepare something ahead of all tests
    def finalizer_func():
        pass
    request.addfinalizer(finalizer_func)


def find_available_port():
    """
    find available port, dirty but it works
    """
    sock = socket.socket()
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port
