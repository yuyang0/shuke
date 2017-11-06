#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
import pytest
import socket

import vagrant

from . import server, settings


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
    if valgrind:
        assert check_valgrind_error(srv.get_stderr())


@pytest.fixture(scope="session", autouse=True)
def start_vagrant(request):
    vgt = vagrant.Vagrant(root=os.path.join(settings.REPO_ROOT, "vagrant"))
    vgt.up(provision=True)
    # prepare something ahead of all tests
    # request.addfinalizer(finalizer_function)


def find_available_port():
    """
    find available port, dirty but it works
    """
    sock = socket.socket()
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def check_valgrind_error(ss):
    success = [
        "definitely lost: 0 bytes",
        "no leaks are possible",
    ]
    for succ in success:
        if ss.find(succ) != -1:
            return True
    return False


def check_pid(pid):
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True
