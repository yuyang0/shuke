#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import pytest
import socket

from . import server


@pytest.fixture(scope="module")
def dns_srv(request):
    conf = getattr(request.module, "conf", None)
    overrides = getattr(request.module, "overrides", {})
    valgrind = getattr(request.module, "valgrind", False)

    srv = server.DNSServer(conf, overrides, valgrind)
    if srv.cf["data_store"].lower() == "redis":
        srv.redis_clear()
        zone_init_str = getattr(request.module, "zone_init_str", None)
        if zone_init_str:
            srv.write_zone_to_redis(zone_init_str)
    srv.start()

    yield srv
    srv.stop()
    print(srv.get_stderr())
    if valgrind:
        assert check_valgrind_error(srv.get_stderr())


@pytest.fixture(scope="session")
def redis_srv(request):
    srv = server.RedisServer()
    yield srv
    srv.stop()


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
