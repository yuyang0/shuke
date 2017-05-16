#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os.path
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import server, utils, zone2redis, settings

if __name__ == "__main__":
    psr = zone2redis.ZoneParser("./assets/example.z")
    print(psr)

    print(settings.DEFAULT_CONF)
    srv = server.DNSServer(overrides={"port": utils.find_available_port()}, valgrind=True)
    print(srv.cf_str)
    # open("/home/yangyu/aaaa.conf", "wb").write(srv.cf_str.encode("utf8"))

    srv.start()
    # print(srv.info())
    time.sleep(10)
    srv.stop()
    stderr = srv.get_stderr()
    print(stderr)
    print(utils.check_valgrind_error(stderr))
