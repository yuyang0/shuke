#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import

import sys
from os.path import dirname, abspath
import pytest

sys.path.insert(0, dirname(dirname(abspath(__file__))))
from support import dns_srv, settings, utils

overrides = {
    "data_store": "file",
    # "zone_files": {"example.com.": settings.EXAMPLE_ZONE_FILE},
    "admin_port": utils.find_available_port(),
    "port": utils.find_available_port(),
}
valgrind = True

def cmp_rrset(ss1, ss2):
    set1 = set(ss1.split("\n"))
    set2 = set(ss2.split("\n"))
    set1 = {ele.strip(" ") for ele in set1}
    set2 = {ele.strip(" ") for ele in set2}
    return set1 == set2


def test_zone_set(dns_srv):
    zone_str = """
$origin 111.com.
$ttl 86400
@	SOA	dns1.111.com.	hostmaster.111.com. (
		2001062501 ; serial
		21600      ; refresh after 6 hours
		3600       ; retry after 1 hour
		604800     ; expire after 1 week
		86400 )    ; minimum TTL of 1 day
www1 4800 IN A 133.2.3.4
     4800 IN A 134.4.5.6
    """
    print(dns_srv.admin_cmd("zone set 111.com. \"%s\"" % zone_str))
    rrset_ss = dns_srv.admin_cmd("zone get_rrset 111.com SOA")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 86400 IN SOA dns1.111.com. hostmaster.111.com. 2001062501 21600 3600 604800 86400\n")
    rrset_ss = dns_srv.admin_cmd("zone get_rrset www1.111.com A")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 4800 IN A 133.2.3.4\n 4800 IN A 134.4.5.6\n")
