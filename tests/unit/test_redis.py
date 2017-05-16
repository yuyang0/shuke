#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import

import sys
from os.path import dirname, abspath
import time
import pytest

sys.path.insert(0, dirname(dirname(abspath(__file__))))
from support import dns_srv, settings, utils

overrides = {
    "data_store": "redis",
    "admin_port": utils.find_available_port(),
    "port": utils.find_available_port(),
}
valgrind = True

zone_init_str  = """
$origin example.com.
$ttl 86400
@	SOA	dns1.example.com.	hostmaster.example.com. (
		2001062501 ; serial
		21600      ; refresh after 6 hours
		3600       ; retry after 1 hour
		604800     ; expire after 1 week
		86400 )    ; minimum TTL of 1 day
www1 4800 IN A 133.2.3.4
     4800 IN A 134.4.5.6
"""

def cmp_rrset(ss1, ss2):
    set1 = set(ss1.split("\n"))
    set2 = set(ss2.split("\n"))
    set1 = {ele.strip(" ") for ele in set1}
    set2 = {ele.strip(" ") for ele in set2}
    return set1 == set2

def test_redis_init(dns_srv):
    rrset_ss = dns_srv.admin_cmd("zone get_rrset example.com SOA")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 86400 IN SOA dns1.example.com. hostmaster.example.com. 2001062501 21600 3600 604800 86400\n")
    rrset_ss = dns_srv.admin_cmd("zone get_rrset www1.example.com A")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 4800 IN A 133.2.3.4\n 4800 IN A 134.4.5.6\n")


def test_redis_add(dns_srv):
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
    dns_srv.write_zone_to_redis(zone_str)
    print(dns_srv.admin_cmd("zone reload 111.com."))
    time.sleep(5)
    rrset_ss = dns_srv.admin_cmd("zone get_rrset 111.com SOA")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 86400 IN SOA dns1.111.com. hostmaster.111.com. 2001062501 21600 3600 604800 86400\n")
    rrset_ss = dns_srv.admin_cmd("zone get_rrset www1.111.com A")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 4800 IN A 133.2.3.4\n 4800 IN A 134.4.5.6\n")

    zone_str = """
$origin 111.com.
$ttl 86400
@	SOA	dns1.111.com.	hostmaster.111.com. (
		2001062502 ; serial
		21600      ; refresh after 6 hours
		3600       ; retry after 1 hour
		604800     ; expire after 1 week
		86400 )    ; minimum TTL of 1 day
www1 4800 IN A 133.2.3.4
     4800 IN A 134.4.5.6

www2 4800 IN A 133.2.3.7
     4800 IN A 134.4.5.8
    """
    dns_srv.write_zone_to_redis(zone_str)
    print(dns_srv.admin_cmd("zone reload 111.com."))
    time.sleep(5)
    rrset_ss = dns_srv.admin_cmd("zone get_rrset 111.com SOA")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 86400 IN SOA dns1.111.com. hostmaster.111.com. 2001062502 21600 3600 604800 86400\n")
    rrset_ss = dns_srv.admin_cmd("zone get_rrset www2.111.com A")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 4800 IN A 133.2.3.7\n 4800 IN A 134.4.5.8\n")

def test_redis_del(dns_srv):
    zone_str = """
$origin 222.com.
$ttl 86400
@	SOA	dns1.222.com.	hostmaster.222.com. (
		2001062501 ; serial
		21600      ; refresh after 6 hours
		3600       ; retry after 1 hour
		604800     ; expire after 1 week
		86400 )    ; minimum TTL of 1 day
www1 4800 IN A 133.2.3.4
     4800 IN A 134.4.5.6
    """
    dns_srv.write_zone_to_redis(zone_str)
    print(dns_srv.admin_cmd("zone reload 222.com."))
    time.sleep(5)
    rrset_ss = dns_srv.admin_cmd("zone get_rrset 222.com SOA")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 86400 IN SOA dns1.222.com. hostmaster.222.com. 2001062501 21600 3600 604800 86400\n")
    rrset_ss = dns_srv.admin_cmd("zone get_rrset www1.222.com A")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 4800 IN A 133.2.3.4\n 4800 IN A 134.4.5.6\n")

    dns_srv.redis_delete_zone("222.com.")
    print(dns_srv.admin_cmd("zone reload 222.com."))
    time.sleep(5)
    zone_ss = dns_srv.admin_cmd("zone get 222.com")
    assert zone_ss == "zone 222.com. not found"


def test_redis_reloadall(dns_srv):
    zone_str = """
$origin 333.com.
$ttl 86400
@	SOA	dns1.333.com.	hostmaster.333.com. (
		2001062501 ; serial
		21600      ; refresh after 6 hours
		3600       ; retry after 1 hour
		604800     ; expire after 1 week
		86400 )    ; minimum TTL of 1 day
www1 4800 IN A 133.2.3.4
     4800 IN A 134.4.5.6
    """
    dns_srv.write_zone_to_redis(zone_str)
    print(dns_srv.admin_cmd("zone reloadall"))
    time.sleep(5)
    rrset_ss = dns_srv.admin_cmd("zone get_rrset 333.com SOA")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 86400 IN SOA dns1.333.com. hostmaster.333.com. 2001062501 21600 3600 604800 86400\n")
    rrset_ss = dns_srv.admin_cmd("zone get_rrset www1.333.com A")
    # print(rrset_ss)
    assert cmp_rrset(rrset_ss, " 4800 IN A 133.2.3.4\n 4800 IN A 134.4.5.6\n")
