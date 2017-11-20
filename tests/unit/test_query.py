#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import sys
from os.path import dirname, abspath
import pytest

sys.path.insert(0, dirname(dirname(abspath(__file__))))
from support import constants

overrides = {
    "zone_source.type": "file",
    # "zone_files": {"example.com.": constants.EXAMPLE_ZONE_FILE},
    "core.minimize_resp": False,
}
valgrind = False


def collect_rdata(rrset_list):
    lst = []
    for rrset in rrset_list:
        lst += [item.to_text() for item in rrset.items]
    return set(lst)


def collect_names(rrset_list):
    return {str(rrset.name) for rrset in rrset_list}


def test_query_a(dns_srv):
    msg = dns_srv.dns_query("test-a.example.com.", "A")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and \
        len(msg.authority) == 1 and len(msg.additional) == 4

    addresses = collect_rdata(msg.answer)
    assert collect_names(msg.answer) == {"test-a.example.com."}
    assert set(addresses) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    assert collect_names(msg.authority) == {"example.com."}
    assert collect_rdata(msg.authority) == {'dNs2.exAmple.com.', 'dns1.examPle.com.'}
    # print(len(aut_list), len(aut.items), addresses)

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2"}


def test_query_aaaa(dns_srv):
    msg = dns_srv.dns_query("test-aaaa.example.com.", "AAAA")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and\
        len(msg.authority) == 1 and len(msg.additional) == 4

    addresses = collect_rdata(msg.answer)
    assert collect_names(msg.answer) == {"test-aaaa.example.com."}
    assert set(addresses) == {"aaaa:bbbb::5", "aaaa:bbbb::6", "aaaa:bbbb::7"}

    assert collect_names(msg.authority) == {"example.com."}
    assert collect_rdata(msg.authority) == {'dNs2.exAmple.com.', 'dns1.examPle.com.'}

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2"}


def test_query_txt(dns_srv):
    msg = dns_srv.dns_query("test-txt.example.com.", "TXT")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and\
        len(msg.authority) == 1 and len(msg.additional) == 4
    assert collect_names(msg.answer) == {"test-txt.example.com."}
    assert collect_rdata(msg.answer) == {'" 11 " " 22 "', '" 33 " " 44 "', '" 55 " " 66 "'}

    assert collect_names(msg.authority) == {"example.com."}
    assert collect_rdata(msg.authority) == {'dNs2.exAmple.com.', 'dns1.examPle.com.'}

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2"}


def test_query_mx(dns_srv):
    msg = dns_srv.dns_query("test-mx.example.com.", "MX")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and\
        len(msg.authority) == 1 and len(msg.additional) == 8
    assert collect_names(msg.answer) == {"test-mx.example.com."}
    assert collect_rdata(msg.answer) == {'20 mail2.example.com.', '10 maIl.examplE.com.'}

    assert collect_names(msg.authority) == {"example.com."}
    assert collect_rdata(msg.authority) == {'dNs2.exAmple.com.', 'dns1.examPle.com.'}

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2",
                         "10.0.1.5", "10.0.1.6", "aaaa:bbbb::5", "aaaa:bbbb::6"}


def test_query_cname(dns_srv):
    msg = dns_srv.dns_query("test-cname.example.com.", "cname")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and\
        len(msg.authority) == 1 and len(msg.additional) == 5
    assert collect_names(msg.answer) == {"test-cname.example.com."}
    assert collect_rdata(msg.answer) == {'www1.example.com.'}

    assert collect_names(msg.authority) == {"example.com."}
    assert collect_rdata(msg.authority) == {'dNs2.exAmple.com.', 'dns1.examPle.com.'}

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2",
                         "10.0.0.33", "10.0.0.34", "10.0.0.35"}


def test_query_cname_other(dns_srv):
    """
    cname record's  don't belong to this server.
    """
    msg = dns_srv.dns_query("www.example.com.", "cname")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and\
        len(msg.authority) == 0 and len(msg.additional) == 0
    assert collect_names(msg.answer) == {"www.example.com."}
    assert collect_rdata(msg.answer) == {'www.other.com.'}


def test_query_ns(dns_srv):
    msg = dns_srv.dns_query("example.com.", "NS")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and\
        len(msg.authority) == 0 and len(msg.additional) == 4

    assert collect_names(msg.answer) == {"example.com."}
    assert collect_rdata(msg.answer) == {'dns1.examPle.com.', 'dNs2.exAmple.com.'}

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2"}


def test_query_soa(dns_srv):
    msg = dns_srv.dns_query("example.com.", "SOA")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and\
        len(msg.authority) == 1 and len(msg.additional) == 4

    assert collect_names(msg.answer) == {"example.com."}
    assert collect_rdata(msg.answer) == {'dns1.example.com. hostmaster.example.com. 2001062501 21600 3600 604800 86400'}

    assert collect_names(msg.authority) == {"example.com."}
    assert collect_rdata(msg.authority) == {'dNs2.exAmple.com.', 'dns1.examPle.com.'}

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2"}


def test_query_srv(dns_srv):
    msg = dns_srv.dns_query("_sip._tcp.example.com.", "SRV")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and\
        len(msg.authority) == 1 and len(msg.additional) == 5

    assert collect_names(msg.answer) == {"_sip._tcp.example.com."}
    assert collect_rdata(msg.answer) == {'10 60 5060 biGbox.example.com.',
                                         '10 20 5060 smallbox1.example.com.',
                                         '10 20 5060 smallbox2.example.com.', \
                                         "20 0 5060 backupbox.example.com."}

    assert collect_names(msg.authority) == {"example.com."}
    assert collect_rdata(msg.authority) == {'dNs2.exAmple.com.', 'dns1.examPle.com.'}

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2",
                         "197.2.3.4", "197.2.3.5"}


def test_query_subsub(dns_srv):
    msg = dns_srv.dns_query("test-sub.sub.example.com.", "A")
    assert len(msg.question) == 1 and len(msg.answer) == 1 and \
        len(msg.authority) == 1 and len(msg.additional) == 4

    addresses = collect_rdata(msg.answer)
    assert collect_names(msg.answer) == {"test-sub.sub.example.com."}
    assert set(addresses) == {"10.0.0.1", "10.0.0.2"}

    assert collect_names(msg.authority) == {"example.com."}
    assert collect_rdata(msg.authority) == {'dNs2.exAmple.com.', 'dns1.examPle.com.'}
    # print(len(aut_list), len(aut.items), addresses)

    add_rdata = collect_rdata(msg.additional)
    assert add_rdata == {"10.0.1.1", "aaaa:bbbb::1", "10.0.1.2", "aaaa:bbbb::2"}
