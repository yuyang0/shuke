#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
from os import path
import random
import argparse
from urllib import request
from pymongo import MongoClient
from pymongo.errors import BulkWriteError


CUR_DIR = path.dirname(path.realpath(__file__))

def to_abs_domain(domain, origin):
    if domain.endswith(origin):
        return domain
    if domain == "@":
        return origin
    if domain.endswith("."):
        raise Exception("domain doesn't belong to this zone" % domain)
    return ".".join([domain, origin])


def to_relative_domain(domain, origin):
    if domain == "@":
        return domain
    if domain == origin:
        return "@"
    if domain.endswith(origin):
        l = len(domain) - len(origin) - 1
        return domain[:l]
    return domain


class ZoneMongo(object):
    def __init__(self, host, port, dbname="zone"):
        self.r = MongoClient(host=host, port=port)
        self.dbname = dbname

    def __getattr__(self, name):
        try:
            return getattr(self.r, name)
        except AttributeError:
            raise AttributeError("ZoneMongo instance has no %s attribute." % name)

    def write_to_mongo(self, dot_origin, rr_list):
        db = self.r[self.dbname]
        col = db[dot_origin[:-1]]
        col.insert_many(rr_list)

    def del_zone(self, dot_origin):
        db = self.r[self.dbname]
        if dot_origin.endswith("."):
            dot_origin = dot_origin[:-1]
        db.remove_collection(dot_origin)

    def del_db(self):
        self.r.drop_database(self.dbname)


def gen_a_zone(zone_name, subdomains):
    dot_origin = zone_name
    if not dot_origin.endswith("."):
        dot_origin += "."
    rr_list = []
    soa_rr = {
        "name": "@",
        "ttl": 86400,
        "type": "SOA",
        "rdata": "dns1.%s hostmaster.%s 2001062501 21600 3600 604800 86400" % (dot_origin, dot_origin),
    }
    ns_rr = {
        "name": "@",
        "ttl": 86400,
        "type": "NS",
        "rdata": "dns1.%s" % dot_origin,
    }
    rr_list.append(soa_rr)
    rr_list.append(ns_rr)
    for subdomain in subdomains:
        rr = {
            "name": subdomain,
            "ttl": 86400,
            "type": "A",
            "rdata": "127.0.0.2"
        }
        rr_list.append(rr)
    return dot_origin, rr_list


def parse_cmd_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-Nz', '--num-zones', default=10000, type=int, help="number of zones")
    parser.add_argument('-Ns', '--num-subdomains', default=100, type=int, help="number of sumdomain per zone")
    parser.add_argument('-Mh', '--mongo_host', default="127.0.0.1", help='mongodb host(default: 127.0.0.1)')
    parser.add_argument('-Mp', '--mongo_port', default=27017, type=int, help='mongodb port(default: 27017)')
    return parser.parse_args()


def remote_get_list(url):
    resp = request.urlopen(url).read()
    resp = resp.decode("utf8").strip("\n")
    return resp.split("\n")


def gen_zone_data(parsed):
    num_zones = parsed.num_zones
    num_domains = parsed.num_subdomains
    zm = ZoneMongo(parsed.mongo_host, parsed.mongo_port)
    # total_zone_list = remote_get_list("https://raw.githubusercontent.com/DNSPod/oh-my-free-data/master/src/dnspod-top10000-domains-20170308.txt")
    # total_subdomain_list = remote_get_list("https://raw.githubusercontent.com/DNSPod/oh-my-free-data/master/src/dnspod-top2000-sub-domains.txt")

    total_zone_list = remote_get_list("file://%s/dnspod-top10000-domains-20170308.txt" % CUR_DIR)
    total_subdomain_list = remote_get_list("file://%s/dnspod-top2000-sub-domains.txt" % CUR_DIR)
    total_subdomain_list = [name for name in total_subdomain_list if not name.startswith("*")]
    zone_list = random.sample(total_zone_list, num_zones)
    print(len(total_zone_list), len(total_subdomain_list), len(zone_list))
    # print(zone_list)
    zm.del_db()
    for idx, zname in enumerate(zone_list):
        subdomains = random.sample(total_subdomain_list, num_domains)
        dot_origin, rr_list = gen_a_zone(zname, subdomains)
        try:
            zm.write_to_mongo(dot_origin, rr_list)
        except BulkWriteError as bwe:
            print(bwe.details)
            print(dot_origin, rr_list)
            raise

        print("add zone: ", idx, zname)


if __name__ == '__main__':
    parsed = parse_cmd_args()
    gen_zone_data(parsed)
