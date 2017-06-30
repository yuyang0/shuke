#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import argparse
import io
from collections import defaultdict
from pymongo import MongoClient


def tokenize(ss):
    literal = False
    lst = []
    i = 0
    while i < len(ss) and ss[i] in " \t\n":
        i += 1
    start = end = i

    while i < len(ss):
        c = ss[i]
        if c == "\\":
            i += 2
            end += 2
            continue
        if c == '"':
            if literal:
                literal = False
            else:
                literal = True
            i += 1
            end += 1
            continue
        if literal:
            i += 1
            end += 1
            continue
        if c in " \n\t":
            lst.append(ss[start: end])
            while i < len(ss) and ss[i] in " \n\t":
                i += 1
            start = end = i
            continue
        i += 1
        end += 1

    if start < end:
        lst.append(ss[start:end])
    return lst


def find_char(line, c):
    literal = False
    i = 0
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] == '"':
            if literal:
                literal = False
            else:
                literal = True
            i += 1
            continue
        if literal:
            i += 1
            continue
        if line[i] == c:
            return i
        i += 1
    if literal:
        raise Exception("unbalnced double quote")
    return -1


def remove_comment(line):
    idx = find_char(line, ";")
    if idx >= 0:
        line = line[:idx]
    return line.rstrip(" \n\t\v")


def read_record(fp):
    line = ""
    while not line:
        line = fp.readline()
        if not line:
            return ""
        line = remove_comment(line)
    open_idx = find_char(line, '(')
    if open_idx < 0:
        return line
    line = line[:open_idx] + ' ' + line[open_idx+1:]
    close_idx = find_char(line, ")")
    if close_idx >= 0:
        line = line[:close_idx] + ' ' + line[close_idx+1:]
        return line
    while close_idx < 0:
        new_line = fp.readline()
        if not new_line:
            raise Exception("unbalanced parens")
        new_line = remove_comment(new_line)
        if not new_line:
            continue
        close_idx = find_char(new_line, ")")
        if close_idx >= 0:
            new_line = new_line[:close_idx] + ' ' + new_line[close_idx+1:]
        line += (' ' + new_line)
    return line


def read_directives(fp):
    dot_origin = None
    ttl = None
    while True:
        record = read_record(fp)
        if record[0] != "$":
            return dot_origin, ttl, record
        parts = record.split()
        if parts[0].upper() == "$ORIGIN":
            dot_origin = parts[1]
        elif parts[0].upper() == "$TTL":
            ttl = int(parts[1])
        else:
            raise Exception("unknown directive.")


def parse_ttl_cls_type(tokens, prev_ttl):
    dns_types = ["A", "AAAA", "NS", "CNAME", "SOA", "TXT", "SRV", "PTR", "MX"]
    dns_type = None
    ttl = prev_ttl
    for i in range(3):
        token = tokens.pop(0)
        if token.upper() in dns_types:
            dns_type = token.upper()
            break
        elif token.upper() == "IN":
            continue
        else:
            ttl = int(token)
    if dns_type is None:
        raise Exception("no dns type")
    return ttl, dns_type, tokens


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


def parse_zone_str(ss):
    dot_origin = None
    rr_list = []

    with io.StringIO(ss) as fp:
        dot_origin, default_ttl, record = read_directives(fp)
        dot_origin = dot_origin.lower()

        prev_domain = None
        prev_ttl = default_ttl

        while record:
            remain = record
            if record[0] in ' \t':
                if prev_domain is None:
                    raise Exception("no domain name")
                domain = prev_domain
                tokens = tokenize(remain)
            else:
                tokens = tokenize(remain)
                domain = tokens.pop(0)
            domain = domain.lower()
            domain = to_relative_domain(domain, dot_origin)

            ttl, dns_type, tokens = parse_ttl_cls_type(tokens, prev_ttl)
            if not ttl:
                raise Exception("ttl is None")
            rdata_txt = ' '.join(tokens)
            v = {
                "name": domain,
                "ttl": ttl,
                "type": dns_type,
                "rdata": rdata_txt,
            }
            rr_list.append(v)
            abs_domain = to_abs_domain(domain, dot_origin)

            prev_domain = domain
            prev_ttl = ttl
            record = read_record(fp)
    return dot_origin, rr_list


def parse_zone_file(fname):
    with open(fname, "r") as fp:
        return parse_zone_str(fp.read())


class ZoneMongo(object):
    def __init__(self, host, port, dbname="zone"):
        self.r = MongoClient(host=host, port=port)
        self.dbname = dbname

    def __getattr__(self, name):
        try:
            return getattr(self.r, name)
        except AttributeError:
            raise AttributeError("ZoneMongo instance has no %s attribute." % name)

    def file_to_mongo(self, fname):
        dot_origin, rr_list = parse_zone_file(fname)
        self.write_to_mongo(dot_origin, rr_list)

    def str_to_mongo(self, ss):
        dot_origin, rr_list = parse_zone_str(ss)
        self.write_to_mongo(dot_origin, rr_list)

    def write_to_mongo(self, dot_origin, rr_list):
        db = self.r[self.dbname]
        col = db[dot_origin[:-1]]
        col.insert_many(rr_list)

    def del_zone(self, dot_origin):
        db = self.r[self.dbname]
        db.remove_collection(dot_origin)

    def debug_zone_file(self, fname):
        dot_origin, rr_list = parse_zone_file(fname)
        ss = "dotOrigin: {}\n".format(dot_origin)
        for ele in rr_list:
            # ss += " ".join(ele.values())
            ss += ' '.join([ele['name'], str(ele['ttl']), ele['type'], ele['rdata']]) + '\n'
        return ss

    def debug_zone_str(self, ss):
        dot_origin, soa, sub_domains, rr_map = parse_zone_str(ss)
        ss = "dotOrigin: {}\nsoa: {}\n{}\n".format(dot_origin, soa, sub_domains)
        for k, v in rr_map.items():
            ss += "{} ==> {}\n".format(k, v)
        return ss


def parse_cmd_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help="zone file")
    parser.add_argument('-Mh', '--mongo_host', default="127.0.0.1", help='mongodb host(default: 127.0.0.1)')
    parser.add_argument('-Mp', '--mongo_port', default=27017, type=int, help='mongodb port(default: 27017)')
    return parser.parse_args()


if __name__ == '__main__':
    parsed = parse_cmd_args()
    zm = ZoneMongo(parsed.mongo_host, parsed.mongo_port)
    zm.file_to_mongo(parsed.file)
    print(zm.debug_zone_file(parsed.file))
    # zr.del_zone("example.com.")
