#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import io
from collections import defaultdict
import redis


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
    sub_domains = set()
    rr_map = defaultdict(set)
    soa = None

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
            sub_domains.add(domain)

            ttl, dns_type, tokens = parse_ttl_cls_type(tokens, prev_ttl)
            if not ttl:
                raise Exception("ttl is None")
            tokens[:0] = [str(ttl), "IN", dns_type]
            redis_txt = ' '.join(tokens)
            if dns_type == "SOA":
                soa = redis_txt
            else:
                abs_domain = to_abs_domain(domain, dot_origin)
                rr_map[abs_domain].add(redis_txt)

            prev_domain = domain
            prev_ttl = ttl
            record = read_record(fp)
    return dot_origin, soa, sub_domains, rr_map


def parse_zone_file(fname):
    with open(fname, "r") as fp:
        return parse_zone_str(fp.read())


class ZoneRedis(object):
    def __init__(self, host, port, origins_key="*origins*",
                 soa_prefix="s", zone_prefix="z"):
        self.r = redis.Redis(host=host, port=port, decode_responses=True)
        self.origins_key = origins_key
        self.soa_prefix = soa_prefix
        self.zone_prefix = zone_prefix

    def __getattr__(self, name):
        try:
            return getattr(self.r, name)
        except AttributeError:
            raise AttributeError("ZoneRedis instance has no %s attribute." % name)

    def file_to_redis(self, fname):
        dot_origin, soa, sub_domains, rr_map = parse_zone_file(fname)
        self.write_to_redis(dot_origin, soa, sub_domains, rr_map)

    def str_to_redis(self, ss):
        dot_origin, soa, sub_domains, rr_map = parse_zone_str(ss)
        self.write_to_redis(dot_origin, soa, sub_domains, rr_map)

    def write_to_redis(self, dot_origin, soa, sub_domains, rr_map):
        pipe = self.r.pipeline()
        pipe.sadd(self.origins_key, dot_origin)
        pipe.sadd("%s:%s" % (self.zone_prefix, dot_origin), *sub_domains)
        pipe.set("%s:%s" % (self.soa_prefix, dot_origin), soa)
        for k, v in rr_map.items():
            pipe.sadd(k, *v)
        pipe.execute()

    def del_zone(self, dot_origin):
        sub_domains = self.r.smembers("%s:%s" % (self.zone_prefix, dot_origin))
        pipe = self.r.pipeline()
        pipe.srem(self.origins_key, dot_origin)
        pipe.delete("%s:%s" % (self.soa_prefix, dot_origin))
        pipe.delete("%s:%s" % (self.zone_prefix, dot_origin))
        for domain in sub_domains:
            abs_domain = to_abs_domain(domain, dot_origin)
            pipe.delete(abs_domain)
        pipe.execute()

    def debug_zone_file(self, fname):
        dot_origin, soa, sub_domains, rr_map = parse_zone_file(fname)
        ss = "dotOrigin: {}\nsoa: {}\n{}\n".format(dot_origin, soa, sub_domains)
        for k, v in rr_map.items():
            ss += "{} ==> {}\n".format(k, v)
        return ss

    def debug_zone_str(self, ss):
        dot_origin, soa, sub_domains, rr_map = parse_zone_str(ss)
        ss = "dotOrigin: {}\nsoa: {}\n{}\n".format(dot_origin, soa, sub_domains)
        for k, v in rr_map.items():
            ss += "{} ==> {}\n".format(k, v)
        return ss



if __name__ == '__main__':
    zr = ZoneRedis("127.0.0.1", 6379)
    zr.flushall()
    zr.sadd(zr.origins_key, "aa")
    zr.file_to_redis("../tests/assets/example.z")
    print(zr.debug_zone_file("../tests/assets/example.z"))
    # zr.del_zone("example.com.")
