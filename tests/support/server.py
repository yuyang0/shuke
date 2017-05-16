#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import socket
import struct
import subprocess
import shlex
import time
import tempfile

import dns.message
import dns.query
import redis

from . import settings, zone2redis, utils
from .zone2redis import ZoneRedis


def start_srv(cmd, stdin=None, stdout=None, stderr=None):
    print("start", cmd)
    args = cmd if isinstance(cmd, (tuple, list,)) else shlex.split(cmd)
    p = subprocess.Popen(args, stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True)
    time.sleep(1)
    if p.poll() is not None:
        raise Exception("cannot start %s" % (cmd))
    return p


def stop_srv(popen):
    if popen.poll() is not None:
        return
    popen.terminate()
    popen.wait()


def to_conf(d):
    def list_to_conf(l):
        return ' [\n' + ' '.join(l) + '\n]\n'

    def dict_to_conf(d):
        l = [" %s %s \n" % (k, v) for k, v in d.items()]
        return ' {\n' + ''.join(l) + '}\n'

    ret_list = []
    for k, v in d.items():
        if isinstance(v, list):
            v_ss = list_to_conf(v)
        elif isinstance(v, dict):
            v_ss = dict_to_conf(v)
        else:
            v_ss = str(v) + '\n'
        ret_list.append("%s %s" % (k, v_ss))
    return ''.join(ret_list)


def read_conf(fname):
    with open(fname, "rb") as fp:
        ss = fp.read()
        return eval(ss)


def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


class AdminClient(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, int(port)))

    def send(self, msg):
        b_msg = msg.encode("utf8")
        b_msg = struct.pack('>I', len(b_msg)) + b_msg
        self.sock.sendall(b_msg)

    def recv(self):
        raw_msglen = recvall(self.sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return recvall(self.sock, msglen).decode("utf8")

    def exec_cmd(self, ss):
        self.send(ss)
        return self.recv()

    def close(self):
        self.sock.close()


class DNSServer(object):
    def __init__(self, conf=None, overrides=None, valgrind=False):
        self.popen = None
        if conf is None:
            conf = settings.DEFAULT_CONF
        self.cf = read_conf(conf)
        if overrides:
            self.cf.update(overrides)
        # override redis host and redis port
        if self.cf["data_store"].lower() == "redis":
            self.cf["redis_host"] = settings.REDIS_HOST
            self.cf["redis_port"] = settings.REDIS_PORT
            self.zr = ZoneRedis(settings.REDIS_HOST, settings.REDIS_PORT,
                                origins_key=self.cf["redis_origins_key"],
                                soa_prefix=self.cf["redis_soa_prefix"],
                                zone_prefix=self.cf["redis_zone_prefix"])
        self.valgrind = valgrind
        self.stderr = tempfile.TemporaryFile(mode="w+", encoding="utf8")

        self.cf_str = to_conf(self.cf)
        self.fp = tempfile.NamedTemporaryFile()
        self.fp.write(self.cf_str.encode("utf8"))
        self.fp.flush()
        fname = self.fp.name

        if self.valgrind:
            # TODO find the bug of possible lost and still reachable memory
            # self.cmd = "valgrind --leak-check=full --show-leak-kinds=all %s -c %s" % (settings.DNS_BIN, fname)
            self.cmd = "valgrind --leak-check=full --show-reachable=no --show-possibly-lost=no %s -c %s" % (settings.DNS_BIN, fname)
        else:
            self.cmd = "%s -c %s" % (settings.DNS_BIN, fname)

    def start(self):
        assert self.popen is None
        try:
            self.popen = start_srv(self.cmd, stderr=self.stderr)
        except Exception as e:
            raise Exception("%s, stderr: %s" % (str(e), self.get_stderr()))
        self.admin_cli = AdminClient(self.cf["admin_host"], self.cf["admin_port"])

    def stop(self):
        self.admin_cli.close()
        self.fp.close()
        if self.popen:
            stop_srv(self.popen)
            self.popen = None

    def get_stderr(self):
        self.stderr.seek(0)
        return self.stderr.read()

    def set_zone(self, ss):
        return self.admin_cmd("zone set \"%s\"" % ss)

    def info(self):
        return self.admin_cmd("info")

    def admin_cmd(self, cmd):
        return self.admin_cli.exec_cmd(cmd)

    def dns_query(self, name, ty, use_tcp=False):
        dns_hosts = self.cf["bind"]
        dns_port = self.cf["port"]
        if len(dns_hosts) > 0:
            dns_host = dns_hosts[0]
        else:
            dns_host = ""
        q = dns.message.make_query(name, ty)
        if use_tcp:
            return dns.query.tcp(q, dns_host, port=dns_port)
        else:
            return dns.query.udp(q, dns_host, port=dns_port)

    def isalive(self):
        return self.popen.poll() is not None

    def redis_clear(self):
        self.zr.flushall()

    def write_zone_to_redis(self, zone_ss):
        self.zr.str_to_redis(zone_ss)

    def redis_set_soa(self, soa, dot_origin):
        self.zr.set("%s:%s" % (self.cf["redis_soa_prefix"], dot_origin), soa)

    def redis_delete_zone(self, dot_origin):
        self.zr.del_zone(dot_origin)
