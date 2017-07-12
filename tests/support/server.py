#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
import signal
import socket
import struct
import subprocess
import shlex
import time
import copy
import tempfile

import dns.message
import dns.query
import pymongo

from . import settings, zone2mongo, utils
from .config import default_cfg
from .zone2mongo import ZoneMongo


def start_srv(cmd, stdin=None, stdout=None, stderr=None, timeout=10):
    print("start", cmd)
    args = cmd if isinstance(cmd, (tuple, list,)) else shlex.split(cmd)
    p = subprocess.Popen(args, stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True)
    time.sleep(timeout)
    print("poll : %s\n" % p.poll())
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
        return ' [\n' + ' '.join(l) + '\n]'

    def dict_to_conf(d):
        l = [" %s %s \n" % (k, v) for k, v in d.items()]
        return ' {\n' + ''.join(l) + '}'

    ret_list = []
    for k, v in d.items():
        if isinstance(v, list):
            v_ss = list_to_conf(v)
        elif isinstance(v, dict):
            v_ss = dict_to_conf(v)
        elif isinstance(v, bool):
            v_ss = "yes" if v else "no"
        else:
            v_ss = str(v)
        ret_list.append("%s %s" % (k, v_ss))
    return '\n'.join(ret_list)


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
    def __init__(self, overrides=None, valgrind=False):
        self.pid = None
        self.popen = None
        self.cf = copy.deepcopy(default_cfg)
        if overrides:
            self.cf.update(overrides)
        # override mongo host and mongo port
        if self.cf["data_store"].lower() == "mongo":
            if "mongo_host" not in self.cf:
                self.cf["mongo_host"] = settings.MONGO_HOST
            if "mongo_port" not in self.cf:
                self.cf["mongo_port"] = settings.MONGO_PORT
            self.zm = ZoneMongo(settings.MONGO_HOST, settings.MONGO_PORT, self.cf["mongo_dbname"])
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
            self.popen = self._start_srv(self.cmd, stderr=self.stderr)
        except Exception as e:
            raise Exception("%s, stderr: %s" % (str(e), self.get_stderr()))
        self.admin_cli = AdminClient(self.cf["admin_host"], self.cf["admin_port"])

    def _start_srv(self, cmd, stdin=None, stdout=None, stderr=None, timeout=10):
        print("start", cmd)
        args = cmd if isinstance(cmd, (tuple, list,)) else shlex.split(cmd)
        p = subprocess.Popen(args, stdin=stdin, stdout=stdout,
                             stderr=stderr, close_fds=True)
        time.sleep(timeout)
        # when run daemon mode, p.pid doesn't return the right pid
        if self.cf['daemonize'].lower() in ("no", "off", "false"):
            if p.poll() is not None:
                raise Exception("cannot start %s" % (cmd))
        else:
            # when run daemon mode, p.pid doesn't return the right pid
            # so we need get pid from pidfile
            pidfile = self.cf["pidfile"]
            if not os.path.isfile(pidfile):
                raise Exception("cannot start %s" % (cmd))
            with open(pidfile, "r") as fp:
                self.pid = int(fp.read())
            if not utils.check_pid(self.pid):
                raise Exception("cannot start %s" % (cmd))
        print("poll : %s, pid1: %s, pid2: %s\n" % (p.poll(), p.pid, self.pid))
        return p

    def _stop_srv(self):
        if self.cf['daemonize'].lower() in ("no", "off", "false"):
            if self.popen.poll() is not None:
                return
            self.popen.terminate()
            self.popen.wait()
        else:
            os.kill(self.pid, signal.SIGTERM)
            # wait util process exit
            while True:
                if utils.check_pid(self.pid) is False:
                    break

    def stop(self):
        self.admin_cli.close()
        self.fp.close()
        if self.popen:
            self._stop_srv()
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

    def dns_query(self, name, ty, use_tcp=True):
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

    def mongo_clear(self):
        self.zm.del_all_zones()

    def write_zone_to_mongo(self, zone_ss):
        self.zm.str_to_mongo(zone_ss)

    def mongo_delete_zone(self, dot_origin):
        self.zm.del_zone(dot_origin)
