#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
import socket
import struct
import subprocess
import shlex
import time
import copy
import tempfile

import yaml

import dns.message
import dns.query
import vagrant
from fabric.api import env, execute, task, sudo
from fabric.operations import put
from fabric.contrib import files

from . import settings
from .zone2mongo import ZoneMongo


DNS_BIN = '/shuke/build/shuke-server'


@task
def start_shuke(cmd, pidfile="/var/run/shuke_53.pid"):
    sudo('%s' % cmd, sudo=True)


@task
def stop_shuke(pidfile):
    if files.is_exist(pidfile, sudo=True):
        sudo("kill -9 `cat %s`" % pidfile)


@task
def shuke_is_running(pidfile):
    if files.is_exist(pidfile, sudo=True):
        res = sudo("kill -0 `cat %s`" % pidfile)
        return res.return_code == 0
    return False


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
        with open(os.path.join(settings.REPO_ROOT, "vagrant", "test.yaml")) as fp:
            self.cf = yaml.load(fp)
        if overrides:
            self.cf.update(overrides)
        # override mongo host and mongo port
        if self.cf["data_store"].lower() == "mongo":
            if "mongo_host" not in self.cf:
                self.cf["mongo_host"] = settings.MONGO_HOST
            if "mongo_port" not in self.cf:
                self.cf["mongo_port"] = settings.MONGO_PORT
            self.zm = ZoneMongo(settings.MONGO_HOST,
                                settings.MONGO_PORT,
                                self.cf["mongo_dbname"])
        self.valgrind = valgrind
        self.stderr = tempfile.TemporaryFile(mode="w+", encoding="utf8")

        self.cf_str = yaml.dump(self.cf)
        self.fp = tempfile.NamedTemporaryFile()
        self.fp.write(self.cf_str.encode("utf8"))
        self.fp.flush()
        fname = self.fp.name

        put(fname, fname)

        if self.valgrind:
            # TODO find the bug of possible lost and still reachable memory
            self.cmd = "valgrind --leak-check=full --show-reachable=no --show-possibly-lost=no %s -c %s" % (DNS_BIN, fname)
        else:
            self.cmd = "%s -c %s" % (DNS_BIN, fname)
        self.vagrant = vagrant.Vagrant(root=os.path.join(settings.REPO_ROOT, "vagrant"))

    def _execute(self, fn, *args, **kwargs):
        v = self.vagrant
        env.hosts = [v.user_hostname_port()]
        env.key_filename = v.keyfile()
        env.disable_known_hosts = True  # useful for when the vagrant box ip changes.
        execute(fn, *args, **kwargs)  # run a fabric task on the vagrant host.

    def start(self):
        try:
            self._start_srv(self.cmd, stderr=self.stderr)
        except Exception as e:
            raise Exception("%s, stderr: %s" % (str(e), self.get_stderr()))
        self.admin_cli = AdminClient(self.cf["admin_host"],
                                     self.cf["admin_port"])

    def _start_srv(self, cmd, stdout=None, stderr=None, timeout=10):
        self._execute(start_shuke)

    def _stop_srv(self):
        self._execute(stop_shuke, self.cf["pidfile"])

    def stop(self):
        self.admin_cli.close()
        self.fp.close()
        self._stop_srv()

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
        self._execute(shuke_is_running)

    def mongo_clear(self):
        self.zm.del_all_zones()

    def write_zone_to_mongo(self, zone_ss):
        self.zm.str_to_mongo(zone_ss)

    def mongo_delete_zone(self, dot_origin):
        self.zm.del_zone(dot_origin)
