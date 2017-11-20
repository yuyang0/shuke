#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
import socket
import struct
import time
import tempfile
import io

import toml

import dns.message
import dns.query
import vagrant
from fabric.api import env, execute, task, sudo, get, settings
from fabric.operations import put
from fabric.contrib import files

from . import constants
from .zone2mongo import ZoneMongo


DNS_BIN = '/shuke/build/shuke-server'


def check_valgrind_error(ss):
    success = [
        "definitely lost: 0 bytes",
        "no leaks are possible",
    ]
    for succ in success:
        if ss.find(succ) != -1:
            return True
    return False


def check_pid(pid):
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


@task
def start_shuke(cmd, pidfile, config):
    put(config, config)
    sudo('%s' % cmd)
    for i in range(10):
        if files.exists(pidfile, use_sudo=True):
            break
        time.sleep(2)
    else:
        raise Exception("shuke doesn't start correctly.")
    time.sleep(5)


@task
def stop_shuke(pidfile):
    if files.exists(pidfile, use_sudo=True):
        fd = io.BytesIO()
        get(pidfile, fd, use_sudo=True)
        pid = int(fd.getvalue())
        print("pid is ", pid)

        sudo("kill -15 %s" % pid)
        for i in range(10):
            with settings(warn_only=True):
                res = sudo("kill -0 %s" % pid)
                # wait until the process exit.
                if res.failed:
                    break
            time.sleep(2)
        else:
            raise Exception("shuke doesn't stop correctly.")


@task
def shuke_is_running(pidfile):
    if files.exists(pidfile, use_sudo=True):
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
        self.host = host if host else "127.0.0.1"
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, int(self.port)))

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


def update_nested_dict(d, overrides):
    def update_one(d, k, v):
        k_list = k.split(".")
        if len(k_list) == 0:
            return
        elif len(k_list) == 1:
            d[k_list[0]] = v
        else:
            old_v = d[k_list[0]]
            for kk in k_list[1:-1]:
                old_v = old_v[kk]
            old_v[k_list[-1]] = v
    for k, v in overrides.items():
        update_one(d, k, v)


class DNSServer(object):
    def __init__(self, overrides=None, valgrind=False):
        self.pid = None
        with open(os.path.join(constants.ASSETS_DIR, "test.toml")) as fp:
            self.cf = toml.load(fp)
        if overrides:
            update_nested_dict(self.cf, overrides)
        self.cf["core"].pop("admin_host", None)
        # extract some field from cf
        self.data_store = self.cf["zone_source"]["type"].lower()
        self.pidfile = self.cf["core"]["pidfile"]
        self.admin_host = self.cf["core"].get("admin_host", None)
        self.admin_port = self.cf["core"].get("admin_port", None)
        self.dns_port = self.cf["core"]["port"]
        self.dns_host = self.cf["core"]["bind"]

        # override mongo host and mongo port
        mongo_conf = self.cf["zone_source"]["mongo"]
        if self.data_store == "mongo":
            self.zm = ZoneMongo(constants.MONGO_HOST,
                                constants.MONGO_PORT,
                                mongo_conf["dbname"])
        self.valgrind = valgrind

        self.cf_str = toml.dumps(self.cf)
        self.fp = tempfile.NamedTemporaryFile()
        self.fp.write(self.cf_str.encode("utf8"))
        self.fp.flush()
        fname = self.fp.name

        if self.valgrind:
            # TODO find the bug of possible lost and still reachable memory
            self.cmd = "valgrind --leak-check=full --show-reachable=no --show-possibly-lost=no %s -c %s" % (DNS_BIN, fname)
        else:
            self.cmd = "%s -c %s" % (DNS_BIN, fname)
        self.vagrant = vagrant.Vagrant(root=os.path.join(constants.REPO_ROOT, "vagrant"))

    def _execute(self, fn, *args, **kwargs):
        v = self.vagrant
        env.hosts = [v.user_hostname_port()]
        env.key_filename = v.keyfile()
        env.disable_known_hosts = True  # useful for when the vagrant box ip changes.
        execute(fn, *args, **kwargs)  # run a fabric task on the vagrant host.

    def start(self):
        try:
            self._start_srv()
        except Exception as e:
            raise Exception("%s" % (str(e),))
        self.admin_cli = AdminClient(self.admin_host,
                                     self.admin_port)

    def _start_srv(self, timeout=10):
        self._execute(start_shuke, self.cmd, self.pidfile, self.fp.name)

    def _stop_srv(self):
        self._execute(stop_shuke, self.pidfile)

    def isalive(self):
        self._execute(shuke_is_running, self.pidfile)

    def stop(self):
        self.admin_cli.close()
        self.fp.close()
        self._stop_srv()

    def set_zone(self, ss):
        return self.admin_cmd("zone set \"%s\"" % ss)

    def info(self):
        return self.admin_cmd("info")

    def admin_cmd(self, cmd):
        return self.admin_cli.exec_cmd(cmd)

    def dns_query(self, name, ty, use_tcp=True):
        dns_hosts = self.dns_host
        dns_port = self.dns_port
        if len(dns_hosts) > 0:
            dns_host = dns_hosts[0]
        else:
            dns_host = ""
        q = dns.message.make_query(name, ty)
        if use_tcp:
            return dns.query.tcp(q, dns_host, port=dns_port)
        else:
            return dns.query.udp(q, dns_host, port=dns_port)

    def mongo_clear(self):
        self.zm.del_all_zones()

    def write_zone_to_mongo(self, zone_ss):
        self.zm.str_to_mongo(zone_ss)

    def mongo_delete_zone(self, dot_origin):
        self.zm.del_zone(dot_origin)


if __name__ == "__main__":
    srv = DNSServer(overrides={"valgrind": False})
    print(srv.cf_str)

    srv.start()
    # print(srv.info())
    time.sleep(10)
    srv.stop()
