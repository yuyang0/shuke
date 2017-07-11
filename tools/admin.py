#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import sys
import readline
import socket
import argparse
import struct


PY3 = (sys.version_info.major >= 3)

if not PY3:
    input = raw_input


def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    if PY3:
        msg = msg.encode("utf8")
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)


def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    msg = recvall(sock, msglen)
    if PY3:
        msg = msg.decode("utf8")
    return msg


def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b'' if PY3 else ''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


def parse_cmd_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', required=True, help='server address.')
    return parser.parse_args()


def create_cli_socket(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    print("connect to %s:%s\n" % (ip, port))
    return s


def main():
    parsed = parse_cmd_args()
    PROMPT = 'shuke %s > ' % parsed.address
    ip, port = parsed.address.split(':')
    s = create_cli_socket(ip, port)
    while True:
        data = input(PROMPT)
        send_msg(s, data)
        data = recv_msg(s)
        if data is None:
            # reconnect to server
            s = create_cli_socket(ip, port)
            continue
        print(data)


if __name__ == '__main__':
    main()
