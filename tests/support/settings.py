#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
from os.path import dirname, abspath
import subprocess

REPO_ROOT = dirname(dirname(dirname(abspath(__file__))))
DNS_BIN = os.path.join(REPO_ROOT, "src/cdns-server")

ASSETS_DIR = os.path.join(REPO_ROOT, "tests/assets")
DEFAULT_CONF = os.path.join(ASSETS_DIR, "default.conf")
EXAMPLE_ZONE_FILE = os.path.join(ASSETS_DIR, "example.z")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

# REDIS_BIN = subprocess.check_output("which redis-server", shell=True).decode("utf8").strip(" \n")
# REDIS_EXISTS = REDIS_BIN.startswith("/")
