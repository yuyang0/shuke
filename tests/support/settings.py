#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
from os.path import dirname, abspath
import subprocess

REPO_ROOT = dirname(dirname(dirname(abspath(__file__))))
DNS_BIN = os.path.join(REPO_ROOT, "build/shuke-server")

ASSETS_DIR = os.path.join(REPO_ROOT, "tests/assets")
DEFAULT_CONF = os.path.join(ASSETS_DIR, "default.conf")
EXAMPLE_ZONE_FILE = os.path.join(ASSETS_DIR, "example.z")

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = int(os.getenv("MONGO_PORT", 6379))

# REDIS_BIN = subprocess.check_output("which redis-server", shell=True).decode("utf8").strip(" \n")
# REDIS_EXISTS = REDIS_BIN.startswith("/")
