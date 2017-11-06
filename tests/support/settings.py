#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""

"""
from __future__ import print_function, division, absolute_import
import os
from os.path import dirname, abspath


REPO_ROOT = dirname(dirname(dirname(abspath(__file__))))


MONGO_HOST = os.getenv("MONGO_HOST", "127.0.0.1")
MONGO_PORT = int(os.getenv("MONGO_PORT", 27117))

GUEST_REPO_ROOT = "/shuke"
ASSETS_DIR = os.path.join(REPO_ROOT, "tests/assets")
EXAMPLE_ZONE_FILE = os.path.join(ASSETS_DIR, "example.z")
