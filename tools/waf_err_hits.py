# -*- coding: utf-8 -*-
"""从 waf 容器 docker logs（含 nginx error 日志）提取命中的 CRS 规则 id+msg。"""
import collections
import re
import subprocess
import sys

name = sys.argv[1] if len(sys.argv) > 1 else "multi-round-lab-waf-jboss-1"
r = subprocess.run(["docker", "logs", name], capture_output=True, text=True, errors="replace")
hits = collections.Counter()
for line in (r.stdout + r.stderr).splitlines():
    for m in re.finditer(r'\[id "(\d{6})"\][^\[]*\[msg "([^"]+)"\]', line):
        hits[(m.group(1), m.group(2)[:80])] += 1
for (rid, msg), n in sorted(hits.items(), key=lambda x: (-x[1], x[0])):
    print("%-8s %4dx  %s" % (rid, n, msg))
