# -*- coding: utf-8 -*-
"""只打印命中规则的审计事务：时间 / 响应码 / 规则列表 / 入站或出站评分。"""
import json
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else \
    r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\state\waf_stdout.log"
for line in open(path, encoding="utf-8", errors="replace"):
    s = line.strip()
    if not s.startswith("{"):
        m = re.search(r"Access denied.*Total Score: (\d+)", s)
        if m:
            print("[error-line]", s[:110])
        continue
    try:
        j = json.loads(s)
    except Exception:
        continue
    msgs = j.get("messages") or []
    if not msgs:
        continue
    ts = (j.get("transaction") or {}).get("time_stamp", "?")
    print("==", ts)
    for m in msgs:
        print("    %-8s %s" % (m.get("ruleId"), m.get("message", "")[:70]))
