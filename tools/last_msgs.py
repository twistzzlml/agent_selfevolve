# -*- coding: utf-8 -*-
"""解析 waf8.log：列出每条审计事务的时间/评分/命中规则。"""
import json

seen = []
fails = 0
for line in open(r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\state\waf8.log",
                 encoding="utf-8", errors="replace"):
    s = line.strip()
    if not s.startswith("{"):
        continue
    try:
        j = json.loads(s)
    except Exception as e:
        fails += 1
        if fails <= 3:
            print("FAIL", str(e)[:60], "len", len(s))
        continue
    msgs = j.get("messages") or []
    ts = (j.get("transaction") or {}).get("time_stamp", "?")
    resp = (j.get("response") or {}).get("http_code")
    seen.append((ts, resp, [(m.get("ruleId"), m.get("message", "")[:60]) for m in msgs]))
print("json fails:", fails, "parsed:", len(seen))
for ts, code, rules in seen[-6:]:
    print(ts, "->", code)
    for rid, msg in rules:
        print("    ", rid, msg)
