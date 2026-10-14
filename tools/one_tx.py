# -*- coding: utf-8 -*-
"""按 unique_id 片段提取单条审计事务的规则清单。"""
import json
import sys

frag = sys.argv[1]
path = sys.argv[2] if len(sys.argv) > 2 else \
    r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\state\wafgeo.log"
for line in open(path, encoding="utf-8", errors="replace"):
    if frag not in line or not line.strip().startswith("{"):
        continue
    try:
        j = json.loads(line)
    except Exception:
        print("该行 JSON 损坏（可能是与 stderr 交错的截断行）")
        break
    for m in j.get("messages") or []:
        print("  %-8s %s" % (m.get("ruleId"), m.get("message", "")[:70]))
    break
