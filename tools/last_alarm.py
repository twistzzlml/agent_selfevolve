# -*- coding: utf-8 -*-
"""打印最后 N 条 alarm 的类型/拦截状态/算法。"""
import json
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
path = r"rasp\%s\logs\alarm\alarm.log" % (sys.argv[2] if len(sys.argv) > 2 else "ofbiz")
rows = []
for line in open(path, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        j = json.loads(line)
    except Exception:
        continue
    rows.append((j.get("event_time"), j.get("attack_type"),
                 j.get("intercept_state"), j.get("plugin_algorithm"),
                 str(j.get("attack_params", {}).get("command", ""))[:40] or
                 str(j.get("attack_params", {}).get("hostname", ""))[:40]))
for r in rows[-n:]:
    print(r)
