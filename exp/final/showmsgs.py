# -*- coding: utf-8 -*-
"""Print ruleId+message for each message in captured audit lines."""
import json
import re

data = open(r"D:\科研\keyan\cloud_agent\.tmp\jb0927.log", encoding="utf-8", errors="replace").read()
for line in data.splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        j = json.loads(line)
    except Exception:
        continue
    tr = j.get("transaction", {})
    msgs = tr.get("messages") or []
    code = (tr.get("response", {}) or {}).get("http_code")
    uri = str((tr.get("request", {}) or {}).get("uri", ""))[:80]
    print("==", tr.get("time_stamp"), code, uri)
    for m in msgs:
        d = m.get("details", {}) or {}
        print("   ", d.get("ruleId"), "|", (m.get("message") or "")[:70])
        print("      match:", (d.get("match") or "")[:140])
