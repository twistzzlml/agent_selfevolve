# -*- coding: utf-8 -*-
"""打印日志文件里所有带 messages 的事务：python dump_msgs.py <file>"""
import json
import sys

path = sys.argv[1]
for line in open(path, encoding="utf-8", errors="replace"):
    s = line.strip()
    if not s.startswith("{") or '"messages"' not in s:
        continue
    try:
        j = json.loads(s)
    except Exception:
        continue
    ms = j.get("messages") or []
    if not ms:
        continue
    print("==", j.get("transaction", {}).get("time_stamp"), "->",
          (j.get("response") or {}).get("http_code"))
    for m in ms:
        print("   %-8s %s" % (m.get("ruleId"), m.get("message", "")[:64]))
