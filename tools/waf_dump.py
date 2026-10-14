# -*- coding: utf-8 -*-
"""打印 waf 审计 JSON 每条事务的方法/URI/响应码/消息数/消息内容。"""
import json
import subprocess
import sys

name = sys.argv[1] if len(sys.argv) > 1 else "multi-round-lab-waf-jboss-1"
r = subprocess.run(["docker", "logs", name],
                   capture_output=True, text=True, errors="replace")
for line in (r.stdout + r.stderr).splitlines():
    s = line.strip()
    if not s.startswith("{"):
        continue
    try:
        j = json.loads(s)
    except Exception:
        print("PARSE-FAIL", s[:120])
        continue
    t = j.get("transaction", {})
    req = t.get("request") or {}
    resp = j.get("response")
    code = resp.get("http_code") if isinstance(resp, dict) else resp
    msgs = j.get("messages") or []
    print("%s %s -> %s | msgs=%d" % (req.get("method"), str(req.get("uri"))[:50],
                                     code, len(msgs)))
    for m in msgs:
        print("     rule %-8s %s" % (m.get("ruleId"), str(m.get("message", ""))[:100]))
