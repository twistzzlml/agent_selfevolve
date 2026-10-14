# -*- coding: utf-8 -*-
"""解析 waf 容器 docker logs 里的 CRS 审计 JSON：
按 response.http_code 判定拦截，打印每条 403 事务的命中规则。"""
import json
import subprocess
import sys

name = sys.argv[1] if len(sys.argv) > 1 else "multi-round-lab-waf-jboss-1"
r = subprocess.run(["docker", "logs", name],
                   capture_output=True, text=True, errors="replace")
ok = 0
for line in (r.stdout + r.stderr).splitlines():
    s = line.strip()
    if not s.startswith("{"):
        continue
    try:
        j = json.loads(s)
    except Exception:
        continue
    ok += 1
    t = j.get("transaction", {})
    resp = (j.get("response") or {}).get("http_code")
    req = (t.get("request") or {})
    method, uri = req.get("method"), req.get("uri")
    if resp == 403:
        print("--- 403: %s %s" % (method, uri))
        for m in j.get("messages", []) or []:
            print("    rule %-8s %s" % (m.get("ruleId"), str(m.get("message", ""))[:100]))
print("total transactions:", ok)
