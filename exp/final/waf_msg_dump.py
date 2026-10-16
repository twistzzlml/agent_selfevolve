# -*- coding: utf-8 -*-
"""Dump full message objects for transactions matching keywords."""
import json
import subprocess
import sys

r = subprocess.run(["docker", "logs", "multi-round-lab-waf-geoserver-1"], capture_output=True,
                   text=True, errors="replace")
for line in (r.stdout or "").splitlines():
    s = line.strip()
    if not s.startswith("{"):
        continue
    try:
        j = json.loads(s)
    except Exception:
        continue
    tr = j.get("transaction", {})
    uri = str((tr.get("request", {}) or {}).get("uri", ""))
    ts = tr.get("time_stamp", "")
    if ("19:56:3" in ts or "19:27:23" in ts) and ("ows" in uri or "rest" in uri):
        msgs = tr.get("messages") or []
        code = (tr.get("response", {}) or {}).get("http_code")
        print("=" * 10, ts, code, uri[:100])
        for m in msgs:
            print(json.dumps(m, ensure_ascii=False)[:400])
