# -*- coding: utf-8 -*-
"""Final-round helper: dump a target WAF audit log and summarize rule hits.
Usage: python waf_audit.py ofbiz [--since 10m] [--raw N]
Read-only. Writes nothing to the lab tree except this file's own dir.
"""
import argparse
import json
import subprocess

WAF = {
    "jboss": "multi-round-lab-waf-jboss-1",
    "ofbiz": "multi-round-lab-waf-ofbiz-1",
    "geoserver": "multi-round-lab-waf-geoserver-1",
    "shiro": "multi-round-lab-waf-shiro-1",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--since", default="30m")
    ap.add_argument("--raw", type=int, default=0)
    a = ap.parse_args()

    cmd = ["docker", "logs", WAF[a.target], "--since", a.since]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    data = (r.stdout or "") + (r.stderr or "")
    lines = data.splitlines()
    txs = []
    cur = None
    for l in lines:
        s = l.strip()
        if s.startswith("{"):
            try:
                cur = json.loads(s)
                txs.append(cur)
            except Exception:
                cur = None
        elif cur is not None and '"messages"' in s:
            pass
    hits = {}
    blocked = 0
    for j in txs:
        tr = j.get("transaction", {})
        msgs = tr.get("messages") or []
        if tr.get("action") == "Intercepted" or tr.get("status") == 403:
            blocked += 1
        for m in msgs:
            rid = str(m.get("ruleId") or m.get("id"))
            hits[rid] = hits.get(rid, 0) + 1
    print("[waf-%s] transactions=%d intercepted/403=%d" % (a.target, len(txs), blocked))
    print("[waf-%s] rule hits: %s" % (a.target, json.dumps(hits, sort_keys=True) if hits else "(none)"))
    if a.raw:
        n = 0
        for j in txs[-a.raw:]:
            tr = j.get("transaction", {})
            print("--- %s %s -> %s | msgs=%s" % (
                tr.get("request", {}).get("method", "?"),
                (tr.get("request", {}).get("url") or "?")[:120],
                tr.get("response", {}).get("status"),
                [(m.get("ruleId"), (m.get("msg") or "")[:60]) for m in (tr.get("messages") or [])]))


if __name__ == "__main__":
    main()
