# -*- coding: utf-8 -*-
"""Scan a saved docker-logs capture (or live target WAF log) for transactions
whose URI contains any of the given keywords; print status + rule ids + matches.
Usage: python waf_json_scan.py <capture-file-or-TARGETNAME> <kw1> [kw2...]
"""
import json
import subprocess
import sys

WAF = {
    "jboss": "multi-round-lab-waf-jboss-1",
    "ofbiz": "multi-round-lab-waf-ofbiz-1",
    "geoserver": "multi-round-lab-waf-geoserver-1",
    "shiro": "multi-round-lab-waf-shiro-1",
}


def iter_lines(src):
    if src in WAF:
        r = subprocess.run(["docker", "logs", WAF[src]], capture_output=True, text=True,
                           errors="replace")
        for l in (r.stdout or "").splitlines() + (r.stderr or "").splitlines():
            yield l
    else:
        with open(src, encoding="utf-8", errors="replace") as fh:
            for l in fh:
                yield l


def main():
    src, kws = sys.argv[1], [k.lower() for k in sys.argv[2:]]
    n = bad = hit = 0
    for line in iter_lines(src):
        s = line.strip()
        if not s.startswith("{"):
            continue
        n += 1
        try:
            j = json.loads(s)
        except Exception:
            bad += 1
            continue
        tr = j.get("transaction", {})
        uri = str((tr.get("request", {}) or {}).get("uri", ""))
        if any(k in uri.lower() for k in kws):
            hit += 1
            msgs = tr.get("messages") or []
            code = (tr.get("response", {}) or {}).get("http_code")
            ts = tr.get("time_stamp")
            rids = []
            for m in msgs:
                d = m.get("details", {}) or {}
                rids.append(str(d.get("ruleId") or m.get("ruleId") or m.get("id") or "?"))
            print(">> %s | %s | %s | %s" % (ts, code, uri[:120], rids))
            for m in msgs:
                d = m.get("details", {}) or {}
                print("      %s %s | match=%s" % (d.get("ruleId"), (m.get("message") or "")[:70],
                                                  (d.get("match") or "")[:110]))
    print("json=%d bad=%d shown=%d" % (n, bad, hit))


if __name__ == "__main__":
    main()
