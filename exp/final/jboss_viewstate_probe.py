# -*- coding: utf-8 -*-
"""Inspect admin-console login.seam form: viewState shape + fields."""
import re

import requests
import urllib3

urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

r = s.get("http://127.0.0.1:18380/admin-console/login.seam", timeout=30)
print("login.seam ->", r.status_code, len(r.content))
html = r.text
fields = re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', html)
for n, v in fields:
    print("input:", n, "=>", (v[:90] + ("... len=%d" % len(v) if len(v) > 90 else "")))
m = re.search(r'name="javax\.faces\.ViewState"[^>]*value="([^"]*)"', html)
if m:
    print("VIEWSTATE len:", len(m.group(1)), "| head:", m.group(1)[:80])
sel = re.findall(r'<select[^>]*name="([^"]+)"', html)
print("selects:", sel)
