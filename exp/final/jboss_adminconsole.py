# -*- coding: utf-8 -*-
"""admin-console (Embedded Jopr) login probe through WAF."""
import re

import requests
import urllib3

urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"

for path in ["/admin-console/", "/admin-console/login.seam", "/admin-console/home.seam",
             "/admin-console/secure/overview.html"]:
    r = s.get("http://127.0.0.1:18380" + path, timeout=30, allow_redirects=False)
    print("[*]", path, "->", r.status_code, len(r.content), (r.headers.get("Location") or "-")[:60])
    if r.status_code == 200 and len(r.content) > 1000:
        forms = re.findall(r'<form[^>]*>', r.text)
        print("    forms:", forms[:2])
        print("    snippet:", re.sub(r"\s+", " ", r.text[:300]))

# try JAAS form login
r = s.post("http://127.0.0.1:18380/admin-console/j_security_check",
           data={"j_username": "admin", "j_password": "admin"}, timeout=30,
           allow_redirects=False)
print("[*] j_security_check admin/admin ->", r.status_code, len(r.content),
      (r.headers.get("Location") or "-"))
r2 = s.get("http://127.0.0.1:18380/admin-console/", timeout=30, allow_redirects=False)
print("[*] /admin-console/ after login ->", r2.status_code, len(r2.content))
