# -*- coding: utf-8 -*-
"""Retry MBean inspection; print error body; try variants."""
import requests
import urllib3

urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

variants = [
    ("inspect with Host evil.com", "http://127.0.0.1:18380/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.admin%3Aservice%3DDeploymentFileRepository", {"Host": "evil.com"}),
    ("inspect default Host", "http://127.0.0.1:18380/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.admin%3Aservice%3DDeploymentFileRepository", {}),
    ("console index default Host", "http://127.0.0.1:18380/jmx-console/", {}),
    ("inspect decoded colon", "http://127.0.0.1:18380/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.admin:service=DeploymentFileRepository", {}),
]
for label, url, hdrs in variants:
    r = s.get(url, auth=("admin", "admin"), timeout=30, headers=hdrs)
    print("=" * 15, label, "->", r.status_code, len(r.content))
    body = r.text
    if r.status_code != 200:
        print(body[:400].replace("\n", " "))
    else:
        import re
        for m in re.finditer(r'methodName=([\w$]+)', body):
            pass
        print(sorted(set(re.findall(r'methodName=([\w$]+)', body))))
