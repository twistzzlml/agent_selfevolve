# -*- coding: utf-8 -*-
"""Final round - JBoss recon: console faces through WAF 18380."""
import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18380"
s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"


def show(label, r):
    auth = r.headers.get("WWW-Authenticate", "-")
    print("[*] %-40s HTTP %s | len=%d | auth=%s | %s" %
          (label, r.status_code, len(r.content), auth[:40], r.text[:100].replace("\n", " ")))


for path in ["/jmx-console/", "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.admin%3Aservice%3DDeploymentFileRepository",
             "/web-console/", "/admin-console/", "/status", "/invoker/readonly",
             "/invoker/JMXInvokerServlet", "/invoker/EJBInvokerServlet"]:
    try:
        r = s.get(BASE + path, timeout=30, allow_redirects=False)
        show(path[:40], r)
    except Exception as e:
        print("[!]", path, str(e)[:80])
