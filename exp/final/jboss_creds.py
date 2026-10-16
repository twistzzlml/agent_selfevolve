# -*- coding: utf-8 -*-
"""JBoss jmx-console default-credential probe through WAF."""
import requests
import urllib3

urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"

for u, p in [("admin", "admin"), ("admin", "password"), ("root", "root"),
             ("jboss", "jboss"), ("admin", "jboss"), ("admin", "")]:
    r = s.get("http://127.0.0.1:18380/jmx-console/", auth=(u, p), timeout=30,
              allow_redirects=False)
    print("%s:%s -> %s (%dB)" % (u, p, r.status_code, len(r.content)))
