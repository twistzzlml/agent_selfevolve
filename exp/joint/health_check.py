# -*- coding: utf-8 -*-
"""Joint deployment: business matrix + labels + RASP liveness (read-only)."""
import subprocess
import sys

sys.path.insert(0, r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\exp")
from common import session  # noqa: E402

s = session()

print("=== business matrix (through WAF ports only) ===")
checks = [
    ("jboss", "http://127.0.0.1:18380/", 200),
    ("ofbiz", "https://127.0.0.1:18381/webtools/control/main", 200),
    ("geoserver", "http://127.0.0.1:18382/geoserver/web/", 200),
    ("shiro", "http://127.0.0.1:18383/", 302),
]
for name, url, expect in checks:
    try:
        r = s.get(url, timeout=60, allow_redirects=False)
        prot = r.headers.get("X-Protected-By", "-")
        print("[%-9s] %s -> HTTP %s (expect %s) bytes=%d X-Protected-By=%s"
              % (name, url, r.status_code, expect, len(r.content), prot))
    except Exception as e:  # noqa: BLE001
        print("[%-9s] %s -> ERROR %s" % (name, url, e))

print("\n=== AppArmor labels (PID1) ===")
for c in ("multi-round-lab-jboss-1", "multi-round-lab-ofbiz-1",
          "multi-round-lab-geoserver-1", "multi-round-lab-shiro-1"):
    r = subprocess.run(["docker", "exec", c, "cat", "/proc/1/attr/current"],
                       capture_output=True, text=True)
    print(c, "->", (r.stdout + r.stderr).strip())

print("\n=== java process flags (agent / hardening) ===")
for c, pat in (("multi-round-lab-jboss-1", "javaagent|tmpdir|UsePerfData"),
               ("multi-round-lab-shiro-1", "javaagent|tmpdir|UsePerfData"),
               ("multi-round-lab-geoserver-1", "javaagent|tmpdir|UsePerfData")):
    r = subprocess.run(["docker", "exec", c, "sh", "-c",
                        "tr '\\0' '\\n' < /proc/1/cmdline | grep -E '%s' | sed -n '1,6p'" % pat],
                       capture_output=True, text=True)
    print(c, "->", (r.stdout + r.stderr).strip().replace("\n", " | "))
