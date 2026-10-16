# -*- coding: utf-8 -*-
"""Read crash dump header (read-only) + wait for OFBiz to come back up."""
import subprocess
import time

r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "sh", "-c",
                    "ls -l --full-time /usr/src/apache-ofbiz/hs_err_pid1.log; "
                    "sed -n '1,30p' /usr/src/apache-ofbiz/hs_err_pid1.log"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr[:500])

for i in range(30):
    time.sleep(5)
    rr = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "sh", "-c",
                         "netstat -tln 2>/dev/null | grep 8443 || cat /proc/net/tcp | head -8"],
                        capture_output=True, text=True)
    out = rr.stdout
    if "8443" in out or "2093" in out.lower():
        print("[%02d] ofbiz listening: %s" % (i, out.strip()[:400]))
        break
    print("[%02d] waiting..." % i)
