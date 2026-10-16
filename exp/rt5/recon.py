# -*- coding: utf-8 -*-
"""RT5 recon: read-only inventory of target containers."""
import subprocess

TARGETS = ["jboss", "shiro", "ofbiz", "geoserver"]
CMDS = [
    "id; echo CWD=$(readlink /proc/1/cwd); echo PID1=$(cat /proc/1/comm)",
    "ls -la /root/ 2>&1 | sed -n '1,15p'; echo ---shadow---; ls -l /etc/shadow; wc -c /etc/shadow",
    "ls -l /tmp/ 2>&1; ls -ld /run/aa-tmp 2>&1",
]

def run(name, cmd):
    r = subprocess.run(["docker", "exec", name, "sh", "-c", cmd],
                       capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip()

for p in TARGETS:
    name = "multi-round-lab-%s-1" % p
    print("=" * 20, p, "=" * 20)
    for cmd in CMDS:
        out, err = run(name, cmd)
        print("--- [%s]" % cmd[:60])
        if out:
            print(out)
        if err:
            print("ERR:", err[:300])
