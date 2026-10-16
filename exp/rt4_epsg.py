# -*- coding: utf-8 -*-
import collections
import subprocess

out = subprocess.run(["wsl", "dmesg"], capture_output=True, text=True,
                     errors="replace").stdout
lines = [l for l in out.splitlines() if "EPSG_creation_lock" in l]
print("EPSG lock denials total:", len(lines))
for l in lines[-3:]:
    print(l[:230])
lines2 = [l for l in out.splitlines() if "aa-geoserver" in l and 'apparmor="DENIED"' in l]
print("aa-geoserver DENIED total:", len(lines2))
ops = collections.Counter(l.split('operation="')[1].split('"')[0] for l in lines2)
print("by op:", dict(ops))
