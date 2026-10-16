# -*- coding: utf-8 -*-
"""RT-4 audit helper: read WSL dmesg AppArmor DENIED records, dedupe by (profile, mask, comm, path)."""
import re
import subprocess
import sys
from collections import Counter

out = subprocess.run(["wsl", "dmesg"], capture_output=True, text=True,
                     errors="replace").stdout + subprocess.run(
    ["wsl", "dmesg"], capture_output=True, text=True, errors="replace").stderr

pat = re.compile(
    r'apparmor="DENIED" operation="(\S+)" class="(\S+)" profile="(\S+)" '
    r'name="([^"]*)" pid=(\d+) comm="([^"]*)" requested_mask="([^"]*)" denied_mask="([^"]*)"')

seen = {}
for m in pat.finditer(out):
    op, cls, prof, name, pid, comm, req, den = m.groups()
    key = (prof, op, req, comm, name)
    t = None
    # capture first-seen timestamp
    idx = m.start()
    ts = out.rfind("audit(", 0, idx)
    if ts >= 0:
        t = out[ts + 6: out.find(")", ts)].split(":")[0]
    if key not in seen:
        seen[key] = t

flt = sys.argv[1] if len(sys.argv) > 1 else None
rows = sorted(seen.items(), key=lambda kv: kv[1] or "")
cnt = Counter(k[0] for k in seen)
print("== totals per profile: " + ", ".join("%s=%d" % kv for kv in sorted(cnt.items())))
for (prof, op, req, comm, name), t in rows:
    if flt and flt not in (prof + name + comm + op):
        continue
    print("t=%s %-12s op=%-12s req=%-4s comm=%-12s %s" % (t, prof, op, req, comm, name))
