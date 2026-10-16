# -*- coding: utf-8 -*-
"""Joint-round helper: search historical ofbiz rasp.log for jndi/plugin events (read-only)."""
import io

p = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\rasp\ofbiz\logs\rasp\rasp.log"
d = io.open(p, encoding="utf-8", errors="replace").read()
lines = d.splitlines()
print("total lines", len(lines))
for kw in ("jndi", "plugin", "JNDI", "block", "Block", "SecurityException"):
    print("##### keyword:", kw)
    n = 0
    for ln in lines:
        if kw in ln:
            print(ln[:220])
            n += 1
            if n > 8:
                break
