# -*- coding: utf-8 -*-
"""Joint-round helper: locate jndi algorithm in plugin js (read-only)."""
import io
import re

d = io.open(r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\rasp\ofbiz\plugins\official.js", encoding="utf-8").read()
print("total len", len(d))
for m in re.finditer(r"jndi", d):
    i = m.start()
    line_start = d.rfind("\n", 0, i) + 1
    line_end = d.find("\n", i)
    line = d[line_start:line_end].strip()
    if len(line) > 160:
        line = line[:160]
    print(i, "|", line)
