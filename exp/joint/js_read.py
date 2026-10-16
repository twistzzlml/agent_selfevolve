# -*- coding: utf-8 -*-
"""Joint-round helper: read regions of the plugin js (read-only)."""
import io
import sys

d = io.open(r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\rasp\ofbiz\plugins\official.js", encoding="utf-8").read()
regions = [(99300, 99500), (99540, 99750), (16200, 16260)]
for a, b in regions:
    print("===== region", a, b)
    print(d[a:b])
