# -*- coding: utf-8 -*-
"""Joint-round helper: freshness of host-side rasp alarm logs (EROFS evidence, read-only)."""
import os
import time

for t in ("shiro", "jboss", "geoserver", "ofbiz"):
    d = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\rasp\%s\logs\alarm" % t
    try:
        for f in os.listdir(d):
            p = os.path.join(d, f)
            print(t, f, os.path.getsize(p), time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(p))))
    except Exception as e:
        print(t, "ERR", e)
