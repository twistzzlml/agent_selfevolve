# -*- coding: utf-8 -*-
"""Joint-round helper: extract algorithmConfig JSON from official.js (read-only)."""
import io
import json
import re

for t in ("ofbiz", "shiro", "jboss", "geoserver"):
    p = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\rasp\%s\plugins\official.js" % t
    d = io.open(p, encoding="utf-8", errors="replace").read()
    m = re.search(r'algorithmConfig\s*=\s*(\{.*?\})\s*;?\s*\n', d, re.S)
    if not m:
        # find the meta blob
        i = d.find('"all_log"')
        print(t, "no direct match; all_log at", i)
        if i != -1:
            print(d[max(0, i - 400):i + 100].replace("\n", " ")[:600])
        continue
    blob = m.group(1)
    try:
        cfg = json.loads(blob)
        print("===", t, "meta:", cfg.get("meta"))
        for k in ("jndi_disable_all", "ssrf_userinput", "command_reflect", "deserialization_blacklist", "writeFile_deser", "writeFile_rememberme"):
            if k in cfg:
                print("   ", k, "=", cfg[k].get("action") if isinstance(cfg[k], dict) else cfg[k])
    except Exception as e:
        print(t, "parse fail", e, blob[:200])
