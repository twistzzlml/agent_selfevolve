# -*- coding: utf-8 -*-
"""Joint-round helper: enumerate Config/ModuleLoader property & env reads (read-only)."""
import re
import zipfile

BASE = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab"


def strings_from(data):
    pat = re.compile(rb"[\x20-\x7e]{3,}")
    return [m.group().decode() for m in pat.finditer(data)]


z = zipfile.ZipFile(BASE + r"\rasp\ofbiz\rasp-engine.jar")
targets = []
for n in z.namelist():
    if n.endswith(".class") and (
        "config/ConfigBase" in n or "config/Config" in n or "ModuleLoader" in n
        or "HookHandler" in n or "hook/JNDIHook" in n
    ):
        targets.append(n)
for t in sorted(set(targets)):
    data = z.read(t)
    ss = strings_from(data)
    hits = [s for s in ss if any(k in s for k in ("getenv", "getProperty", "hooks.ignore", "hooksIgnore", "doCheckWithoutRequest", "isRequestThread", "processComplete", "jndi", "JNDI", "ignore"))]
    if hits:
        print("===", t)
        seen = set()
        for s in hits:
            if s not in seen and len(s) < 90:
                seen.add(s)
                print("   ", repr(s))
