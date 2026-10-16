# -*- coding: utf-8 -*-
"""Joint-round helper: inspect ModuleLoader/Logger repo classes for base-dir & log path (read-only)."""
import re
import zipfile

BASE = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab"


def strings_from(data):
    pat = re.compile(rb"[\x20-\x7e]{4,}")
    return [m.group().decode() for m in pat.finditer(data)]


z = zipfile.ZipFile(BASE + r"\rasp\shiro\rasp.jar")
targets = ["com/baidu/openrasp/ModuleLoader.class"]
for n in z.namelist():
    if "Logger" in n and n.endswith(".class") and "log4j" in n:
        targets.append(n)
for t in targets:
    try:
        data = z.read(t)
    except KeyError:
        continue
    print("===", t)
    for s in strings_from(data):
        if any(k in s.lower() for k in ("log", "path", "dir", "home", "base")):
            print("   ", s)
