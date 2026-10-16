# -*- coding: utf-8 -*-
"""Joint-round helper: find classes referencing both 'log.path' and System.getProperty (read-only)."""
import re
import zipfile

BASE = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab"


def strings_from(data):
    pat = re.compile(rb"[\x20-\x7e]{4,}")
    return [m.group().decode() for m in pat.finditer(data)]


z = zipfile.ZipFile(BASE + r"\rasp\shiro\rasp-engine.jar")
for n in z.namelist():
    if not n.endswith(".class"):
        continue
    data = z.read(n)
    if b"log.path" in data and b"getProperty" in data:
        print("=== ", n)
        for s in strings_from(data):
            if any(k in s for k in ("log", "path", "Property", "rasp")):
                print("   ", s)
