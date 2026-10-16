# -*- coding: utf-8 -*-
"""Joint-round helper: check NativeLibraryUtil/ArchitectureDetector for JUL + sh usage (read-only)."""
import re
import zipfile

BASE = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab"


def strings_from(data):
    pat = re.compile(rb"[\x20-\x7e]{3,}")
    return [m.group().decode() for m in pat.finditer(data)]


z = zipfile.ZipFile(BASE + r"\rasp\shiro\rasp-engine.jar")
for n in z.namelist():
    if "nativelib" in n and n.endswith(".class"):
        data = z.read(n)
        ss = strings_from(data)
        hits = [s for s in ss if "logging" in s or "sh" == s.strip() or "/bin/sh" in s or "uname" in s or "getRuntime" in s or "Logger" in s]
        if hits:
            print("===", n)
            for s in hits[:15]:
                print("   ", repr(s))
