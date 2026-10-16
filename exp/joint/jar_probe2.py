# -*- coding: utf-8 -*-
"""Joint-round helper: dump strings of specific classes from rasp-engine.jar (read-only)."""
import re
import sys
import zipfile

BASE = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab"


def strings_from(data):
    pat = re.compile(rb"[\x20-\x7e]{4,}")
    return [m.group().decode() for m in pat.finditer(data)]


if __name__ == "__main__":
    jar = BASE + r"\rasp\shiro\rasp-engine.jar"
    z = zipfile.ZipFile(jar)
    for n in z.namelist():
        if n.endswith("Config.class") and "config" in n.lower():
            data = z.read(n)
            ss = strings_from(data)
            interesting = [s for s in ss if ("log" in s.lower() or "path" in s.lower() or "getProperty" in s)][:60]
            print("===", n, len(ss))
            for s in interesting:
                print("   ", s)
