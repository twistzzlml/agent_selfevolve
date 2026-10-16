# -*- coding: utf-8 -*-
"""Joint-round helper: inspect rasp jars for log-path config handling (read-only)."""
import re
import sys
import zipfile

BASE = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab"


def strings_from(data):
    # crude ASCII strings extractor
    pat = re.compile(rb"[\x20-\x7e]{4,}")
    return [m.group().decode() for m in pat.finditer(data)]


def probe(jar, needle):
    z = zipfile.ZipFile(jar)
    hits = []
    for n in z.namelist():
        if not n.endswith(".class"):
            continue
        data = z.read(n)
        if needle.encode() in data:
            ss = [s for s in strings_from(data) if needle in s or "log.path" in s or "rasp.home" in s or "log_path" in s]
            hits.append((n, ss[:12]))
    return hits


if __name__ == "__main__":
    for j in (BASE + r"\rasp\shiro\rasp-engine.jar", BASE + r"\rasp\shiro\rasp.jar"):
        print("===", j)
        try:
            z = zipfile.ZipFile(j)
            print("entries:", len(z.namelist()))
            z.close()
        except Exception as e:
            print("ERR", e)
            continue
        for needle in ("log.path", "getProperty"):
            for n, ss in probe(j, needle)[:6]:
                print("--", n)
                for s in ss:
                    print("   ", s)
