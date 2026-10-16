# -*- coding: utf-8 -*-
"""R2 iteration: patch the four AppArmor profiles in place."""
import io, os

D = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\defense\apparmor"

def patch(fname, replacements):
    p = os.path.join(D, fname)
    s = io.open(p, encoding="utf-8").read()
    for old, new in replacements:
        if old not in s:
            print(f"[WARN] {fname}: pattern not found: {old[:50]!r}")
        s = s.replace(old, new)
    io.open(p, "w", encoding="utf-8", newline="\n").write(s)
    print("patched", fname)

patch("aa-jboss", [
    ("/jboss-6.1.0.Final/ rwk,", "/jboss-6.1.0.Final/ rwkm,"),
    ("/jboss-6.1.0.Final/** rwk,", "/jboss-6.1.0.Final/** rwkm,"),
])
patch("aa-shiro", [
    ("/run/aa-tmp/ rwk,", "/run/aa-tmp/ rwkm,"),
    ("/run/aa-tmp/shiro/ rwk,", "/run/aa-tmp/shiro/ rwkm,"),
    ("/run/aa-tmp/shiro/** rwk,", "/run/aa-tmp/shiro/** rwkm,"),
    ("  /etc/ r,\n  /etc/** r,",
     "  /etc/ r,\n  /etc/** r,\n  /root/ r,\n  /root/** rm,"),
])
patch("aa-ofbiz", [
    ("/usr/src/apache-ofbiz/ rwk,", "/usr/src/apache-ofbiz/ rwkm,"),
    ("/usr/src/apache-ofbiz/** rwk,", "/usr/src/apache-ofbiz/** rwkm,"),
    ("/run/aa-tmp/ rwk,", "/run/aa-tmp/ rwkm,"),
    ("/run/aa-tmp/ofbiz/ rwk,", "/run/aa-tmp/ofbiz/ rwkm,"),
    ("/run/aa-tmp/ofbiz/** rwk,", "/run/aa-tmp/ofbiz/** rwkm,"),
    ("  /etc/ r,\n  /etc/** r,",
     "  /etc/ r,\n  /etc/** r,\n  /root/ r,\n  /root/** rm,"),
])
patch("aa-geoserver", [
    ("/mnt/geoserver/ rwk,", "/mnt/geoserver/ rwkm,"),
    ("/mnt/geoserver/** rwk,", "/mnt/geoserver/** rwkm,"),
    ("/run/aa-tmp/ rwk,", "/run/aa-tmp/ rwkm,"),
    ("/run/aa-tmp/geo/ rwk,", "/run/aa-tmp/geo/ rwkm,"),
    ("/run/aa-tmp/geo/** rwk,", "/run/aa-tmp/geo/** rwkm,"),
    ("/usr/bin/basename ix,",
     "/usr/bin/basename ix,\n  /usr/bin/getconf ix,\n  /usr/bin/lscpu ix,"),
    ("  /sys/** r,", "  /sys/** r,\n  /root/.cache/ rwkm,\n  /root/.cache/** rwkm,"),
])
print("done")
