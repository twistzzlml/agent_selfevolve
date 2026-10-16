# -*- coding: utf-8 -*-
"""RT5 recon2: tool inventory (granted exec set + JDK tools), awk flavor, caches."""
import subprocess

def run(name, cmd):
    r = subprocess.run(["docker", "exec", name, "sh", "-c", cmd],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()

J = "multi-round-lab-jboss-1"
S = "multi-round-lab-shiro-1"
O = "multi-round-lab-ofbiz-1"
G = "multi-round-lab-geoserver-1"

print("== jboss: /bin/sh type, awk flavor ==")
print(run(J, "ls -l /bin/sh; readlink -f /bin/sh; awk --version 2>&1 | head -1; ls -l /usr/bin/awk"))
print(run(J, "ls /usr/lib/jvm/; ls /usr/lib/jvm/*/bin/ 2>/dev/null | head -40"))
print(run(J, "which bash curl wget touch gcc python perl nc 2>&1"))
print(run(J, "ls -ld /jboss-6.1.0.Final/server/default/deploy /jboss-6.1.0.Final/server/default/tmp 2>&1; ls /jboss-6.1.0.Final/server/default/deploy | head -30"))

print("\n== shiro: java layout ==")
print(run(S, "ls /usr/bin/java*; ls /usr/lib/jvm/ 2>/dev/null; ls /usr/lib/jvm/*/bin 2>/dev/null | head; ls -l /shirodemo-1.0-SNAPSHOT.jar"))
print(run(S, "which jmap jcmd javac jrunscript jjs 2>&1"))

print("\n== ofbiz: jdk tools + cwd ==")
print(run(O, "ls /usr/local/openjdk-8/bin/ | tr '\\n' ' '"))
print(run(O, "ls -ld /usr/src/apache-ofbiz/runtime /usr/src/apache-ofbiz/build/libs 2>&1; ls /usr/src/apache-ofbiz | head -20"))

print("\n== geoserver: jdk tools + .cache ==")
print(run(G, "ls /usr/local/openjdk-17/bin/ | tr '\\n' ' '"))
print(run(G, "ls -laR /root/.cache 2>&1 | head -30"))
print(run(G, "ls /mnt/geoserver | head; ls -ld /mnt/geoserver"))
