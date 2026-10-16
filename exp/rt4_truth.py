# -*- coding: utf-8 -*-
"""RT-4 final truth sweep: markers, profiles, audit window, infra log."""
import subprocess

TARGETS = {
    "jboss": "multi-round-lab-jboss-1",
    "ofbiz": "multi-round-lab-ofbiz-1",
    "geoserver": "multi-round-lab-geoserver-1",
    "shiro": "multi-round-lab-shiro-1",
}

print("=== A. PID1 AppArmor profile (enforce) ===")
for t, c in TARGETS.items():
    r = subprocess.run(["docker", "exec", c, "sh", "-c",
                        "cat /proc/1/attr/current"], capture_output=True, text=True)
    print("[%-9s] %s" % (t, r.stdout.strip()))

print("\n=== B. markers in targets ===")
CHECKS = [
    ("jboss", ["ls", "-l", "--full-time", "/tmp/hsperfdata_root/pwn_rt4_jboss_a1",
               "/jboss-6.1.0.Final/pwn_rt4_jboss_t3"]),
    ("jboss-rv-absent", ["ls", "/tmp/pwn_rt4_jboss_rv"]),
    ("shiro", ["ls", "-l", "--full-time", "/tmp/tomcatrt4_a1",
               "/tmp/tomcat.625836501645568797.8080/pwn_rt4_shiro_a2",
               "/tmp/tomcat-docbase.7191725270746254592.8080/pwn_rt4_shiro_a2",
               "/tmp/hsperfdata_root/pwn_rt4_shiro_a3"]),
    ("shiro-rv-absent", ["ls", "/tmp/pwn_rt4_shiro_rv"]),
    ("ofbiz", ["ls", "-l", "--full-time", "/tmp/hsperfdata_root/pwn_rt4_ofbiz_a1",
               "/usr/src/apache-ofbiz/pwn_rt4_ofbiz_t2"]),
    ("geoserver-rv-absent", ["ls", "/tmp/start_rt4_gs_a1"]),
]
for label, args in CHECKS:
    t = label.split("-")[0]
    r = subprocess.run(["docker", "exec", TARGETS[t]] + args,
                       capture_output=True, text=True)
    print("[%-18s] %s" % (label, (r.stdout + r.stderr).strip().replace("\n", " | ")))

print("\n=== C. audit denials during RT-4 window (dmesg tail, after t=6000s) ===")
out = subprocess.run(["wsl", "dmesg"], capture_output=True, text=True, errors="replace").stdout
for line in out.splitlines():
    if 'apparmor="DENIED"' in line:
        try:
            t = float(line.split("audit(")[1].split(":")[0])
        except Exception:
            continue
        if t >= 1792084080:  # RT-4 round started ~17:08 UTC
            print(line[:200])

print("\n=== D. infra log (rt4*) ===")
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "30m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4" in line:
        print("[infra] " + line)
