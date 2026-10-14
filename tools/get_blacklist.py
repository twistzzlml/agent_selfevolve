# -*- coding: utf-8 -*-
"""提取 official.js 里 deserialization_blacklist 的类名清单与三条算法的 action。"""
import io
import re
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "shiro"
t = io.open(r"rasp\%s\plugins\official.js" % target, encoding="utf-8").read()

m = re.search(r"deserialization_blacklist:\s*\{.*?\n\s*\}", t, re.S)
if m:
    print("== deserialization_blacklist 块原文 ==")
    print(m.group(0)[:1200])
print()
for k in ("command_reflect", "ssrf_userinput"):
    m = re.search(k + r":\s*\{[^}]*action:\s*'([^']+)'", t)
    print(k, "action =", m.group(1) if m else "not found")
