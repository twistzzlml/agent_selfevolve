# -*- coding: utf-8 -*-
"""UTF-8 安全地把 rasp/<target>/plugins/official.js 的 all_log 切到 false。"""
import io
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "ofbiz"
p = r"rasp\%s\plugins\official.js" % target
t = io.open(p, encoding="utf-8").read()
if "all_log: false" in t:
    print("already false")
    sys.exit(0)
assert "all_log: true" in t, "all_log: true not found"
io.open(p, "w", encoding="utf-8", newline="").write(
    t.replace("all_log: true", "all_log: false", 1))
print("patched all_log -> false for", target)
