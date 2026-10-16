#!/usr/bin/env python3
# Summarize AppArmor audit messages from dmesg, grouped by profile/op/path-pattern.
import re, collections, subprocess

out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
cnt = collections.Counter()
for line in out.splitlines():
    if 'apparmor="ALLOWED"' not in line and 'apparmor="DENIED"' not in line:
        continue
    def f(key, q='"'):
        m = re.search(key + '="([^"]*)"', line)
        return m.group(1) if m else ""
    state = f("apparmor")
    prof, op, name = f("profile"), f("operation"), f("name")
    req, den = f("requested_mask"), f("denied_mask")
    if state != "ALLOWED":      # complain mode: ALLOWED == would-be-denied
        continue
    prof = prof.split("//")[0]
    if name:
        name = re.sub(r"\d+", "N", name)
    cnt[(prof, op, name or "-", req, den)] += 1

for (prof, op, name, req, den), n in sorted(cnt.items(), key=lambda kv: -kv[1]):
    print(f"{n:6d}  {prof:13s} {op:24s} req={req:8s} den={den:8s} {name[:88]}")
print("total would-be-denied ops:", sum(cnt.values()))
