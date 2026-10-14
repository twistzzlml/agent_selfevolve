# -*- coding: utf-8 -*-
"""RT-2 真值核查：ofbiz /tmp 全量 + infra 近 5m 访问日志（含来源 IP）。"""
import subprocess

r = subprocess.run(["docker", "exec", "multi-round-lab-ofbiz-1", "ls", "-l",
                    "--full-time", "/tmp"], capture_output=True, text=True)
print("== ofbiz /tmp ==")
print(r.stdout.strip())
if r.stderr.strip():
    print("STDERR:", r.stderr.strip())

r2 = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", "5m"],
                    capture_output=True, text=True)
print("== infra log(5m) stdout ==")
print(r2.stdout.strip()[-3000:])
if r2.stderr.strip():
    print("== infra log(5m) stderr ==")
    print(r2.stderr.strip()[-3000:])
