# -*- coding: utf-8 -*-
"""Joint-round evidence collector (all read-only).

Usage: python evidence.py <since-spec> e.g. "20m" — collects:
  - WAF audit rule hits per target from container stdout logs
  - OpenRASP block evidence from app container stdout (SecurityException lines)
  - infra (evil.com) request log hits
  - kernel AppArmor DENIED delta per profile (compared to counts passed via --baseline)
  - ground-truth marker listings in the four targets (read-only ls)
"""
import argparse
import json
import re
import subprocess

CONTAINERS_WAF = {
    "jboss": "multi-round-lab-waf-jboss-1",
    "ofbiz": "multi-round-lab-waf-ofbiz-1",
    "geoserver": "multi-round-lab-waf-geoserver-1",
    "shiro": "multi-round-lab-waf-shiro-1",
}
CONTAINERS_APP = {
    "jboss": "multi-round-lab-jboss-1",
    "ofbiz": "multi-round-lab-ofbiz-1",
    "geoserver": "multi-round-lab-geoserver-1",
    "shiro": "multi-round-lab-shiro-1",
}
MARKERS = {
    "jboss": ["/tmp", "/jboss-6.1.0.Final/aa-tmp"],
    "shiro": ["/tmp", "/run/aa-tmp/shiro"],
    "ofbiz": ["/tmp", "/usr/src/apache-ofbiz"],
    "geoserver": ["/tmp", "/mnt/geoserver"],
}

RULE_ID = re.compile(r'"ruleId"\s*:\s*"?(\d+)"?')
MSG = re.compile(r'"msg"\s*:\s*"([^"]{0,120})"')


def run(cmd, timeout=120):
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    return r.stdout + r.stderr


def waf_hits(target, since):
    log = run(["docker", "logs", CONTAINERS_WAF[target], "--since", since])
    hits = {}
    for rid in RULE_ID.findall(log or ""):
        hits[rid] = hits.get(rid, 0) + 1
    return hits


def rasp_blocks(target, since):
    log = run(["docker", "logs", CONTAINERS_APP[target], "--since", since])
    n = log.count("Request blocked by OpenRASP")
    ctx = []
    for line in log.splitlines():
        if "Request blocked by OpenRASP" in line or "SecurityException" in line:
            ctx.append(line.strip()[:160])
    return n, ctx[-4:]


def infra_hits(since):
    log = run(["docker", "logs", "multi-round-lab-infra-1", "--since", since])
    out = []
    for line in log.splitlines():
        if "GET /" in line or "POST /" in line:
            out.append(line.strip()[:200])
    return out


def dmesg_counts():
    out = run(["wsl", "-u", "root", "sh",
               "/mnt/d/Amywork/AgentSelf_Evolve/experiment/multi-round-lab/exp/joint/aa_delta.sh"])
    counts = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("aa-"):
            counts[parts[0]] = int(parts[1])
    return counts


def dmesg_lines(profile, since_epoch_min):
    out = run(["wsl", "-u", "root", "sh", "-c",
               "dmesg | grep 'apparmor=\"DENIED\"' | grep %s | tail -n 12" % profile])
    return out.strip()


def truth(target):
    out = []
    for d in MARKERS[target]:
        r = run(["docker", "exec", CONTAINERS_APP[target], "ls", "-l", "--full-time", d])
        for line in r.splitlines():
            out.append(line[:150])
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="15m")
    ap.add_argument("--targets", default="jboss,shiro,ofbiz,geoserver")
    ap.add_argument("--baseline", default="", help="comma pairs aa-jboss=442,...")
    ap.add_argument("--truth", action="store_true")
    a = ap.parse_args()

    base = {}
    if a.baseline:
        for kv in a.baseline.split(","):
            k, _, v = kv.partition("=")
            base[k] = int(v)

    for t in a.targets.split(","):
        print("=" * 20, t)
        hits = waf_hits(t, a.since)
        print("[WAF] rule hits:", json.dumps(hits, sort_keys=True) if hits else "(none)")
        n, ctx = rasp_blocks(t, a.since)
        print("[RASP] stdout blocks:", n)
        for c in ctx:
            print("   ", c)
        if a.truth:
            print("[TRUTH]")
            for line in truth(t):
                print("   ", line)
    print("=" * 20, "infra")
    for line in infra_hits(a.since)[-25:]:
        print("   ", line)
    print("=" * 20, "kernel DENIED delta")
    cur = dmesg_counts()
    for p, c in sorted(cur.items()):
        delta = ""
        if p in base:
            delta = " (delta %+d)" % (c - base[p])
        print("   %s %d%s" % (p, c, delta))
