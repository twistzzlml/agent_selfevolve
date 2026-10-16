# -*- coding: utf-8 -*-
"""RT5 final sweep: OFBiz post-restart tamper persistence + full audit summary."""
import subprocess

def run(name, cmd):
    r = subprocess.run(["docker", "exec", name, "sh", "-c", cmd],
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()

O = "multi-round-lab-ofbiz-1"
print("=== OFBiz tamper survived 2 restarts? ===")
print(run(O, "cat /usr/src/apache-ofbiz/VERSION; echo; ls -l --full-time "
              "/usr/src/apache-ofbiz/pwn_rt4_ofbiz_t2 "
              "/usr/src/apache-ofbiz/rt5_mv_src /usr/src/apache-ofbiz/rt5_lnk "
              "/usr/src/apache-ofbiz/pwn_jdwp_marker 2>&1; echo; ls -l "
              "/usr/src/apache-ofbiz/hs_err_pid1.log 2>&1"))

print("\n=== audit: per-profile DENIED totals ===")
r = subprocess.run(["wsl", "-u", "root", "--", "bash", "-c",
                    "dmesg | grep 'apparmor=\"DENIED\"' | wc -l; "
                    "for p in aa-jboss aa-shiro aa-ofbiz aa-geoserver; do "
                    "echo -n \"$p: \"; dmesg | grep 'apparmor=\"DENIED\"' | grep -c \"$p\"; done"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr)

print("=== audit: this round's key lines (rt5) ===")
r = subprocess.run(["wsl", "-u", "root", "--", "bash", "-c",
                    "dmesg | grep 'apparmor=\"DENIED\"' | grep -E 'rt5|dash|java_pid' | tail -12"],
                   capture_output=True, text=True)
print(r.stdout + r.stderr)
