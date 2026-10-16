# -*- coding: utf-8 -*-
"""Extract JBoss's own commons-collections 3.2 jar for gen-time compilation."""
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
out = os.path.join(HERE, "cc32_jboss.jar")
r = subprocess.run(["docker", "cp",
                    "multi-round-lab-jboss-1:/jboss-6.1.0.Final/client/commons-collections.jar",
                    out], capture_output=True, text=True)
print("rc", r.returncode, r.stdout, r.stderr.strip()[:300])
print("size", os.path.getsize(out) if os.path.exists(out) else "MISSING")
