# -*- coding: utf-8 -*-
"""Joint-round helper: grep infra container log for callback paths since N minutes (read-only)."""
import re
import subprocess
import sys

mins = sys.argv[1] if len(sys.argv) > 1 else "10m"
pat = sys.argv[2] if len(sys.argv) > 2 else "/rt"
r = subprocess.run(["docker", "logs", "multi-round-lab-infra-1", "--since", mins],
                   capture_output=True, text=True, errors="replace")
for line in (r.stdout + r.stderr).splitlines():
    if pat in line:
        print(line.strip()[:200])
