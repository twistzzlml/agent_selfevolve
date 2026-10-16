#!/bin/sh
# Load/reload the four target AppArmor profiles into the (shared WSL2) kernel.
# Usage: aa_load.sh [complain|enforce]   (default enforce)
# Must run as root in the Ubuntu WSL distro (profiles are kernel-global).
MODE=${1:-enforce}
BASE=/mnt/d/Amywork/AgentSelf_Evolve/experiment/multi-round-lab/defense/apparmor

[ -d /sys/kernel/security ] || mkdir -p /sys/kernel/security
mountpoint -q /sys/kernel/security 2>/dev/null || mount -t securityfs securityfs /sys/kernel/security

for P in aa-jboss aa-shiro aa-ofbiz aa-geoserver; do
  if [ "$MODE" = "complain" ]; then
    sed 's/mediate_deleted)/mediate_deleted,complain)/' "$BASE/$P" > "/tmp/$P.prof"
  else
    cp "$BASE/$P" "/tmp/$P.prof"
  fi
  if apparmor_parser -r "/tmp/$P.prof" 2>/tmp/parser.err; then
    echo "loaded $P ($MODE)"
  else
    echo "FAILED $P:"; cat /tmp/parser.err
  fi
done
echo "---"
aa-status | sed -n '1,14p'
