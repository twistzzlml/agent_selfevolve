#!/bin/sh
# Joint-round helper: print AppArmor DENIED audit lines for a profile with audit serial > $1.
# Usage: aa_new.sh <profile> <last_serial>
P=$1
S=${2:-0}
dmesg | grep 'apparmor="DENIED"' | grep "$P" | awk -v s="$S" '
{
  # extract serial from audit(1792091405.580:67420)
  if (match($0, /:[0-9]+\)/)) {
    ser = substr($0, RSTART+1, RLENGTH-2) + 0
    if (ser > s) print $0
  }
}'
