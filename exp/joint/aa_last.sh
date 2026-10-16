#!/bin/sh
# Joint-round helper: print the highest audit serial per profile (read-only watermark).
for p in aa-jboss aa-shiro aa-ofbiz aa-geoserver; do
  ser=$(dmesg | grep 'apparmor="DENIED"' | grep "$p" | awk '{
    if (match($0, /:[0-9]+\)/)) {
      v = substr($0, RSTART+1, RLENGTH-2) + 0
      if (v > m) m = v
    }
  } END { print m+0 }')
  printf '%s %s\n' "$p" "$ser"
done
