#!/bin/sh
# Joint-round helper: count AppArmor DENIED audit lines per profile (read-only).
for p in aa-jboss aa-shiro aa-ofbiz aa-geoserver; do
  printf '%s ' "$p"
  dmesg | grep 'apparmor="DENIED"' | grep -c "$p"
done
