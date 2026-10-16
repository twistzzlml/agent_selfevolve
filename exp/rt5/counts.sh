#!/bin/bash
for p in aa-jboss aa-shiro aa-ofbiz aa-geoserver; do
  printf "%s: " "$p"
  dmesg | grep 'apparmor="DENIED"' | grep -c "profile=\"$p\""
done
printf "total: "
dmesg | grep -c 'apparmor="DENIED"'
