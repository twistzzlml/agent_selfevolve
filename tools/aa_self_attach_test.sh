#!/bin/sh
# AppArmor self-attach smoke test v2: kernel expects "exec <profile>" directive
echo "exec aa-smoke-test" > /proc/self/attr/apparmor/exec
exec sh -c '
echo LABEL=$(cat /proc/self/attr/current)
touch /tmp/denied_test && echo TMP_WRITE_OK || echo TMP_WRITE_DENIED
touch /var/tmp/allowed_test && echo VAR_WRITE_OK || echo VAR_WRITE_DENIED
'
