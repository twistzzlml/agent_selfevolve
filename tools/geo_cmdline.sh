#!/bin/sh
# 打印容器内所有进程的命令行（截断 260 字符）
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  c=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
  echo "$p | $(echo $c | cut -c1-260)"
done
