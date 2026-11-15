# -*- coding: utf-8 -*-
"""把 FPK 上传到 OESP 并安装 / 验证（凭据只从本地 secrets 文件读取）。"""
import os
import sys
import shlex
import argparse
import paramiko

CRED = os.path.expanduser("~/.workbuddy/secrets/oesp_cred.txt")


def load_cred():
    d = {}
    with open(CRED, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
    return d


def run(ssh, cmd, pwd, sudo=False, timeout=300):
    if sudo:
        cmd = "echo %s | sudo -S -p '' bash -c %s" % (shlex.quote(pwd), shlex.quote(cmd))
    _, out, err = ssh.exec_command(cmd, timeout=timeout)
    o = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    rc = out.channel.recv_exit_status()
    return rc, o.strip(), e.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fpk", default="")
    ap.add_argument("--host", default=os.environ.get("OESP_HOST", "192.168.3.5"))
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    a = ap.parse_args()
    cred = load_cred()
    user, pwd = cred["OESP_USER"], cred["OESP_PASS"]
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(a.host, port=22, username=user, password=pwd, timeout=20,
                allow_agent=False, look_for_keys=False)
    print("已连接 %s" % a.host)

    remote = "/tmp/" + (os.path.basename(a.fpk) if a.fpk else "ipsense.fpk")
    if a.fpk and not a.verify_only:
        sftp = ssh.open_sftp()
        sz = os.path.getsize(a.fpk)
        print("上传 %s (%.2f MB) -> %s" % (a.fpk, sz / 1048576.0, remote))
        sftp.put(a.fpk, remote)
        sftp.close()
        rc, o, e = run(ssh, "ls -l %s; md5sum %s" % (remote, remote), pwd)
        print(o or e)

    if a.uninstall:
        rc, o, e = run(ssh, "appcenter-cli uninstall ipsense", pwd, sudo=True)
        print("卸载 rc=%s\n%s\n%s" % (rc, o, e))
        ssh.close()
        return

    if not a.verify_only:
        for c in ("appcenter-cli manual-install enable",
                  "appcenter-cli install-fpk %s -v 1" % remote,
                  "appcenter-cli status ipsense"):
            rc, o, e = run(ssh, c, pwd, sudo=True, timeout=420)
            print("\n$ %s\nrc=%s\n%s%s" % (c, rc, o[-1500:], "\n[stderr] " + e if e else ""))

    print("\n===== 验证 =====")
    checks = [
        ("socket", "ls -l /vol1/@appcenter/ipsense/app.sock 2>&1"),
        ("进程", "ps -ef | grep '[i]psense/server/gateway.py' | head -3"),
        ("健康检查(直连)", "curl -s --max-time 5 --unix-socket /vol1/@appcenter/ipsense/app.sock http://localhost/api/health"),
        ("健康检查(带前缀)", "curl -s --max-time 5 --unix-socket /vol1/@appcenter/ipsense/app.sock 'http://localhost/app/ipsense/api/health'"),
        ("首页字节", "curl -s --max-time 8 --unix-socket /vol1/@appcenter/ipsense/app.sock http://localhost/ | wc -c"),
        ("首页标题", "curl -s --max-time 8 --unix-socket /vol1/@appcenter/ipsense/app.sock http://localhost/ | grep -o '<title>[^<]*</title>' | head -1"),
        ("统计概览", "curl -s --max-time 8 --unix-socket /vol1/@appcenter/ipsense/app.sock 'http://localhost/api/status?rng=24h' | head -c 500"),
        ("数据源", "curl -s --max-time 8 --unix-socket /vol1/@appcenter/ipsense/app.sock http://localhost/api/sources | head -c 600"),
        ("应用日志", "tail -25 /var/log/apps/ipsense.log 2>&1"),
        ("应用列表", "appcenter-cli list 2>/dev/null | grep -i ipsense | head -3"),
    ]
    for name, c in checks:
        rc, o, e = run(ssh, c, pwd, sudo=name in ("应用列表",), timeout=60)
        print("\n--- %s (rc=%s) ---\n%s%s" % (name, rc, o[:1200], ("\n[err] " + e[:300]) if e else ""))
    ssh.close()


if __name__ == "__main__":
    main()
