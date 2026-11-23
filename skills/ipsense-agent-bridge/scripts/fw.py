#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fw · ipsense 处置通道（1.1.27 起；1.1.29 行为线 / 通道收敛）：在应用之外，通过 SSH + sudo 在 NAS 上封禁 / 解封 IP。

与 mh 分工：
  mh  —— 提交单唯一手眼，只改 orders.json 的状态 / 总结；
  fw  —— 处置通道，不读 orders.json、不调 /api/mh/write，只管 NAS 上的封禁规则。

通道收敛（用户 2026-11-23 拍板：「不走 iptables 冗余加固了，走飞牛设置防火墙」）：
  * 处置**只走飞牛原生防火墙** /usr/trim/etc/fw.conf，不再下发任何 iptables / nft 规则；
    真机实测 11-22 23:02 重启后 iptables 规则全部消失，而 fw.conf 的 deny 规则
    由 security_service 重新加载进 eBPF、UI「防火墙 → 入站规则」里也一直可见，
    证明 iptables 是易失且多余的，收敛为单通道更可靠、更贴合用户诉求。
  * 永久封禁（不带 --ttl）= 写 fw.conf 的 allow:false 入站拒绝规则 + reload
    security_service；规则落盘、重启 NAS 后服务自行重建，UI 可见、可审计。
  * 临时封禁（--ttl N>0）也写同一条 fw.conf 规则，另下发一个自包含后台脚本：
    到期用 python3 删该 IP 的原生 deny 规则、重载服务、清 rules.json 登记、自删脚本；
    若 NAS 在 TTL 内重启导致后台脚本丢失，由 fw status/list 按 rules.json 的
    expires 惰性补删（单通道兜底），避免临时规则变成事实永久。
  * fw unban 只清原生防火墙规则、TTL 脚本与 rules.json，固定输出
    rollback: fw unban <ip>。

后端能力（只读探测）：
  1. fnOS 原生防火墙 /usr/trim/etc/fw.conf（唯一处置通道，持久化 + UI 可见）；
  2. security_service（把 fw.conf 加载进 eBPF，systemctl restart 触发即时生效）；
  3. python3（临时封禁到期脚本自包含改 fw.conf 所需，真机实测 3.11.2 可用）。
  iptables 与 ipblocker（防护 → 封禁名单）均**不参与处置**：前者重启即失，
  后者只是应用层登录防护、拦不到普通 HTTP 访问。

规则用 fw.conf 的 memo 前缀标记，只清理自己下发的 allow:false 规则，不碰用户其它规则。
支持 SSH 密钥与账号密码两种认证，共用 ~/.ipsense/bridge.json 的连接参数；
sudo 密码从环境变量 / 凭据文件读，绝不写入配置、日志、输出。

依赖：非 local 模式一律用 paramiko 建立 SSH + sudo 通道，因此 fw 必需 paramiko
（pip install paramiko），即便 auth=key 也一样；只有 mode=local 例外。
这与 mh 的 key 模式（走系统 ssh -i、不依赖 paramiko）不同，安装时不要漏装。
完整安装步骤见 SKILL.md 的「0.5 安装与首次配置」。
"""
import argparse
import base64
import datetime
import io
import json
import os
import shlex
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mh  # noqa: E402  复用 load_cfg / CRED_FILE / emit

STATE_DIR = "/vol1/@appdata/ipsense/fw"
STATE = STATE_DIR + "/rules.json"
DEFAULT_TTL = 0                       # 0 = 永久封禁，不自动解封
FW_CONF = "/usr/trim/etc/fw.conf"
FW_BACKUP = STATE_DIR + "/fw.conf.bak"
FW_SERVICE = "security_service"
NATIVE_MEMO = "ips:"                  # fw.conf 的 memo 上限 20 字符，用短前缀
CHANNEL = "native"                    # 唯一处置通道：飞牛原生防火墙
IPB_SOCK = "/run/trim_ipblocker.sock"  # 仅只读探测，不参与处置


# ---------------- 连接 ----------------
def _password():
    p = os.environ.get("IPSENSE_SSH_PASSWORD") or os.environ.get("OESP_PASS")
    if p:
        return p
    if os.path.isfile(mh.CRED_FILE):
        for line in io.open(mh.CRED_FILE, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                if k.strip() == "OESP_PASS":
                    return v.strip()
    return ""


def _connect():
    """返回 (ssh_or_None, cfg, pwd)。local 模式返回 None，直接本机执行。"""
    cfg = mh.load_cfg()
    if cfg.get("mode") == "local":
        return None, cfg, _password()
    try:
        import paramiko
    except ImportError:
        sys.stderr.write("fw 需要 paramiko：pip install paramiko\n")
        sys.exit(3)
    key = cfg.get("key", "")
    kwargs = dict(hostname=cfg.get("host", ""), port=int(cfg.get("port", 22) or 22),
                  username=cfg.get("user", "root"), timeout=15,
                  allow_agent=False, look_for_keys=False)
    pwd = _password()
    if key and os.path.isfile(key):
        kwargs["key_filename"] = key
    if pwd:
        kwargs["password"] = pwd
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(**kwargs)
    return ssh, cfg, pwd


def _run(ssh, cfg, pwd, cmd, sudo=True, timeout=40):
    if ssh is None:                       # agent 就装在 NAS 上
        r = subprocess.run(["bash", "-c", cmd], capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    if sudo:
        if pwd:
            stdin, o, e = ssh.exec_command(
                "sudo -S bash -c " + shlex.quote(cmd), timeout=timeout)
            stdin.write(pwd + "\n")
            stdin.flush()
        else:
            _, o, e = ssh.exec_command(
                "sudo -n bash -c " + shlex.quote(cmd), timeout=timeout)
    else:
        _, o, e = ssh.exec_command(cmd, timeout=timeout)
    out = o.read().decode("utf-8", "replace")
    err = e.read().decode("utf-8", "replace")
    return o.channel.recv_exit_status(), out, err


# ---------------- 规则状态（落在 NAS）----------------
def _load_state(ssh, cfg, pwd):
    rc, out, err = _run(ssh, cfg, pwd, "cat %s 2>/dev/null || echo '{}'" % STATE)
    try:
        d = json.loads(out.strip() or "{}")
    except (ValueError, TypeError):
        d = {}
    d.setdefault("version", 1)
    d.setdefault("rules", [])
    return d


def _save_state(ssh, cfg, pwd, st):
    blob = base64.b64encode(json.dumps(st, ensure_ascii=False).encode("utf-8")).decode("ascii")
    cmd = ("mkdir -p %s && echo %s | base64 -d > %s && chmod 644 %s" %
           (STATE_DIR, blob, STATE, STATE))
    rc, out, err = _run(ssh, cfg, pwd, cmd)
    return rc == 0


# ---------------- fnOS 原生防火墙 fw.conf（唯一处置通道）----------------
def _native_read(ssh, cfg, pwd):
    """返回 (raw, data)。data 为 None 表示配置不存在 / 不可解析。"""
    rc, out, err = _run(ssh, cfg, pwd, "cat %s 2>/dev/null" % FW_CONF, sudo=True)
    if rc != 0 or not (out or "").strip():
        return "", None
    try:
        return out, json.loads(out)
    except (ValueError, TypeError):
        return out, None


def _native_profile(data):
    return data[0] if isinstance(data, list) else data


def _native_memo(ip):
    return "%s%s" % (NATIVE_MEMO, ip)


def _native_is_ours(r, ip=None):
    """只认本工具下发的 allow:false 规则，绝不碰用户其它规则。"""
    if not isinstance(r, dict):
        return False
    memo = r.get("memo") or ""
    if not memo.startswith(NATIVE_MEMO) or r.get("allow") is not False:
        return False
    if ip is not None:
        return (r.get("ips") or {}).get("ip") == ip
    return True


def _native_deny(ip, priority):
    """照抄 UI 生成的规则结构：入站 / 全端口 / 指定 IP / 拒绝。"""
    return {
        "ifname": "ALL",
        "flowdir": 1,
        "ports": {"type": 1, "ranges": {"ports": [],
                  "range": {"from": 1, "to": 65535}, "process": []}},
        "pro": 0,
        "ips": {"type": 0, "ip": ip, "cidr": {"net": "", "len": 0},
                "country": ""},
        "allow": False,
        "priority": priority,
        "memo": _native_memo(ip),
        "enable": True,
    }


def _native_write(ssh, cfg, pwd, data):
    """同目录临时文件 + mv 原子替换，保留 644 root:root；首次写入留一份原始备份。"""
    blob = base64.b64encode(
        json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    tmp = "/usr/trim/etc/.fw.conf.ipsense.tmp"
    cmd = ("mkdir -p %s && [ -f %s ] || cp -a %s %s 2>/dev/null; "
           "echo %s | base64 -d > %s && chown root:root %s && chmod 644 %s && "
           "mv -f %s %s && echo NATIVE_WROTE" %
           (STATE_DIR, FW_BACKUP, FW_CONF, FW_BACKUP,
            blob, tmp, tmp, tmp, tmp, FW_CONF))
    rc, out, err = _run(ssh, cfg, pwd, cmd, sudo=True)
    return rc == 0, (out + err).strip()[:200]


def _native_add(ssh, cfg, pwd, ip):
    raw, data = _native_read(ssh, cfg, pwd)
    if data is None:
        return False, "fw.conf 不存在或不可解析，单通道无兜底，无法封禁"
    prof = _native_profile(data)
    rules = prof.setdefault("rules", [])
    rules[:] = [r for r in rules if not _native_is_ours(r, ip)]      # 幂等
    maxp = max([r.get("priority", 0) for r in rules] or [0])
    rules.append(_native_deny(ip, maxp + 1))
    ok, msg = _native_write(ssh, cfg, pwd, data)
    return ok, ("原生防火墙已登记 deny 规则 priority=%d（重启后由 %s 重建）" %
                (maxp + 1, FW_SERVICE)) if ok else ("原生写入失败：" + msg)


def _native_del(ssh, cfg, pwd, ip):
    raw, data = _native_read(ssh, cfg, pwd)
    if data is None:
        return False, False, "fw.conf 不存在或不可解析"
    prof = _native_profile(data)
    rules = prof.setdefault("rules", [])
    before = len(rules)
    rules[:] = [r for r in rules if not _native_is_ours(r, ip)]
    changed = len(rules) != before
    if not changed:
        return True, False, "原生防火墙无本工具规则"
    ok, msg = _native_write(ssh, cfg, pwd, data)
    return ok, changed, ("已删除 %d 条原生 deny 规则" % (before - len(rules))) if ok else msg


def _native_list(ssh, cfg, pwd):
    raw, data = _native_read(ssh, cfg, pwd)
    if data is None:
        return []
    return [((r.get("ips") or {}).get("ip"), r.get("priority"))
            for r in _native_profile(data).get("rules", []) if _native_is_ours(r)]


def _native_reload(ssh, cfg, pwd):
    """触发 security_service 重新加载 fw.conf 到 BPF（即时生效）。

    单通道下这是唯一即时生效路径：即使本次 reload 失败，fw.conf 已落盘，
    重启 NAS 后服务会自行重建规则；失败信息如实回传，不静默吞掉。
    """
    try:
        rc, out, err = _run(ssh, cfg, pwd,
                            "systemctl restart %s && echo RELOADED" % FW_SERVICE,
                            sudo=True, timeout=25)
        return rc == 0, (out + err).strip()[:160]
    except Exception as ex:
        return False, repr(ex)


# ---------------- 临时封禁到期脚本（自包含、只操作原生防火墙）----------------
def _ttl_cmd(ip, ttl):
    """临时封禁到期自动解封（单通道版）：自包含脚本删 fw.conf 原生 deny 规则、
    reload security_service、清 rules.json 登记、最后自删。

    用 setsid -f + 全 fd 重定向 + 子 shell 后台，避免后台进程持有 SSH channel
    的 stdout 导致 paramiko o.read() 一直不 EOF（1.1.28 交付后真机实测踩过）。
    脚本内嵌一段 python3（真机实测 3.11.2 可用）改 fw.conf，不依赖 agent 本机的 fw.py。
    """
    script = "%s/unban_%s.sh" % (STATE_DIR, ip.replace(".", "_"))
    tmp = "/usr/trim/etc/.fw.conf.ipsense.ttl.tmp"
    py = (
        "import json, os\n"
        "FW = %r\nST = %r\nIP = %r\nMEMO = %r\nTMP = %r\n" %
        (FW_CONF, STATE, ip, _native_memo(ip), tmp) +
        "try:\n"
        "    d = json.load(open(FW))\n"
        "    p = d[0] if isinstance(d, list) else d\n"
        "    p['rules'] = [r for r in p.get('rules', [])\n"
        "                  if not (isinstance(r, dict) and r.get('memo') == MEMO\n"
        "                          and r.get('allow') is False)]\n"
        "    with open(TMP, 'w') as f:\n"
        "        f.write(json.dumps(d, separators=(',', ':')))\n"
        "    os.chown(TMP, 0, 0)\n"
        "    os.chmod(TMP, 0o644)\n"
        "    os.replace(TMP, FW)\n"
        "except Exception:\n"
        "    pass\n"
        "try:\n"
        "    s = json.load(open(ST))\n"
        "    s['rules'] = [r for r in s.get('rules', []) if r.get('ip') != IP]\n"
        "    with open(ST, 'w') as f:\n"
        "        f.write(json.dumps(s, ensure_ascii=False))\n"
        "except Exception:\n"
        "    pass\n"
    )
    body = ("#!/bin/sh\nsleep %d\npython3 - <<'PYFW'\n%sPYFW\n"
            "systemctl restart %s >/dev/null 2>&1 || true\nrm -f %s\nexit 0\n" %
            (ttl, py, FW_SERVICE, script))
    b = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return ("echo %s | base64 -d > %s && chmod 700 %s && "
            "( setsid -f %s </dev/null >/dev/null 2>&1 & ) ; echo TTL_SCHEDULED"
            % (b, script, script, script))


def _prune_expired(ssh, cfg, pwd, st, dry=False):
    """惰性补删：TTL 到期（或后台脚本因 NAS 重启丢失）时清原生 deny 规则。"""
    now = time.time()
    changed = False
    need_reload = False
    keep = []
    for r in st["rules"]:
        if r.get("expires", 0) and r["expires"] <= now:
            if not dry:
                ok, ch, _ = _native_del(ssh, cfg, pwd, r["ip"])
                if ok and ch:
                    need_reload = True
                _run(ssh, cfg, pwd,
                     "rm -f %s/unban_%s.sh" % (STATE_DIR, r["ip"].replace(".", "_")),
                     sudo=True)
            changed = True
        else:
            keep.append(r)
    st["rules"] = keep
    if need_reload and not dry:
        _native_reload(ssh, cfg, pwd)
    return changed


# ---------------- 子命令 ----------------
def cmd_status(a):
    ssh, cfg, pwd = _connect()
    out = {"ok": True, "mode": cfg.get("mode", "ssh"),
           "auth": cfg.get("auth", "key"), "channel": CHANNEL,
           "backends": {}, "rules": []}
    # 后端探测（只读）：唯一通道 fw.conf + security_service + python3
    rc, o, e = _run(ssh, cfg, pwd,
                    "ls -l %s 2>/dev/null; echo ---; "
                    "systemctl is-active %s 2>/dev/null; echo ---; "
                    "command -v python3; echo ---; ls -l %s 2>/dev/null" %
                    (FW_CONF, FW_SERVICE, IPB_SOCK))
    out["backends"]["fw_conf"] = FW_CONF in o
    out["backends"]["security_service"] = "active" in o
    out["backends"]["python3"] = "python3" in o
    out["backends"]["ipblocker_present"] = IPB_SOCK in o
    out["note"] = ("处置只走 fw.conf；iptables 重启即失、ipblocker 只管登录防护，"
                   "均不参与封禁（故「防护 → 封禁名单」为空是正常的）")
    st = _load_state(ssh, cfg, pwd)
    _prune_expired(ssh, cfg, pwd, st)
    _save_state(ssh, cfg, pwd, st)
    out["active_rules"] = _native_list(ssh, cfg, pwd)
    out["rules"] = st["rules"]
    out["native_rules"] = _native_list(ssh, cfg, pwd)
    out["native_persistent"] = True
    if ssh:
        ssh.close()
    return mh.emit(out)


def cmd_list(a):
    ssh, cfg, pwd = _connect()
    st = _load_state(ssh, cfg, pwd)
    changed = _prune_expired(ssh, cfg, pwd, st)
    if changed:
        _save_state(ssh, cfg, pwd, st)
    out = {"ok": True, "channel": CHANNEL, "rules": st["rules"],
           "native_rules": _native_list(ssh, cfg, pwd),
           "now": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
    if ssh:
        ssh.close()
    return mh.emit(out)


def cmd_ban(a):
    ip = a.ip.strip()
    if not mh_ip_ok(ip):
        sys.stderr.write("非法 IP：%s\n" % ip)
        return 2
    ttl = int(a.ttl or 0)
    if ttl < 0:
        sys.stderr.write("--ttl 必须为非负整数（0 = 永久封禁）\n")
        return 2
    permanent = (ttl == 0)
    if a.dry_run:
        would = ["写入 %s 的 deny 规则（memo=%s，入站/全端口/拒绝）并原子替换" %
                 (FW_CONF, _native_memo(ip)),
                 "systemctl restart %s 立即加载进 eBPF" % FW_SERVICE]
        if ttl > 0:
            would.append("下发自包含 TTL 脚本（%ds 后删原生规则 + reload + 清登记 + 自删）" % ttl)
        return mh.emit({"ok": True, "dry_run": True, "channel": CHANNEL,
                        "ip": ip, "ttl": ttl, "permanent": permanent,
                        "reason": a.reason or "", "would_run": would,
                        "native_plan": ("飞牛原生防火墙单通道：永久规则落盘、重启保持、UI 可见"
                                        if permanent else
                                        "同样写原生规则，另加 TTL 到期自动解封，重启靠 rules.json 惰性兜底")})
    ssh, cfg, pwd = _connect()

    # ① 唯一处置通道：写 fw.conf 的 deny 规则（幂等，只认自己的 memo）
    native_ok, native_note = _native_add(ssh, cfg, pwd, ip)
    if not native_ok:
        sys.stderr.write("封禁失败（原生防火墙）：%s\n" % native_note)
        if ssh:
            ssh.close()
        return 1

    # ② reload security_service：让规则即时进 eBPF（单通道唯一即时生效路径）
    r_ok, r_msg = _native_reload(ssh, cfg, pwd)
    native_reload = r_msg if r_ok else (
        "reload 失败（规则已落盘，重启 NAS 后服务会自行加载）：" + r_msg)

    # ③ 临时封禁：下发自包含到期脚本（只删原生规则，不碰 iptables）
    ttl_note = ""
    if ttl > 0:
        try:
            _run(ssh, cfg, pwd, _ttl_cmd(ip, ttl), sudo=True, timeout=12)
        except Exception:
            ttl_note = ("TTL 后台任务下发异常（不影响封禁，由 rules.json 的 expires + "
                        "fw status/list 惰性补删兜底）")

    # ④ 状态登记
    st = _load_state(ssh, cfg, pwd)
    st["rules"] = [r for r in st["rules"] if r.get("ip") != ip]
    st["rules"].append({
        "ip": ip, "ttl": ttl, "permanent": permanent,
        "reason": a.reason or "", "channel": CHANNEL,
        "created": int(time.time()),
        "expires": 0 if permanent else int(time.time()) + ttl,
        "created_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "native": True,
    })
    _save_state(ssh, cfg, pwd, st)
    if ssh:
        ssh.close()
    return mh.emit({"ok": True, "channel": CHANNEL, "ip": ip, "ttl": ttl,
                    "permanent": permanent, "reason": a.reason or "",
                    "native": True, "native_note": native_note,
                    "native_reload": native_reload,
                    "rollback": "fw unban %s" % ip, "ttl_note": ttl_note})


def cmd_unban(a):
    ip = a.ip.strip()
    if not mh_ip_ok(ip):
        sys.stderr.write("非法 IP：%s\n" % ip)
        return 2
    if a.dry_run:
        return mh.emit({"ok": True, "dry_run": True, "channel": CHANNEL, "ip": ip,
                        "would_run": ["删除 %s 中 memo=%s 的 deny 规则并 reload %s" %
                                      (FW_CONF, _native_memo(ip), FW_SERVICE),
                                      "清理 TTL 脚本与 rules.json 登记"]})
    ssh, cfg, pwd = _connect()
    n_ok, n_changed, n_note = _native_del(ssh, cfg, pwd, ip)
    n_reload = "skipped (no native rule changed)"
    if n_changed and n_ok:
        r_ok, r_msg = _native_reload(ssh, cfg, pwd)
        n_reload = r_msg if r_ok else ("reload 失败：" + r_msg)
    # 清掉可能残留的 TTL 脚本
    _run(ssh, cfg, pwd,
         "rm -f %s/unban_%s.sh" % (STATE_DIR, ip.replace(".", "_")), sudo=True)
    st = _load_state(ssh, cfg, pwd)
    st["rules"] = [r for r in st["rules"] if r.get("ip") != ip]
    _save_state(ssh, cfg, pwd, st)
    if ssh:
        ssh.close()
    return mh.emit({"ok": n_ok, "channel": CHANNEL, "ip": ip,
                    "native": bool(n_changed and n_ok),
                    "native_note": n_note, "native_reload": n_reload})


def mh_ip_ok(ip):
    import socket
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except (OSError, ValueError):
        return False


def main():
    ap = argparse.ArgumentParser(
        prog="fw", description="ipsense 处置通道：在 NAS 上封禁 / 解封 IP（只走飞牛原生防火墙，mh 只管提交单）")
    sub = ap.add_subparsers(dest="cmd")
    q = sub.add_parser("status", help="探测后端与当前原生防火墙规则")
    q.set_defaults(fn=cmd_status)
    q = sub.add_parser("list", help="列出本工具下发的原生防火墙规则")
    q.set_defaults(fn=cmd_list)
    q = sub.add_parser("ban", help="封禁 IP（不带 --ttl 即永久封禁、重启保持，只写飞牛原生防火墙）")
    q.add_argument("ip"); q.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    q.add_argument("--reason", default=""); q.add_argument("--dry-run", action="store_true")
    q.set_defaults(fn=cmd_ban)
    q = sub.add_parser("unban", help="解封 IP（清飞牛原生防火墙 deny 规则）")
    q.add_argument("ip"); q.add_argument("--dry-run", action="store_true")
    q.set_defaults(fn=cmd_unban)
    a = ap.parse_args()
    if not getattr(a, "fn", None):
        ap.print_help()
        return 0
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
