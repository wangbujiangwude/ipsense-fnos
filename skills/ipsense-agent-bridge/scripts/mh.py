#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mh · ipsense 提交单「工程状态」的唯一读写接口（agent 侧，短命进程）。

分工（1.1.27）：
  * SKILL.md 是「规矩/大脑」：红线、流程、争议判定、证据位置、防呆约束；
  * 本 CLI 是提交单唯一的「手和眼」：对工程状态的一切感知（读）与修改（写）
    都通过 mh 命令完成，agent 不直接读文件、不直接拼接口、不在浏览器里长驻；
  * fw CLI 是「处置通道」：封禁 / 解封 IP，在应用之外通过 SSH + sudo 落到 NAS。

四条硬约束：
  1) 短命进程：每次调用一个进程，跑完即退；状态全部落在 NAS 的 orders.json。
  2) 读写分层：state/read/show/prompt/path/ip/check 只发 GET；
     prepare/commit/discard/mark-done/restore 只发 POST /api/mh/write。
  3) 只改提交单：写命令只改 orders.json 里的提交单状态与总结，
     明确不碰用户页面（ui/*）、配置、日志，也不碰任何防火墙 / 系统设施。
     key revoke 是独立的管理接口，只动密钥授权，不改提交单状态。
  4) 乐观锁防串台：读时拿到的 receipt 绑定 rev；提交时服务端复核 rev。

零第三方依赖（password 模式需要可选 paramiko）：Python 3 标准库 + curl / ssh。
setup 是唯一例外：一次性引导在 NAS 上建 SSH 授权，需要 paramiko（SSH 模式）。
连通方式：
  local    —— agent 就装在 NAS 上，直读本机 Unix socket，无需 SSH；
  key      —— SSH 密钥免密（默认，走系统 ssh -i）；
  password —— SSH 账号密码（走 paramiko，密码只从环境变量 / 凭据文件读，不落配置）。
"""
import argparse
import base64
import datetime
import getpass
import io
import json
import os
import platform
import secrets
import shlex
import shutil
import subprocess
import sys
import time

DEFAULT_SOCKET = "/vol1/@appcenter/ipsense/app.sock"
DEFAULT_ORDERS = "/vol1/@appdata/ipsense/orders.json"
CFG_PATH = os.path.expanduser("~/.ipsense/bridge.json")
CRED_FILE = os.path.expanduser("~/.workbuddy/secrets/oesp_cred.txt")

# 提交单写命令只到 /api/mh/write，payload 里 action 必须落在白名单里。
WRITE_ACTIONS = ("prepare", "commit", "discard")
KEYAUTH_REVOKE = "/api/keyauth/revoke"
TABS = ("pending", "done", "revert", "all")

# ---- mh setup：一次性引导建密钥授权（与 keyauth.py 的数据结构严格对齐）----
KEYDIR = "/vol1/@appdata/ipsense/keys"          # revoke 白名单目录，路径必须落在这里
KEYAUTH_JSON = "/vol1/@appdata/ipsense/keyauth.json"
MARK = "ipsense-agent-bridge"                    # authorized_keys 行尾标记
LOCAL_KEY = os.path.expanduser("~/.ipsense/agent_ed25519")
SETUP_STEPS = 8


# ---------------- 配置与密码 ----------------
def load_cfg():
    if not os.path.isfile(CFG_PATH):
        sys.stderr.write(
            "尚未配置。先运行：mh init --mode ssh --host <NAS地址>\n"
            "（agent 装在 NAS 上可直接 mh init，自动识别 local 模式）\n")
        sys.exit(2)
    with io.open(CFG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_cfg(cfg):
    os.makedirs(os.path.dirname(CFG_PATH), exist_ok=True)
    with io.open(CFG_PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(CFG_PATH, 0o600)
    except Exception:
        pass


def detect_local():
    return os.path.exists(DEFAULT_SOCKET)


def load_password(cfg=None):
    """密码只从环境变量 / 凭据文件读，绝不写进 bridge.json、日志或输出。"""
    p = os.environ.get("IPSENSE_SSH_PASSWORD") or os.environ.get("OESP_PASS")
    if p:
        return p
    if os.path.isfile(CRED_FILE):
        for line in io.open(CRED_FILE, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                if k.strip() == "OESP_PASS":
                    return v.strip()
    sys.stderr.write(
        "password 模式需要密码：设 IPSENSE_SSH_PASSWORD 环境变量，"
        "或在 %s 里写 OESP_PASS=...\n" % CRED_FILE)
    sys.exit(3)


# ---------------- 远程执行（供 fw 复用）----------------
def run_remote(cfg, cmd, sudo=False, timeout=40):
    """在 NAS 上执行一条 shell 命令，返回 (rc, stdout, stderr)。

    local    本机直跑；key    系统 ssh -i；password  paramiko + sudo -S。
    """
    mode = cfg.get("mode", "ssh")
    auth = cfg.get("auth", "key")
    host = cfg.get("host", "")
    user = cfg.get("user", "root")
    port = int(cfg.get("port", 22) or 22)

    if mode == "local":
        full = cmd
        r = subprocess.run(["bash", "-c", full], capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    if auth == "password":
        try:
            import paramiko
        except ImportError:
            sys.stderr.write("password 模式需要 paramiko：pip install paramiko\n")
            sys.exit(3)
        pwd = load_password(cfg)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=user, password=pwd, timeout=15,
                    allow_agent=False, look_for_keys=False)
        if sudo:
            stdin, o, e = ssh.exec_command(
                "sudo -S bash -c " + shlex.quote(cmd), timeout=timeout)
            stdin.write(pwd + "\n")
            stdin.flush()
        else:
            _, o, e = ssh.exec_command(cmd, timeout=timeout)
        out = o.read().decode("utf-8", "replace")
        err = e.read().decode("utf-8", "replace")
        rc = o.channel.recv_exit_status()
        ssh.close()
        return rc, out, err

    # 默认密钥通道
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=accept-new", "-p", str(port)]
    if cfg.get("key"):
        args += ["-i", cfg["key"]]
    args += ["%s@%s" % (user, host),
             " ".join(shlex.quote(a) for a in ["bash", "-c", cmd])]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        sys.stderr.write("缺少 ssh 命令；可改用 --auth password 走 paramiko\n")
        sys.exit(3)
    except subprocess.TimeoutExpired:
        sys.stderr.write("连接超时，请检查 SSH 地址 / 密钥 / 应用是否在运行\n")
        sys.exit(3)
    return r.returncode, r.stdout or "", r.stderr or ""


# ---------------- HTTP（提交单接口）----------------
def _curl_args(cfg, api_path, method="GET", payload=None):
    url = "http://localhost" + api_path
    args = ["curl", "-sS", "--max-time", "10", "--unix-socket",
            cfg.get("socket", DEFAULT_SOCKET)]
    if method == "POST":
        assert api_path in ("/api/mh/write", KEYAUTH_REVOKE), "写接口不在白名单内"
        if api_path == "/api/mh/write":
            assert (payload or {}).get("action") in WRITE_ACTIONS, "未知写动作"
        args += ["-X", "POST", "-H", "Content-Type: application/json",
                 "-d", json.dumps(payload or {}, ensure_ascii=False)]
    args += [url]
    return args


def call(cfg, api_path, method="GET", payload=None, timeout=30):
    """GET 只读 / POST 只写白名单接口。"""
    args = _curl_args(cfg, api_path, method, payload)
    mode = cfg.get("mode", "ssh")
    auth = cfg.get("auth", "key")
    if mode == "local":
        cmd = args
    elif auth == "password":
        cmd = ["sshpass-placeholder"]      # 走 run_remote 分支
    else:
        remote = " ".join(shlex.quote(a) for a in args)
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "StrictHostKeyChecking=accept-new",
               "-p", str(cfg.get("port", 22))]
        if cfg.get("key"):
            cmd += ["-i", cfg["key"]]
        cmd += ["%s@%s" % (cfg.get("user", "root"), cfg.get("host", "")), remote]
    if auth == "password" and mode != "local":
        rc, out, err = run_remote(cfg, " ".join(shlex.quote(a) for a in args))
        return _Result(rc, out, err)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return _Result(r.returncode, r.stdout or "", r.stderr or "")
    except FileNotFoundError:
        sys.stderr.write("缺少命令：%s\n" % cmd[0])
        sys.exit(3)
    except subprocess.TimeoutExpired:
        sys.stderr.write("连接超时，请检查 SSH 地址 / 密钥 / 应用是否在运行\n")
        sys.exit(3)


class _Result(object):
    def __init__(self, rc, stdout, stderr):
        self.returncode, self.stdout, self.stderr = rc, stdout, stderr


def req(cfg, api_path, method="GET", payload=None, raw=False):
    r = call(cfg, api_path, method, payload)
    out = (r.stdout or "").strip()
    if r.returncode != 0:
        sys.stderr.write("请求失败：%s\n" % ((r.stderr or "").strip() or out[:200]))
        sys.exit(1)
    if raw:
        return out
    try:
        d = json.loads(out)
    except (ValueError, TypeError):
        sys.stderr.write("返回不是 JSON：%s\n" % out[:200])
        sys.exit(1)
    if isinstance(d, dict) and d.get("ok") is False:
        sys.stderr.write("操作被拒：%s\n" % d.get("msg", "未知原因"))
        sys.exit(4)                     # 4 = 回执过期 / 状态冲突 / 防呆拒绝
    return d


def emit(d):
    sys.stdout.write(json.dumps(d, ensure_ascii=False, indent=2) + "\n")
    return 0


# ---------------- init / check ----------------
def cmd_init(a):
    mode = a.mode or ("local" if detect_local() else "ssh")
    cfg = {
        "mode": mode,
        "auth": a.auth or ("local" if mode == "local" else "key"),
        "socket": a.socket or DEFAULT_SOCKET,
        "orders_path": a.orders or DEFAULT_ORDERS,
        "host": a.host or "",
        "user": a.user or "root",
        "port": a.port or 22,
        "key": a.key or "",
    }
    if mode == "ssh" and not cfg["host"]:
        print("检测到 agent 不在 NAS 本机，需要配置 SSH。")
        if not sys.stdin.isatty():
            sys.stderr.write(
                "非交互环境，请显式传参，例如：\n"
                "  mh init --mode ssh --host 192.168.1.10 --user root "
                "--auth key --key ~/.ipsense/agent_ed25519\n"
                "  mh init --mode ssh --host 192.168.1.10 --user root "
                "--auth password   # 密码走环境变量 / 凭据文件\n")
            return 2
        cfg["host"] = input("NAS 的 SSH 地址（IP / 域名）：").strip()
        cfg["user"] = (input("SSH 用户名 [root]：").strip() or "root")
        port = input("SSH 端口 [22]：").strip()
        cfg["port"] = int(port) if port.isdigit() else 22
        if cfg["auth"] == "key":
            cfg["key"] = input("私钥路径：").strip()
    # 防误覆盖：重跑 init 会整体替换 bridge.json，先留一份带时间戳的备份，
    # 避免一次手滑把可用的连接配置冲掉（2026-11-23 实测踩过）。
    if os.path.isfile(CFG_PATH):
        try:
            with io.open(CFG_PATH, "r", encoding="utf-8") as f:
                old = f.read()
            if old.strip() and old.strip() != json.dumps(
                    cfg, ensure_ascii=False, indent=2).strip():
                bak = CFG_PATH + ".bak." + time.strftime("%Y%m%d%H%M%S")
                with io.open(bak, "w", encoding="utf-8", newline="\n") as f:
                    f.write(old)
                try:
                    os.chmod(bak, 0o600)
                except Exception:
                    pass
                print("已备份原配置：%s" % bak)
        except Exception as ex:
            sys.stderr.write("备份原配置失败（仍继续写入）：%s\n" % ex)
    save_cfg(cfg)
    print("已写入配置：%s" % CFG_PATH)
    print("  连通方式：%s / 认证：%s" % (cfg["mode"], cfg["auth"]))
    if cfg["mode"] == "ssh":
        print("  目标：%s@%s:%s" % (cfg["user"], cfg["host"], cfg["port"]))
        if cfg["auth"] == "key":
            print("  建议：专用只读密钥；用户可在提交单「密钥授权区」随时撤销。")
        else:
            print("  密码从 IPSENSE_SSH_PASSWORD / 凭据文件读取，不写入本配置。")
    print("  提交单文件：%s" % cfg["orders_path"])
    print("下一步：mh check")
    return 0


# ---------------- setup：一步步引导建 SSH 密钥授权（1.1.29 新增） ----------------
# 边界：setup 是「一次性引导」例外命令，只碰 SSH 授权与本机 ~/.ipsense/ 配置，
# 不改提交单 orders.json、不碰防火墙、不动用户其它密钥、不把私钥写进任何可见产物。
# 与 src/app/server/keyauth.py 的数据结构严格对齐，保证 UI 可见、mh key revoke 可撤销。

def _setup_password(interactive, required):
    """密码只从环境变量 / 凭据文件 / 交互输入取，绝不落配置、不打印。"""
    p = os.environ.get("IPSENSE_SSH_PASSWORD") or os.environ.get("OESP_PASS")
    if not p and os.path.isfile(CRED_FILE):
        for line in io.open(CRED_FILE, encoding="utf-8"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                if k.strip() == "OESP_PASS":
                    p = v.strip()
                    break
    if not p and interactive:
        try:
            p = getpass.getpass("SSH / sudo 密码（不回显，不写入任何配置）：")
        except Exception:
            p = ""
    if not p and required:
        sys.stderr.write(
            "password 引导需要密码：设 IPSENSE_SSH_PASSWORD 环境变量，或在 %s 里写 "
            "OESP_PASS=...；也可改用 --bootstrap key（配好免密 sudo 或提供密码）。\n" % CRED_FILE)
        sys.exit(3)
    return p


class _SetupChan(object):
    """引导期受控通道：一次连接里跑完 8 步。SSH 模式统一用 paramiko（sudo -S 喂密码），
    local 模式直接本机跑。与日常命令的 run_remote 分开，避免改动稳定路径。"""

    def __init__(self, boot, host, user, port, key, pwd, login_pwd):
        self.boot, self.ssh = boot, None
        self.pwd = pwd
        if boot in ("password", "key"):
            try:
                import paramiko
            except ImportError:
                sys.stderr.write(
                    "mh setup 的 SSH 引导需要 paramiko：pip install paramiko\n"
                    "（日常 mh check / read 在 auth=key 下不需要它，fw 也需要，装一次即可）\n")
                sys.exit(3)
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kw = dict(hostname=host, port=port, username=user, timeout=20,
                      allow_agent=False, look_for_keys=False)
            if boot == "password":
                kw["password"] = login_pwd
            else:
                kw["key_filename"] = key
            try:
                self.ssh.connect(**kw)
            except Exception as ex:
                sys.stderr.write("bootstrap 连接失败：%s\n" % ex)
                sys.exit(3)

    def run(self, cmd, sudo=False, timeout=90):
        try:
            if self.boot == "local":
                if sudo:
                    full = (["sudo", "-S", "bash", "-c", cmd] if self.pwd else
                            ["sudo", "-n", "bash", "-c", cmd])
                    r = subprocess.run(full, input=(self.pwd + "\n") if self.pwd else None,
                                       capture_output=True, text=True, timeout=timeout)
                else:
                    r = subprocess.run(["bash", "-c", cmd], capture_output=True,
                                       text=True, timeout=timeout)
                return r.returncode, r.stdout or "", r.stderr or ""
            wrapped = ("sudo -S bash -c " + shlex.quote(cmd)) if (sudo and self.pwd) else (
                      ("sudo -n bash -c " + shlex.quote(cmd)) if sudo else cmd)
            stdin, o, e = self.ssh.exec_command(wrapped, timeout=timeout)
            if sudo and self.pwd:
                stdin.write(self.pwd + "\n")
                stdin.flush()
            out = o.read().decode("utf-8", "replace")
            err = e.read().decode("utf-8", "replace")
            rc = o.channel.recv_exit_status()
            # sudo -S 会把密码提示写进 stderr，剔除避免误判失败
            err = "\n".join(ln for ln in err.splitlines()
                            if "password for" not in ln and "[sudo]" not in ln)
            return rc, out, err
        except Exception as ex:
            return 1, "", repr(ex)

    def close(self):
        if self.ssh is not None:
            try:
                self.ssh.close()
            except Exception:
                pass


def _setup_plan(boot, host, user, port, device):
    return [
        "[1/%d] 环境体检：Python / paramiko / ssh / curl；检查本机 ~/.ipsense/ 现状" % SETUP_STEPS,
        "[2/%d] 收集 NAS SSH 连接信息（%s@%s:%s · bootstrap=%s · device=%s）" %
        (SETUP_STEPS, user, host, port, boot, device),
        "[3/%d] 建立 bootstrap 连接，动态读取 NAS 侧 $HOME（不猜 ~<user>，实测二者可不同）" % SETUP_STEPS,
        "[4/%d] NAS 上生成专用 ed25519 密钥对：%s/<grant_id>（ssh-keygen -N ''，带标记注释）" %
        (SETUP_STEPS, KEYDIR),
        "[5/%d] 公钥追加到 $HOME/.ssh/authorized_keys，行尾带 %s:<grant_id>；改前留 .bak" %
        (SETUP_STEPS, MARK),
        "[6/%d] 写 %s（合并已有 grants，不覆盖）；改前留 .bak" % (SETUP_STEPS, KEYAUTH_JSON),
        "[7/%d] 私钥取回本机 %s（600），写 %s（auth=key）；改前均留 .bak" %
        (SETUP_STEPS, LOCAL_KEY.replace("\\", "/"), CFG_PATH.replace("\\", "/")),
        "[8/%d] 验证：mh check / mh key status / fw status" % SETUP_STEPS,
    ]


def _setup_backup_local(path, ts):
    if os.path.isfile(path):
        try:
            shutil.copy2(path, path + ".bak." + ts)
            return True
        except Exception:
            pass
    return False


def cmd_setup(a):
    # --yes / IPSENSE_NONINTERACTIVE 强制非交互；部分终端（Windows Git Bash）对
    # /dev/null 的 isatty() 仍返回 True，所以交互分支另有 EOFError 兜底。
    interactive = (bool(sys.stdin.isatty()) and not a.yes
                   and not os.environ.get("IPSENSE_NONINTERACTIVE"))
    boot = a.bootstrap or ("local" if detect_local() else "password")
    host, user, port = a.host or "", a.user or "root", a.port or 22
    device = a.device or platform.node() or "agent-pc"
    key = a.key or ""

    # [2/8] 连接信息：非交互且缺 host 时只打印示例，不卡 input()
    if boot != "local" and not host:
        if not interactive:
            sys.stderr.write(
                "非交互环境请显式传 --host，例如：\n"
                "  mh setup --host 192.168.1.10 --user root --bootstrap password\n"
                "  mh setup --host 192.168.1.10 --user root --bootstrap key --key ~/.ssh/id_ed25519\n"
                "  mh setup --bootstrap local        # agent 就装在 NAS 上\n"
                "  mh setup --dry-run                # 只看 8 步演练，不连不改\n")
            return 2
        try:
            host = input("NAS 的 SSH 地址（IP / 域名）：").strip()
            user = (input("SSH 用户名 [root]：").strip() or "root")
            pp = input("SSH 端口 [22]：").strip()
            port = int(pp) if pp.isdigit() else 22
        except (EOFError, KeyboardInterrupt):
            sys.stderr.write(
                "\n未读到交互输入（非交互环境）。请显式传参，例如：\n"
                "  mh setup --host <NAS地址> --user root --bootstrap password\n"
                "  mh setup --dry-run   # 只看演练，不连不改\n")
            return 2
    if boot == "key" and not key:
        if interactive:
            try:
                key = input("bootstrap 用的已有私钥路径：").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
        if not key:
            sys.stderr.write("--bootstrap key 需要 --key <已有私钥路径>\n")
            return 2

    plan = _setup_plan(boot, host, user, port, device)

    # --dry-run：只演示，不连接、不落地、不生成密钥
    if a.dry_run:
        print("[mh setup --dry-run] 演练模式：不会连接 NAS、不会修改任何文件、不会生成密钥。\n")
        for line in plan:
            print("  " + line)
        print("\n演练结束。确认无误后去掉 --dry-run 实际执行；"
              "已有 active 授权时默认跳过，要重建加 --force。")
        return 0

    # [1/8] 环境体检
    print("[1/%d] 环境体检" % SETUP_STEPS)
    if boot != "local":
        try:
            import paramiko  # noqa: F401
            print("      paramiko: OK")
        except ImportError:
            sys.stderr.write("      缺少 paramiko：pip install paramiko\n")
            return 3
    print("      本机配置：%s  %s" %
          (("已存在" if os.path.isfile(CFG_PATH) else "未创建（全新）"),
           ("私钥已存在" if os.path.isfile(LOCAL_KEY) else "私钥未创建")))

    print("[2/%d] 连接信息：%s@%s:%s · bootstrap=%s · device=%s" %
          (SETUP_STEPS, user, host, port, boot, device))

    pwd = _setup_password(interactive, required=(boot == "password"))
    login_pwd = pwd if boot == "password" else None
    ch = _SetupChan(boot, host, user, port, key, pwd, login_pwd)

    # [3/8] 连通 + 动态取 $HOME（实测 fnOS 的 HOME 目录名可不等于用户名）
    print("[3/%d] 建立 bootstrap 连接并读取 NAS 侧 $HOME" % SETUP_STEPS)
    rc, home, err = ch.run('printf %s "$HOME"', timeout=30)
    home = (home or "").strip().splitlines()[-1].strip() if (home or "").strip() else ""
    if rc != 0 or not home.startswith("/"):
        ch.close()
        sys.stderr.write("      取 $HOME 失败：%s\n" % (err or "空返回")[:200])
        return 1
    ak = home + "/.ssh/authorized_keys"
    print("      HOME=%s  →  authorized_keys=%s" % (home, ak))

    # 幂等：已有 active 授权默认不重复建
    rc, old_state, _ = ch.run("cat %s 2>/dev/null" % KEYAUTH_JSON, sudo=True, timeout=30)
    try:
        parsed = json.loads(old_state) if rc == 0 and old_state.strip() else {}
        old_grants = parsed.get("grants", []) if isinstance(parsed, dict) else []
    except (ValueError, TypeError):
        old_grants = []
    actives = [g for g in old_grants
               if isinstance(g, dict) and g.get("status") == "active"]
    if actives and not a.force:
        ch.close()
        print("      已存在 active 授权：%s" %
              ", ".join(str(g.get("id", "?")) for g in actives))
        print("      无需重跑。要重建请加 --force（旧授权仍保留，可在「密钥授权区」撤销）。")
        return 0

    ts = time.strftime("%Y%m%d%H%M%S")
    gid = "mh1-" + secrets.token_hex(6)          # revoke 要求 mh1- 前缀
    comment = "%s:%s" % (MARK, gid)
    priv = KEYDIR + "/" + gid
    pub = priv + ".pub"
    q = shlex.quote

    # [4/8] 生成专用密钥对
    print("[4/%d] 在 NAS 上生成专用 ed25519 密钥对：%s" % (SETUP_STEPS, priv))
    gen = ("mkdir -p %s && chmod 700 %s && rm -f %s %s && "
           "ssh-keygen -t ed25519 -f %s -N '' -C %s -q && "
           "chmod 600 %s && chmod 644 %s && echo GEN_OK" %
           (KEYDIR, KEYDIR, q(priv), q(pub), q(priv), q(comment), q(priv), q(pub)))
    rc, out, err = ch.run(gen, sudo=True)
    if "GEN_OK" not in out:
        ch.close()
        sys.stderr.write("      生成密钥失败：%s %s\n" % (out[:200], err[:200]))
        return 1
    rc, pub_data, err = ch.run("cat %s" % q(pub), sudo=True)
    pub_data = (pub_data or "").strip()
    if not pub_data.startswith("ssh-ed25519 "):
        ch.close()
        sys.stderr.write("      读公钥失败：%s\n" % (err or pub_data)[:200])
        return 1
    publine = (pub_data if pub_data.endswith(comment)
               else pub_data + " " + comment)
    rc, lf, _ = ch.run("ssh-keygen -lf %s" % q(pub), sudo=True)
    fp = next((t for t in (lf or "").split() if t.startswith("SHA256:")), "")
    print("      指纹：%s" % (fp or "(未取到)"))

    # [5/8] 追加 authorized_keys（带标记、留 .bak、修属主）
    print("[5/%d] 公钥追加进 %s（带 %s 标记）" % (SETUP_STEPS, ak, comment))
    bak_ak = "%s.ipsense.bak.%s" % (ak, ts)
    akm = ("mkdir -p %s/.ssh && chmod 700 %s/.ssh && touch %s && "
           "(cp -p %s %s 2>/dev/null || true) ; "
           "(grep -qF %s %s || printf '%%s\\n' %s >> %s) ; "
           "(chown -R %s %s/.ssh 2>/dev/null || true) ; "
           "chmod 600 %s ; grep -qF %s %s && echo AK_OK" %
           (q(home), q(home), q(ak), q(ak), q(bak_ak), q(gid), q(ak),
            q(publine), q(ak), q(user), q(home), q(ak), q(gid), q(ak)))
    rc, out, err = ch.run(akm, sudo=True)
    if "AK_OK" not in out:
        ch.close()
        sys.stderr.write("      写 authorized_keys 失败：%s %s\n" % (out[:200], err[:200]))
        return 1
    print("      已留备份：%s" % bak_ak)

    # [6/8] 写 keyauth.json（合并已有 grants，绝不覆盖用户其它授权）
    print("[6/%d] 写 %s（合并已有 grants）" % (SETUP_STEPS, KEYAUTH_JSON))
    grant = {
        "id": gid,
        "fingerprint": fp,
        "pubkey": publine,
        "comment": comment,
        "device": device,
        "created_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "status": "active",
        "revoked_at": "",
        "authorized_keys": ak,
        "private_key": priv,
        "public_key": pub,
        "note": "由 mh setup 一步步引导生成；可在提交单「密钥授权区」随时撤销",
    }
    grants = [g for g in old_grants
              if not (isinstance(g, dict) and g.get("id") == gid)] + [grant]
    state = {"version": 1, "grants": grants}
    blob = base64.b64encode(
        json.dumps(state, ensure_ascii=False, indent=2).encode("utf-8")).decode("ascii")
    bak_state = "%s.bak.%s" % (KEYAUTH_JSON, ts)
    stm = ("cp -p %s %s 2>/dev/null || true ; "
           "printf %%s %s | base64 -d > %s.tmp && chmod 644 %s.tmp && "
           "mv %s.tmp %s && echo STATE_OK" %
           (q(KEYAUTH_JSON), q(bak_state), q(blob), q(KEYAUTH_JSON),
            q(KEYAUTH_JSON), q(KEYAUTH_JSON), q(KEYAUTH_JSON)))
    rc, out, err = ch.run(stm, sudo=True)
    if "STATE_OK" not in out:
        ch.close()
        sys.stderr.write("      写 keyauth.json 失败：%s %s\n" % (out[:200], err[:200]))
        return 1

    # [7/8] 取回私钥（只进内存→本机文件，绝不打印）+ 写本机配置
    print("[7/%d] 私钥取回本机 %s（600，不进 UI / 报告 / 日志）" % (SETUP_STEPS, LOCAL_KEY))
    rc, priv_data, err = ch.run("cat %s" % q(priv), sudo=True)
    if "BEGIN OPENSSH PRIVATE KEY" not in (priv_data or ""):
        ch.close()
        sys.stderr.write("      取回私钥失败：%s\n" % (err or "")[:200])
        return 1
    ch.close()
    os.makedirs(os.path.dirname(LOCAL_KEY), exist_ok=True)
    b1 = _setup_backup_local(LOCAL_KEY, ts)
    with io.open(LOCAL_KEY, "w", encoding="utf-8", newline="\n") as f:
        f.write(priv_data if priv_data.endswith("\n") else priv_data + "\n")
    try:
        os.chmod(LOCAL_KEY, 0o600)
    except Exception:
        pass
    b2 = _setup_backup_local(CFG_PATH, ts)
    cfg = {
        "mode": "local" if boot == "local" else "ssh",
        "auth": "local" if boot == "local" else "key",
        "socket": DEFAULT_SOCKET,
        "orders_path": DEFAULT_ORDERS,
        "host": host, "user": user, "port": port,
        "key": "" if boot == "local" else LOCAL_KEY.replace("\\", "/"),
        "grant_id": gid, "device": device,
    }
    save_cfg(cfg)
    print("      已写 %s（auth=key）%s" %
          (CFG_PATH, "；原文件已备份 .bak." + ts if (b1 or b2) else ""))

    # [8/8] 验证（用新配置实跑，不打印私钥）
    print("[8/%d] 验证" % SETUP_STEPS)
    here = os.path.dirname(os.path.abspath(__file__))
    checks = (("mh check", [sys.executable, os.path.join(here, "mh.py"), "check"]),
              ("mh key status", [sys.executable, os.path.join(here, "mh.py"), "key", "status"]),
              ("fw status", [sys.executable, os.path.join(here, "fw.py"), "status"]))
    env = dict(os.environ)
    env["PYTHONPYCACHEPREFIX"] = os.path.join(
        os.path.dirname(LOCAL_KEY), "_setup_pycache")
    for name, argv in checks:
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=90, env=env)
            ok = (r.returncode == 0)
            out = (r.stdout or "").strip()
            detail = ""
            if out.startswith("{"):
                try:
                    d = json.loads(out)
                    inner = d.get("data", d) if isinstance(d, dict) else d
                    if name == "mh key status":
                        gs = inner.get("grants", []) if isinstance(inner, dict) else []
                        detail = "授权 %d 条（%s 已在列）" % (len(gs), gid)
                    elif name == "fw status":
                        detail = "channel=%s · fw_conf=%s" % (
                            d.get("channel"), (d.get("backends") or {}).get("fw_conf"))
                    else:
                        detail = "ok=%s" % (d.get("ok") if isinstance(d, dict) else "?")
                except (ValueError, TypeError):
                    detail = out.splitlines()[-1][:80]
            elif out:
                detail = out.splitlines()[0][:80]
            if not ok:
                detail = ((r.stderr or "").strip().splitlines() or [detail])[-1][:80]
            print("      [%s] %s%s" % ("OK" if ok else "WARN", name,
                                      ("  ·  " + detail) if detail else ""))
        except Exception as ex:
            print("      [WARN] %s  ·  %s" % (name, ex))

    print("\n=== 配置完成 ===")
    print("  grant_id   : %s" % gid)
    print("  指纹       : %s" % (fp or "(未取到)"))
    print("  设备       : %s" % device)
    print("  本机私钥   : %s (600)" % LOCAL_KEY)
    print("  NAS 授权   : %s" % KEYAUTH_JSON)
    print("  撤销方式   : mh key revoke --grant-id %s，或提交单「密钥授权区」点撤销" % gid)
    print("  下一步     : mh check / mh read pending / fw status")
    return 0


def cmd_check(a):
    cfg = load_cfg()
    d = req(cfg, "/api/health")
    v = d.get("version", "?") if isinstance(d, dict) else "?"
    print("已连通 · ipsense %s · 方式 %s / 认证 %s" %
          (v, cfg.get("mode", "ssh"), cfg.get("auth", "key")))
    print("读提交单：mh read pending   写提交单：mh prepare / mh commit")
    print("密钥授权：mh key status     处置通道：fw status")
    return 0


def cmd_path(a):
    cfg = load_cfg()
    d = req(cfg, "/api/mh/path")
    return emit(d.get("data", d) if isinstance(d, dict) else d)


# ---------------- 读命令（只发 GET） ----------------
def _tab_of(a):
    """区名支持两种写法：`mh read pending`（提示词里的简写）与 `mh read --tab pending`。"""
    pos = getattr(a, "tab_pos", None)
    return pos if pos in TABS else a.tab


def cmd_state(a):
    cfg = load_cfg()
    tab = _tab_of(a)
    d = req(cfg, "/api/mh/state?tab=" + tab)
    return emit(d.get("data", d) if isinstance(d, dict) else d)


def cmd_read(a):
    cfg = load_cfg()
    tab = _tab_of(a)
    d = req(cfg, "/api/mh/state?tab=" + tab)
    return emit(d.get("data", d) if isinstance(d, dict) else d)


def cmd_show(a):
    cfg = load_cfg()
    d = req(cfg, "/api/mh/show?ip=" + a.ip)
    return emit(d.get("data", d) if isinstance(d, dict) else d)


def cmd_prompt(a):
    cfg = load_cfg()
    tab = _tab_of(a)
    sys.stdout.write(req(cfg, "/api/mh/prompt?tab=" + tab, raw=True) + "\n")
    return 0


def cmd_ip(a):
    cfg = load_cfg()
    d = req(cfg, "/api/ip?ip=" + a.ip)
    return emit(d.get("data", d) if isinstance(d, dict) else d)


# ---------------- 密钥授权（1.1.27） ----------------
def cmd_key_status(a):
    cfg = load_cfg()
    d = req(cfg, "/api/keyauth/state")
    return emit(d.get("data", d) if isinstance(d, dict) else d)


def cmd_key_revoke(a):
    cfg = load_cfg()
    d = req(cfg, KEYAUTH_REVOKE, "POST", {"grant_id": a.grant_id})
    return emit(d.get("data", d) if isinstance(d, dict) else d)


# ---------------- 写命令（只发 POST /api/mh/write） ----------------
def cmd_prepare(a):
    cfg = load_cfg()
    if not a.receipt:
        sys.stderr.write("防呆：prepare 需要 --receipt（先 mh read 拿回执）\n")
        return 2
    d = req(cfg, "/api/mh/write", "POST", {"action": "prepare", "receipt": a.receipt})
    return emit(d.get("data", d) if isinstance(d, dict) else d)


def cmd_commit(a):
    cfg = load_cfg()
    if not a.token:
        sys.stderr.write("防呆：commit 需要 --token（先 mh prepare 拿预备令牌）\n")
        return 2
    d = req(cfg, "/api/mh/write", "POST",
            {"action": "commit", "token": a.token, "summary": a.summary or ""})
    return emit(d.get("data", d) if isinstance(d, dict) else d)


def cmd_discard(a):
    cfg = load_cfg()
    if not a.token:
        sys.stderr.write("防呆：discard 需要 --token\n")
        return 2
    d = req(cfg, "/api/mh/write", "POST", {"action": "discard", "token": a.token})
    return emit(d.get("data", d) if isinstance(d, dict) else d)


def _one_shot(cfg, receipt, summary):
    """mark-done / restore 一步到位：prepare -> commit，仍走同一套校验与乐观锁。"""
    if not receipt:
        sys.stderr.write("防呆：需要 --receipt（先 mh read 拿回执）\n")
        return 2
    if not summary:
        sys.stderr.write("防呆：需要 --summary（已完成区要显示 AI 总结的大致操作）\n")
        return 2
    p = req(cfg, "/api/mh/write", "POST", {"action": "prepare", "receipt": receipt})
    plan = (p.get("data") or {}).get("plan") or {}
    token = plan.get("token")
    if not token:
        sys.stderr.write("prepare 未返回预备令牌，提交取消\n")
        return 4
    c = req(cfg, "/api/mh/write", "POST",
            {"action": "commit", "token": token, "summary": summary})
    return emit(c.get("data", c) if isinstance(c, dict) else c)


def cmd_mark_done(a):
    return _one_shot(load_cfg(), a.receipt, a.summary)


def cmd_restore(a):
    return _one_shot(load_cfg(), a.receipt, a.summary or "已按标注一键复原到变更前配置")


def cmd_orders(a):
    """1.1.22 遗留只读别名：读提交单快照。新流程请用 mh read <tab>。"""
    cfg = load_cfg()
    d = req(cfg, "/api/orders")
    return emit(d.get("data", d) if isinstance(d, dict) else d)


def main():
    ap = argparse.ArgumentParser(
        prog="mh",
        description="ipsense 提交单工程状态的唯一读写接口（skill=规矩，mh=手眼，fw=处置）")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("init", help="引导配置 SSH / 本机直连")
    p.add_argument("--mode", choices=["local", "ssh"])
    p.add_argument("--auth", choices=["key", "password", "local"])
    p.add_argument("--host"); p.add_argument("--user"); p.add_argument("--port", type=int)
    p.add_argument("--key"); p.add_argument("--socket"); p.add_argument("--orders")
    p.set_defaults(fn=cmd_init)

    q = sub.add_parser(
        "setup",
        help="一步步引导：自动生成 ed25519 密钥对 / 配 SSH 授权 / 写 bridge.json（新用户用这个）")
    q.add_argument("--host"); q.add_argument("--user", default="root")
    q.add_argument("--port", type=int, default=22)
    q.add_argument("--bootstrap", choices=["password", "key", "local"], default=None)
    q.add_argument("--key", help="--bootstrap key 时已有的私钥路径")
    q.add_argument("--device", help="设备名（默认取本机 hostname）")
    q.add_argument("--force", action="store_true", help="已有 active 授权也重建")
    q.add_argument("--dry-run", action="store_true", help="只演示 8 步，不连不改")
    q.add_argument("--yes", action="store_true",
                   help="强制非交互（不询问，需显式传 --host / --key）")
    q.set_defaults(fn=cmd_setup)

    for name, help_, fn in (
        ("check", "检查连通性与版本", cmd_check),
        ("path", "打印提交单路径与接口清单", cmd_path),
        ("orders", "（弃用）读提交单快照", cmd_orders),
    ):
        q = sub.add_parser(name, help=help_)
        q.set_defaults(fn=fn)

    for name, help_, fn in (
        ("state", "四区状态 / 计数 / 回执 / 流水", cmd_state),
        ("read", "读取某区数据区（给 AI）", cmd_read),
        ("prompt", "一句话提示词 + 读取路径", cmd_prompt),
    ):
        q = sub.add_parser(name, help=help_)
        q.add_argument("--tab", choices=list(TABS), default="pending")
        q.add_argument("tab_pos", nargs="?", default=None, choices=list(TABS),
                       help="区名简写，如 mh read pending（与 --tab 等价）")
        q.set_defaults(fn=fn)

    q = sub.add_parser("show", help="单条完整证据 + 总结 + 历史 + 回执")
    q.add_argument("ip"); q.set_defaults(fn=cmd_show)

    q = sub.add_parser("ip", help="单 IP 完整画像证据")
    q.add_argument("ip"); q.set_defaults(fn=cmd_ip)

    # 1.1.27 密钥授权管理
    pk = sub.add_parser("key", help="密钥授权：查看 / 撤销")
    ks = pk.add_subparsers(dest="keycmd")
    q = ks.add_parser("status", help="列出授权（指纹/公钥/时间/设备/状态）")
    q.set_defaults(fn=cmd_key_status)
    q = ks.add_parser("revoke", help="撤销一份授权")
    q.add_argument("--grant-id", required=True); q.set_defaults(fn=cmd_key_revoke)

    q = sub.add_parser("prepare", help="校验回执，生成可确认的变更预备")
    q.add_argument("--receipt", required=True); q.set_defaults(fn=cmd_prepare)

    q = sub.add_parser("commit", help="确认预备并落库（乐观锁复核）")
    q.add_argument("--token", required=True); q.add_argument("--summary", default="")
    q.set_defaults(fn=cmd_commit)

    q = sub.add_parser("discard", help="丢弃一份预备")
    q.add_argument("--token", required=True); q.set_defaults(fn=cmd_discard)

    q = sub.add_parser("mark-done", help="一步：待处理 → 已完成")
    q.add_argument("--receipt", required=True); q.add_argument("--summary", required=True)
    q.set_defaults(fn=cmd_mark_done)

    q = sub.add_parser("restore", help="一步：待撤回 → 已复原")
    q.add_argument("--receipt", required=True); q.add_argument("--summary", default="")
    q.set_defaults(fn=cmd_restore)

    a = ap.parse_args()
    if not getattr(a, "fn", None):
        ap.print_help()
        return 0
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
