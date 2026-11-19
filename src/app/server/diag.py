# -*- coding: utf-8 -*-
"""1.1.15：运行日志一键导出（脱敏诊断包）。

设计红线：
- 只读取本机日志与聚合状态，不读取 events.db 里的原始事件行；
- 所有文本统一过 scrub()：地图 KEY / 令牌 / 口令 / 邮箱抹除，来访 IP 只保留前两段；
- 配置先按键名剔除，再整体过 scrub()，双重保险；
- 每段独立容错，缺文件 / 接口异常都写明原因，不抛 500、不伪造数据；
- 输出一份可直接贴进 Issue 的纯文本，不含任何可识别个人身份的信息。
"""
import os
import re
import sys
import json
import time
import platform

MAX_LINES = 400
READ_CAP = 2 * 1024 * 1024       # 单个日志最多回读 2 MB，避免大文件卡住 HTTP 线程

# 配置里明确含密钥 / 出口 IP / 私有路径的键，直接剔除，不进入导出文本
DROP_CFG_KEYS = (
    "map_key", "map_keys", "map_custom", "home_ip", "home_proxy_ip",
    "home_geo", "home_source", "home_locate_at", "ignore_ips",
)

IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
# 至少 3 组冒号才算 IPv6：避免把日志里的 15:21:07 时间戳误伤
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F:]*\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# 允许 map_key / api_key / securityJsCode 这类带前缀的键名
SECRET_RE = re.compile(
    r"(?i)(^|[?&\s;,'\"(])((?:[a-z0-9_\-]*_)?"
    r"(?:key|ak|tk|token|secret|password|passwd|authorization|cookie|"
    r"apikey|securityjscode))(\s*[:=]\s*)([\"']?)([^\s,;&\"']{4,})")
BEARER_RE = re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]{8,}")
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                    re.S)


def scrub(text):
    """文本级脱敏。顺序：先长结构（PEM / Bearer），再键值，再 IP / 邮箱。"""
    s = str(text if text is not None else "")
    s = PEM_RE.sub("***PRIVATE KEY REDACTED***", s)
    s = BEARER_RE.sub("Bearer ***REDACTED***", s)
    s = SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + m.group(3) +
                      m.group(4) + "***REDACTED***", s)
    s = IPV6_RE.sub("***IPv6***", s)
    s = IPV4_RE.sub(lambda m: "%s.%s.*.*" % (m.group(1), m.group(2)), s)
    s = EMAIL_RE.sub("***@***", s)
    return s


def redact_config(cfg):
    """配置白名单式脱敏：先剔键，再把路径等值里的 IP 也抹掉。"""
    out = {}
    for k, v in (cfg or {}).items():
        if k in DROP_CFG_KEYS:
            out[k] = "<已移除>"
            continue
        if isinstance(v, str):
            out[k] = scrub(v)
        elif isinstance(v, (list, dict)):
            out[k] = json.loads(scrub(json.dumps(v, ensure_ascii=False)))
        else:
            out[k] = v
    return out


def tail(path, n=MAX_LINES):
    """从文件尾部回读最多 n 行；不存在 / 读失败返回可读说明，不抛异常。"""
    if not path or not os.path.isfile(path):
        return ["(文件不存在：%s)" % path]
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - READ_CAP))
            data = f.read(READ_CAP)
        lines = data.decode("utf-8", "replace").splitlines()
        if size > READ_CAP:
            lines = ["(文件较大，仅导出最后 %d 字节)" % len(data)] + lines
        return lines[-n:] if lines else ["(文件为空)"]
    except Exception as e:
        return ["(读取失败：%s)" % e]


def dump_json(obj):
    try:
        return scrub(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    except Exception as e:
        return "(序列化失败：%s)" % e


class Bundle(object):
    def __init__(self, app):
        self.app = app
        self.L = []

    def head(self, title, note=""):
        self.L.append("")
        self.L.append("=" * 72)
        self.L.append("== " + title)
        if note:
            self.L.append("   " + note)
        self.L.append("=" * 72)

    def kv(self, k, v):
        self.L.append("%-22s %s" % (k + ":", scrub(v)))

    def block(self, lines):
        self.L.extend(scrub(x) for x in lines)

    def safe(self, title, fn):
        self.head(title)
        try:
            fn()
        except Exception as e:
            self.L.append("(采集失败：%s)" % type(e).__name__ + " " + str(e)[:160])

    def text(self):
        return "\n".join(self.L) + "\n"


def build_bundle(app):
    """生成完整诊断文本。每段独立容错，绝不因为一个日志文件缺失而 500。"""
    now = time.time()
    b = Bundle(app)
    L = b.L
    L.append("IP 动态感知（ipsense）· 运行日志诊断包")
    L.append("生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)))
    L.append("说明：本文件已自动脱敏。地图 KEY / 令牌 / 口令已抹除；")
    L.append("      来访 IP 只保留前两段（例 220.205.*.*），不含完整 IP、邮箱、原始日志行。")
    L.append("      应用仍然只观测、不封禁、不改防火墙、不自动处置。")
    L.append("反馈时请连同：复现步骤、截图（含顶部状态标）、设备架构与 fnOS 版本一起提交。")

    def env():
        dest = os.environ.get("TRIM_APPDEST", "")
        var = os.environ.get("TRIM_PKGVAR", "")
        ver = (getattr(sys.modules.get("__main__"), "VERSION", "")
               or getattr(app, "version", "") or "1.1.16")
        b.kv("应用版本", ver)
        b.kv("Python", sys.version.split()[0])
        b.kv("系统 / 架构", "%s / %s" % (platform.system(), platform.machine()))
        b.kv("APP_DEST", dest or "(未设置环境变量)")
        b.kv("TRIM_PKGVAR", var or "(未设置环境变量)")
        b.kv("主日志", "/var/log/apps/ipsense.log")
        b.kv("兜底日志", os.path.join(var or "/vol1/@appdata/ipsense", "app.log"))
        b.kv("生命周期日志", os.path.join(var or "/vol1/@appdata/ipsense", "cmd.log"))
        b.kv("数据库大小", _human(os.path.getsize(app.store.db_path))
             if os.path.isfile(app.store.db_path) else "(不存在)")
        b.kv("离线库就绪", app.geo.ready)
        if not app.geo.ready:
            b.kv("离线库错误", getattr(app.geo, "error", ""))
        b.kv("运行时长", "%.1f 秒" % max(0.0, now - getattr(app, "started", now)))
    b.safe("1. 运行环境", env)

    def runtime():
        var = os.environ.get("TRIM_PKGVAR") or "/vol1/@appdata/ipsense"
        b.kv("进程 PID 文件", os.path.join(var, "ipsense.pid"))
        pid = ""
        try:
            with open(os.path.join(var, "ipsense.pid"), "r", encoding="utf-8") as f:
                pid = f.read().strip()
        except Exception:
            pass
        b.kv("记录的 PID", pid or "(无)")
        b.kv("socket", os.path.join(
            os.environ.get("TRIM_APPDEST", "/var/apps/ipsense/target"), "app.sock"))
        b.kv("socket 存在", os.path.exists(os.path.join(
            os.environ.get("TRIM_APPDEST", "/var/apps/ipsense/target"), "app.sock")))
    b.safe("2. 进程与 socket", runtime)

    def status():
        b.block(["-- /api/status（聚合状态，原始事件行不导出） --"])
        L.append(dump_json(app.store.status("24h")))
        b.block(["-- 数据源状态 --"])
        L.append(dump_json(app.sources_safe()))
        b.block(["-- 数据源计数 --"])
        L.append(dump_json(app.store.sources_stat()))
        b.block(["-- 在线归属校验 --"])
        L.append(dump_json(app.verifier.stats() if app.verifier else {"enabled": False}))
    b.safe("3. 聚合状态与数据源", status)

    def database():
        with app.store.lock:
            n = app.store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            mx = app.store.conn.execute("SELECT MAX(ts) FROM events").fetchone()[0]
            kinds = [dict(r) for r in app.store.conn.execute(
                "SELECT scope, COUNT(*) n FROM events GROUP BY scope ORDER BY n DESC")]
            gc = app.store.geo_cache_count()
        b.kv("事件总数", n)
        b.kv("最近事件", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mx)) if mx else "(空库)")
        b.kv("归属缓存条数", gc)
        b.block(["-- 按范围计数（只含聚合数字，无 IP） --"])
        L.append(dump_json(kinds))
    b.safe("4. 数据库概况", database)

    def config():
        b.block(["以下配置已剔除 map_key / map_keys / map_custom / 出口 IP / 忽略 IP 等敏感键；"])
        b.block(["路径中的 IP 也已抹除。完整配置请勿公开分享。"])
        L.append(dump_json(redact_config(app.settings.all())))
    b.safe("5. 配置（脱敏）", config)

    def logs():
        var = os.environ.get("TRIM_PKGVAR") or "/vol1/@appdata/ipsense"
        files = [
            ("主运行日志 /var/log/apps/ipsense.log", "/var/log/apps/ipsense.log"),
            ("运行日志兜底副本 app.log", os.path.join(var, "app.log")),
            ("生命周期日志 cmd.log", os.path.join(var, "cmd.log")),
        ]
        for title, path in files:
            b.head(title, path)
            lines = tail(path, MAX_LINES)
            if len(lines) == 1 and lines[0].startswith("(文件不存在"):
                b.block(lines)
                b.block(["(该路径不可写或未生成时为空，属正常情况)"])
            else:
                b.block(lines)
    b.safe("6. 运行日志（尾部 %d 行，已脱敏）" % MAX_LINES, logs)

    def ending():
        b.block([
            "提交 Issue 时建议一并提供：",
            "  1. 本诊断包（设置 → 最底部「运行日志一键导出」）",
            "  2. 复现步骤：点了什么、期望什么、实际出现什么",
            "  3. 截图 / 录屏，请保留顶部状态标与其悬停提示",
            "  4. 设备架构（uname -m）与 fnOS 版本",
            "  5. 安装的 FPK 文件名（all / x86 / arm）",
            "  6. 问题出现的时间点（便于在日志里定位）",
            "",
            "仓库：https://github.com/wangbujiangwude/ipsense-fnos",
            "排障指南：docs/排障指南.md",
            "请勿公开分享未脱敏的 config.json、events.db 或原始访问日志。",
        ])
    b.safe("7. 反馈清单", ending)
    return b.text()


def _human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%d B" % n
