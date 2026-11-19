# -*- coding: utf-8 -*-
"""1.1.17：前端运行时报错采集、落盘与一键导出。

为什么单独一个文件：软件之前的诊断包只有服务端日志（collector / cmd.log），
浏览器侧的 JS 异常、地图 SDK 加载失败、接口 4xx/5xx 只显示在页面上，
用户一关页面就没了 —— 这正是「SDK 没正常加载」这类问题最难定位的原因。

设计边界：
- 只写 $TRIM_PKGVAR/runtime_errors.jsonl，不进 events.db、不写主运行日志；
- 每条记录字段白名单 + 长度截断 + 复用 diag.scrub() 脱敏；
  URL 里的 key/token、来访 IP、邮箱、票据一律不落盘；
- 环形上限 500 条 / 512 KB，超出裁掉最旧的，不会撑爆 NAS 存储；
- 只提供「上报 / 查询 / 导出」，不提供删除接口，也不接受任意路径或任意字段；
- 只观测、不封禁、不改防火墙、不自动处置：这里不做任何自动修复动作。

导出文本可直接贴给 AI 或 Issue，含环境上下文、按类型汇总、地图 SDK 专项、
逐条明细与反馈清单。
"""
import json
import os
import platform
import sys
import threading
import time

from diag import scrub

MAX_ITEMS = 500
MAX_BATCH = 50
MAX_FILE_BYTES = 512 * 1024
EXPORT_LIMIT = 200

# 字段白名单：任何未列出的前端字段一律丢弃，避免把请求体 / 票据带进日志
STR_FIELDS = {
    "kind": 40, "level": 16, "msg": 500, "src": 300, "stack": 1500,
    "url": 300, "provider": 60, "host": 120, "ver": 24, "ua": 260,
    "page": 160, "mapState": 24, "mapError": 400, "pill": 60, "tag": 16,
}
NUM_FIELDS = ("ts", "line", "col", "status", "dur", "count")

KIND_NAME = {
    "js": "JS 运行时异常",
    "rejection": "未处理的 Promise 拒绝",
    "resource": "资源加载失败",
    "map_sdk": "地图 SDK 加载 / 就绪失败",
    "api": "接口请求失败",
    "manual": "用户手动记录",
}
MAP_HOST_HINT = ("map.qq.com", "webapi.amap.com", "api.map.baidu.com",
                 "api.tianditu.gov.cn", "webapiamap.com")


def _clip(v, n):
    return scrub(str(v if v is not None else "")[:n])


def _num(v, default=0):
    try:
        f = float(v)
        if f != f or f in (float("inf"), float("-inf")):
            return default
        return f
    except (TypeError, ValueError):
        return default


class RuntimeLog(object):
    """线程安全的 JSONL 环形日志。"""

    def __init__(self, var_dir=None):
        base = var_dir or os.environ.get("TRIM_PKGVAR") or "/vol1/@appdata/ipsense"
        self.path = os.path.join(base, "runtime_errors.jsonl")
        self.lock = threading.Lock()

    def _normalize(self, raw, ctx):
        if not isinstance(raw, dict):
            return None
        e = {}
        for k, n in STR_FIELDS.items():
            v = raw.get(k, (ctx or {}).get(k, ""))
            e[k] = _clip(v, n)
        for k in NUM_FIELDS:
            e[k] = _num(raw.get(k, 0), 0)
        if not e["ts"] or e["ts"] <= 0:
            e["ts"] = time.time()
        if not e["kind"]:
            e["kind"] = "js"
        if not e["level"]:
            e["level"] = "error"
        if e["count"] < 1:
            e["count"] = 1
        # 上下文类字段以本次上报的 ctx 为准，单条里伪造的 ver/provider 不覆盖
        for k in ("ver", "provider", "mapState", "mapError", "pill", "ua", "page"):
            cv = (ctx or {}).get(k)
            if cv:
                e[k] = _clip(cv, STR_FIELDS[k])
        return e

    def add(self, items, ctx=None):
        """接收前端批量上报；返回实际落盘条数。任何异常都不向上抛。"""
        if not isinstance(items, list) or not items:
            return 0
        rows = []
        for raw in items[:MAX_BATCH]:
            try:
                e = self._normalize(raw, ctx)
                if e:
                    rows.append(e)
            except Exception:
                continue
        if not rows:
            return 0
        with self.lock:
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    for e in rows:
                        f.write(json.dumps(e, ensure_ascii=False) + "\n")
                self._trim()
                return len(rows)
            except Exception:
                return 0

    def _trim(self):
        """按条数 / 体积裁掉最旧的记录，重写文件（调用方已持锁）。"""
        try:
            size = os.path.getsize(self.path)
            with open(self.path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) <= MAX_ITEMS and size <= MAX_FILE_BYTES:
                return
            keep, total = [], 0
            for line in reversed(lines):
                if len(keep) >= MAX_ITEMS or total >= MAX_FILE_BYTES:
                    break
                keep.append(line.rstrip("\n"))
                total += len(line.encode("utf-8", "replace"))
            with open(self.path, "w", encoding="utf-8") as f:
                f.write("\n".join(reversed(keep)) + ("\n" if keep else ""))
        except Exception:
            pass

    def recent(self, limit=EXPORT_LIMIT):
        """返回最近 limit 条，最新在前；文件不存在 / 损坏行跳过。"""
        try:
            limit = max(1, min(EXPORT_LIMIT, int(limit or EXPORT_LIMIT)))
        except (TypeError, ValueError):
            limit = EXPORT_LIMIT
        with self.lock:
            try:
                if not os.path.isfile(self.path):
                    return []
                with open(self.path, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-MAX_ITEMS:]
            except Exception:
                return []
        out = []
        for line in reversed(lines):
            try:
                e = json.loads(line)
                if isinstance(e, dict):
                    out.append(e)
            except Exception:
                continue
        return out[:limit]

    def count(self):
        with self.lock:
            try:
                if not os.path.isfile(self.path):
                    return 0
                with open(self.path, "r", encoding="utf-8") as f:
                    return sum(1 for _ in f)
            except Exception:
                return 0

    def size(self):
        try:
            return os.path.getsize(self.path)
        except Exception:
            return 0


def _stamp(ts):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
    except Exception:
        return "-"


def _version(app):
    return (getattr(app, "version", "") or
            getattr(sys.modules.get("__main__"), "VERSION", "") or "1.1.17")


def format_section(items, limit=100):
    """给 diag.build_bundle() 复用：章节正文行列表。"""
    L = []
    items = (items or [])[:limit]
    if not items:
        L.append("(尚无前端运行时报错记录)")
        L.append("说明：1.1.17 起，页面 JS 异常 / 地图 SDK 加载失败 / 接口失败会自动上报并落盘；")
        L.append("      旧版本页面或未打开过页面时无记录属正常情况。")
        return L
    kinds = {}
    for e in items:
        k = e.get("kind", "js")
        kinds[k] = kinds.get(k, 0) + int(e.get("count", 1) or 1)
    L.append("共 %d 条（本段展示最近 %d 条），按类型：%s" % (
        len(items), len(items),
        " / ".join("%s %d" % (KIND_NAME.get(k, k), v)
                   for k, v in sorted(kinds.items(), key=lambda x: -x[1]))))
    L.append("最新：%s    最早：%s" % (_stamp(items[0].get("ts")),
                                    _stamp(items[-1].get("ts"))))
    L.append("")
    for i, e in enumerate(items, 1):
        L.append("%03d [%s] %s | %s | %s" % (
            i, _stamp(e.get("ts")), e.get("level", ""),
            KIND_NAME.get(e.get("kind"), e.get("kind", "")),
            e.get("msg", "")))
        for k, label in (("src", "来源"), ("url", "URL"), ("stack", "堆栈")):
            v = e.get(k)
            if v:
                L.append("      %s: %s" % (label, str(v)[:400]))
        extra = []
        for k, label in (("provider", "底图"), ("host", "域名"),
                         ("mapState", "底图状态"), ("pill", "状态标")):
            if e.get(k):
                extra.append("%s=%s" % (label, e.get(k)))
        if int(e.get("count", 1) or 1) > 1:
            extra.append("重复 %s 次" % e.get("count"))
        if extra:
            L.append("      " + " · ".join(extra))
    return L


def build_export(app=None, limit=EXPORT_LIMIT):
    """生成「运行报错一键导出」纯文本。"""
    rt = app if isinstance(app, RuntimeLog) else (
        getattr(app, "rtlog", None) if app is not None else None)
    if rt is None:
        rt = RuntimeLog()
    items = rt.recent(limit)
    L = []
    A = L.append
    A("IP 动态感知（ipsense）· 运行时报错导出")
    A("生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    A("应用版本：%s" % _version(app))
    A("系统 / 架构：%s / %s" % (platform.system(), platform.machine()))
    A("说明：本文件只收录软件运行时真正报出来的错（浏览器 JS 异常、地图 SDK 加载失败、")
    A("      资源加载失败、接口 4xx/5xx 与超时），并已自动脱敏：KEY / 令牌 / 口令 / 邮箱")
    A("      已抹除，来访 IP 只保留前两段，原始事件行与数据库明细不包含在内。")
    A("      应用仍然只观测、不封禁、不改防火墙、不自动处置。")
    A("=" * 72)
    A("")
    A("[1] 概览")
    A("  落盘记录总数      %d 条" % rt.count())
    A("  本次导出          %d 条" % len(items))
    A("  日志文件          %s" % rt.path)
    A("  日志文件大小      %s" % _human(rt.size()))
    if items:
        last = items[0]
        A("  最近一次报错      %s" % _stamp(last.get("ts")))
        A("  页面版本 / 底图   %s / %s" % (last.get("ver", "") or "?",
                                        last.get("provider", "") or "?"))
        A("  当时底图状态      %s" % (last.get("mapState", "") or "?"))
        A("  当时顶部状态标    %s" % (last.get("pill", "") or "?"))
        A("  浏览器 UA         %s" % (last.get("ua", "") or "?"))
        A("  页面地址          %s" % (last.get("page", "") or "?"))
        kinds = {}
        for e in items:
            k = e.get("kind", "js")
            kinds[k] = kinds.get(k, 0) + int(e.get("count", 1) or 1)
        A("  按类型            %s" % " / ".join(
            "%s %d" % (KIND_NAME.get(k, k), v)
            for k, v in sorted(kinds.items(), key=lambda x: -x[1])))
    A("")
    A("[2] 地图 SDK 专项（用户最常反馈的「底图没加载」）")
    maps = [e for e in items
            if e.get("kind") == "map_sdk" or
            any(h in (str(e.get("src", "")) + str(e.get("url", "")) +
                      str(e.get("host", ""))) for h in MAP_HOST_HINT)]
    if not maps:
        A("  (本次记录里没有地图 SDK 加载 / 就绪失败)")
        A("  排查顺序：① 设置里看「底图诊断」② 看 KEY 是否有效、是否绑定 Web 端")
        A("           ③ 看浏览器是否拦截了 SDK 域名 ④ 换一家服务商预设做对照")
    else:
        for i, e in enumerate(maps, 1):
            A("  %02d %s | %s | %s" % (i, _stamp(e.get("ts")),
                                      e.get("provider", "") or "?",
                                      e.get("msg", "")))
            if e.get("host"):
                A("       域名: %s" % e.get("host"))
            if e.get("mapError"):
                A("       页面提示: %s" % e.get("mapError"))
            if e.get("stack"):
                A("       堆栈: %s" % str(e.get("stack"))[:400])
    A("")
    A("[3] 逐条明细（最新在前，已脱敏）")
    A("")
    L.extend(format_section(items, limit))
    A("")
    A("[4] 反馈时请一并提供")
    A("  1. 本文件（设置 → 最底部「运行报错一键导出」）")
    A("  2. 运行日志诊断包（同页「导出运行日志」，已包含本文件的摘要章节）")
    A("  3. 复现步骤：点了什么、期望什么、实际出现什么，以及问题发生的时间点")
    A("  4. 截图 / 录屏，请保留顶部状态标与底图错误提示条")
    A("  5. 设备架构（uname -m）、fnOS 版本、安装的 FPK 文件名（all / x86 / arm）")
    A("")
    A("仓库：https://github.com/wangbujiangwude/ipsense-fnos")
    A("排障指南：docs/排障指南.md")
    A("=" * 72)
    return "\n".join(L) + "\n"


def _human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%d B" % n
