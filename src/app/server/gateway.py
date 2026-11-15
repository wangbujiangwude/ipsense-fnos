# -*- coding: utf-8 -*-
"""IP 动态感知 · fnOS 原生应用后端。

只监听 $TRIM_APPDEST/app.sock（AF_UNIX），由飞牛 nginx 把 /app/ipsense/* 转发进来。
零第三方依赖：Python 3 标准库 + sqlite3 + 随包内置的 ip2region xdb。
"""
import os
import re
import sys
import json
import time
import signal
import socket
import shutil
import threading
import subprocess
import urllib.parse
import traceback

APP_NAME = "ipsense"
VERSION = "1.1.14"
PREFIX = "/app/" + APP_NAME
APP_DEST = os.environ.get("TRIM_APPDEST", "/var/apps/%s/target" % APP_NAME)
VAR_DIR = os.environ.get("TRIM_PKGVAR") or "/vol1/@appdata/%s" % APP_NAME
SOCK_PATH = os.path.join(APP_DEST, "app.sock")
PID_PATH = os.path.join(VAR_DIR, "%s.pid" % APP_NAME)
DB_PATH = os.path.join(VAR_DIR, "events.db")
CFG_PATH = os.path.join(VAR_DIR, "config.json")
LOG_PATH = "/var/log/apps/%s.log" % APP_NAME
UI_DIR = os.path.join(APP_DEST, "ui")
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
        ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon",
        ".txt": "text/plain; charset=utf-8", ".csv": "text/csv; charset=utf-8"}

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from settings import Settings, MAP_KEY_PLACEHOLDER           # noqa: E402
from geoip import GeoResolver                                # noqa: E402
from geosource import GeoVerifier                            # noqa: E402
from store import Store                                      # noqa: E402
from collector import Collector                              # noqa: E402
from locate import current as locate_current, run as locate_run   # noqa: E402
from summary import (                                             # noqa: E402
    SummaryWriter, build_summary, write_summary, validate_dir,
    path_allowed, LATEST_NAME,
)


def pyexe():
    """fnOS 应用环境里 sys.executable 可能是空串，必须逐个回退。"""
    import shutil as _sh
    for c in (sys.executable, _sh.which("python3"), _sh.which("python"),
              "/usr/bin/python3", "/usr/bin/python", "/usr/local/bin/python3"):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "python3"


def log(msg):
    line = "%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    for p in (LOG_PATH, os.path.join(VAR_DIR, "app.log")):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "a", encoding="utf-8") as f:
                f.write(line)
            return
        except Exception:
            continue


class App(object):
    def __init__(self):
        os.makedirs(VAR_DIR, exist_ok=True)
        self.settings = Settings(CFG_PATH)
        self.geo = GeoResolver(DATA_DIR)
        self.store = Store(DB_PATH, int(self.settings.get("keep_days", 30) or 30))
        # 1.0.9：升级后订正历史脏值（英文国名 / province=中国 / 坐标与省份脱钩）
        try:
            _norm = self.store.normalize_events()
            log("normalize_events: %s" % json.dumps(_norm, ensure_ascii=False))
        except Exception as e:
            log("normalize_events error: %s" % traceback.format_exc())
        self.verifier = GeoVerifier(self.store, self.geo, self.settings, log)
        self.collector = None
        self.started = time.time()
        self.lock = threading.RLock()
        self._upgrade_running = False
        log("app init: dest=%s var=%s geo=%s verify=%s" % (
            APP_DEST, VAR_DIR, self.geo.ready, self.verifier is not None))
        if not self.geo.ready:
            log("geo error: %s" % getattr(self.geo, "error", ""))
        # 1.1.9：汇总日志后台生成线程。间隔 / 目录 / 开关都从配置实时读取，
        # 改设置无需重启；线程 30 秒后才首次检查，不占启动关键路径。
        self.summary = SummaryWriter(self)

    def sources_safe(self):
        """采集器尚未启动时给 /api/status、/api/sources 一个同形状的安全返回值。

        1.1.1 把采集器启动挪到后台，socket 立即就绪；这几秒内若就收到请求，
        不能因为 app.collector 还是 None 而返回 500。
        """
        if self.collector:
            return self.collector.status()
        return {"starting": True, "queue": 0, "syslog_ok": False,
                "syslog_error": "", "knock_enabled": False, "knock_installed": False,
                "fnos_audit": True, "auth_rotated": True, "lan_separate": True,
                "lan": {"count": 0, "ips": 0}, "tailers": [], "hits": {},
                "geo_ready": self.geo.ready,
                "geo_error": getattr(self.geo, "error", ""), "started": self.started}

    def warmup(self):
        """预计算首屏聚合，页面第一次请求直接命中缓存（预热项有效期 60 s）。"""
        s, ttl = self.store, 60
        for fn in (
            lambda: s.status("24h", _ttl=ttl),
            lambda: s.trend("24h", _ttl=ttl),
            lambda: s.ranking("24h", 12, _ttl=ttl),
            lambda: s.hotspots("24h", 120, _ttl=ttl),
            # 1.1.3：首屏一次取 30 条，卡片显示前 8 条，放大面板复用同一份完整列表
            lambda: s.web_overview("24h", 30, _ttl=ttl),
            lambda: s.geo_distribution("24h", "all", 40, _ttl=ttl),
            lambda: s.sources_stat(_ttl=ttl),
            lambda: s.lan_stat(_ttl=ttl),
        ):
            try:
                fn()
            except Exception as e:
                log("warmup step error: %s" % e)
        log("warmup done")
        # 在线校验队列最重（聚合 + 逐 IP 在线请求），放到预热之后，
        # 避免启动瞬间与首屏抢 store.lock / 抢网络。
        time.sleep(2)
        if self.verifier and self.settings.get("geo_verify_enabled", True):
            try:
                self.verifier.queue_top(
                    int(self.settings.get("geo_verify_batch", 60) or 60))
            except Exception as e:
                log("geo queue_top: %s" % e)

    def boot_async(self):
        """1.1.1：socket 先就绪，采集器 / 回填 / 预热全部后台化。"""
        def run():
            try:
                self.start_collector(backfill=True)
            except Exception:
                log("boot collector error: %s" % traceback.format_exc())
            try:
                self.warmup()
            except Exception:
                log("warmup error: %s" % traceback.format_exc())
        threading.Thread(target=run, name="ipsense-boot", daemon=True).start()

    def start_collector(self, backfill=True):
        with self.lock:
            if self.collector:
                self.collector.stop()
            self.collector = Collector(self.store, self.geo, self.settings.all(), log)
            # 1.1.0：升级后给历史 Web 事件补协议 / 来路 / 会话字段。
            # dedup 键含 raw，旧行不会被重复 INSERT，只做按 dedup 的精确 UPDATE。
            # 真机旧库实测 243349 行，解析 + UPDATE 需数十秒；必须放后台线程，
            # 否则 serve() 在 bind socket 之前被阻塞，应用中心健康检查会超时。
            self._spawn_web_upgrade()
            self.collector.start(do_backfill=backfill)
        # 1.1.1：在线校验队列已从启动关键路径移到 warmup() 末尾排队。
        return self.collector

    def _spawn_web_upgrade(self):
        """后台补历史字段，不占启动关键路径；meta / 标志位双重防重复。"""
        if self._upgrade_running or self.store.get_meta("web_fields_v110") == "1":
            return
        self._upgrade_running = True
        c = self.collector

        def run():
            try:
                _up = self.store.upgrade_web_events(c.parse_web)
                log("upgrade_web_events: %s" % json.dumps(_up, ensure_ascii=False))
            except Exception as e:
                log("upgrade_web_events error: %s" % e)
            finally:
                with self.lock:
                    self._upgrade_running = False
        threading.Thread(target=run, name="web-fields-upgrade", daemon=True).start()

    def reload_collector(self):
        log("reload collector after config change")
        return self.start_collector(backfill=False)

    def trigger_backfill(self, force=True):
        """后台全量回填历史日志，不阻塞 HTTP 服务。"""
        def run():
            try:
                c = Collector(self.store, self.geo, self.settings.all(), log)
                n = c.backfill(force=force)
                log("manual backfill finished: %d events" % n)
            except Exception as e:
                log("manual backfill error: %s" % e)
        threading.Thread(target=run, name="backfill-manual", daemon=True).start()
        return True

    def close(self):
        try:
            self.collector.stop()
        except Exception:
            pass
        try:
            self.verifier.stop_evt.set()
        except Exception:
            pass
        try:
            self.summary.stop()
        except Exception:
            pass
        self.store.close()


# ---------------- HTTP ----------------
def qs(query):
    d = urllib.parse.parse_qs(query or "", keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in d.items()}


def api(app, method, path, query, body):
    p = qs(query)
    rng = p.get("rng") or app.settings.get("chart_range", "24h")

    if path == "/api/health":
        return 200, {"ok": True, "app": APP_NAME, "version": VERSION,
                     "uptime": round(time.time() - app.started, 1),
                     "geo_ready": app.geo.ready, "time": time.time()}
    if path == "/api/status":
        return 200, {"ok": True, "data": app.store.status(rng),
                     "sources": app.sources_safe(), "sources_stat": app.store.sources_stat(),
                     "geo_verify": app.verifier.stats() if app.verifier else None}
    if path == "/api/trend":
        return 200, {"ok": True, "data": app.store.trend(rng)}
    if path == "/api/ranking":
        return 200, {"ok": True, "data": app.store.ranking(rng, int(p.get("limit", 12) or 12))}
    # 1.1.0：一份 combined 日志派生出的五组视图。细粒度接口与总览共用同一次聚合，
    # 前端默认只请求 /api/web/overview，避免高频轮询把三张卡刷满。
    if path in ("/api/web/overview", "/api/protocols", "/api/referrers",
                "/api/pages", "/api/devices"):
        ov = app.store.web_overview(rng, int(p.get("limit", 10) or 10))
        if path == "/api/web/overview":
            return 200, {"ok": True, "data": ov}
        if path == "/api/protocols":
            return 200, {"ok": True, "data": {
                "protocols": ov["protocols"], "protocol_verdict": ov["protocol_verdict"],
                "summary": ov["summary"]}}
        if path == "/api/referrers":
            return 200, {"ok": True, "data": {
                "referrers": ov["referrers"], "sessions": ov["summary"]["sessions"]}}
        if path == "/api/pages":
            return 200, {"ok": True, "data": {
                "pages": ov["pages"], "entries": ov["entries"]}}
        return 200, {"ok": True, "data": {"devices": ov["devices"]}}
    # 1.1.3：五张分析卡的条目下钻。只放行白名单维度，name 由前端从卡片条目原样带回，
    # 后端用与 web_overview 相同的归一化函数反查原始键，不信任任何 SQL 片段。
    if path == "/api/web/breakdown":
        dim = p.get("dim", "")
        name = p.get("name", "")
        if dim not in ("proto", "referer", "page", "entry", "device"):
            return 400, {"ok": False, "msg": "未知维度"}
        if not name:
            return 400, {"ok": False, "msg": "缺少条目名称"}
        return 200, {"ok": True, "data": app.store.web_breakdown(
            dim, name, rng, min(200, int(p.get("limit", 50) or 50)))}
    if path == "/api/geodist":
        scope = p.get("scope", "all")
        if scope not in ("cn", "overseas", "all"):
            scope = "all"
        # 只返回聚合数字与内置中心点坐标，不产出任何边界 / 区划轮廓数据
        return 200, {"ok": True, "data": app.store.geo_distribution(
            rng, scope, int(p.get("limit", 40) or 40))}
    if path == "/api/records":
        return 200, {"ok": True, "data": app.store.records(
            page=int(p.get("page", 1) or 1), size=min(100, int(p.get("size", 20) or 20)),
            scope=p.get("scope", ""), verdict=p.get("verdict", ""),
            source=p.get("source", ""), q=p.get("q", ""), rng=p.get("range", "all"),
            proto=p.get("proto", ""))}
    if path == "/api/events":
        return 200, {"ok": True, "data": app.store.events_since(
            int(p.get("since", 0) or 0), min(500, int(p.get("limit", 200) or 200)))}
    if path == "/api/live":
        lim = min(200, int(p.get("limit", 80) or 80))
        return 200, {"ok": True,
                     "data": app.collector.live(lim) if app.collector else []}
    if path == "/api/hotspots":
        return 200, {"ok": True, "data": app.store.hotspots(rng, min(200, int(p.get("limit", 120) or 120))),
                     "home": {"lat": app.settings.get("home_lat"), "lng": app.settings.get("home_lng"),
                              "label": app.settings.get("home_label")},
                     "map_configured": app.settings.map_configured()}
    if path == "/api/ip":
        ip = p.get("ip", "")
        if not ip:
            return 400, {"ok": False, "msg": "缺少 ip"}
        win = p.get("window", "")
        detail = app.store.ip_detail(ip, int(win) if win.isdigit() else None)
        return 200, {"ok": True, "data": detail, "geo": app.geo.lookup(ip),
                     "verification": app.verifier.details(ip) if app.verifier else None}
    if path == "/api/group" and method == "POST":
        # 地图圆点点击：按一组 IP 取回该来源点的逐条连接时间
        try:
            payload = json.loads(body.decode("utf-8", "replace") or "{}")
            if not isinstance(payload, dict):
                raise ValueError("请求体必须是 JSON 对象")
            ips = payload.get("ips") or []
            if not isinstance(ips, list) or not ips:
                raise ValueError("缺少 ips 列表")
            ips = [str(x) for x in ips if isinstance(x, (str, int))][:200]
            if not ips:
                raise ValueError("ips 列表为空")
            return 200, {"ok": True, "data": app.store.group_detail(
                ips, payload.get("rng", "all"), min(120, int(payload.get("limit", 40) or 40)))}
        except Exception as e:
            return 400, {"ok": False, "msg": str(e)}
    if path == "/api/geo":
        ip = p.get("ip", "")
        return 200, {"ok": True, "data": app.geo.lookup(ip),
                     "verification": app.verifier.details(ip) if app.verifier else None}
    if path == "/api/geo/verify":
        ip = p.get("ip", "")
        if not ip:
            return 400, {"ok": False, "msg": "缺少 ip"}
        if not app.verifier:
            return 503, {"ok": False, "msg": "多源校验器未就绪"}
        force = p.get("force", "").lower() in ("1", "true", "yes")
        return 200, app.verifier.verify(ip, force=force)
    if path == "/api/geo/detail":
        ip = p.get("ip", "")
        return 200, {"ok": True,
                     "data": app.verifier.details(ip) if app.verifier else None}
    if path == "/api/geo/sources":
        return 200, {"ok": True,
                     "data": app.verifier.stats() if app.verifier else {"enabled": False},
                     "cache": app.store.geo_cache_stats()}
    if path == "/api/geo/refresh" and method == "POST":
        if not app.verifier:
            return 503, {"ok": False, "msg": "多源校验器未就绪"}
        n = app.verifier.queue_top(
            int(app.settings.get("geo_verify_batch", 60) or 60))
        return 200, {"ok": True, "queued": n,
                     "msg": "已把 %d 个高频公网 IP 加入后台校验队列" % n}
    if path == "/api/geo/normalize" and method == "POST":
        # 1.0.9：手动重跑历史事件 / 缓存的归一定正
        r = app.store.normalize_events(force=True)
        try:
            app.geo.cache.clear()
        except Exception:
            pass
        return 200, {"ok": True, "data": r, "msg": "历史归属脏值订正完成"}
    if path == "/api/sources":
        return 200, {"ok": True, "data": app.sources_safe(),
                     "stat": app.store.sources_stat(),
                     "geo_verify": app.verifier.stats() if app.verifier else None}
    if path == "/api/config":
        if method == "POST":
            try:
                patch = json.loads(body.decode("utf-8", "replace") or "{}")
                if not isinstance(patch, dict):
                    raise ValueError("配置必须是 JSON 对象")
                cur = app.settings.all()
                if any(k in patch and patch[k] != cur.get(k)
                       for k in ("home_lat", "home_lng", "home_label")):
                    patch["home_source"] = "manual"
                changed = app.settings.update(patch)
                app.store.keep_days = int(app.settings.get("keep_days", 30) or 30)
                app.reload_collector()
                # 1.1.9：保存位置 / 开关 / 间隔一变，立即后台生成一份，
                # 用户不用等下一个周期就能把最新日志交给 AI。
                if any(k in changed for k in ("summary_dir", "summary_enabled",
                                              "summary_interval", "summary_range")):
                    def _gen_now():
                        try:
                            d = app.settings.get("summary_dir", "")
                            if d and app.settings.get("summary_enabled", True):
                                info = app.summary.generate(
                                    d, app.settings.get("summary_range", "24h"))
                                log("summary auto-generate: %s bytes -> %s" % (
                                    info["bytes"], info["latest"]))
                        except Exception as e:
                            log("summary auto-generate error: %s" % e)
                    threading.Thread(target=_gen_now, name="ipsense-summary-now",
                                     daemon=True).start()
                return 200, {"ok": True, "changed": changed, "need_restart": False,
                             "msg": "配置已保存，采集器已重载"}
            except Exception as e:
                return 400, {"ok": False, "msg": str(e)}
        cfg = app.settings.all()
        cfg["map_configured"] = app.settings.map_configured()
        cfg["map_key_placeholder"] = MAP_KEY_PLACEHOLDER
        # 1.1.8：下发合规预设表（只含占位符说明，不含任何有效 KEY）
        cfg["map_providers"] = app.settings.provider_list()
        p = app.settings.current_provider()
        cfg["map_provider"] = p.get("id")
        cfg["map_engine"] = p.get("engine")
        cfg["map_sdk_url"] = app.settings.current_sdk_url("__ipsenseMapReady__")
        # 1.1.9：汇总日志状态（目录有效性 / 上次写入 / 下次时间）随配置下发
        cfg["summary"] = app.summary.status(app.settings.all())
        return 200, {"ok": True, "data": cfg}
    if path == "/api/map/providers":
        # 只读：预设 + 自定义 + 当前选择，供设置界面与自动化验收使用
        p = app.settings.current_provider()
        return 200, {"ok": True, "data": {
            "providers": app.settings.provider_list(),
            "current": p.get("id"), "engine": p.get("engine"),
            "configured": app.settings.map_configured(),
            "sdk_url": app.settings.current_sdk_url("__ipsenseMapReady__"),
            "placeholder": MAP_KEY_PLACEHOLDER,
        }}
    if path == "/api/mapkey":
        configured = app.settings.map_configured()
        return 200, {"ok": True, "configured": configured,
                     "key": app.settings.provider_key() if configured else ""}
    if path == "/api/locate":
        if method == "POST":
            try:
                r = locate_run(app)
                log("locate: ip=%s proxy=%s ok=%s" % (
                    r.get("ip", ""), r.get("proxy_ip", ""), r.get("ok")))
                return 200, r
            except Exception as e:
                log("locate error: %s" % traceback.format_exc())
                return 200, {"ok": False, "msg": "定位异常：%s" % e}
        return 200, {"ok": True, "data": locate_current(app)}
    if path == "/api/reload" and method == "POST":
        app.reload_collector()
        return 200, {"ok": True, "msg": "采集器已重载"}
    if path == "/api/backfill" and method == "POST":
        app.trigger_backfill(force=True)
        return 200, {"ok": True, "msg": "历史日志回填已在后台启动，稍等片刻刷新页面"}
    # ---- 1.1.9：软件汇总日志（给 AI 做设备防护分析） ----
    if path == "/api/summary/status":
        return 200, {"ok": True, "data": app.summary.status(app.settings.all())}
    if path == "/api/summary/preview":
        rng = p.get("rng") or app.settings.get("summary_range", "24h")
        text = build_summary(app, rng)
        return 200, {"ok": True, "data": {
            "text": text, "range": rng,
            "bytes": len(text.encode("utf-8")), "lines": text.count("\n"),
        }}
    if path == "/api/summary/validate" and method == "POST":
        try:
            payload = json.loads(body.decode("utf-8", "replace") or "{}")
            if not isinstance(payload, dict):
                payload = {}
        except Exception:
            payload = {}
        raw = str(payload.get("path", "") or "")
        ok, reason, real = validate_dir(raw)
        return 200, {"ok": ok, "reason": reason, "path": real,
                     "allowed": path_allowed(raw.strip())}
    if path == "/api/summary/generate" and method == "POST":
        try:
            payload = json.loads(body.decode("utf-8", "replace") or "{}")
            if not isinstance(payload, dict):
                payload = {}
            d = str(payload.get("dir") or app.settings.get("summary_dir", "") or "").strip()
            rng = str(payload.get("rng") or app.settings.get("summary_range", "24h"))
            info = write_summary(app, d, build_summary(app, rng))
            app.summary.mark(info)
            return 200, {"ok": True, "data": info, "msg": "汇总日志已生成"}
        except Exception as e:
            app.summary.mark(None, str(e))
            return 400, {"ok": False, "msg": str(e)}
    if path == "/api/summary/download":
        rng = p.get("rng") or app.settings.get("summary_range", "24h")
        return 200, build_summary(app, rng).encode("utf-8"), "text/markdown; charset=utf-8"
    if path == "/api/export":
        rec = app.store.records(page=1, size=100000, rng=p.get("range", rng))
        lines = ["时间,来源,IP,归属,范围,协议,判定,端口,服务,状态码,来路,动作,路径"]
        for r in rec["rows"]:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
            vals = [ts, r["source"], r["ip"],
                    "%s/%s/%s" % (r["country"], r["province"], r["city"]),
                    r["scope"], r.get("proto") or "unknown", r["verdict"],
                    str(r["port"]), r["service"], str(r.get("status") or ""),
                    r.get("referer") or "", r["action"], r["path"]]
            lines.append(",".join('"%s"' % str(v).replace('"', '""') for v in vals))
        return 200, ("\ufeff" + "\n".join(lines)).encode("utf-8"), "text/csv; charset=utf-8"
    return 404, {"ok": False, "msg": "未知接口: %s" % path}


def render_index():
    """首页把 CSS/JS 内联下发：iframe 的票据只存在于页面 URL 的查询串里，
    单独的静态资源请求不带票据，容易被网关判为 invalid token。"""
    def rd(name):
        with open(os.path.join(UI_DIR, name), "r", encoding="utf-8") as f:
            return f.read()
    html = rd("index.html")
    return html.replace("/*__CSS__*/", rd("style.css")).replace("/*__JS__*/", rd("app.js")).encode("utf-8")


def static_file(rel):
    rel = rel.lstrip("/")
    if not rel or rel.endswith("/"):
        rel += "index.html"
    safe = os.path.normpath(rel)
    if safe.startswith("..") or os.path.isabs(safe):
        return None
    path = os.path.join(UI_DIR, safe)
    if not path.startswith(UI_DIR) or not os.path.isfile(path):
        return None
    return path


def send(conn, status, ctype, data):
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
              500: "Internal Server Error"}.get(status, "OK")
    head = ("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
            "Cache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n" % (status, reason, ctype, len(data)))
    try:
        conn.sendall(head.encode("latin1") + data)
    except Exception:
        pass


def handle_conn(conn, app):
    try:
        conn.settimeout(20)
        f = conn.makefile("rb")
        first = f.readline()
        if not first:
            return
        clen = 0
        while True:
            h = f.readline()
            if not h or h in (b"\r\n", b"\n"):
                break
            if h.lower().startswith(b"content-length:"):
                try:
                    clen = int(h.split(b":", 1)[1].strip())
                except ValueError:
                    clen = 0
        parts = first.decode("latin1").strip().split()
        method = parts[0] if parts else "GET"
        target = parts[1] if len(parts) > 1 else "/"
        path, _, query = target.partition("?")
        if path.startswith(PREFIX):                 # ★ 剥掉网关前缀
            path = path[len(PREFIX):] or "/"
        body = f.read(clen) if clen > 0 else b""
        if path.startswith("/api/"):
            try:
                r = api(app, method, path, query, body)
                if len(r) == 3:
                    status, payload, ctype = r
                else:
                    status, payload = r
                    ctype = "application/json; charset=utf-8"
                if isinstance(payload, (dict, list)):
                    payload = json.dumps(payload, ensure_ascii=False,
                                         default=str).encode("utf-8")
                send(conn, status, ctype, payload)
            except Exception as e:
                log("api error %s: %s\n%s" % (path, e, traceback.format_exc()))
                send(conn, 500, "application/json; charset=utf-8",
                     json.dumps({"ok": False, "msg": str(e)}, ensure_ascii=False).encode("utf-8"))
            return
        if path in ("/", "/index.html"):
            try:
                send(conn, 200, "text/html; charset=utf-8", render_index())
            except Exception as e:
                log("index render error: %s" % e)
                send(conn, 500, "text/plain; charset=utf-8", str(e).encode("utf-8"))
            return
        fp = static_file(path)
        if not fp:
            send(conn, 404, "text/plain; charset=utf-8", b"404 Not Found")
            return
        ext = os.path.splitext(fp)[1].lower()
        with open(fp, "rb") as g:
            data = g.read()
        send(conn, 200, MIME.get(ext, "application/octet-stream"), data)
    except Exception as e:
        log("conn error: %s" % e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve():
    app = App()
    # 1.1.1：先 bind / listen，让应用中心健康检查与首页立即可用。
    # 采集器启动、历史回填、在线校验队列、首屏聚合预热全部放到后台线程；
    # 旧版这些同步步骤会让 socket 晚约 8 秒才创建。
    try:
        os.unlink(SOCK_PATH)
    except OSError:
        pass
    os.makedirs(os.path.dirname(SOCK_PATH), exist_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    srv.listen(64)
    os.chmod(SOCK_PATH, 0o666)                      # 网关可能以别的用户连入
    log("serving on %s (pid=%d)" % (SOCK_PATH, os.getpid()))
    app.boot_async()

    def bye(signum, frame):
        log("signal %s, shutting down" % signum)
        try:
            os.unlink(SOCK_PATH)
        except OSError:
            pass
        app.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError as e:
            log("accept error: %s" % e)
            time.sleep(0.2)
            continue
        threading.Thread(target=handle_conn, args=(conn, app), daemon=True).start()


# ---------------- 进程管理 ----------------
def read_pid():
    try:
        with open(PID_PATH) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def cmd_start():
    pid = read_pid()
    if alive(pid) and os.path.exists(SOCK_PATH):
        print("already running pid=%d" % pid)
        return 0
    os.makedirs(VAR_DIR, exist_ok=True)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        out = open(LOG_PATH, "a", encoding="utf-8", errors="replace")
    except Exception:
        out = None
    try:
        p = subprocess.Popen([pyexe(), os.path.abspath(__file__), "serve"],
                             stdout=out or subprocess.DEVNULL,
                             stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, cwd=APP_DEST,
                             start_new_session=True)
    except Exception as e:
        log("start failed: %s" % e)
        return 1
    finally:
        if out:
            out.close()
    with open(PID_PATH, "w") as f:
        f.write(str(p.pid))
    for _ in range(40):
        if os.path.exists(SOCK_PATH):
            print("started pid=%d sock=%s" % (p.pid, SOCK_PATH))
            return 0
        time.sleep(0.25)
    log("socket not created within 10s")
    print("start: socket timeout")
    return 1


def cmd_stop():
    pid = read_pid()
    if alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        for _ in range(30):
            if not alive(pid):
                break
            time.sleep(0.2)
        if alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    for p in (SOCK_PATH, PID_PATH):
        try:
            os.unlink(p)
        except OSError:
            pass
    print("stopped")
    return 0


def cmd_status():
    pid = read_pid()
    ok = alive(pid) and os.path.exists(SOCK_PATH)
    print("status=%s pid=%s sock=%s" % ("running" if ok else "stopped", pid,
                                        "yes" if os.path.exists(SOCK_PATH) else "no"))
    return 0 if ok else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd in ("serve", "supervise"):
        serve()
    elif cmd == "start":
        sys.exit(cmd_start())
    elif cmd == "stop":
        sys.exit(cmd_stop())
    elif cmd == "restart":
        cmd_stop()
        time.sleep(0.6)
        sys.exit(cmd_start())
    elif cmd == "status":
        sys.exit(cmd_status())
    elif cmd == "probe":
        print(json.dumps({"app": APP_NAME, "version": VERSION, "dest": APP_DEST,
                          "var": VAR_DIR, "sock": SOCK_PATH, "ui": UI_DIR,
                          "data": DATA_DIR, "python": pyexe(),
                          "xdb": os.path.isfile(os.path.join(DATA_DIR, "ip2region_v4.xdb"))},
                         ensure_ascii=False, indent=2))
    else:
        print("usage: gateway.py {serve|start|stop|restart|status|supervise|probe}")
        sys.exit(2)


if __name__ == "__main__":
    main()
