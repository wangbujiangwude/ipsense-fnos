# -*- coding: utf-8 -*-
"""2.0.0 B3 · 预警检测引擎（严格纯外发）。

红线（与主包一致）：
  · 只观测 · 不封禁 · 不改防火墙 · 不自动处置
  · 只发消息：不读 / 不写提交单与密钥授权状态文件，不调用处置通道，
    不执行系统命令，不改 SSH 授权文件，不读处置结果
  · 预警配置与历史独立落 notify.json / notify_history.json，
    不进主配置的扁平白名单，也不写事件库

两类异常规则（数据口径如实标注，不夸大）：
  ① IP 端口扫描异常：窗口内同一 IP 的 scan/attack/knock 事件条数，
     或涉及的不同目标端口数超阈值。
  ② 大流量上传下载异常：从 Web 事件 raw 解析 Nginx $body_bytes_sent，
     按 IP 求和判下行字节。combined 日志不含请求体，**无法统计上行**，
     因此只判下行，不冒充「上传 + 下载双向」。
"""
import concurrent.futures
import json
import os
import re
import threading
import time
import traceback

import notify

CONFIG_NAME = "notify.json"
HISTORY_NAME = "notify_history.json"
HISTORY_LIMIT = 200
MB = 1024 * 1024

# combined 日志片段："$request" $status $body_bytes_sent
# group(1)=status, group(2)=bytes；bytes 为 "-" 时正则不匹配，按 0 跳过。
_BYTES_RE = re.compile(r'"[^"]*"\s+(\d{3})\s+(\d+)')

RULE_META = [
    {"id": "scan", "label": "IP 端口扫描异常",
     "desc": "窗口内同一 IP 的异常连接（scan / attack / knock）条数，或涉及的"
             "不同目标端口数超阈值，即判定为扫描探测。",
     "fields": [
         {"key": "window", "label": "检测窗口（分钟）", "type": "number", "min": 1, "max": 120},
         {"key": "hits", "label": "异常连接条数阈值", "type": "number", "min": 2, "max": 100000},
         {"key": "ports", "label": "不同端口数阈值", "type": "number", "min": 2, "max": 65535},
     ]},
    {"id": "traffic", "label": "大流量上传下载异常",
     "desc": "按 IP 累加窗口内 Nginx $body_bytes_sent（下行字节）。"
             "combined 日志不含请求体，无法统计上行，故只判下行，不冒充双向流量。",
     "fields": [
         {"key": "window", "label": "检测窗口（分钟）", "type": "number", "min": 1, "max": 120},
         {"key": "mb", "label": "累计下行阈值（MB）", "type": "number", "min": 1, "max": 100000},
         {"key": "single_mb", "label": "单次响应阈值（MB）", "type": "number", "min": 1, "max": 100000},
     ]},
]

DEFAULTS = {
    "enabled": False,          # 默认关闭：不填渠道、不开开关，绝不会偷偷外发
    "interval": 30,            # 检测间隔（秒）
    "cooldown": 300,           # 同规则同 IP 冷却（秒）
    "global_rate": 10,         # 全局每分钟最多发送条数（防渠道限流）
    "rules": {
        "scan": {"enabled": True, "window": 5, "hits": 20, "ports": 8},
        "traffic": {"enabled": True, "window": 5, "mb": 200, "single_mb": 50},
    },
    "channels": [],
}

# 数值钳制：min, max, 默认值
_CLAMP = {
    "interval": (10, 3600, 30), "cooldown": (30, 86400, 300),
    "global_rate": (1, 120, 10),
    "scan.window": (1, 120, 5), "scan.hits": (2, 100000, 20),
    "scan.ports": (2, 65535, 8),
    "traffic.window": (1, 120, 5), "traffic.mb": (1, 100000, 200),
    "traffic.single_mb": (1, 100000, 50),
}


def _defaults():
    return json.loads(json.dumps(DEFAULTS))


def _clamp(key, v, fallback=None):
    lo, hi, dflt = _CLAMP[key]
    try:
        n = int(v)
    except (TypeError, ValueError):
        n = fallback if fallback is not None else dflt
    return lo if n < lo else (hi if n > hi else n)


def _atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


class NotifyConfig(object):
    """独立配置存储。读时脱敏、写时掩码回填，敏感字段不进主日志。"""

    def __init__(self, var_dir):
        self.path = os.path.join(var_dir, CONFIG_NAME)
        self.lock = threading.RLock()
        self.data = _defaults()
        try:
            os.makedirs(var_dir, exist_ok=True)
            if os.path.isfile(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                if isinstance(saved, dict):
                    self._merge(saved)
        except Exception:
            pass
        self._save()

    def _merge(self, saved):
        for k in ("enabled", "interval", "cooldown", "global_rate"):
            if k in saved:
                self.data[k] = (bool(saved[k]) if k == "enabled"
                                else _clamp(k, saved[k]))
        rules = saved.get("rules") or {}
        if isinstance(rules, dict):
            for rid in ("scan", "traffic"):
                r = rules.get(rid) or {}
                if not isinstance(r, dict):
                    continue
                if "enabled" in r:
                    self.data["rules"][rid]["enabled"] = bool(r["enabled"])
                for k in self.data["rules"][rid]:
                    if k != "enabled" and k in r:
                        key = "%s.%s" % (rid, k)
                        self.data["rules"][rid][k] = _clamp(key, r[k])
        chans = saved.get("channels") or []
        if isinstance(chans, list):
            self.data["channels"] = [self._clean_channel(c, {})
                                     for c in chans
                                     if isinstance(c, dict) and
                                     c.get("channel") in notify.CHANNEL_IDS][:50]

    def _clean_channel(self, c, old):
        """只保留该渠道定义的字段 + 公共字段；敏感字段掩码回填。"""
        ch = c.get("channel")
        allowed = set(("id", "channel", "enabled", "title_prefix",
                       "timeout", "retry")) | set(
            f["key"] for f in notify.CHANNEL_MAP[ch]["fields"])
        out = {}
        for k, v in c.items():
            if k not in allowed:
                continue
            if k == "channel":
                out[k] = ch
            elif k == "enabled":
                out[k] = bool(v) if not isinstance(v, str) else \
                    v.lower() in ("1", "true", "yes", "on")
            elif k in notify.SECRET_KEYS:
                # 掩码 = 用户没改，保留旧值；显式空串 = 主动清空。
                out[k] = old.get(k, "") if (v == notify.MASK or v is None) else str(v)[:600]
            elif k in ("timeout", "retry"):
                try:
                    out[k] = int(v)
                except (TypeError, ValueError):
                    out[k] = old.get(k, notify.DEFAULT_TIMEOUT if k == "timeout" else 0)
            else:
                out[k] = str(v)[:600] if not isinstance(v, (int, float)) else v
        if not out.get("id"):
            out["id"] = "ch-" + os.urandom(4).hex()
        # 缺失的敏感字段：编辑时保留旧值，避免一次保存把已存凭证抹掉
        for k in notify.SECRET_KEYS:
            if k in allowed and k not in out and k in old:
                out[k] = old[k]
        out.setdefault("enabled", True)
        out.setdefault("title_prefix", notify.DEFAULT_PREFIX)
        return out

    def _save(self):
        _atomic_write(self.path, self.data)

    def raw(self):
        with self.lock:
            return json.loads(json.dumps(self.data))

    def public(self):
        """下发给 UI：所有敏感字段打码，不泄露 key / token / 口令 / 昵称。"""
        d = self.raw()
        for c in d.get("channels", []):
            for k in notify.SECRET_KEYS:
                if k in c and c[k]:
                    c[k] = notify.MASK
        return d

    def update(self, patch):
        """校验 + 掩码回填 + 落盘。返回变更说明列表。"""
        if not isinstance(patch, dict):
            raise ValueError("配置必须是 JSON 对象")
        with self.lock:
            old_by_id = {c.get("id"): c for c in self.data.get("channels", [])}
            changed = []
            for k in ("enabled", "interval", "cooldown", "global_rate"):
                if k not in patch:
                    continue
                v = bool(patch[k]) if k == "enabled" else _clamp(k, patch[k])
                if self.data.get(k) != v:
                    self.data[k] = v
                    changed.append(k)
            rules = patch.get("rules")
            if isinstance(rules, dict):
                for rid in ("scan", "traffic"):
                    r = rules.get(rid)
                    if not isinstance(r, dict):
                        continue
                    if "enabled" in r:
                        v = bool(r["enabled"])
                        if self.data["rules"][rid]["enabled"] != v:
                            self.data["rules"][rid]["enabled"] = v
                            changed.append("rules.%s.enabled" % rid)
                    for k in self.data["rules"][rid]:
                        if k == "enabled" or k not in r:
                            continue
                        v = _clamp("%s.%s" % (rid, k), r[k])
                        if self.data["rules"][rid][k] != v:
                            self.data["rules"][rid][k] = v
                            changed.append("rules.%s.%s" % (rid, k))
            if "channels" in patch and isinstance(patch["channels"], list):
                new = []
                for c in patch["channels"][:50]:
                    if not isinstance(c, dict) or c.get("channel") not in notify.CHANNEL_IDS:
                        continue
                    old = old_by_id.get(c.get("id")) or {}
                    new.append(self._clean_channel(c, old))
                if new != self.data.get("channels"):
                    self.data["channels"] = new
                    changed.append("channels")
            if changed:
                self._save()
        return changed

    def enabled_channels(self):
        with self.lock:
            return [dict(c) for c in self.data.get("channels", []) if c.get("enabled")]


class Notifier(object):
    def __init__(self, var_dir, store, log):
        self.cfg = NotifyConfig(var_dir)
        self.store = store
        self.log = log
        self.hist_path = os.path.join(var_dir, HISTORY_NAME)
        self.lock = threading.RLock()
        self.tick_lock = threading.Lock()
        self.history = self._load_history()
        self._last_alert = {}       # (rule, ip) -> 上次告警时间戳
        self._sent_ts = []          # 全局速率：最近 60s 的发送时间戳
        self.stop_evt = threading.Event()
        self.thread = None
        self.stats = {"ticks": 0, "alerts": 0, "sent": 0, "failed": 0,
                      "suppressed": 0, "last_tick": 0, "last_error": ""}

    # ---------------- 历史 ----------------
    def _load_history(self):
        try:
            if os.path.isfile(self.hist_path):
                with open(self.hist_path, "r", encoding="utf-8") as f:
                    h = json.load(f)
                return h[:HISTORY_LIMIT] if isinstance(h, list) else []
        except Exception:
            pass
        return []

    def _push_history(self, rec):
        with self.lock:
            self.history.insert(0, rec)
            del self.history[HISTORY_LIMIT:]
            try:
                _atomic_write(self.hist_path, self.history)
            except Exception as e:
                self.log("notify history write error: %s" % e)

    def history_list(self, limit=50):
        with self.lock:
            return [dict(x) for x in self.history[:max(1, min(200, int(limit)))]]

    # ---------------- 生命周期 ----------------
    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_evt.clear()
        self.thread = threading.Thread(target=self._loop, name="ipsense-notify",
                                       daemon=True)
        self.thread.start()
        self.log("notifier started (enabled=%s, interval=%ss)" % (
            self.cfg.raw()["enabled"], self.cfg.raw()["interval"]))

    def stop(self):
        self.stop_evt.set()

    def _loop(self):
        # 启动后先等一个 interval 再首次检测：不拿启动瞬间的历史数据刷告警。
        while not self.stop_evt.is_set():
            interval = max(10, int(self.cfg.raw().get("interval") or 30))
            if self.stop_evt.wait(interval):
                break
            try:
                self.tick()
            except Exception as e:
                self.stats["last_error"] = "%s: %s" % (type(e).__name__, e)
                self.log("notifier tick error: %s" % traceback.format_exc())

    # ---------------- 检测 ----------------
    def detect(self):
        """只做「观测 + 判定」，返回告警候选列表；不发消息、不做任何处置。"""
        c = self.cfg.raw()
        if not c.get("enabled"):
            return []
        now = time.time()
        alerts = []
        r = c["rules"]["scan"]
        if r.get("enabled"):
            since = now - int(r["window"]) * 60
            try:
                for row in self.store.notify_scan_hits(since):
                    if row["hits"] >= int(r["hits"]) or row["ports"] >= int(r["ports"]):
                        alerts.append({
                            "rule": "scan", "ip": row["ip"],
                            "title": "IP 端口扫描异常 · %s" % row["ip"],
                            "text": ("最近 %s 分钟内，来源 %s 产生 %s 条异常连接"
                                     "（scan / attack / knock），涉及 %s 个不同目标端口。"
                                     "最后活跃 %s。仅作观测提醒，未做任何处置。") % (
                                r["window"], row["ip"], row["hits"], row["ports"],
                                time.strftime("%H:%M:%S", time.localtime(row["last_ts"]))),
                            "detail": {"window_min": r["window"],
                                       "hits": row["hits"], "ports": row["ports"],
                                       "sources": row["sources"]},
                        })
            except Exception as e:
                self.log("notify scan detect error: %s" % e)
        r2 = c["rules"]["traffic"]
        if r2.get("enabled"):
            since = now - int(r2["window"]) * 60
            try:
                total, single = {}, {}
                for ip, raw in self.store.notify_traffic_rows(since):
                    m = _BYTES_RE.search(raw or "")
                    if not m:
                        continue
                    b = int(m.group(2))
                    if b <= 0:
                        continue
                    total[ip] = total.get(ip, 0) + b
                    if b > single.get(ip, 0):
                        single[ip] = b
                for ip, v in total.items():
                    if v >= int(r2["mb"]) * MB or \
                       single.get(ip, 0) >= int(r2["single_mb"]) * MB:
                        alerts.append({
                            "rule": "traffic", "ip": ip,
                            "title": "大流量下行异常 · %s" % ip,
                            "text": ("最近 %s 分钟内，%s 累计下行 %.1f MB"
                                     "（Nginx $body_bytes_sent，单条最大 %.1f MB）。"
                                     "combined 日志不含请求体，上行无法统计；"
                                     "仅作观测提醒，未做任何处置。") % (
                                r2["window"], ip, v / float(MB),
                                single.get(ip, 0) / float(MB)),
                            "detail": {"window_min": r2["window"],
                                       "bytes": v, "single_max": single.get(ip, 0)},
                        })
            except Exception as e:
                self.log("notify traffic detect error: %s" % e)
        return alerts

    # ---------------- 发送（纯外发） ----------------
    def _rate_ok(self, limit):
        now = time.time()
        with self.lock:
            self._sent_ts = [t for t in self._sent_ts if now - t < 60]
            return len(self._sent_ts) < int(limit)

    def _mark_sent(self, n=1):
        with self.lock:
            self._sent_ts.extend([time.time()] * n)

    def _cooldown_ok(self, key, cooldown):
        now = time.time()
        with self.lock:
            last = self._last_alert.get(key, 0)
            if now - last < int(cooldown):
                return False
            self._last_alert[key] = now
            # 防止字典无限增长
            if len(self._last_alert) > 2000:
                for k in list(self._last_alert)[:1000]:
                    self._last_alert.pop(k, None)
            return True

    def _send_one(self, ch, title, text):
        try:
            return notify.send(ch["channel"], title, text, ch)
        except Exception as e:
            return {"ok": False, "channel": ch["channel"],
                    "msg": "%s: %s" % (type(e).__name__, e),
                    "raw": None, "retryable": False}

    def _dispatch(self, alert, c):
        """把一条告警发到所有启用渠道。只发消息，绝不触发任何处置。"""
        key = (alert["rule"], alert["ip"])
        if not self._cooldown_ok(key, c["cooldown"]):
            self.stats["suppressed"] += 1
            return {"suppressed": "cooldown"}
        channels = self.cfg.enabled_channels()
        if not channels:
            self.stats["suppressed"] += 1
            return {"suppressed": "no_channel"}
        if not self._rate_ok(c["global_rate"]):
            self.stats["suppressed"] += 1
            return {"suppressed": "rate_limit"}
        results = []
        if len(channels) == 1:
            results.append(self._send_one(channels[0], alert["title"], alert["text"]))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                futs = [ex.submit(self._send_one, ch, alert["title"], alert["text"])
                        for ch in channels]
                for f in futs:
                    try:
                        results.append(f.result())
                    except Exception as e:
                        results.append({"ok": False, "channel": "?",
                                        "msg": str(e), "raw": None})
        self._mark_sent(len(results))
        ok = sum(1 for r in results if r.get("ok"))
        self.stats["sent"] += ok
        self.stats["failed"] += len(results) - ok
        self.stats["alerts"] += 1
        rec = {"at": time.time(), "rule": alert["rule"], "ip": alert["ip"],
               "title": alert["title"], "text": alert["text"],
               "ok": ok, "total": len(results),
               "results": [{"channel": r.get("channel"), "ok": r.get("ok"),
                            "msg": str(r.get("msg", ""))[:200]} for r in results]}
        self._push_history(rec)
        # 主日志只记渠道与成败，绝不落 token / raw / 完整凭证
        self.log("notify sent: rule=%s ip=%s ok=%s/%s channels=%s" % (
            alert["rule"], alert["ip"], ok, len(results),
            ",".join(r.get("channel", "?") for r in results)))
        return rec

    def tick(self):
        """一次检测 + 发送。tick_lock 防 dispatch_now 与后台线程重入。"""
        if not self.tick_lock.acquire(False):
            return {"busy": True}
        try:
            c = self.cfg.raw()
            self.stats["ticks"] += 1
            self.stats["last_tick"] = time.time()
            alerts = self.detect()
            out = []
            for a in alerts[:20]:           # 单次最多 20 条，避免突发刷屏
                out.append(self._dispatch(a, c))
            return {"alerts": len(alerts), "results": out}
        finally:
            self.tick_lock.release()

    def dispatch_now(self):
        return self.tick()

    def test(self, payload):
        """测试发送：只发一条测试消息，不触发检测、不处置任何东西。"""
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是 JSON 对象")
        ch = payload.get("channel") or {}
        chid = ch.get("channel")
        if chid not in notify.CHANNEL_IDS:
            raise ValueError("未知渠道：%s" % chid)
        # 测试也可能带掩码：按 id 从已存配置回填真实凭证
        real = dict(ch)
        for c in self.cfg.raw().get("channels", []):
            if c.get("id") == ch.get("id") and c.get("channel") == chid:
                for k in notify.SECRET_KEYS:
                    if real.get(k) == notify.MASK:
                        real[k] = c.get(k, "")
                break
        r = notify.send(chid, "ipsense 预警通知测试",
                        "这是一条测试消息，用于确认渠道配置可用。"
                        "仅发送提醒，未触发任何处置、未改动防火墙。", real)
        self._push_history({"at": time.time(), "rule": "test", "ip": "",
                            "title": "预警通知测试", "text": "渠道连通性测试",
                            "ok": 1 if r["ok"] else 0, "total": 1,
                            "results": [{"channel": r["channel"], "ok": r["ok"],
                                         "msg": str(r["msg"])[:200]}]})
        return r

    def state(self):
        s = dict(self.stats)
        c = self.cfg.raw()
        s["enabled"] = c["enabled"]
        s["channels_enabled"] = len(self.cfg.enabled_channels())
        s["channels_total"] = len(c["channels"])
        return {"ok": True, "config": self.cfg.public(),
                "channels": notify.public_channels(), "rules": RULE_META,
                "secret_keys": list(notify.SECRET_KEYS),
                "payload_version": notify.PAYLOAD_VERSION,
                "stats": s, "history": self.history_list(50)}
