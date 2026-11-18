# -*- coding: utf-8 -*-
"""SQLite 事件存储与聚合查询（Python 标准库 sqlite3）。"""
import os
import re
import time
import json
import sqlite3
import threading
import datetime
import hashlib

DAY_FMT = "%Y-%m-%d"

# 1.1.0：只做幂等 ADD COLUMN，不重建 events 表、不丢历史事件。
# 首次升级后老行的新字段为空字符串 / 0，由 upgrade_web_events() 用 raw 重新解析补齐。
EXTRA_COLUMNS = (
    ("layer", "TEXT DEFAULT ''"),
    ("proto", "TEXT DEFAULT ''"),
    ("scheme_conf", "TEXT DEFAULT ''"),
    ("method", "TEXT DEFAULT ''"),
    ("status", "INTEGER DEFAULT 0"),
    ("referer", "TEXT DEFAULT ''"),
    ("ua", "TEXT DEFAULT ''"),
    ("sess_id", "TEXT DEFAULT ''"),
    # 1.1.15：区级归属（安徽省合肥市蜀山区）；离线库无区县时留空，不猜值。
    ("district", "TEXT DEFAULT ''"),
)

GEO_CACHE_COLUMNS = (
    ("district", "TEXT DEFAULT ''"),
    ("district_source", "TEXT DEFAULT ''"),
)


def day_of(ts=None):
    return datetime.datetime.fromtimestamp(ts or time.time()).strftime(DAY_FMT)


class Store(object):
    def __init__(self, db_path, keep_days=30):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.keep_days = keep_days
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=15)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()
        self.last_cleanup = 0
        # 1.1.1：聚合结果短 TTL 缓存。真机 24 万行，status / web_overview 等
        # 每次都要做全范围 GROUP BY；首屏与轮询复用同一份计算，数据最多滞后数秒。
        self._cache = {}
        self._cache_lock = threading.Lock()
        self.cache_ttl = 4.0
        # 1.1.7：每个 key 一把「正在后台重算」的锁，防止过期瞬间的并发穿透。
        self._cache_busy = {}
        # 缓存同时过期时最多只允许一个后台重算。否则 6 个聚合线程一起抢
        # store.lock，反而把不走缓存的 events / records 请求堵在后面。
        self._cache_refresh_sem = threading.Semaphore(1)

    def cached(self, key, fn, ttl=None):
        """按 key 缓存聚合结果；命中直接返回，未命中才真正跑 SQL。

        fn() 内部会取 self.lock（RLock 可重入），这里只用另一把短锁保护字典，
        不会和写库互锁。缓存项自带 ttl，启动预热可写入更长有效期。

        1.1.7 stale-while-revalidate：真机 26 万行 + NAS 磁盘，status /
        web_overview 等冷聚合要 4~8 秒，且都排队等同一把 store.lock。旧实现
        缓存一过期就让请求同步等待，首屏 loadAll 一次并发 9 个接口时最慢的
        请求排到 7.75 秒，逼近前端 15 秒超时，偶发就误报「连接失败」。
        现在过期时先返回上一份旧值，另起一个后台线程单独重算（每 key 同时
        只允许一个），页面请求永远不等冷聚合；重算失败保留旧值下轮再试。
        """
        now = time.time()
        life = self.cache_ttl if ttl is None else float(ttl)
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < hit[1]:
                return hit[2]
            if hit:
                guard = self._cache_busy.get(key)
                if guard is None:
                    guard = threading.Lock()
                    self._cache_busy[key] = guard
                if guard.acquire(False):
                    threading.Thread(target=self._refresh_cache,
                                     args=(key, fn, life, guard),
                                     name="ipsense-cache", daemon=True).start()
                return hit[2]
        val = fn()
        with self._cache_lock:
            self._cache[key] = (now, life, val)
        return val

    def _refresh_cache(self, key, fn, life, guard):
        try:
            # 已有别的 key 在重算就跳过本轮；旧值继续可用，下一轮过期时再试。
            # 全局同时只有一个冷聚合占用 store.lock，不会形成锁风暴。
            if not self._cache_refresh_sem.acquire(False):
                return
            try:
                val = fn()
                with self._cache_lock:
                    self._cache[key] = (time.time(), life, val)
            finally:
                self._cache_refresh_sem.release()
        except Exception:
            # 重算失败不动旧值，下一轮过期时自然重试
            pass
        finally:
            guard.release()

    def clear_cache(self):
        with self._cache_lock:
            self._cache.clear()

    def _init_schema(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       REAL NOT NULL,
            day      TEXT NOT NULL,
            source   TEXT NOT NULL,
            ip       TEXT NOT NULL,
            ipver    INTEGER DEFAULT 4,
            country  TEXT, province TEXT, city TEXT, district TEXT, isp TEXT,
            scope    TEXT,
            lat      REAL, lng REAL,
            port     INTEGER,
            service  TEXT,
            action   TEXT,
            verdict  TEXT,
            path     TEXT,
            raw      TEXT,
            dedup    TEXT UNIQUE,
            layer    TEXT DEFAULT '', proto TEXT DEFAULT '', scheme_conf TEXT DEFAULT '',
            method   TEXT DEFAULT '', status INTEGER DEFAULT 0,
            referer  TEXT DEFAULT '', ua TEXT DEFAULT '', sess_id TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
        CREATE INDEX IF NOT EXISTS idx_events_scope ON events(scope, ts);
        CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict, ts);
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip              TEXT PRIMARY KEY,
            country         TEXT, province TEXT, city TEXT, isp TEXT,
            district        TEXT, district_source TEXT,
            label           TEXT, scope TEXT, lat REAL, lng REAL,
            ipver           INTEGER DEFAULT 4,
            local_country   TEXT, local_province TEXT, local_city TEXT,
            sources         TEXT, confidence TEXT,
            disagree        INTEGER DEFAULT 0,
            online_sources  INTEGER DEFAULT 0,
            checked_at      REAL
        );
        """)
        self.conn.commit()
        self._ensure_columns()

    def _ensure_columns(self):
        """升级旧库：逐列检查后 ADD COLUMN，可反复执行；全新库建表时已含这些列。"""
        have = {r["name"] for r in self.conn.execute("PRAGMA table_info(events)").fetchall()}
        added = []
        for name, decl in EXTRA_COLUMNS:
            if name not in have:
                self.conn.execute("ALTER TABLE events ADD COLUMN %s %s" % (name, decl))
                added.append(name)
        have_geo = {r["name"] for r in self.conn.execute(
            "PRAGMA table_info(geo_cache)").fetchall()}
        for name, decl in GEO_CACHE_COLUMNS:
            if name not in have_geo:
                self.conn.execute(
                    "ALTER TABLE geo_cache ADD COLUMN %s %s" % (name, decl))
                added.append("geo_cache." + name)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_proto ON events(proto, ts)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_sess ON events(sess_id, id)")
        self.conn.commit()
        return added

    @staticmethod
    def dedup_key(ts, source, ip, raw):
        key = "%s|%s|%s|%s" % (round(float(ts), 2), source, ip, (raw or "")[:240])
        return hashlib.md5(key.encode("utf-8", "replace")).hexdigest()[:20]

    INSERT_SQL = ("INSERT OR IGNORE INTO events "
                  "(ts,day,source,ip,ipver,country,province,city,district,isp,scope,lat,lng,"
                  "port,service,action,verdict,path,raw,dedup,"
                  "layer,proto,scheme_conf,method,status,referer,ua,sess_id) "
                  "VALUES (" + ",".join(["?"] * 28) + ")")

    def _row(self, ev):
        ts = float(ev.get("ts") or time.time())
        raw = (ev.get("raw") or "")[:600]
        dk = self.dedup_key(ts, ev.get("source", ""), ev.get("ip", ""), raw)
        return (
            ts, day_of(ts), ev.get("source", "unknown"), ev.get("ip", ""),
            ev.get("ipver", 4), ev.get("country", ""), ev.get("province", ""),
            ev.get("city", ""), ev.get("district", ""), ev.get("isp", ""),
            ev.get("scope", "unknown"),
            ev.get("lat"), ev.get("lng"), ev.get("port") or 0,
            ev.get("service", ""), ev.get("action", ""), ev.get("verdict", "normal"),
            (ev.get("path") or "")[:300], raw, dk,
            ev.get("layer", "") or "", ev.get("proto", "") or "",
            ev.get("scheme_conf", "") or "", (ev.get("method") or "")[:16],
            int(ev.get("status") or 0), (ev.get("referer") or "")[:300],
            (ev.get("ua") or "")[:300], ev.get("sess_id", "") or "",
        )

    def insert(self, ev):
        with self.lock:
            cur = self.conn.execute(self.INSERT_SQL, self._row(ev))
            self.conn.commit()
            return cur.rowcount > 0

    def insert_batch(self, events):
        """一次 commit 批量写入，日志洪峰时也不会拖垮 SQLite。"""
        if not events:
            return 0
        rows = [self._row(ev) for ev in events]
        with self.lock:
            before = self.conn.total_changes
            try:
                self.conn.executemany(self.INSERT_SQL, rows)
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
            return self.conn.total_changes - before

    def get_meta(self, k, default=""):
        with self.lock:
            r = self.conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
            return r["v"] if r else default

    def set_meta(self, k, v):
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO meta(k,v) VALUES (?,?)", (k, str(v)))
            self.conn.commit()

    def cleanup(self, force=False):
        now = time.time()
        if not force and now - self.last_cleanup < 3600:
            return 0
        self.last_cleanup = now
        cut = now - self.keep_days * 86400
        with self.lock:
            cur = self.conn.execute("DELETE FROM events WHERE ts < ?", (cut,))
            self.conn.commit()
            return cur.rowcount

    # ---- 查询 ----
    def _range(self, rng):
        now = time.time()
        table = {"1h": 3600, "6h": 21600, "24h": 86400, "today": None,
                 "7d": 7 * 86400, "30d": 30 * 86400, "all": 0}
        if rng == "today":
            d = datetime.date.today()
            start = time.mktime(d.timetuple())
            return start, now
        sec = table.get(rng, 86400)
        return (now - sec if sec else 0), now

    def status(self, rng="24h", _ttl=None):
        return self.cached("status|%s" % rng,
                           lambda: self._status_uncached(rng), _ttl)

    def _status_uncached(self, rng="24h"):
        start, end = self._range(rng)
        with self.lock:
            c = self.conn.cursor()
            total = c.execute("SELECT COUNT(*) FROM events WHERE ts>=?", (start,)).fetchone()[0]
            uniq = c.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ts>=?", (start,)).fetchone()[0]
            by_scope = {r[0]: r[1] for r in c.execute(
                "SELECT scope,COUNT(*) FROM events WHERE ts>=? GROUP BY scope", (start,))}
            by_verdict = {r[0]: r[1] for r in c.execute(
                "SELECT verdict,COUNT(*) FROM events WHERE ts>=? GROUP BY verdict", (start,))}
            by_source = {r[0]: r[1] for r in c.execute(
                "SELECT source,COUNT(*) FROM events WHERE ts>=? GROUP BY source", (start,))}
            last = c.execute("SELECT ts,ip,scope,verdict FROM events ORDER BY id DESC LIMIT 1").fetchone()
            minute = c.execute("SELECT COUNT(*) FROM events WHERE ts>=?", (time.time() - 60,)).fetchone()[0]
            oldest = c.execute("SELECT MIN(ts) FROM events").fetchone()[0]
        return {
            "range": rng, "total": total, "unique_ip": uniq,
            "cn": by_scope.get("cn", 0), "overseas": by_scope.get("overseas", 0),
            "private": by_scope.get("private", 0), "lan": by_scope.get("lan", 0),
            "unknown": by_scope.get("unknown", 0),
            "normal": by_verdict.get("normal", 0), "scan": by_verdict.get("scan", 0),
            "attack": by_verdict.get("attack", 0), "knock": by_verdict.get("knock", 0),
            "by_source": by_source, "per_minute": minute,
            "last": dict(last) if last else None,
            "oldest": oldest,
        }

    def trend(self, rng="24h", _ttl=None):
        return self.cached("trend|%s" % rng,
                           lambda: self._trend_uncached(rng), _ttl)

    def _trend_uncached(self, rng="24h"):
        start, end = self._range(rng)
        span = max(60, end - start)
        bucket = 60 if span <= 3600 else (300 if span <= 21600 else (3600 if span <= 172800 else 21600))
        b0 = int(start // bucket) * bucket
        rows = {}
        with self.lock:
            for r in self.conn.execute(
                "SELECT CAST(ts/? AS INTEGER)*? AS b, scope, COUNT(*) n "
                "FROM events WHERE ts>=? GROUP BY b, scope", (bucket, bucket, start)):
                b = r["b"] * bucket
                rows.setdefault(b, {"t": b, "all": 0, "cn": 0, "overseas": 0,
                                    "private": 0, "scan": 0})
                k = r["scope"] or "unknown"
                if k == "lan":
                    k = "private"   # 趋势图沿用原有「内网」曲线，避免新增未识别的系列
                rows[b][k] = rows[b].get(k, 0) + r["n"]
                rows[b]["all"] += r["n"]
            for r in self.conn.execute(
                "SELECT CAST(ts/? AS INTEGER)*? AS b, COUNT(*) n FROM events "
                "WHERE ts>=? AND verdict IN ('scan','attack','knock') GROUP BY b",
                    (bucket, bucket, start)):
                b = r["b"] * bucket
                rows.setdefault(b, {"t": b, "all": 0, "cn": 0, "overseas": 0,
                                    "private": 0, "scan": 0})
                rows[b]["scan"] = r["n"]
        out = [rows[k] for k in sorted(rows)]
        return {"bucket": bucket, "start": start, "end": end, "points": out}

    def ranking(self, rng="24h", limit=12, _ttl=None):
        return self.cached("ranking|%s|%s" % (rng, limit),
                           lambda: self._ranking_uncached(rng, limit), _ttl)

    def _ranking_uncached(self, rng="24h", limit=12):
        start, _ = self._range(rng)
        out = {"cn": [], "overseas": []}
        with self.lock:
            for r in self.conn.execute(
                "SELECT COALESCE(NULLIF(province,''),'未细分') k, COUNT(*) n, "
                "COUNT(DISTINCT ip) ips FROM events WHERE ts>=? AND scope='cn' "
                "GROUP BY k ORDER BY n DESC LIMIT ?", (start, limit)):
                out["cn"].append({"name": r["k"], "count": r["n"], "ips": r["ips"]})
            for r in self.conn.execute(
                "SELECT COALESCE(NULLIF(country,''),'未知') k, COUNT(*) n, "
                "COUNT(DISTINCT ip) ips FROM events WHERE ts>=? AND scope='overseas' "
                "GROUP BY k ORDER BY n DESC LIMIT ?", (start, limit)):
                out["overseas"].append({"name": r["k"], "count": r["n"], "ips": r["ips"]})
        return out

    RECORD_COLS = ("id,ts,source,ip,country,province,city,district,isp,scope,lat,lng,port,"
                   "service,action,verdict,path,layer,proto,scheme_conf,method,status,"
                   "referer,ua,sess_id")

    def records(self, page=1, size=20, scope="", verdict="", source="", q="",
                rng="all", proto=""):
        start, _ = self._range(rng)
        where, args = ["ts>=?"], [start]
        if scope:
            where.append("scope=?"); args.append(scope)
        if verdict:
            where.append("verdict=?"); args.append(verdict)
        if source:
            where.append("source=?"); args.append(source)
        if proto:
            where.append("proto=?"); args.append(proto)
        if q:
            where.append("(ip LIKE ? OR country LIKE ? OR province LIKE ? OR city LIKE ? OR path LIKE ?)")
            args += ["%" + q + "%"] * 5
        w = " AND ".join(where)
        with self.lock:
            total = self.conn.execute("SELECT COUNT(*) FROM events WHERE " + w, args).fetchone()[0]
            rows = self.conn.execute(
                "SELECT " + self.RECORD_COLS + " FROM events WHERE " + w +
                " ORDER BY id DESC LIMIT ? OFFSET ?", args + [size, (page - 1) * size]).fetchall()
        return {"total": total, "page": page, "size": size,
                "rows": [dict(r) for r in rows]}

    def events_since(self, since_id=0, limit=200):
        with self.lock:
            rows = self.conn.execute(
                "SELECT " + self.RECORD_COLS + " FROM events WHERE id>? ORDER BY id ASC LIMIT ?",
                (since_id, limit)).fetchall()
            last = self.conn.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
        return {"last_id": last, "events": [dict(r) for r in rows]}

    def hotspots(self, rng="24h", limit=120, _ttl=None):
        return self.cached("hotspots|%s|%s" % (rng, limit),
                           lambda: self._hotspots_uncached(rng, limit), _ttl)

    def _hotspots_uncached(self, rng="24h", limit=120):
        """地图用的活跃来源点（按 IP 聚合，带坐标）。"""
        start, _ = self._range(rng)
        with self.lock:
            rows = self.conn.execute(
                "SELECT ip, MAX(country) country, MAX(province) province, MAX(city) city, "
                "MAX(district) district, "
                "MAX(scope) scope, MAX(lat) lat, MAX(lng) lng, COUNT(*) n, "
                "MAX(verdict) verdict, MAX(ts) last_ts, MAX(id) last_id "
                "FROM events WHERE ts>=? AND lat IS NOT NULL "
                "GROUP BY ip ORDER BY n DESC LIMIT ?", (start, limit)).fetchall()
        return [dict(r) for r in rows]

    # 1.1.1：画像明细的统计窗口。真机热点 IP 可达 19.7 万行，原来 8 条
    # 全历史 GROUP BY / COUNT(DISTINCT ...) 合计约 3.5 s；改为一次按 id 倒序
    # 取窗口（实测 0.041 s）+ Python 内存计数后，端到端约 0.1 s。
    IP_DETAIL_WINDOW = 3000
    GROUP_DETAIL_WINDOW = 3000

    def ip_detail(self, ip, window=None):
        """IP 来源画像：累计次数 / 首末次取全历史精确值，明细在最近窗口内聚合。

        未超过窗口的 IP（绝大多数）语义与旧版完全一致；只有超高频热点 IP 的
        TOP 榜改为「最近 N 条」，并在 window 字段标注口径供前端如实展示。
        """
        win = max(200, min(10000, int(window or self.IP_DETAIL_WINDOW)))
        with self.lock:
            base = self.conn.execute(
                "SELECT COUNT(*) n, MIN(ts) first_ts, MAX(ts) last_ts "
                "FROM events WHERE ip=?", (ip,)).fetchone()
            rows = self.conn.execute(
                "SELECT * FROM events WHERE ip=? ORDER BY id DESC LIMIT ?",
                (ip, win)).fetchall()
        head = dict(rows[0]) if rows else {}
        agg = {"n": base["n"] or 0, "first_ts": base["first_ts"],
               "last_ts": base["last_ts"], "ports": 0, "paths": 0, "sessions": 0}
        if not rows:
            return {"ip": ip, "info": head, "agg": agg, "recent": [],
                    "top_paths": [], "protocols": [], "verdicts": [],
                    "referrers": [], "uas": [],
                    "window": {"rows": 0, "limit": win, "truncated": False}}

        ports, paths, sessions = set(), set(), set()
        cp, cproto, cmanual, cverdict, cref, cua = {}, {}, {}, {}, {}, {}
        recent = []
        for idx, r in enumerate(rows):
            port = r["port"] or 0
            if port:
                ports.add(port)
            path = r["path"] or ""
            if path:
                paths.add(path)
                cp[path] = cp.get(path, 0) + 1
            sess = r["sess_id"] or ""
            if sess:
                sessions.add(sess)
            proto = r["proto"] or "unknown"
            cproto[proto] = cproto.get(proto, 0) + 1
            if (r["scheme_conf"] or "") == "manual":
                cmanual[proto] = cmanual.get(proto, 0) + 1
            verdict = r["verdict"] or "normal"
            cverdict[verdict] = cverdict.get(verdict, 0) + 1
            if (r["layer"] or "") == "web":
                ref = r["referer"] or "-"
                cref[ref] = cref.get(ref, 0) + 1
            ua = r["ua"] or ""
            if ua:
                cua[ua] = cua.get(ua, 0) + 1
            if idx < 20:
                recent.append({k: r[k] for k in (
                    "ts", "source", "port", "service", "action", "verdict",
                    "path", "proto", "scheme_conf", "method", "status",
                    "referer", "ua")})
        agg["ports"], agg["paths"], agg["sessions"] = len(ports), len(paths), len(sessions)
        return {
            "ip": ip,
            "info": head,
            "agg": agg,
            "recent": recent,
            "top_paths": [{"path": k, "n": v} for k, v in
                          sorted(cp.items(), key=lambda x: -x[1])[:8]],
            "protocols": [{"k": k, "n": v, "manual": cmanual.get(k, 0)}
                          for k, v in sorted(cproto.items(), key=lambda x: -x[1])],
            "verdicts": [{"k": k, "n": v} for k, v in
                         sorted(cverdict.items(), key=lambda x: -x[1])],
            "referrers": [{"k": k, "n": v} for k, v in
                          sorted(cref.items(), key=lambda x: -x[1])[:8]],
            "uas": [{"ua": k, "n": v} for k, v in
                    sorted(cua.items(), key=lambda x: -x[1])[:6]],
            "window": {"rows": len(rows), "limit": win,
                       "truncated": (base["n"] or 0) > len(rows)},
        }

    def group_detail(self, ips, rng="all", limit=40, window=None):
        """地图来源点详情：累计值取全历史，明细在最近窗口内聚合。

        ips 来自前端按省/国家合并后的成员列表，保证弹层内容与地图上的圆点严格对应。
        全部使用参数化占位符，避免拼接用户输入。1.1.1 起与单 IP 画像一样窗口化。
        """
        ips = [str(x) for x in (ips or []) if x][:200]
        if not ips:
            return {"ips": [], "total": 0, "first_ts": 0, "last_ts": 0,
                    "recent": [], "top_paths": [],
                    "window": {"rows": 0, "limit": 0, "truncated": False}}
        win = max(200, min(10000, int(window or self.GROUP_DETAIL_WINDOW)))
        start, _ = self._range(rng)
        marks = ",".join("?" for _ in ips)
        args = ips + [start]
        with self.lock:
            base = self.conn.execute(
                "SELECT COUNT(*) n, MIN(ts) first_ts, MAX(ts) last_ts "
                "FROM events WHERE ip IN (%s) AND ts>=?" % marks, args).fetchone()
            rows = self.conn.execute(
                "SELECT * FROM events WHERE ip IN (%s) AND ts>=? "
                "ORDER BY id DESC LIMIT ?" % marks, args + [win]).fetchall()
        sm = {"n": base["n"] or 0, "first_ts": base["first_ts"] or 0,
              "last_ts": base["last_ts"] or 0}
        per_ip, cpath, recent = {}, {}, []
        cap = min(120, max(1, int(limit or 40)))
        for idx, r in enumerate(rows):
            ip = r["ip"]
            a = per_ip.setdefault(ip, {
                "ip": ip, "n": 0, "first_ts": r["ts"], "last_ts": r["ts"],
                "verdict": r["verdict"] or "", "country": r["country"] or "",
                "province": r["province"] or "", "city": r["city"] or "",
                "district": r["district"] or "",
                "isp": r["isp"] or "", "port": r["port"] or 0})
            a["n"] += 1
            if r["ts"] and r["ts"] < a["first_ts"]:
                a["first_ts"] = r["ts"]
            if r["ts"] and r["ts"] > a["last_ts"]:
                a["last_ts"] = r["ts"]
            path = r["path"] or ""
            if path:
                cpath[path] = cpath.get(path, 0) + 1
            if idx < cap:
                recent.append({k: r[k] for k in (
                    "ts", "ip", "source", "port", "service", "action", "verdict",
                    "path", "proto", "scheme_conf", "method", "status", "referer",
                    "country", "province", "city", "isp")})
        return {
            "ips": sorted(per_ip.values(), key=lambda x: -x["n"]),
            "total": sm["n"], "first_ts": sm["first_ts"], "last_ts": sm["last_ts"],
            "recent": recent,
            "top_paths": [{"path": k, "n": v} for k, v in
                          sorted(cpath.items(), key=lambda x: -x[1])[:6]],
            "window": {"rows": len(rows), "limit": win,
                       "truncated": sm["n"] > len(rows)},
        }

    # ---- 多源归属校验缓存（1.0.8）----
    def get_geo_cache(self, ip):
        with self.lock:
            r = self.conn.execute("SELECT * FROM geo_cache WHERE ip=?", (ip,)).fetchone()
        return dict(r) if r else None

    def set_geo_cache(self, ip, geo, vf, local):
        sources = json.dumps(vf.get("sources", []), ensure_ascii=False)
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO geo_cache "
                "(ip,country,province,city,district,district_source,isp,label,scope,lat,lng,ipver,"
                " local_country,local_province,local_city,sources,confidence,"
                " disagree,online_sources,checked_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                    ip, geo.get("country", ""), geo.get("province", ""),
                    geo.get("city", ""), geo.get("district", ""),
                    vf.get("district_source", ""),
                    geo.get("isp", ""), geo.get("label", ""),
                    geo.get("scope", "cn"), geo.get("lat"), geo.get("lng"),
                    geo.get("ipver", 4),
                    local.get("country", ""), local.get("province", ""),
                    local.get("city", ""), sources, vf.get("confidence", "low"),
                    1 if vf.get("disagree") else 0, vf.get("online_sources", 0),
                    vf.get("checked_at", time.time())))
            self.conn.commit()

    def geo_cache_count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM geo_cache").fetchone()[0]

    def geo_cache_stats(self):
        with self.lock:
            r = self.conn.execute(
                "SELECT COUNT(*) n, SUM(CASE WHEN disagree=1 THEN 1 ELSE 0 END) d, "
                "MAX(checked_at) t FROM geo_cache").fetchone()
        return {"count": r["n"] or 0, "disagree": r["d"] or 0,
                "last": r["t"] or 0}

    def apply_geo(self, ip, geo):
        """把多源裁决结果回写到该 IP 的历史公网事件，地图/排名/记录立即生效。"""
        with self.lock:
            cur = self.conn.execute(
                "UPDATE events SET country=?, province=?, city=?, district=?, isp=?, "
                "scope=?, lat=?, lng=? WHERE ip=? AND scope IN ('cn','overseas')",
                (geo.get("country", ""), geo.get("province", ""), geo.get("city", ""),
                 geo.get("district", ""), geo.get("isp", ""),
                 geo.get("scope", "cn"), geo.get("lat"),
                 geo.get("lng"), ip))
            self.conn.commit()
            return cur.rowcount

    def set_district(self, ip, district):
        """手工补充区级归属：事件与缓存一起更新，重载后仍生效。"""
        d = str(district or "").strip()[:40]
        with self.lock:
            cur = self.conn.execute(
                "UPDATE events SET district=? WHERE ip=?", (d, ip))
            self.conn.execute(
                "UPDATE geo_cache SET district=?, district_source=? WHERE ip=?",
                (d, "manual", ip))
            self.conn.commit()
            return cur.rowcount

    def normalize_events(self, force=False):
        """一次性订正历史脏值（1.0.9），幂等，结果记入 meta。

        1.0.8 之前写入的事件里有三类遗留问题：
          - IPv6 的 province 被写成「中国」，污染境内省份排名；
          - 境外国家名残留英文（Mauritius 等），当时 ISO_TO_CN 尚不覆盖；
          - 归属已被多源裁决纠正，坐标却沿用旧库省级中心点，
            出现「安徽省」却画在北京 / 广州。
        geo_cache 也要同步，否则 GeoResolver.lookup() 会继续吐旧值。
        """
        if not force and self.get_meta("geo_normalized") == "1":
            return {"skipped": True, "reason": "已订正过"}
        from geoip import COUNTRY_ALIAS, ISO_TO_CN, PROVINCE_COORDS
        from geosource import norm_city
        out = {}
        with self.lock:
            c = self.conn.cursor()
            cur = c.execute(
                "UPDATE events SET province='' "
                "WHERE province IN ('中国','未知','0','内网地址')")
            out["province_cleared"] = cur.rowcount

            rows = c.execute(
                "SELECT DISTINCT country FROM events "
                "WHERE country GLOB '*[A-Za-z]*'").fetchall()
            cmap = {}
            for (name,) in rows:
                n = (name or "").strip()
                if not n:
                    continue
                cn = COUNTRY_ALIAS.get(n.lower()) or ISO_TO_CN.get(n.upper())
                if cn and cn != n:
                    cmap[n] = cn
            fixed = 0
            for src, dst in cmap.items():
                fixed += c.execute("UPDATE events SET country=? WHERE country=?",
                                   (dst, src)).rowcount
            out["country_fixed"] = fixed
            out["country_map"] = cmap

            # 坐标一致性：境内事件按省份中心点重算；无有效省份（IPv6 / 旧库脏值）
            # 统一到中国中心，避免历史 IPv6 全部打在北京金融街。
            from geoip import COUNTRY_COORDS
            cn_center = COUNTRY_COORDS["中国"]
            coord_fixed = 0
            rs = c.execute(
                "SELECT id, ip, province, lat, lng FROM events "
                "WHERE scope='cn' AND lat IS NOT NULL AND lng IS NOT NULL").fetchall()
            for r in rs:
                clat, clng = PROVINCE_COORDS.get(r["province"] or "") or cn_center
                if abs(r["lat"] - clat) <= 3 and abs(r["lng"] - clng) <= 3:
                    continue
                h = int(hashlib.md5(str(r["ip"]).encode()).hexdigest()[:6], 16)
                lat = clat + ((h % 100) / 100.0 - 0.5) * 1.2
                lng = clng + (((h // 100) % 100) / 100.0 - 0.5) * 1.6
                coord_fixed += c.execute(
                    "UPDATE events SET lat=?, lng=? WHERE id=?",
                    (round(lat, 4), round(lng, 4), r["id"])).rowcount
            out["coord_fixed"] = coord_fixed

            # geo_cache 同步：城市名中英归一 + 坐标与省份一致
            cache_fixed = 0
            rs = c.execute(
                "SELECT ip, country, province, city, lat, lng FROM geo_cache").fetchall()
            for r in rs:
                city = norm_city(r["city"] or "")
                prov = r["province"] or ""
                lat, lng = r["lat"], r["lng"]
                center = PROVINCE_COORDS.get(prov) if (r["country"] or "") == "中国" else None
                if center and lat is not None and lng is not None \
                        and (abs(lat - center[0]) > 3 or abs(lng - center[1]) > 3):
                    h = int(hashlib.md5(str(r["ip"]).encode()).hexdigest()[:6], 16)
                    lat = center[0] + ((h % 100) / 100.0 - 0.5) * 1.2
                    lng = center[1] + (((h // 100) % 100) / 100.0 - 0.5) * 1.6
                label = "·".join([x for x in ((r["country"] or ""), prov, city) if x]) \
                        or "未知归属"
                if city != (r["city"] or "") or lat != r["lat"] or lng != r["lng"]:
                    c.execute("UPDATE geo_cache SET city=?, label=?, lat=?, lng=? WHERE ip=?",
                              (city, label,
                               round(lat, 4) if lat is not None else None,
                               round(lng, 4) if lng is not None else None, r["ip"]))
                    cache_fixed += 1
            out["cache_fixed"] = cache_fixed
            self.conn.commit()
        self.set_meta("geo_normalized", "1")
        return out

    def top_public_ips(self, limit=60):
        # 1.1.1：在线校验只需照顾近期活跃的公网 IP。旧实现对全表 24 万行做
        # GROUP BY，启动时约 1~2 s；限定近 7 天后走 idx_events_ts，几乎无感。
        start = time.time() - 7 * 86400
        with self.lock:
            rows = self.conn.execute(
                "SELECT ip FROM events WHERE ts>=? AND scope IN ('cn','overseas') "
                "GROUP BY ip ORDER BY COUNT(*) DESC LIMIT ?", (start, limit)).fetchall()
        return [r["ip"] for r in rows]

    def lan_stat(self, _ttl=None):
        return self.cached("lan_stat", self._lan_stat_uncached, _ttl)

    def _lan_stat_uncached(self):
        with self.lock:
            n = self.conn.execute(
                "SELECT COUNT(*) FROM events WHERE scope='lan'").fetchone()[0]
            ips = self.conn.execute(
                "SELECT COUNT(DISTINCT ip) FROM events WHERE scope='lan'").fetchone()[0]
        return {"count": n, "ips": ips}

    # ---- 1.1.0：协议 / 来路 / 受访页 / 入口页 / 终端设备 / 地域分布 ----
    REF_LOCAL = re.compile(r"^(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)", re.I)
    STATIC_PATH_RE = re.compile(
        r"(?i)\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map|webp)(\?|$)")

    @staticmethod
    def _clean_path(p):
        """受访页 / 入口页按去掉查询串的 path 聚合，避免 ?_=时间戳 刷满榜单。"""
        return (p or "").split("?", 1)[0] or "/"

    @classmethod
    def _ref_name(cls, r):
        """来路归一：无 referer 记为直接输入；同站显示站内路径，外站显示域名。"""
        if not r or r in ("-", ""):
            return "直接输入网址 / 无来路"
        m = re.match(r"^(https?)://([^/]+)(/[^?#]*)?", r, re.I)
        if not m:
            return r[:80]
        host, p = m.group(2), (m.group(3) or "/")
        if cls.REF_LOCAL.match(host.split(":")[0]):
            return ("站内 · " + p) if p != "/" else ("站内首页 · " + host)
        return host

    @staticmethod
    def _ua_name(ua):
        """UA 粗略归一为「浏览器 · 系统」，不做指纹、不回传任何标识。"""
        s = ua or ""
        low = s.lower()
        if "micromessenger" in low:
            b = "微信内置"
        elif "edg/" in low:
            b = "Edge"
        elif "chrome/" in low or "chromium" in low:
            b = "Chrome"
        elif "firefox/" in low:
            b = "Firefox"
        elif "safari/" in low:
            b = "Safari"
        elif "curl/" in low:
            b = "curl"
        elif "python" in low or "go-http" in low or "java/" in low:
            b = "程序客户端"
        elif "bot" in low or "spider" in low or "crawler" in low:
            b = "爬虫 / 机器人"
        else:
            b = "其它客户端"
        if "Windows" in s:
            o = "Windows"
        elif "Android" in s:
            o = "Android"
        elif "iPhone" in s or "iPad" in s:
            o = "iOS"
        elif "Mac OS" in s:
            o = "macOS"
        elif "Linux" in s:
            o = "Linux"
        else:
            o = "未知系统"
        return b + " · " + o

    @classmethod
    def _merge(cls, rows, namefn, limit, skip_static=False):
        """把 SQL 的细粒度分组按展示名二次合并，并剔除静态资源。"""
        acc = {}
        for r in rows:
            raw = r["k"] or ""
            if skip_static and cls.STATIC_PATH_RE.search(raw):
                continue
            name = namefn(raw)
            a = acc.setdefault(name, {"name": name, "count": 0, "ips": 0})
            a["count"] += r["n"]
            a["ips"] = max(a["ips"], r["ips"] or 0)
        return sorted(acc.values(), key=lambda x: -x["count"])[:limit]

    def web_overview(self, rng="24h", limit=10, _ttl=None):
        return self.cached("webov|%s|%s" % (rng, limit),
                           lambda: self._web_overview_uncached(rng, limit), _ttl)

    def _web_overview_uncached(self, rng="24h", limit=10):
        """一份 combined 日志同时喂出：协议构成、来路、受访页、入口页、终端设备。"""
        start, _ = self._range(rng)
        limit = max(3, min(30, int(limit or 10)))
        with self.lock:
            base = self.conn.execute(
                "SELECT COUNT(*) n, COUNT(DISTINCT ip) ips, COUNT(DISTINCT sess_id) sessions "
                "FROM events WHERE ts>=? AND layer='web'", (start,)).fetchone()
            ref_rows = self.conn.execute(
                "SELECT COALESCE(NULLIF(referer,''),'-') k, COUNT(*) n, COUNT(DISTINCT ip) ips "
                "FROM events WHERE ts>=? AND layer='web' "
                "GROUP BY k ORDER BY n DESC LIMIT 300", (start,)).fetchall()
            page_rows = self.conn.execute(
                "SELECT path k, COUNT(*) n, COUNT(DISTINCT ip) ips FROM events "
                "WHERE ts>=? AND layer='web' AND path<>'' "
                "GROUP BY path ORDER BY n DESC LIMIT 400", (start,)).fetchall()
            # 入口页 = 每个会话（ip + UA + 30 分钟桶）的第一条请求，用 MIN(id) 精确定位
            entry_rows = self.conn.execute(
                "SELECT e.path k, COUNT(*) n, COUNT(DISTINCT e.ip) ips FROM events e "
                "JOIN (SELECT sess_id, MIN(id) mid FROM events "
                "      WHERE ts>=? AND layer='web' AND sess_id<>'' GROUP BY sess_id) s "
                "  ON e.id = s.mid WHERE e.path<>'' "
                "GROUP BY e.path ORDER BY n DESC LIMIT 400", (start,)).fetchall()
            proto_rows = self.conn.execute(
                "SELECT COALESCE(NULLIF(proto,''),'unknown') k, COUNT(*) n, "
                "COUNT(DISTINCT ip) ips, "
                "SUM(CASE WHEN scheme_conf='manual' THEN 1 ELSE 0 END) manual, "
                "SUM(CASE WHEN scheme_conf='medium' THEN 1 ELSE 0 END) inferred "
                "FROM events WHERE ts>=? GROUP BY k ORDER BY n DESC", (start,)).fetchall()
            pxv = self.conn.execute(
                "SELECT COALESCE(NULLIF(proto,''),'unknown') p, "
                "COALESCE(NULLIF(verdict,''),'normal') v, COUNT(*) n "
                "FROM events WHERE ts>=? GROUP BY p, v", (start,)).fetchall()
            ua_rows = self.conn.execute(
                "SELECT ua k, COUNT(*) n, COUNT(DISTINCT ip) ips FROM events "
                "WHERE ts>=? AND ua<>'' GROUP BY ua ORDER BY n DESC LIMIT 300",
                (start,)).fetchall()
        return {
            "range": rng,
            "summary": {"requests": base["n"] or 0, "ips": base["ips"] or 0,
                        "sessions": base["sessions"] or 0},
            "referrers": self._merge(ref_rows, self._ref_name, limit),
            "pages": self._merge(page_rows, self._clean_path, limit, True),
            "entries": self._merge(entry_rows, self._clean_path, limit, True),
            "protocols": [{"name": r["k"], "count": r["n"], "ips": r["ips"],
                           "manual": r["manual"] or 0, "inferred": r["inferred"] or 0}
                          for r in proto_rows],
            "protocol_verdict": [{"proto": r["p"], "verdict": r["v"], "count": r["n"]}
                                 for r in pxv],
            "devices": self._merge(ua_rows, self._ua_name, limit),
        }

    def geo_distribution(self, rng="24h", scope="all", limit=40, _ttl=None):
        return self.cached("geodist|%s|%s|%s" % (rng, scope, limit),
                           lambda: self._geo_distribution_uncached(rng, scope, limit),
                           _ttl)

    def _geo_distribution_uncached(self, rng="24h", scope="all", limit=40):
        """地域数量分布：只返回聚合数字 + 内置中心点坐标。

        合规边界：本接口不产出任何边界 / 区划轮廓数据，前端只在腾讯地图合规底图上
        用「按经纬度聚合的气泡」表达数量；无 key 时走不绘国界的 canvas 降级。
        1.1.2：scope=all 为固定全球视图，境内统一归并到「中国」、境外按国家 / 地区，
        一份数据同时包含境内外全部来源，不再需要前端来回切境内 / 全球。
        """
        start, _ = self._range(rng)
        limit = max(5, min(80, int(limit or 40)))
        from geoip import PROVINCE_COORDS, COUNTRY_COORDS
        if scope == "all":
            # 1.1.15：境内不再统一归并成「中国」一个气泡。
            # 同省访问此前在全球视图里完全看不见，现在按省细分；
            # 境外仍按国家 / 地区，并用 sk 标注该行是境内还是境外。
            sql = ("SELECT CASE WHEN scope='cn' THEN "
                   "COALESCE(NULLIF(province,''),'中国·未细分') "
                   "ELSE COALESCE(NULLIF(country,''),'未知') END k, "
                   "COUNT(*) n, COUNT(DISTINCT ip) ips, "
                   "CASE WHEN scope='cn' THEN 'cn' ELSE 'overseas' END sk "
                   "FROM events "
                   "WHERE ts>=? AND scope IN ('cn','overseas') "
                   "GROUP BY k ORDER BY n DESC LIMIT ?")
            total_sql = ("SELECT COUNT(*) FROM events WHERE ts>=? "
                         "AND scope IN ('cn','overseas')")
            total_args = (start,)
        elif scope == "overseas":
            sql = ("SELECT COALESCE(NULLIF(country,''),'未知') k, COUNT(*) n, "
                   "COUNT(DISTINCT ip) ips FROM events WHERE ts>=? AND scope='overseas' "
                   "GROUP BY k ORDER BY n DESC LIMIT ?")
            total_sql = "SELECT COUNT(*) FROM events WHERE ts>=? AND scope=?"
            total_args = (start, scope)
        else:
            sql = ("SELECT COALESCE(NULLIF(province,''),'未细分') k, COUNT(*) n, "
                   "COUNT(DISTINCT ip) ips FROM events WHERE ts>=? AND scope='cn' "
                   "GROUP BY k ORDER BY n DESC LIMIT ?")
            total_sql = "SELECT COUNT(*) FROM events WHERE ts>=? AND scope=?"
            total_args = (start, scope)
        with self.lock:
            rows = self.conn.execute(sql, (start, limit)).fetchall()
            total = self.conn.execute(total_sql, total_args).fetchone()[0]
        if scope == "all":
            # 1.1.15：省份名在库里可能不统一（离线库「安徽省」/ 在线源「安徽」），
            # 直接按原始值分组会把同一个省拆成两个挨在一起的气泡，既重复计数
            # 又让「同省访问」看起来分散。这里按内置省级行政区表归一后合并，
            # count / ips 累加，不丢任何一条记录；境外国家 / 地区不做归一。
            from geoip import GeoResolver
            merged = {}
            for r in rows:
                k, sk = r["k"], r["sk"]
                if sk == "cn":
                    k = GeoResolver._province_key(k)
                key = (k, sk)
                if key not in merged:
                    merged[key] = {"n": 0, "ips": 0}
                merged[key]["n"] += r["n"]
                merged[key]["ips"] += r["ips"]
            rows = [{"k": k[0], "n": v["n"], "ips": v["ips"], "sk": k[1]}
                    for k, v in merged.items()]
            rows.sort(key=lambda x: -x["n"])
        out = []
        for r in rows:
            name = r["k"]
            keys = r.keys()
            row_scope = (r["sk"] if scope == "all" and "sk" in keys else scope)
            if row_scope == "cn":
                coord = PROVINCE_COORDS.get(name)
                if not coord and name:
                    # 1.1.15：在线源可能给「安徽」而不是「安徽省」，做一次宽松匹配。
                    # 命中不到坐标时 lat/lng 会是 None，前端根本不画气泡，
                    # 表现就是「同省 IP 在地域分布图里不显示」。
                    short = name.replace("省", "").replace("市", "") \
                                .replace("自治区", "").replace("壮族", "") \
                                .replace("回族", "").replace("维吾尔", "")
                    for pk, pv in PROVINCE_COORDS.items():
                        ps = pk.replace("省", "").replace("市", "") \
                               .replace("自治区", "").replace("壮族", "") \
                               .replace("回族", "").replace("维吾尔", "")
                        if short and (ps == short or ps.startswith(short)
                                      or short.startswith(ps)):
                            coord = pv
                            break
            else:
                coord = COUNTRY_COORDS.get(name)
            out.append({"name": name, "count": r["n"], "ips": r["ips"],
                        "scope": row_scope,
                        "lat": coord[0] if coord else None,
                        "lng": coord[1] if coord else None})
        return {"range": rng, "scope": scope, "total": total, "regions": out}

    # ---- 1.1.3：五张分析卡的条目下钻 ------------------------------------
    # 卡片上显示的是「归一化名」（如「站内 · /app/ipsense」「Chrome · Windows」），
    # 库里存的是原始值，且一个展示名可能对应多条原始值（例如同一路径带不同查询串）。
    # 下钻时用与 web_overview 完全相同的归一化函数把展示名反查成原始键集合，
    # 再按同一 cond 查汇总 / IP 明细 / 最近动作，保证卡片数字与明细口径一致。
    WEB_DIMS = {
        "proto":   {"col": "proto",   "namefn": None,          "empty_as": "unknown",
                    "web": False,
                    "note": "协议维度统计全部来源（含 SSH、内核、路由器事件），不限 Web 请求；"
                            "「未识别」对应空协议，combined 日志不含 scheme 时不硬猜。"},
        "referer": {"col": "referer", "namefn": "_ref_name",   "empty_as": "-",
                    "web": True,
                    "note": "来路按 referer 归一化：无来路记为直接输入，同站显示站内路径，外站显示域名。"},
        "page":    {"col": "path",    "namefn": "_clean_path", "nonempty": True,
                    "web": True, "static": True,
                    "note": "受访页按去掉查询串的路径聚合，静态资源（js/css/图片等）已从榜单剔除。"},
        "entry":   {"col": "path",    "namefn": "_clean_path", "nonempty": True,
                    "web": True, "static": True, "entry": True,
                    "note": "入口页 = 每个会话（IP + UA + 30 分钟桶）的第一条请求，"
                            "下钻的 IP 明细同样只统计会话首条，口径与卡片一致。"},
        "device":  {"col": "ua",      "namefn": "_ua_name",    "nonempty": True,
                    "web": False,
                    "note": "终端设备由 User-Agent 粗略归一为「浏览器 · 系统」，不做指纹、不回传标识。"},
    }

    def web_breakdown(self, dim, name, rng="24h", limit=50, _ttl=None):
        if dim not in self.WEB_DIMS:
            return {"ok": False, "msg": "未知维度", "dim": dim, "name": name,
                    "requests": 0, "ips": 0, "ip_list": [], "recent": []}
        return self.cached("webbd|%s|%s|%s|%s" % (dim, name[:200], rng, limit),
                           lambda: self._web_breakdown_uncached(dim, name, rng, limit),
                           _ttl)

    def _web_breakdown_uncached(self, dim, name, rng, limit):
        conf = self.WEB_DIMS[dim]
        start, _ = self._range(rng)
        name = (name or "")[:200]
        limit = max(5, min(200, int(limit or 50)))
        col = conf["col"]

        # 1) 与 web_overview 同源的原始分组，反查展示名对应的所有原始键
        with self.lock:
            if conf.get("entry"):
                raw_rows = self.conn.execute(
                    "SELECT e.%s k, COUNT(*) n, COUNT(DISTINCT e.ip) ips FROM events e "
                    "JOIN (SELECT sess_id, MIN(id) mid FROM events "
                    "      WHERE ts>=? AND layer='web' AND sess_id<>'' GROUP BY sess_id) s "
                    "  ON e.id = s.mid WHERE e.%s<>'' GROUP BY e.%s" % (col, col, col),
                    (start,)).fetchall()
            else:
                where = ["ts>=?"]
                if conf.get("web"):
                    where.append("layer='web'")
                if conf.get("nonempty"):
                    where.append("%s<>''" % col)
                sel = ("COALESCE(NULLIF(%s,''),'%s')" % (col, conf["empty_as"])) \
                      if "empty_as" in conf else col
                raw_rows = self.conn.execute(
                    "SELECT %s k, COUNT(*) n, COUNT(DISTINCT ip) ips FROM events "
                    "WHERE %s GROUP BY k" % (sel, " AND ".join(where)),
                    (start,)).fetchall()

        namefn = getattr(self, conf["namefn"]) if conf.get("namefn") else None
        keys, card_count = [], 0
        for r in raw_rows:
            raw = r["k"] or ""
            if conf.get("static") and self.STATIC_PATH_RE.search(raw):
                continue
            norm = raw if namefn is None else namefn(raw)
            if norm != name:
                continue
            keys.append(raw)
            card_count += r["n"]

        # 2) 把哨兵值（'-' / 'unknown'）还原成「空串」条件，其余走参数化 IN
        sentinel = conf.get("empty_as")
        real_keys = ([k for k in keys if k != sentinel] if sentinel else keys)[:400]
        has_empty = bool(sentinel and sentinel in keys)
        conds, args = [], []
        if real_keys:
            conds.append("%s IN (%s)" % (col, ",".join("?" * len(real_keys))))
            args += real_keys
        if has_empty:
            if dim == "proto":
                conds.append("(proto='' OR proto IS NULL OR proto='unknown')")
            else:
                # 无来路可能是空串，也可能是 Nginx 原文写的 '-'；两者都要命中
                conds.append("(referer='' OR referer IS NULL OR referer='-')")
        empty_out = {"ok": False, "dim": dim, "name": name, "range": rng,
                     "msg": "该条目在当前时间范围内没有匹配的记录",
                     "requests": 0, "ips": 0, "first_ts": None, "last_ts": None,
                     "card_count": card_count, "raw_keys": 0, "ip_list": [],
                     "recent": [], "note": conf["note"]}
        if not conds:
            return empty_out
        cond = "(" + " OR ".join(conds) + ")"

        # 3) 汇总 / IP 明细 / 最近动作共用同一个 cond；入口页走会话首条 JOIN
        if conf.get("entry"):
            from_where = (
                "FROM events e JOIN (SELECT sess_id, MIN(id) mid FROM events "
                "WHERE ts>=? AND layer='web' AND sess_id<>'' GROUP BY sess_id) s "
                "ON e.id = s.mid WHERE " + cond)
            pfx = "e."
            base_args = [start]
        else:
            extra = " AND layer='web'" if conf.get("web") else ""
            from_where = "FROM events WHERE ts>=?" + extra + " AND " + cond
            pfx = ""
            base_args = [start]

        with self.lock:
            srow = self.conn.execute(
                "SELECT COUNT(*) n, COUNT(DISTINCT %sip) ips, MIN(%sts) first_ts, "
                "MAX(%sts) last_ts %s" % (pfx, pfx, pfx, from_where),
                base_args + args).fetchone()
            ip_rows = self.conn.execute(
                "SELECT %sip ip, COUNT(*) n, MIN(%sts) first_ts, MAX(%sts) last_ts, "
                "MAX(%scountry) country, MAX(%sprovince) province, MAX(%scity) city, "
                "MAX(%sdistrict) district, "
                "MAX(%sisp) isp, MAX(%sscope) scope, MAX(%sverdict) verdict, "
                "MAX(%sproto) proto %s GROUP BY %sip ORDER BY n DESC LIMIT ?" %
                (pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx,
                 pfx, pfx, pfx, from_where, pfx),
                base_args + args + [limit]).fetchall()
            rec_rows = self.conn.execute(
                "SELECT %sts ts, %sip ip, %sproto proto, %sverdict verdict, "
                "%saction action, %spath path, %sport port, %sstatus status, "
                "%smethod method, %sreferer referer %s ORDER BY %sid DESC LIMIT 20" %
                (pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, from_where, pfx),
                base_args + args).fetchall()
        return {
            "ok": True, "dim": dim, "name": name, "range": rng,
            "requests": srow["n"] or 0, "ips": srow["ips"] or 0,
            "first_ts": srow["first_ts"], "last_ts": srow["last_ts"],
            "card_count": card_count, "raw_keys": len(keys),
            "ip_list": [dict(r) for r in ip_rows],
            "recent": [dict(r) for r in rec_rows],
            "note": conf["note"],
        }

    def upgrade_web_events(self, parse_web, force=False, batch=1000):
        """升级补字段：用已入库行的 raw 重新解析，按 dedup 精确 UPDATE。

        dedup = md5(ts|source|ip|raw)，历史行不会被重新 INSERT；直接补列即可，
        不重建表、不丢任何一条记录。结果记入 meta，重复启动不会反复扫描。

        真机旧库可达数十万行：按 id 游标分页、每批单独提交，解析期间不持有
        store.lock，避免长事务把采集器写库和 HTTP 请求一起卡住。调用方应放在
        后台线程，不要占住 serve() 的启动关键路径。
        """
        if not force and self.get_meta("web_fields_v110") == "1":
            return {"skipped": True, "reason": "已回填过", "scanned": 0, "updated": 0}
        scanned = updated = 0
        last_id = 0
        while True:
            with self.lock:
                rows = self.conn.execute(
                    "SELECT id,dedup,raw FROM events WHERE source='local_web' "
                    "AND (proto IS NULL OR proto='') AND id>? ORDER BY id LIMIT ?",
                    (last_id, batch)).fetchall()
            if not rows:
                break
            last_id = rows[-1]["id"]
            updates = []
            for r in rows:
                ev = parse_web(r["raw"] or "")
                if not ev:
                    continue
                updates.append((ev.get("layer", ""), ev.get("proto", ""),
                                ev.get("scheme_conf", ""), ev.get("method", ""),
                                int(ev.get("status") or 0), ev.get("referer", ""),
                                ev.get("ua", ""), ev.get("sess_id", ""), r["dedup"]))
            if updates:
                with self.lock:
                    self.conn.executemany(
                        "UPDATE events SET layer=?,proto=?,scheme_conf=?,method=?,status=?,"
                        "referer=?,ua=?,sess_id=? WHERE dedup=?", updates)
                    self.conn.commit()
                updated += len(updates)
            scanned += len(rows)
            if len(rows) < batch:
                break
        self.set_meta("web_fields_v110", "1")
        return {"scanned": scanned, "updated": updated}

    def sources_stat(self, _ttl=None):
        return self.cached("sources_stat", self._sources_stat_uncached, _ttl)

    def _sources_stat_uncached(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT source,COUNT(*) n,MAX(ts) last_ts FROM events GROUP BY source").fetchall()
        return {r["source"]: {"count": r["n"], "last_ts": r["last_ts"]} for r in rows}

    def close(self):
        with self.lock:
            self.conn.close()
