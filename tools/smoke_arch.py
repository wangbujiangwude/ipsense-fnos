# -*- coding: utf-8 -*-
"""跨架构运行时冒烟：同一份脚本在 x86_64 与 aarch64 上执行，checks 应逐项一致。

用法：python tools/smoke_arch.py <server_dir>
  server_dir 是包含 gateway.py / geoip.py / data/ip2region_v4.xdb 的目录。

只做只读计算与内存 SQLite，不监听端口、不写设备文件、不改任何配置。
输出 JSON 到 stdout；env 段允许随架构不同，checks 段必须完全一致。
"""
import io
import os
import sys
import json
import socket
import struct
import sqlite3
import platform
import hashlib

SERVER = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "app", "server")
sys.path.insert(0, SERVER)

CHECKS = {}


def rec(name, fn):
    try:
        CHECKS[name] = fn()
    except Exception as e:
        CHECKS[name] = {"__error__": "%s: %s" % (type(e).__name__, str(e))}


def _modules():
    import gateway, geoip, geosource, store, collector, settings, summary, map_providers, locate
    return {
        "loaded": sorted(["gateway", "geoip", "geosource", "store", "collector",
                          "settings", "summary", "map_providers", "locate"]),
        "version": gateway.VERSION,
        "app_name": gateway.APP_NAME,
        "prefix": gateway.PREFIX,
    }


def _xdb():
    import geoip
    path = os.path.join(SERVER, "data", geoip.XDB_NAME)
    raw = io.open(path, "rb").read()
    s = geoip.XdbSearcher(path)
    ips = ("8.8.8.8", "114.114.114.114", "1.1.1.1", "223.5.5.5",
           "45.155.205.113", "2001:db8::1")
    return {
        "md5": hashlib.md5(raw).hexdigest(),
        "size": len(raw),
        "version": s.version,
        "count": s.count,
        "index_start": s.start,
        "index_end": s.end,
        "lookup": dict((ip, s.search_raw(ip)) for ip in ips),
    }


def _struct_le():
    packed = struct.pack("<HHIII", 2, 1, 1700000000, 100, 200)
    return {"bytes": packed.hex(),
            "unpack": list(struct.unpack_from("<HHIII", packed, 0))}


def _inet_pton():
    out = {}
    for fam, ip in ((socket.AF_INET, "1.2.3.4"),
                    (socket.AF_INET, "255.255.255.255"),
                    (socket.AF_INET6, "::1"),
                    (socket.AF_INET6, "2001:db8::8a2e:370:7334")):
        out["ok:" + ip] = socket.inet_pton(fam, ip).hex()
    for bad in ("11:20:31", "999.1.1.1", ""):
        try:
            socket.inet_pton(socket.AF_INET, bad)
            v4 = "accepted"
        except (OSError, ValueError):
            v4 = "rejected"
        try:
            socket.inet_pton(socket.AF_INET6, bad)
            v6 = "accepted"
        except (OSError, ValueError):
            v6 = "rejected"
        out["bad:" + (bad or "<empty>")] = [v4, v6]
    return out


CASES = [
    '{"logged_time":"2026-11-14T11:20:31.123Z","client_ip":"45.155.205.113",'
    '"auth_decision":"unauthorized","status_code":401,"host":"nas.cn",'
    '"path":"/login","scheme":"https"}',
    '{"time":1794655258,"client_ip":"220.205.86.196","auth_decision":"session",'
    '"status_code":200,"forwarded_proto":"https"}',
    '{"ts":1794655258000,"ip":"8.8.8.8","waf_action":"block","status":403}',
    '{"client_ip":"203.0.113.9","action":"allow","host":"x.cn","path":"/"}',
    "2026-11-14 11:20:31 45.155.205.113 GET /probe 404",
    '{"client_ip":"2001:db8::8a2e:370:7334","event":"auth_failed"}',
    "no ip here",
    "2026-11-14 11:20:31 12:00:00",
    "{broken json",
]


def _knock():
    import collector
    o = collector.Collector.__new__(collector.Collector)
    o.cfg = {"knock_app_port": 8999}
    out = []
    for line in CASES:
        ev = o.parse_knock_app(line)
        if ev is None:
            out.append(None)
        else:
            out.append({k: ev.get(k) for k in
                        ("ip", "source", "action", "proto", "verdict", "port",
                         "status", "path", "method")})
    return out


def _sqlite():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE events (ts INTEGER, ip TEXT, source TEXT, action TEXT, n INTEGER)")
    rows = [(1794655258, "1.1.1.1", "knock_app", "认证通过", 3),
            (1794655259, "2.2.2.2", "knock_app", "认证被拒", 5),
            (1794655260, "1.1.1.1", "local_web", "GET /", 1)]
    c.executemany("INSERT INTO events VALUES (?,?,?,?,?)", rows)
    total = c.execute("SELECT COUNT(*), SUM(n) FROM events").fetchone()
    grouped = c.execute(
        "SELECT action, SUM(n) FROM events WHERE source='knock_app' "
        "GROUP BY action ORDER BY action").fetchall()
    c.close()
    return {"total": list(total), "grouped": [list(x) for x in grouped]}


def _constants():
    import settings, summary, map_providers, geoip
    d = settings.DEFAULTS
    return {
        "settings_keys": sorted([k for k in d if "knock" in k]),
        "source_knock_app": d["source_knock_app"],
        "knock_app_port": d["knock_app_port"],
        "knock_app_dir": d["knock_app_dir"],
        "keep_days": d["keep_days"],
        "syslog_port": d["syslog_port"],
        "engines": list(map_providers.ENGINES),
        "provider_ids": list(map_providers.PROVIDER_IDS),
        "src_knock_app": summary.SRC_NAME.get("knock_app"),
        "proto_web": summary.PROTO_NAME.get("web"),
        "private_192": geoip.is_private("192.168.1.1"),
        "private_8888": geoip.is_private("8.8.8.8"),
    }


def main():
    env = {
        "machine": platform.machine(),
        "byteorder": sys.byteorder,
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "sys_platform": sys.platform,
        "server": SERVER.replace("\\", "/"),
    }
    rec("modules", _modules)
    rec("xdb", _xdb)
    rec("struct_le", _struct_le)
    rec("inet_pton", _inet_pton)
    rec("knock_parse", _knock)
    rec("sqlite", _sqlite)
    rec("constants", _constants)
    errs = [k for k, v in CHECKS.items()
            if isinstance(v, dict) and "__error__" in v]
    print(json.dumps({"env": env, "checks": CHECKS,
                      "errors": errs, "ok": not errs},
                     ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not errs else 1


if __name__ == "__main__":
    sys.exit(main())
