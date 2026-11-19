# -*- coding: utf-8 -*-
"""1.1.16 后端运行时冒烟：真实临时 SQLite 建表 + 端口订正 + 脏值固化 + 安全边界。"""
import os
import sys
import time
import tempfile
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "app", "server"))
import collector          # noqa: E402
import store              # noqa: E402
import geosource          # noqa: E402

ok, fail = 0, 0


def chk(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print("  OK   " + name)
    else:
        fail += 1
        print("  FAIL " + name + (" | " + str(detail) if detail else ""))


print("=== 1. Web 日志端口解析 ===")
LINE = ('1.2.3.4 - - [19/Nov/2026:09:12:33 +0800] '
        '"GET /x HTTP/1.1" 200 0 "https://a.com/f/" "UA"')
chk("combined 标准格式无端口 -> 0", collector.web_log_port("https://a.com/f/", LINE) == 0)
chk("Referer 带端口也不采纳（来源页端口 ≠ 目标端口）",
    collector.web_log_port("https://a.com:8443/f/", LINE) == 0)
chk("真机同站 Referer :5666 不被采纳",
    collector.web_log_port("http://192.168.3.5:5666/app/ipsense/", LINE) == 0)
chk("行尾 $server_port -> 8443", collector.web_log_port("", LINE + " 8443") == 8443)
chk("行尾没有独立端口时不误取状态码", collector.web_log_port("", LINE) == 0)
chk("非法端口 99999 被拒", collector.web_log_port("", LINE + " 99999") == 0)

print("=== 2. 临时 SQLite：端口订正 ===")
tmp = tempfile.mkdtemp(prefix="ipsense116_")
s = None
try:
    db = os.path.join(tmp, "t.db")
    s = store.Store(db)
    s.conn.execute("INSERT INTO events (ts,day,source,ip,port) VALUES (?,?,?,?,?)",
                   (time.time(), "2026-11-19", "local_web", "1.2.3.4", 5666))
    s.conn.execute("INSERT INTO events (ts,day,source,ip,port) VALUES (?,?,?,?,?)",
                   (time.time(), "2026-11-19", "fnos_audit", "1.2.3.5", 22))
    s.conn.commit()
    n = s.normalize_web_ports(5666)
    chk("历史 5666 一次性订正为 0", n == 1, "rows=" + str(n))
    chk("Web 事件 port 已为 0",
        s.conn.execute("SELECT port FROM events WHERE source='local_web'").fetchone()[0] == 0)
    chk("非 Web 来源的真实端口不受影响",
        s.conn.execute("SELECT port FROM events WHERE source='fnos_audit'").fetchone()[0] == 22)
    chk("端口订正幂等", s.normalize_web_ports(5666) == 0)

    print("=== 3. 临时 SQLite：离线库脏值固化 ===")
    s.conn.execute(
        "INSERT INTO geo_cache "
        "(ip,country,province,city,local_country,local_province,local_city,disagree) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("39.144.239.169", "中国", "安徽省", "合肥", "中国", "重庆市", "重庆市", 1))
    s.conn.commit()
    n = s.normalize_local_geo()
    chk("「重庆市」脏值被识别并固化", n == 1, "rows=" + str(n))
    f = s.local_fix("39.144.239.169")
    chk("local_fix 返回在线裁决值",
        bool(f) and f.get("province") == "安徽省" and f.get("city") == "合肥", f)
    chk("geo_cache.local_province 已同步为安徽省",
        s.conn.execute("SELECT local_province FROM geo_cache "
                       "WHERE ip='39.144.239.169'").fetchone()[0] == "安徽省")
    chk("脏值订正幂等", s.normalize_local_geo() == 0)
    s.put_local_fix("39.144.239.169", {"country": "中国", "province": "安徽省",
                                       "city": "合肥", "district": "蜀山区"})
    chk("put_local_fix 可覆写并带区级",
        (s.local_fix("39.144.239.169") or {}).get("district") == "蜀山区")
finally:
    if s:
        s.conn.close()
    shutil.rmtree(tmp, ignore_errors=True)

print("=== 4. 自定义区级接口安全边界（不发真实请求） ===")
cfg = {"geo_district_api_enabled": True, "geo_district_field": "data.district"}
for u in ("http://a.com/?ip={ip}",
          "https://127.0.0.1/?ip={ip}",
          "https://192.168.1.5/?ip={ip}",
          "https://172.20.1.1/?ip={ip}",
          "https://169.254.169.254/?ip={ip}",
          "https://localhost/?ip={ip}",
          "https://a.com/?q=fixed"):
    cfg["geo_district_api"] = u
    chk("拒绝 " + u[:44], geosource.fetch_custom_district("1.2.3.4", cfg) is None)
cfg["geo_district_api"] = "https://a.com/?ip={ip}"
cfg["geo_district_api_enabled"] = False
chk("开关关闭时完全不请求", geosource.fetch_custom_district("1.2.3.4", cfg) is None)
cfg["geo_district_api_enabled"] = True
chk("IPv6 字面主机被拒",
    geosource.fetch_custom_district("1.2.3.4", dict(cfg,
        geo_district_api="https://[::1]/?ip={ip}")) is None)

print("\n=== 结果：%d 项通过 / %d 项失败 ===" % (ok, fail))
sys.exit(1 if fail else 0)
