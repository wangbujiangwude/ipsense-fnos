# -*- coding: utf-8 -*-
"""1.1.15 后端运行时冒烟：district 透传 / 地域省级细分 / 省份坐标宽松匹配。

用临时 SQLite 真实建表并写入事件，逐一调用被补丁改过的聚合接口，
确保 SQL 占位符、列名、返回字段都在真实连接上跑得通。
运行：python tools/smoke_115_store.py
"""
import os
import sys
import time
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "app", "server"))

import store  # noqa: E402
import diag   # noqa: E402

ok, fail = 0, 0


def chk(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print("  PASS  " + name + ("  " + extra if extra else ""))
    else:
        fail += 1
        print("  FAIL  " + name + ("  " + extra if extra else ""))


def ev(ip, province, city, district, scope, country, lat, lng,
       proto="https", path="/app/ipsense/", source="local_web"):
    return {
        "ts": time.time(), "source": source, "ip": ip, "ipver": 4,
        "country": country, "province": province, "city": city,
        "district": district, "isp": "联通", "scope": scope,
        "lat": lat, "lng": lng, "port": 443, "service": "https",
        "action": "GET " + path, "verdict": "normal", "path": path,
        "raw": "example raw line", "dedup": "d-" + ip + "-" + str(time.time_ns()),
        "layer": "web", "proto": proto, "scheme_conf": "manual",
        "method": "GET", "status": 200, "referer": "-",
        "ua": "Mozilla/5.0", "sess_id": "s-" + ip,
    }


tmp = tempfile.mkdtemp(prefix="ipsense-115-")
db = os.path.join(tmp, "events.db")
s = store.Store(db, keep_days=30)

rows = [
    ev("220.205.91.142", "安徽", "合肥", "蜀山区", "cn", "中国", 31.82, 117.23),
    ev("112.28.131.131", "安徽省", "合肥", "蜀山区", "cn", "中国", 31.82, 117.23),
    ev("113.108.1.1", "广东省", "广州", "", "cn", "中国", 23.13, 113.26),
    ev("8.8.8.8", "", "Mountain View", "", "overseas", "美国", 37.4, -122.1),
]
n = s.insert_batch(rows)

print("=== 1. 写入与列升级 ===")
chk("insert_batch 写入 4 行", n == 4, "n=" + str(n))
cols = [r["name"] for r in s.conn.execute("PRAGMA table_info(events)")]
chk("events 含 district 列", "district" in cols)
gcols = [r["name"] for r in s.conn.execute("PRAGMA table_info(geo_cache)")]
chk("geo_cache 含 district / district_source",
    "district" in gcols and "district_source" in gcols)
rec = s.records(page=1, size=20)
chk("records 返回 district", "district" in (rec["rows"][0] if rec["rows"] else {}),
    str(sorted(set(r.get("district", "") for r in rec["rows"]))))

print("\n=== 2. 地域数量分布：境内按省 + 省份坐标宽松匹配 ===")
gd = s.geo_distribution("24h", "all", 40)
regions = gd["regions"]
by_name = {r["name"]: r for r in regions}
chk("境内不再归并成一个「中国」", "中国" not in by_name,
    "regions=" + str([(r["name"], r["scope"]) for r in regions]))
chk("省级行带 scope=cn", any(r["scope"] == "cn" for r in regions))
chk("境外行带 scope=overseas", any(r["scope"] == "overseas" for r in regions))
cn_rows = [r for r in regions if r["scope"] == "cn"]
chk("每个境内省份都有坐标（含短名「安徽」宽松匹配）",
    all(r["lat"] is not None and r["lng"] is not None for r in cn_rows),
    str([(r["name"], r["lat"], r["lng"]) for r in cn_rows]))
chk("境内省级行数量 >= 2（同省不再被吞）", len(cn_rows) >= 2,
    str(len(cn_rows)) + " 个省级气泡")
chk("短名「安徽」与「安徽省」已归一合并，不重复计数",
    "安徽" not in by_name and "安徽省" in by_name and
    by_name["安徽省"]["count"] == 2,
    "安徽省 count=" + str(by_name.get("安徽省", {}).get("count")))

print("\n=== 3. 五卡下钻 IP 明细带 district ===")
wb = s.web_breakdown("proto", "https", "24h", 50)
chk("web_breakdown 正常返回", wb.get("ok") is True,
    "ips=" + str(wb.get("ips")))
iplist = wb.get("ip_list") or []
chk("ip_list 非空", len(iplist) > 0, str(len(iplist)) + " 行")
chk("ip_list 每行含 district 键", all("district" in r for r in iplist),
    str(sorted(set(r.get("district", "") for r in iplist))))
chk("下钻明细读到「蜀山区」",
    any(r.get("district") == "蜀山区" for r in iplist))

print("\n=== 4. 整组画像 IP 明细带 district ===")
grp = s.group_detail(["220.205.91.142", "112.28.131.131"], "all", 40)
gips = grp.get("ips") or []
chk("group_detail 返回 IP 明细", len(gips) > 0, str(len(gips)) + " 行")
chk("group_detail 每行含 district 键", all("district" in r for r in gips),
    str([r.get("district") for r in gips]))

print("\n=== 5. 脱敏诊断包 ===")
txt = diag.build_bundle(type("App", (), {
    "version": "1.1.15", "store": s, "cfg": {
        "map_key": "SUPERSECRETKEY123456", "map_provider": "amap",
        "home_lat": 22.54, "keep_days": 30},
    "geo": type("G", (), {"ready": True})(),
    "verifier": None, "collector": None,
    "start_ts": time.time() - 3600,
})())
chk("诊断包为非空文本", isinstance(txt, str) and len(txt) > 100,
    str(len(txt)) + " 字符")
chk("地图 KEY 未泄漏", "SUPERSECRETKEY123456" not in txt)
chk("含脱敏说明", "脱敏" in txt)

print("\n=== 结果：%d 项通过 / %d 项失败 ===" % (ok, fail))
sys.exit(1 if fail else 0)
