# -*- coding: utf-8 -*-
"""本地离线自检：不连设备，验证归属库、日志解析、SQLite 聚合、API 与首页内联。"""
import os
import sys
import time
import json
import shutil
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "src", "app", "server")
UI = os.path.join(ROOT, "src", "app", "ui")

tmp = tempfile.mkdtemp(prefix="ipsense-test-")
appdest = os.path.join(tmp, "app")
var = os.path.join(tmp, "var")
os.makedirs(os.path.join(appdest, "ui"), exist_ok=True)
for f in os.listdir(UI):
    s = os.path.join(UI, f)
    if os.path.isfile(s):
        shutil.copy(s, os.path.join(appdest, "ui", f))
os.environ["TRIM_APPDEST"] = appdest
os.environ["TRIM_PKGVAR"] = var
sys.path.insert(0, SERVER)

import gateway                                    # noqa: E402
from collector import Collector                    # noqa: E402
from geoip import GeoResolver                     # noqa: E402

ok = 0
fail = []


def check(name, cond, extra=""):
    global ok
    if cond:
        ok += 1
        print("  [OK] %s %s" % (name, extra))
    else:
        fail.append(name)
        print("  [FAIL] %s %s" % (name, extra))


print("=== 1. 离线归属库 ===")
geo = GeoResolver(os.path.join(SERVER, "data"))
check("xdb 就绪", geo.ready, getattr(geo, "error", ""))
for ip, expect_scope, expect_country in (
        ("8.8.8.8", "overseas", "美国"),
        ("114.114.114.114", "cn", "中国"),
        ("220.205.66.123", "cn", "中国"),
        ("1.1.1.1", "overseas", "澳大利亚"),
        ("45.155.205.113", "overseas", "荷兰"),
        ("192.168.3.38", "private", "")):
    r = geo.lookup(ip)
    check("归属 " + ip, r["scope"] == expect_scope and
          (not expect_country or r["country"] == expect_country),
          "-> %s / %s / %s" % (r["scope"], r["country"], r["province"]))

print("=== 2. 日志解析 ===")
app = gateway.App()
cfg = app.settings.all()
c = Collector(app.store, geo, cfg)
app.collector = c
now = time.strftime("%d/%b/%Y:%H:%M:%S +0800", time.localtime())
# 用例时间戳必须相对「现在」生成，否则跨天后会掉出 24h 窗口，第 3 节的
# 入库 / 境内外分离 / 境内排名断言会假失败。带本机时区偏移，to_ts() 可精确还原。
import datetime as _dt
_iso = (_dt.datetime.now().astimezone() - _dt.timedelta(minutes=60)).isoformat(timespec="seconds")
cases = [
    ('web-normal', c.parse_web('203.0.113.9 - - [%s] "GET /app/ipsense/ HTTP/1.1" 200 1234 "-" "UA"' % now)),
    ('web-scan', c.parse_web('45.155.205.113 - - [%s] "GET /.env HTTP/1.1" 404 0 "-" "UA"' % now)),
    ('auth-fail', c.parse_auth('%s fn-OESP sshd[1]: Failed password for root from 91.240.118.1 port 5555 ssh2' % _iso)),
    ('auth-invalid', c.parse_auth('%s fn-OESP sshd[1]: Invalid user admin from 8.8.8.8 port 4444' % _iso)),
    ('router', c.parse_router('<4> kernel: DROP IN=eth0 SRC=185.220.101.1 DST=192.168.3.5 DPT=22')),
    ('knock', c.parse_kern('%s kernel: IPSENSE-KNOCK SRC=1.1.1.1 DPT=7000' % _iso)),
]
batch = []
for name, ev in cases:
    check("解析 " + name, ev is not None, "-> %s" % (ev and ev["verdict"]))
    if ev:
        batch.append(ev)
c._flush(batch)

print("=== 3. SQLite 聚合 ===")
st = app.store.status("24h")
check("事件已入库", st["total"] >= len(batch), "total=%d" % st["total"])
check("境内/境外分离", st["cn"] >= 1 and st["overseas"] >= 4,
      "cn=%d overseas=%d" % (st["cn"], st["overseas"]))
tr = app.store.trend("24h")
check("趋势有数据点", len(tr["points"]) >= 1, "points=%d" % len(tr["points"]))
rk = app.store.ranking("24h")
check("境外排名", len(rk["overseas"]) >= 1, str(rk["overseas"][:2]))
check("境内排名", len(rk["cn"]) >= 1, str(rk["cn"][:2]))
rec = app.store.records(page=1, size=10)
check("记录分页", rec["total"] >= len(batch), "total=%d" % rec["total"])
hs = app.store.hotspots("24h")
check("热点带坐标", all(h["lat"] is not None for h in hs) and len(hs) >= 1,
      "hotspots=%d" % len(hs))
det = app.store.ip_detail("45.155.205.113")
check("IP 画像", det["agg"].get("n", 0) >= 1, str(det["agg"]))

print("=== 4. HTTP API ===")
for path in ("/api/health", "/api/status?rng=24h", "/api/trend?rng=24h",
             "/api/ranking?rng=24h", "/api/records?page=1", "/api/events?since=0",
             "/api/live", "/api/hotspots?rng=24h", "/api/config", "/api/mapkey",
             "/api/sources", "/api/geo?ip=8.8.8.8", "/api/ip?ip=8.8.8.8"):
    p, _, q = path.partition("?")
    try:
        r = gateway.api(app, "GET", p, q, b"")
        check("API " + p, r[0] == 200 and (isinstance(r[1], dict) and r[1].get("ok") is True))
    except Exception as e:
        check("API " + p, False, repr(e))
r = gateway.api(app, "POST", "/api/config", "", b'{"keep_days": 14}')
check("API 配置保存", r[0] == 200 and r[1]["ok"], str(r[1].get("changed")))

print("=== 5. 首页内联 ===")
try:
    html = gateway.render_index().decode("utf-8")
    check("首页体积", len(html) > 30000, "%d 字节" % len(html))
    check("CSS/JS 已内联", "/*__CSS__*/" not in html and "/*__JS__*/" not in html)
    check("含地图合规提示", "腾讯地图" in html and "坐标散点示意" in html)
    import re
    check("key 由用户配置注入（未写死）",
          "function mapSdkUrl(p, key, cb)" in html and
          "encodeURIComponent(key || '')" in html and
          "map.qq.com/api/gljs" in html and "{key}" in html)
    check("未内置任何真实 key",
          not re.search(r"[A-Z0-9]{5}(-[A-Z0-9]{5}){4,}", html))
except Exception as e:
    check("首页渲染", False, repr(e))

print("=== 6. 弧线渲染（1.0.5 重做） ===")
js = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
check("贝塞尔弧线", "function arcControl" in js and "bezierAt" in js)
check("按省/国家合并来源", "function buildArcs" in js and "h.province" in js and "h.country" in js)
check("弯曲幅度与距离成比例", "d.dist * bend" in js and "Math.max(1.2" not in js)
check("近距来源不画弧", "near += b.ips" in js and "arcNear" in js)
check("近距来源只画点", "nearPts" in js and "styleId: 'near' + tier" in js)
check("整条弧线单段单色（1.0.11 取代渐隐分段）",
      "g.segs = wrapSegs(full);" in js and
      "styleId: 't' + b.tier," in js and "ARC_BANDS" not in js)
check("细线不压底图", "w: 3, cw: 2.2" in js and "'#ef4444'" in js)
check("数据指纹短路", "function refreshArcData" in js and "S.heavySig" in js)
check("图层增量同步", "function syncGeos" in js and "layer.add" in js)
check("延迟合并绘制", "function requestMapDraw" in js and "setTimeout(function" in js)
check("后台暂停轮询", "document.hidden" in js)
cfg4 = app.settings.all()
check("新配置项默认值", cfg4.get("map_arc_limit") == 16 and
      abs(float(cfg4.get("map_arc_bend", 0)) - 0.12) < 1e-6 and
      cfg4.get("map_arc_animate") is True and cfg4.get("map_heavy_refresh") == 12)
check("首页含新设置项", "map_heavy_refresh" in gateway.render_index().decode("utf-8"))

print("=== 7. 地图圆点点击交互（1.0.6 / 1.0.7） ===")
html6 = gateway.render_index().decode("utf-8")
css6 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
gw6 = open(os.path.join(SERVER, "gateway.py"), encoding="utf-8").read()
st6 = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
check("首页不再有地图内浮层", 'id="worldPop"' not in html6 and "map-pop" not in css6)
check("详情抽屉标题可动态修改", 'id="detailTitle"' in html6)
check("标题引导点击圆点", "点击圆点打开 IP 来源画像" in html6)
check("画像组件样式已内联", ".ip-item" in css6 and ".profile-btn" in css6)
check("TMap 圆点绑定 click 与 hover", "m.marks.on('click'" in js and "m.marks.on('mousemove'" in js)
check("点击命中兼容多种 SDK 事件", "function geoId" in js and "function nearestMark" in js)
check("canvas 散点模式也可点击", "function canvasHit" in js and "bindCanvasPicks()" in js)
check("点击直接打开画像抽屉", "function openPointInfo" in js and "openDetail(ms[0].ip, hit)" in js)
check("单 IP 圆点复用表格行画像", "openDetail(ms[0].ip, hit)" in js)
check("多 IP 圆点展示整组画像", "function openGroupProfile" in js and "profileHead(title" in js)
check("本机点走同款抽屉", "function openHomeProfile" in js and "mi.home =" in js)
check("本机点优先命中", "homeHit = idx.home" in js and "hd < 0.2" in js)
check("同组 IP 可切换并一键返回", "function samePointBlock" in js and "bindIpSwitches" in js)
check("抽屉打开时重置事件绑定", "detailBody').onclick = null" in js)
check("后端新增 /api/group", '"/api/group"' in gw6 and "def group_detail" in st6)
try:
    ips6 = [h["ip"] for h in hs[:3]] or ["45.155.205.113"]
    body6 = json.dumps({"ips": ips6, "rng": "all", "limit": 20}).encode("utf-8")
    code6, resp6 = gateway.api(app, "POST", "/api/group", "", body6)
    d6 = resp6.get("data", {}) if isinstance(resp6, dict) else {}
    check("POST /api/group 返回 200", code6 == 200 and resp6.get("ok") is True)
    check("返回逐条连接时间", bool(d6.get("recent")) and
          all("ts" in x and "ip" in x for x in d6["recent"]),
          "recent=%d" % len(d6.get("recent", [])))
    check("返回每 IP 聚合与末次时间", bool(d6.get("ips")) and
          all("last_ts" in x for x in d6["ips"]))
    check("返回总次数与时间范围", d6.get("total", 0) >= 1 and d6.get("last_ts", 0) > 0)
    code7, resp7 = gateway.api(app, "POST", "/api/group", "", b'{"ips":[]}')
    check("空 ips 列表被拒绝", code7 == 400 and resp7.get("ok") is False)
except Exception as e:
    check("POST /api/group 功能验证", False, repr(e))
check("版本号 1.1.14", gateway.VERSION == "1.1.14")

print("=== 8. 画像版式复用（1.0.7） ===")
check("表格行与地图点共用 openDetail", "function openDetail(ip, groupHit)" in js)
check("公共画像渲染函数齐备", all(("function " + f) in js for f in
      ("profileHead", "kvRow", "pathBlock", "bindIpSwitches", "samePointBlock")))
check("单 IP 画像字段表与最近动作", "['IP 地址', ip]" in js and "最近 20 条动作" in js)
check("整组画像含高频路径与逐条动作", "高频路径</h3>" in js and "最近 20 条动作（精确到秒）" in js)
check("首页同时含记录表与画像抽屉", "IP 来源记录" in html6 and "IP 来源画像" in html6)

print("=== 9. 多源归属校验与新数据来源（1.0.8） ===")
import geosource                                  # noqa: E402
col_src = open(os.path.join(SERVER, "collector.py"), encoding="utf-8").read()
geo_src = open(os.path.join(SERVER, "geosource.py"), encoding="utf-8").read()
st_src = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
set_src = open(os.path.join(SERVER, "settings.py"), encoding="utf-8").read()
man_src = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()

# 多数派裁决：3 家在线源一致判安徽合肥，本地库误判河北石家庄
_vlocal = geo.lookup_uncached("220.205.66.123")
_vonline = [
    {"source": "ip-api.com", "country": "中国", "province": "安徽", "city": "合肥",
     "isp": "联通", "lat": 31.82, "lng": 117.23},
    {"source": "ip.sb", "country": "中国", "province": "安徽", "city": "合肥",
     "isp": "China Unicom", "lat": 31.82, "lng": 117.23},
    {"source": "ipinfo.io", "country": "中国", "province": "安徽", "city": "合肥",
     "isp": "AS140726", "lat": 31.86, "lng": 117.28},
]
_vgeo, _vf = geosource.vote(_vlocal, _vonline)
check("多源多数派裁决修正本地库误判", _vgeo["province"] == "安徽省" and _vgeo["scope"] == "cn",
      "本地=%s → 裁决=%s" % (_vlocal["province"], _vgeo["province"]))
check("3 家在线源一致时置信度为高", _vf["confidence"] == "high" and _vf["online_sources"] == 3)
check("记录源间分歧供前端提示", _vf["disagree"] is True and len(_vf["sources"]) == 4)
check("裁决采用在线城市级坐标", _vgeo["lat"] == 31.82 and _vgeo["lng"] == 117.23)
check("国家名归一（ISO / 英文 / 港澳台）",
      geosource.norm_country("MU") == "毛里求斯" and
      geosource.norm_country("HK") == "中国香港" and
      geosource.norm_prov("Anhui") == "安徽")
check("在线不可用时回退离线库", geosource.vote(_vlocal, [])[1]["confidence"] == "offline")
check("三家在线源并行查询", "ThreadPoolExecutor(3)" in geo_src)
check("GeoResolver 支持缓存钩子", all(hasattr(geo, m) for m in
      ("attach", "lookup_uncached", "invalidate")))
check("IPv6 不再把 province 写成中国", geo.lookup_uncached("2408:8244::1")["province"] == "")
check("境外英文国名有兜底归一", "COUNTRY_ALIAS" in open(os.path.join(SERVER, "geoip.py"), encoding="utf-8").read())

check("geo_cache 表与缓存方法齐备", all(hasattr(app.store, m) for m in
      ("get_geo_cache", "set_geo_cache", "geo_cache_count", "geo_cache_stats",
       "apply_geo", "top_public_ips", "lan_stat")) and "CREATE TABLE IF NOT EXISTS geo_cache" in st_src)
app.store.set_geo_cache("9.9.9.9", _vgeo, _vf, _vlocal)
check("校验结果可写入并读回缓存", (app.store.get_geo_cache("9.9.9.9") or {}).get("province") == "安徽省")
check("apply_geo 可回写历史事件", isinstance(app.store.apply_geo("9.9.9.9", _vgeo), int))

_c8 = Collector(app.store, geo, app.settings.all(), lambda m: None)
_tline = ('2026-11-10T09:47:05+08:00 fn-OESP sshd[1]: TRIMEVENT:'
          '{"from":"user","eventId":"SshdLoginAuthFail",'
          '"data":{"IP":"1.2.3.4","user":"root"},"datetime":1794275225}')
_tev = _c8.parse_trimevent(_tline)
check("TRIMEVENT 认证失败判 attack", bool(_tev) and _tev["source"] == "fnos_audit" and
      _tev["verdict"] == "attack" and _tev["ip"] == "1.2.3.4")
check("TRIMEVENT 登出不产生事件",
      _c8.parse_trimevent(_tline.replace("SshdLoginAuthFail", "SshdLogonout")) is None)
_fline = "2026-11-10T09:00:00+08:00 fn-OESP sshd[1]: Failed password for root from 5.6.7.8 port 44396 ssh2"
check("sshd 文本失败登录仍可解析",
      (_c8.parse_auth_any(_fline) or {}).get("verdict") == "attack")
check("auth tailer 使用复合解析器", any(t.parser == _c8.parse_auth_any for t in _c8.tailers))
check("轮转日志方法与回填入口存在", all(x in col_src for x in
      ("def rotated_paths", "def read_rotated", "backfill rotated", "gzip.open")))
check("内网地址单独归类为 lan", '"scope": "lan"' in col_src and 'is_private(ip)' in col_src)
check("回填链路也过滤 ignore_ips", "if ip in ignore:" in col_src)

_lanline = "2026-11-10T09:01:00+08:00 fn-OESP sshd[1]: Failed password for root from 192.168.3.38 port 1 ssh2"
_lev = _c8.parse_auth_any(_lanline)
_c8._flush([_lev] if _lev else [])
_lrow = app.store.conn.execute(
    "SELECT scope,country,lat FROM events WHERE ip='192.168.3.38' ORDER BY id DESC LIMIT 1").fetchone()
check("内网事件落库为 lan 且无归属无坐标",
      bool(_lrow) and _lrow["scope"] == "lan" and _lrow["country"] == "" and _lrow["lat"] is None)
_b = app.store.conn.execute("SELECT COUNT(*) FROM events WHERE ip='127.0.0.1'").fetchone()[0]
_ign = _c8.parse_auth_any("2026-11-10T09:02:00+08:00 fn-OESP sshd[1]: Failed password for root from 127.0.0.1 port 1 ssh2")
_c8._flush([_ign] if _ign else [])
_a = app.store.conn.execute("SELECT COUNT(*) FROM events WHERE ip='127.0.0.1'").fetchone()[0]
check("忽略 IP 不再被回填写入", _a == _b)
check("趋势图把 lan 并入内网曲线", 'if k == "lan"' in st_src)

check("新配置项默认值齐备",
      app.settings.get("geo_verify_enabled") is True and
      app.settings.get("geo_verify_days") == 30 and
      app.settings.get("source_fnos_audit") is True and
      app.settings.get("source_auth_rotated") is True and
      app.settings.get("lan_separate") is True and
      "geo_verify_enabled" in set_src)
check("新增 4 个归属校验 API", all(('"/api/geo/%s"' % x) in gw6
      for x in ("verify", "detail", "sources", "refresh")))
check("/api/ip 与 /api/status 返回核验信息",
      '"verification": app.verifier.details' in gw6 and '"geo_verify": app.verifier.stats' in gw6)
_c8a, _r8a = gateway.api(app, "GET", "/api/geo/sources", "", b"")
check("GET /api/geo/sources 返回健康状态",
      _c8a == 200 and _r8a.get("ok") is True and "source_names" in _r8a.get("data", {}))
_c8b, _r8b = gateway.api(app, "POST", "/api/geo/refresh", "", b"{}")
check("POST /api/geo/refresh 入队成功", _c8b == 200 and _r8b.get("ok") is True and "queued" in _r8b)
_c8c, _r8c = gateway.api(app, "GET", "/api/geo/detail", "ip=9.9.9.9", b"")
check("GET /api/geo/detail 读回核验明细",
      _c8c == 200 and (_r8c.get("data") or {}).get("province") == "安徽省")

check("画像新增多源核验区块", "function verifyBlock" in js and "归属核验 · 多源交叉" in js)
check("单 IP 画像渲染核验结果", "verifyBlock(ip, r.verification)" in js)
check("核验按钮与重新渲染绑定",
      "function bindDetailEvents" in js and 'data-act="verify"' in js and
      "api/geo/verify?ip=" in js)
check("设置页新增数据源分组与状态",
      "归属信息源 · 多源交叉校验" in html6 and "function renderGeoSources" in js and
      "btnGeoRefresh" in js)
check("设置页新开关与字段齐备", all(x in js for x in
      ("sw('geo_verify_enabled'", "fld('geo_verify_days'", "sw('source_fnos_audit'",
       "sw('source_auth_rotated'", "sw('lan_separate'")))
check("核验样式已内联", all(x in css6 for x in (".verify-box", ".vf-tag", ".vs-row")))
check("记录表新增局域网与 fnOS 审计筛选", 'value="lan"' in html6 and 'value="fnos_audit"' in html6)
check("指标卡显示已核验 IP 数", "已核验 ' + num(S.geoVerify.cached)" in js)
check("manifest 版本 1.1.14", "version                    = 1.1.14" in man_src)

print("=== 10. 准确性订正（1.0.9） ===")
check("英文城市名归一为中文",
      geosource.norm_city("Hefei") == "合肥" and
      geosource.norm_city("Guangzhou") == "广州" and
      geosource.norm_city("Singapore") == "新加坡" and
      geosource.norm_city("Port Louis") == "路易港" and
      geosource.norm_city("石家庄市") == "石家庄")

# 本地库判广东，三家在线源判安徽且只有一家给坐标：裁决后必须落在合肥
_vlocal2 = geo.lookup_uncached("112.28.131.131")
_vonline2 = [
    {"source": "ip-api.com", "country": "中国", "province": "安徽", "city": "合肥",
     "isp": "移动", "lat": 31.82, "lng": 117.23},
    {"source": "ip.sb", "country": "中国", "province": "安徽", "city": "Hefei",
     "isp": "China Mobile", "lat": None, "lng": None},
    {"source": "ipinfo.io", "country": "中国", "province": "安徽", "city": "Hefei",
     "isp": "AS9808", "lat": None, "lng": None},
]
_vgeo2, _vf2b = geosource.vote(_vlocal2, _vonline2)
check("裁决坐标与省份一致（安徽不再画到广州）",
      _vgeo2["province"] == "安徽省" and _vgeo2["city"] == "合肥" and
      _vgeo2["lat"] == 31.82 and _vgeo2["lng"] == 117.23,
      "lat=%s lng=%s city=%s" % (_vgeo2["lat"], _vgeo2["lng"], _vgeo2["city"]))
_vonline3 = [dict(o, lat=None, lng=None) for o in _vonline2]
_vgeo3, _ = geosource.vote(_vlocal2, _vonline3)
check("在线源全无坐标时按省级中心点重算",
      abs(_vgeo3["lat"] - 31.82) < 1.5 and abs(_vgeo3["lng"] - 117.23) < 1.5)
check("坐标一致性逻辑已写入 geosource", "PROVINCE_COORDS.get(province)" in geo_src)

check("normalize_events 方法存在", "def normalize_events" in st_src)
check("启动时自动执行订正", "self.store.normalize_events()" in gw6)
check("手动订正 API 存在", '"/api/geo/normalize"' in gw6)
check("设置页新增历史订正按钮", "btnGeoNormalize" in js and "api/geo/normalize" in js)

# 造两条历史脏值验证实际订正效果
app.store.conn.execute(
    "INSERT INTO events(ts,day,source,ip,country,province,city,scope,lat,lng,dedup) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    (time.time(), "2026-11-10", "local_web", "2408:8444::beef",
     "中国", "中国", "Hefei", "cn", 39.9236, 116.36, "selftest-norm-1"))
app.store.conn.execute(
    "INSERT INTO events(ts,day,source,ip,country,province,city,scope,lat,lng,dedup) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    (time.time(), "2026-11-10", "local_web", "102.220.161.89",
     "Mauritius", "Port Louis", "", "overseas", -20.16, 57.50, "selftest-norm-2"))
app.store.conn.commit()
_nr = app.store.normalize_events(force=True)
_r1 = app.store.conn.execute(
    "SELECT country,province,lat,lng FROM events WHERE dedup='selftest-norm-1'").fetchone()
_r2 = app.store.conn.execute(
    "SELECT country,province,lat,lng FROM events WHERE dedup='selftest-norm-2'").fetchone()
check("订正 province=中国 与 IPv6 北京坐标",
      _r1["province"] == "" and abs(_r1["lat"] - 35.86) < 3 and abs(_r1["lng"] - 104.20) < 3,
      "lat=%s lng=%s" % (_r1["lat"], _r1["lng"]))
check("订正英文国名 Mauritius", _r2["country"] == "毛里求斯")
check("订正返回统计字段", all(k in _nr for k in
      ("province_cleared", "country_fixed", "coord_fixed", "cache_fixed")))
check("省份排名不再把空省份兜底成国家名",
      "COALESCE(NULLIF(province,''),'未细分')" in st_src and
      all(x["name"] != "中国" for x in app.store.ranking("24h")["cn"]))
_c10, _r10 = gateway.api(app, "POST", "/api/geo/normalize", "", b"{}")
check("POST /api/geo/normalize 可重跑",
      _c10 == 200 and _r10.get("ok") is True and "data" in _r10)

print("=== 11. 连线按连接频率热力着色（1.0.10） ===")
import re as _re
import subprocess as _sp
_js10 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_css10 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_html10 = open(os.path.join(UI, "index.html"), encoding="utf-8").read()
check("5 档热力色阶常量", "ARC_LEVELS = 5" in _js10 and "ARC_HEAT = [" in _js10)
check("低频冷色 / 高频红色", "'#5cc3dd'" in _js10 and "'#ef4444'" in _js10)
check("两张地图共用同一色阶",
      "function arcStyles()" in _js10 and _js10.count("styles: arcStyles()") == 2)
check("整条弧线统一单色", "styleId: 't' + b.tier," in _js10 and
      "color: ARC_HEAT[t - 1]" in _js10)
check("相对频率分级函数存在", "function assignHeat" in _js10 and "Math.log1p" in _js10)
check("旧固定阈值已移除",
      "function tierOf" not in _js10 and "[1, 2, 3].forEach(function (tier)" not in _js10)
check("GL 样式表按 5 档生成", "ARC_TIER_IDS.forEach(function (t)" in _js10)
check("Canvas 两处按 5 档分组",
      _js10.count("ARC_TIER_IDS.forEach(function (tier)") == 2)
check("细线宽度断言仍成立", "w: 3, cw: 2.2" in _js10 and "'#ef4444'" in _js10)
check("频率色阶图例容器", 'id="worldHeat"' in _html10 and 'id="cnHeat"' in _html10)
check("图例由单一数据源生成",
      "function renderHeatLegends" in _js10 and "ARC_HEAT.map" in _js10)
check("图例样式内联", ".heat-legend" in _css10 and ".hl-sw" in _css10)
check("地图说明标注频率着色", "连线颜色按连接频率由冷到热" in _html10)
check("近距点与弧线共用同一频率池", "assignHeat(list.concat(nearList))" in _js10)
check("来源圆点按频率着色（TMap）",
      "function markStyles" in _js10 and "out['src' + t]" in _js10 and
      "styleId: 'src' + b.tier" in _js10 and "styleId: 'near' + tier" in _js10)
check("散点模式圆点同色阶",
      "ARC_HEAT[tier - 1]" in _js10 and "ARC_HEAT[(p.tier || 3) - 1]" in _js10)
check("近距点指纹含频率档", "[p.lat, p.lng, tier].join('|')" in _js10)
check("旧固定境内外线色已移除", "OS_ARC" not in _js10 and "CN_ARC" not in _js10)
# 抽出 app.js 里真实的 assignHeat 交给 Node 执行，验证分档行为而不是只看字符串
_m10 = _re.search(r"  function assignHeat\(list\) \{.*?\n    return list;\n  \}", _js10, _re.S)
_node10 = ("var ARC_LEVELS=5;\n%s\n"
           "var a=[0,6.38905609893065,53.598150033144236,"
           "402.4287934927351,2980.9579870417283].map(function(n){return {n:n};});\n"
           "assignHeat(a);\nvar b=[{n:5},{n:5}];assignHeat(b);\n"
           "var c=[{n:76},{n:1478}];assignHeat(c);\n"
           "console.log(JSON.stringify([a.map(function(x){return x.tier;}),"
           "b.map(function(x){return x.tier;}),"
           "c.map(function(x){return x.tier;})]));\n") % (_m10.group(0) if _m10 else "")
try:
    _tiers = json.loads(_sp.check_output(["node", "-e", _node10],
                                         stderr=_sp.STDOUT).decode("utf-8"))
    check("最低频档 1 / 最高频档 5 / 中间档齐全",
          _tiers[0] == [1, 2, 3, 4, 5], str(_tiers[0]))
    check("频率全部相同时统一落中档", _tiers[1] == [3, 3], str(_tiers[1]))
    # 真机式稀疏数据：广东省弧线 76 次、安徽省近距点 1478 次，必须拉开到青 / 红
    check("稀疏数据下低频线档 1 / 高频近距点档 5",
          _tiers[2] == [1, 5], str(_tiers[2]))
except Exception as _e:
    check("assignHeat 真实分档行为", False, repr(_e))

print("=== 12. 连线整条统一单色（1.0.11） ===")
check("分段常量与几何已移除", all(x not in _js10 for x in
      ("ARC_BANDS", "ARC_BAND", "g.bands", "bandColors", "band.band")))
check("弧线整条一次生成",
      "g.segs = wrapSegs(full);" in _js10 and "bands.push" not in _js10)
check("TMap 样式表只剩 5 个",
      "out['t' + t] = new SDK.PolylineStyle" in _js10 and
      "t' + t + 'b'" not in _js10)
check("styleId 不含段号", "styleId: 't' + b.tier," in _js10 and
      "styleId: 't' + b.tier + 'b'" not in _js10)
check("Canvas 按档单色描边",
      "ctx.strokeStyle = ARC_HEAT[tier - 1];" in _js10 and
      "ARC_BANDS - 1" not in _js10)
check("图例与圆点共用一维色阶",
      "ARC_HEAT.map(function (c, i)" in _js10 and "][1]" not in _js10)
# 抽出真实 ARC_HEAT 交给 Node 执行，确认是一维 5 色而不是 5×3 明度矩阵
_m11 = _re.search(r"  var ARC_HEAT = \[.*?\n  \];", _js10, _re.S)
_node11 = "%s\nconsole.log(JSON.stringify(ARC_HEAT));\n" % (
    _m11.group(0) if _m11 else "var ARC_HEAT=[];")
try:
    _heat11 = json.loads(_sp.check_output(
        ["node", "-e", _node11], stderr=_sp.STDOUT).decode("utf-8"))
    check("Node 实取色阶为一维 5 色",
          len(_heat11) == 5 and _heat11[0] == "#5cc3dd" and
          _heat11[4] == "#ef4444", str(_heat11))
except Exception as _e:
    check("Node 实取色阶为一维 5 色", False, repr(_e))
_docs11 = open(os.path.join(ROOT, "docs", "使用说明.md"),
               encoding="utf-8").read()
check("使用说明解释旧版分段原因",
      "为什么以前一条线会分成几段颜色" in _docs11 and
      "整条连线统一单色" in _docs11)
check("版本号在文档与 manifest 一致", "1.1.14" in man_src and "1.1.14" in _docs11)

print("=== 13. 弧线圆滑化与抽屉滚轮拦截（1.0.12） ===")
_js12 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_css12 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_docs12 = open(os.path.join(ROOT, "docs", "使用说明.md"),
               encoding="utf-8").read()
check("三次贝塞尔双控制点",
      "c1: { lat: from.lat + dLat / 3" in _js12 and
      "c2: { lat: from.lat + dLat * 2 / 3" in _js12)
check("bezierAt 改三次公式",
      "var u = 1 - t, a = u * u * u" in _js12 and "3 * u * u * t" in _js12)
check("旧二次贝塞尔已移除", all(x not in _js12 for x in
      ("g.ctrl", "ctrl: {", "b = 2 * u * t")))
check("采样点按距离自适应 24~64",
      "Math.max(24, Math.min(64, Math.round(d.dist * 1.5) + 24))" in _js12 and
      "Math.max(8, Math.min(20," not in _js12)
check("顶点偏移保持 0.5h", "var off = 2 * h / 3" in _js12 and "0.5h" in _js12)
check("腾讯地图连线端点圆头", "lineCap: 'round'" in _js12)
check("Canvas 保留 round join", "ctx.lineJoin = 'round'; ctx.lineCap = 'round'" in _js12)
check("地图滚轮缩放开关", "function setMapScroll(on)" in _js12 and
      "m.setScrollable(on)" in _js12)
check("抽屉开合切换滚轮缩放",
      "setMapScroll(false);" in _js12 and "setMapScroll(true);" in _js12)
check("地图异步创建后补开关", "setMapScroll(!drawerOpen());" in _js12)
check("wheel 捕获拦截",
      "window.addEventListener('wheel'" in _js12 and
      "passive: false, capture: true" in _js12 and
      "e.stopImmediatePropagation();" in _js12)
check("抽屉内保留正常滚动", "inOverlayScroll(e.target)" in _js12 and
      "classList.contains('drawer')" in _js12)
check("抽屉滚动隔离", "overscroll-behavior:contain" in _css12)
check("使用说明新增曲线与滚轮 FAQ",
      "点开 IP 信息后，滚轮还会缩放地图吗" in _docs12 and "三次贝塞尔" in _docs12)
# 抽出真实几何函数交给 Node 执行，验证曲线端点、采样数与最大折角
_m13 = _re.search(r"  function geoDist\(.*?(?=\n  function wrapSegs\()",
                  _js12, _re.S)
_node13 = """
var S = { arcBend: 0.12 };
%s
var A = {lat: 37.77, lng: -122.42}, B = {lat: 22.5431, lng: 114.0579};
var g = arcControl(A, B, 'overseas');
var pts = []; for (var i = 0; i <= g.n; i++) pts.push(bezierAt(g, i / g.n));
function turn(p, q, r) {
  var k = Math.cos((p.lat + q.lat + r.lat) / 3 * Math.PI / 180);
  var v1x = (q.lng - p.lng) * k, v1y = q.lat - p.lat;
  var v2x = (r.lng - q.lng) * k, v2y = r.lat - q.lat;
  var m1 = Math.sqrt(v1x*v1x + v1y*v1y), m2 = Math.sqrt(v2x*v2x + v2y*v2y);
  if (m1 < 1e-9 || m2 < 1e-9) return 0;
  var c = (v1x*v2x + v1y*v2y) / (m1*m2);
  return Math.acos(Math.max(-1, Math.min(1, c))) * 180 / Math.PI;
}
var maxTurn = 0;
for (var i = 1; i < pts.length - 1; i++) {
  var t = turn(pts[i-1], pts[i], pts[i+1]); if (t > maxTurn) maxTurn = t;
}
console.log(JSON.stringify({ n: g.n, p0: pts[0], pEnd: pts[pts.length-1],
  toLat: g.to.lat, toLng: g.to.lng, maxTurn: maxTurn }));
""" % (_m13.group(0) if _m13 else "")
try:
    _c13 = json.loads(_sp.check_output(
        ["node", "-e", _node13], stderr=_sp.STDOUT).decode("utf-8"))
    check("Node 实测采样数 24~64", 24 <= _c13["n"] <= 64, str(_c13["n"]))
    check("Node 实测曲线起点精确",
          abs(_c13["p0"]["lat"] - 37.77) < 1e-6 and
          abs(_c13["p0"]["lng"] + 122.42) < 1e-6, str(_c13["p0"]))
    check("Node 实测曲线终点精确",
          abs(_c13["pEnd"]["lat"] - _c13["toLat"]) < 1e-6 and
          abs(_c13["pEnd"]["lng"] - _c13["toLng"]) < 1e-6, str(_c13["pEnd"]))
    check("Node 实测长弧最大折角 < 5°", _c13["maxTurn"] < 5,
          "%.3f°" % _c13["maxTurn"])
    print("  曲线实测：n=%d 段，最大折角 %.3f°" % (_c13["n"], _c13["maxTurn"]))
except Exception as _e:
    check("Node 实测三次贝塞尔曲线", False, repr(_e))

print("=== 14. 协议维度 / 五卡 / 地域数量分布（1.1.0） ===")
import collector as _colmod14
_c14src = open(os.path.join(SERVER, "collector.py"), encoding="utf-8").read()
_s14src = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
_g14src = open(os.path.join(SERVER, "gateway.py"), encoding="utf-8").read()
_set14src = open(os.path.join(SERVER, "settings.py"), encoding="utf-8").read()
_j14src = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_css14src = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_h14src = open(os.path.join(UI, "index.html"), encoding="utf-8").read()
_man14src = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()
_chg14src = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rdm14src = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_doc14src = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()

check("gateway 版本 1.1.14", gateway.VERSION == "1.1.14")
_health14 = gateway.api(app, "GET", "/api/health", "", b"")[1]
check("health 返回 1.1.14", _health14.get("version") == "1.1.14")

# --- combined 解析与协议置信度 ---
_c14 = Collector(app.store, geo, app.settings.all(), lambda m: None)
_line14 = ('203.0.113.77 - - [%s] "GET /app/ipsense/?_=123 HTTP/1.1" 200 1234 '
           '"https://example.com/a" "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"' % now)
_e14 = _c14.parse_web(_line14)
check("combined 解析 referer 与 UA", bool(_e14) and
      _e14["referer"] == "https://example.com/a" and "Chrome/120.0" in _e14["ua"])
check("combined 解析 method / status / path",
      bool(_e14) and _e14["method"] == "GET" and _e14["status"] == 200 and
      _e14["path"] == "/app/ipsense/?_=123")
check("外站来路不猜协议，标 Web 未识别",
      bool(_e14) and _e14["proto"] == "web" and _e14["scheme_conf"] == "none")
check("Web 事件 layer 标 web", bool(_e14) and _e14["layer"] == "web")
check("会话 ID 16 位且可复算", bool(_e14) and len(_e14["sess_id"]) == 16 and
      _e14["sess_id"] == _colmod14.session_id("203.0.113.77", _e14["ua"], _e14["ts"]))
_e14b = _c14.parse_web('203.0.113.78 - - [%s] "GET / HTTP/1.1" 200 12' % now)
check("末两段缺失的日志仍可解析",
      bool(_e14b) and _e14b["referer"] == "" and _e14b["ua"] == "" and
      _e14b["proto"] == "web")
check("手动覆盖优先级最高",
      _colmod14.infer_scheme("https://example.com/", {"web_scheme_override": "http"})
      == ("http", "manual"))
check("同站来路推断标 medium",
      _colmod14.infer_scheme("https://192.168.3.5/app/", {}) == ("https", "medium"))
check("localhost 同站来路可推断",
      _colmod14.infer_scheme("http://localhost:5666/x", {}) == ("http", "medium"))
check("外站来路不猜协议",
      _colmod14.infer_scheme("https://example.com/", {}) == ("", "none"))
check("无来路不猜协议", _colmod14.infer_scheme("-", {}) == ("", "none"))
check("非法覆盖值回退到不猜",
      _colmod14.infer_scheme("-", {"web_scheme_override": "ftp"}) == ("", "none"))

_a14 = _c14.parse_auth(
    '%s fn-OESP sshd[1]: Failed password for root from 91.240.118.1 port 5555 ssh2' % _iso)
_k14 = _c14.parse_kern(
    '%s kernel: IPSENSE-KNOCK SRC=1.1.1.1 PROTO=UDP DPT=7000' % _iso)
_r14 = _c14.parse_router(
    '<4> kernel: DROP IN=eth0 PROTO=ICMP SRC=185.220.101.1 DPT=22')
check("SSH 事件 layer=auth / proto=ssh",
      bool(_a14) and _a14["layer"] == "auth" and _a14["proto"] == "ssh")
check("内核事件按 PROTO 标 udp",
      bool(_k14) and _k14["layer"] == "knock" and _k14["proto"] == "udp")
check("路由器事件按 PROTO 标 icmp",
      bool(_r14) and _r14["layer"] == "net" and _r14["proto"] == "icmp")
check("协议与判定仍是两个独立字段",
      bool(_a14) and _a14["proto"] == "ssh" and _a14["verdict"] == "attack")

# --- 幂等补列与索引 ---
_cols14 = {x["name"] for x in app.store.conn.execute(
    "PRAGMA table_info(events)").fetchall()}
check("events 表 8 个新列齐备", all(x in _cols14 for x in
      ("layer", "proto", "scheme_conf", "method", "status", "referer",
       "ua", "sess_id")))
_idxs14 = {x["name"] for x in app.store.conn.execute(
    "PRAGMA index_list(events)").fetchall()}
check("新增协议与会话索引",
      "idx_events_proto" in _idxs14 and "idx_events_sess" in _idxs14)
check("升级用幂等 ADD COLUMN，不重建表",
      "PRAGMA table_info(events)" in _s14src and
      "ALTER TABLE events ADD COLUMN" in _s14src and "EXTRA_COLUMNS" in _s14src)

# --- 五卡聚合：造一批有区分度的 combined 行 ---
_ua14w = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"
_ua14m = "Mozilla/5.0 (iPhone) Safari/605.1"
_web14lines = [
    '203.0.113.10 - - [%s] "GET /app/ipsense/ HTTP/1.1" 200 100 "https://192.168.3.5/start" "%s"' % (now, _ua14w),
    '203.0.113.10 - - [%s] "GET /app/ipsense/detail?_=1 HTTP/1.1" 200 100 "https://192.168.3.5/app/ipsense/" "%s"' % (now, _ua14w),
    '203.0.113.11 - - [%s] "GET /app/ipsense/static/app.js HTTP/1.1" 200 100 "https://192.168.3.5/" "%s"' % (now, _ua14m),
    '203.0.113.12 - - [%s] "GET /welcome HTTP/1.1" 200 100 "https://example.com/ref" "%s"' % (now, _ua14m),
]
_web14evs = [_c14.parse_web(x) for x in _web14lines]
_c14._flush([x for x in _web14evs if x])
_ov14 = app.store.web_overview("24h", 10)
check("web_overview 七组视图齐备", all(k in _ov14 for k in
      ("summary", "protocols", "protocol_verdict", "referrers", "pages",
       "entries", "devices")))
check("总览统计请求 / IP / 会话",
      _ov14["summary"]["requests"] >= 4 and _ov14["summary"]["sessions"] >= 1)
check("协议构成含 https 与 Web 未识别",
      {x["name"] for x in _ov14["protocols"]} >= {"https", "web"})
check("协议构成统计 medium 置信度",
      any(x["name"] == "https" and x["inferred"] >= 3
          for x in _ov14["protocols"]))
check("协议 × 判定交叉视图", len(_ov14["protocol_verdict"]) >= 2)
_refs14 = [x["name"] for x in _ov14["referrers"]]
check("无来路归一为直接输入", "直接输入网址 / 无来路" in _refs14)
check("同站来路显示站内路径",
      any(x.startswith("站内 · ") or x.startswith("站内首页") for x in _refs14))
check("外站来路只显示域名", "example.com" in _refs14)
_pages14 = [x["name"] for x in _ov14["pages"]]
check("受访页按去查询串的 path 聚合",
      "/app/ipsense/detail" in _pages14 and
      "/app/ipsense/detail?_=1" not in _pages14)
check("受访页剔除静态资源", not any("app.js" in x for x in _pages14))
check("入口页取会话首条请求",
      "/app/ipsense/" in [x["name"] for x in _ov14["entries"]])
check("入口页也剔除静态资源",
      not any("app.js" in x["name"] for x in _ov14["entries"]))
_dev14 = [x["name"] for x in _ov14["devices"]]
check("终端设备归一为浏览器 · 系统",
      "Chrome · Windows" in _dev14 and "Safari · iOS" in _dev14)

# --- 地域数量分布的合规边界 ---
_gc14 = app.store.geo_distribution("24h", "cn", 40)
_go14 = app.store.geo_distribution("24h", "overseas", 40)
check("地域分布返回 scope / total / regions",
      _gc14["scope"] == "cn" and "total" in _gc14 and "regions" in _gc14)
check("全球分布按国家聚合", _go14["scope"] == "overseas")
_regions14 = _gc14["regions"] + _go14["regions"]
check("地域只返回聚合数字与中心点",
      bool(_regions14) and all(set(x) == {"name", "count", "ips", "lat", "lng"}
                               for x in _regions14))
check("地域输出不含边界 / GeoJSON / 多边形字段",
      bool(_regions14) and all(not any(k in x for k in
          ("geometry", "coordinates", "boundary", "polygon", "geojson"))
          for x in _regions14))
check("地域坐标来自内置中心点表",
      "PROVINCE_COORDS" in _s14src and "COUNTRY_COORDS" in _s14src)
check("地域合规声明写入后端",
      "不产出任何边界" in _s14src and "def geo_distribution" in _s14src)

# --- 历史字段回填 ---
_before14 = app.store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
_old14 = app.store.conn.execute(
    "SELECT id,dedup,raw FROM events WHERE source='local_web' AND proto<>'' LIMIT 1").fetchone()
app.store.set_meta("web_fields_v110", "")
if _old14:
    app.store.conn.execute(
        "UPDATE events SET layer='',proto='',scheme_conf='',method='',status=0,"
        "referer='',ua='',sess_id='' WHERE id=?", (_old14["id"],))
    app.store.conn.commit()
_up14 = app.store.upgrade_web_events(_c14.parse_web, force=True)
_after14 = app.store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
_fix14 = app.store.conn.execute(
    "SELECT proto,sess_id,ua FROM events WHERE id=?", (_old14["id"],)).fetchone() if _old14 else None
check("历史回填不重复 INSERT", _after14 == _before14)
check("历史 Web 行按 dedup 精确补字段",
      bool(_fix14) and bool(_fix14["proto"]) and len(_fix14["sess_id"]) == 16,
      "scanned=%d updated=%d" % (_up14["scanned"], _up14["updated"]))
check("回填结果写入 meta 防重复扫描",
      app.store.get_meta("web_fields_v110") == "1")
check("meta 已置位时重复启动直接跳过",
      app.store.upgrade_web_events(_c14.parse_web).get("skipped") is True)
check("历史回填按 id 游标分页、每批单独提交",
      "AND id>? ORDER BY id LIMIT ?" in _s14src and
      "batch=1000" in _s14src and "self.conn.commit()" in _s14src)
check("历史回填放后台线程，不阻塞 serve 启动",
      "_spawn_web_upgrade" in _g14src and "web-fields-upgrade" in _g14src and
      "_upgrade_running" in _g14src and
      _g14src.index("self._spawn_web_upgrade()") <
      _g14src.index("self.collector.start(do_backfill=backfill)"))

# --- 新 API ---
for _p14 in ("/api/web/overview", "/api/protocols", "/api/referrers",
             "/api/pages", "/api/devices", "/api/geodist?scope=cn",
             "/api/geodist?scope=overseas"):
    _pp14, _, _qq14 = _p14.partition("?")
    try:
        _c14api, _r14api = gateway.api(app, "GET", _pp14, _qq14, b"")
        check("API " + _p14, _c14api == 200 and
              isinstance(_r14api, dict) and _r14api.get("ok") is True)
    except Exception as _e:
        check("API " + _p14, False, repr(_e))
_, _r14prot = gateway.api(app, "GET", "/api/protocols", "", b"")
check("细粒度接口只返回协议子集",
      set(_r14prot["data"]) == {"protocols", "protocol_verdict", "summary"})
_, _r14pages = gateway.api(app, "GET", "/api/pages", "", b"")
check("页面接口同时返回受访页与入口页",
      set(_r14pages["data"]) == {"pages", "entries"})
_, _r14dev = gateway.api(app, "GET", "/api/devices", "", b"")
check("设备接口只返回设备子集", set(_r14dev["data"]) == {"devices"})
_, _r14geo = gateway.api(app, "GET", "/api/geodist", "scope=bogus", b"")
check("非法 scope 回退到全球口径", (_r14geo["data"] or {}).get("scope") == "all")
_, _r14rec = gateway.api(app, "GET", "/api/records", "proto=https&page=1", b"")
check("记录表按协议筛选",
      _r14rec.get("ok") is True and
      len(_r14rec["data"]["rows"]) >= 1 and
      all(x["proto"] == "https" for x in _r14rec["data"]["rows"]))
_x14 = gateway.api(app, "GET", "/api/export", "", b"")
_csv14raw = _x14[1]
_csv14 = _csv14raw.decode("utf-8") if isinstance(_csv14raw, bytes) else str(_csv14raw)
check("导出 CSV 表头含协议 / 状态码 / 来路",
      "时间,来源,IP,归属,范围,协议,判定,端口,服务,状态码,来路,动作,路径" in _csv14)

# --- 前端与文档 ---
_html14 = gateway.render_index().decode("utf-8")
check("首页内联全球分布与合并排名模块", all(x in _html14 for x in
      ("全球 IP 来源分布", "访问统计与排名", "rankCard", "rankSum",
       "rankCn", "rankOs", "geoCanvas", "geoLegend")))
check("首页内联五张分析卡", all(x in _html14 for x in
      ("访问协议构成", "来路", "受访页", "入口页", "终端设备", "webCards")))
check("记录表新增协议筛选", 'id="fProto"' in _html14)
check("前端协议 / 地域函数齐备", all(("function " + f) in _j14src for f in
      ("protoChip", "renderMiniList", "renderWebCards", "renderGeoDist",
       "drawGeoCanvas", "drawGeoMarkers", "openRegionProfile", "assignGeoTier")))
check("地域气泡标签碰撞避让", "var clash = labels.some" in _j14src)
check("滚轮开关覆盖三张地图", "[S.world, S.cn, S.geoMap]" in _j14src)
check("设置页新增 web_scheme_override",
      "fld('web_scheme_override'" in _j14src and
      '"web_scheme_override": ""' in _set14src)
check("全球分布与双榜样式已内联", all(x in _css14src for x in
      (".geodist", ".rank-cols", ".rank-col", ".mini-card", ".proto-chip")))
check("首页内联合规说明",
      "不绘制国界" in _html14 and "边界以官方地图为准" in _html14)
check("版本在四处文档与 manifest 一致",
      "version                    = 1.1.14" in _man14src and
      "**1.1.14（当前版本）**" in _chg14src and
      "**1.1.14（当前版本）**" in _rdm14src and "1.1.14" in _doc14src)
check("版本行倒序且旧版不再标当前",
      _chg14src.index("**1.1.14（当前版本）**") < _chg14src.index("**1.1.1**") and
      "**1.1.1（当前版本）**" not in _chg14src and
      "**1.1.0（当前版本）**" not in _chg14src and
      "**1.0.12（当前版本）**" not in _chg14src)
check("更新日志只用三种 emoji", not any(x in _chg14src for x in
      ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("README 部署命令指向 1.1.14",
      "build/ipsense_1.1.14_all.fpk" in _rdm14src)
check("使用说明解释 Web 未识别与协议覆盖",
      "Web 未识别" in _doc14src and "web_scheme_override" in _doc14src)
check("使用说明解释地域图合规边界",
      "不产出任何国界 / 省界轮廓数据" in _doc14src and
      "官方合规底图为准" in _doc14src)
check("端口敲门仍保持只观测",
      "只观测" in _rdm14src and "只观测" in _chg14src)

print("\n=== 15. 启动与画像性能（1.1.1） ===")
_s15 = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
_g15 = open(os.path.join(SERVER, "gateway.py"), encoding="utf-8").read()
_j15 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_p15 = open(os.path.join(ROOT, "tools", "make_preview.py"), encoding="utf-8").read()
_m15 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()

check("当前版本已同步", gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m15)
check("画像窗口常量存在",
      "IP_DETAIL_WINDOW = 3000" in _s15 and "GROUP_DETAIL_WINDOW = 3000" in _s15)
check("一次窗口查询取代 8 条全历史聚合",
      "ORDER BY id DESC LIMIT ?" in _s15 and
      "COUNT(DISTINCT port) ports, COUNT(DISTINCT path) paths" not in _s15)
check("全历史只保留 COUNT / MIN / MAX",
      "SELECT COUNT(*) n, MIN(ts) first_ts, MAX(ts) last_ts " in _s15)
check("画像如实回传窗口口径",
      '"truncated": (base["n"] or 0) > len(rows)' in _s15)
check("聚合缓存默认 4 秒 TTL", "self.cache_ttl = 4.0" in _s15)
check("缓存方法与清理入口齐备",
      "def cached(self, key, fn, ttl=None)" in _s15 and
      "def clear_cache(self)" in _s15)
check("八个聚合入口支持自定义 TTL", _s15.count("_ttl=None") >= 8)
check("缓存命中返回同一结果对象",
      app.store.status("24h") is app.store.status("24h"))
check("预热与启动解耦函数齐备",
      all(("def " + f) in _g15 for f in ("warmup", "boot_async", "sources_safe")))
check("预热缓存有效期 60 秒", "s, ttl = self.store, 60" in _g15)
check("serve 先 bind / listen 再后台 boot",
      _g15.index("srv.bind(SOCK_PATH)") < _g15.index("srv.listen(64)") <
      _g15.index("app.boot_async()"))
check("serve 内不再同步启动采集器",
      "app.start_collector(backfill=True)" not in
      _g15[_g15.index("def serve():"):_g15.index("    def bye")])
check("在线校验队列移到 warmup 之后",
      "queue_top" in _g15[_g15.index("def warmup(self)"):_g15.index("def boot_async")])
check("top_public_ips 限定近 7 天", "time.time() - 7 * 86400" in _s15)
check("采集器未就绪时状态接口降级", "app.sources_safe()" in _g15)
check("/api/ip 支持 window 参数", 'p.get("window", "")' in _g15)
check("前端请求加超时兜底",
      "AbortController" in _j15 and "请求超时，请稍后重试" in _j15)
check("GET 与其它方法超时分开",
      "method && method !== 'GET' ? 30000 : 15000" in _j15)
check("加载态文案明确", "正在读取该 IP 的访问画像" in _j15 and
      "正在读取该来源点的画像" in _j15)
check("画像标注统计口径", "统计口径" in _j15 and "num(w.rows)" in _j15)
check("预览 mock 同步窗口口径",
      "window:{rows:3000,limit:3000,truncated:true}" in _p15)

_d15 = app.store.ip_detail("45.155.205.113")
check("画像字段结构保持兼容",
      all(k in _d15 for k in ("ip", "info", "agg", "recent", "top_paths",
                              "protocols", "verdicts", "referrers", "uas", "window")))
check("画像聚合字段齐备",
      all(k in _d15["agg"] for k in ("n", "first_ts", "last_ts",
                                     "ports", "paths", "sessions")))
check("top_paths 仍为 path / n",
      all(("path" in x and "n" in x) for x in _d15["top_paths"]))
check("协议构成含 manual 字段",
      all("manual" in x for x in _d15["protocols"]))
check("最近动作不超过 20 条", len(_d15["recent"]) <= 20)
check("整组画像同样回传窗口口径",
      "window" in app.store.group_detail(["45.155.205.113"], "all", 40))
_c15ip, _r15ip = gateway.api(app, "GET", "/api/ip",
                             "ip=45.155.205.113&window=500", b"")
check("/api/ip window 参数生效",
      _c15ip == 200 and _r15ip["data"]["window"]["limit"] == 500)
_c15st, _r15st = gateway.api(app, "GET", "/api/status", "", b"")
check("采集器未就绪时 /api/status 仍可用",
      _c15st == 200 and isinstance(_r15st.get("sources"), dict))

print("\n=== 16. 全球 IP 分布与排名合并（1.1.2） ===")
_s16 = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
_g16 = open(os.path.join(SERVER, "gateway.py"), encoding="utf-8").read()
_j16 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_h16 = open(os.path.join(UI, "index.html"), encoding="utf-8").read()
_c16 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_p16 = open(os.path.join(ROOT, "tools", "make_preview.py"), encoding="utf-8").read()
_m16 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()
_ch16 = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rd16 = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_dc16 = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
_html16 = gateway.render_index().decode("utf-8")

check("当前版本已同步到五处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m16 and
      "**1.1.14（当前版本）**" in _ch16 and
      "**1.1.14（当前版本）**" in _rd16 and "1.1.14" in _dc16)
_ga16 = app.store.geo_distribution("24h", "all", 40)
check("scope=all 返回全球口径",
      _ga16["scope"] == "all" and "total" in _ga16 and bool(_ga16["regions"]))
check("scope=all 境内归并到中国、境外按国家",
      "CASE WHEN scope='cn' THEN '中国'" in _s16 and
      "scope IN ('cn','overseas')" in _s16)
check("scope=all 仍只出聚合数字与中心点",
      all(set(x) == {"name", "count", "ips", "lat", "lng"}
          for x in _ga16["regions"]))
check("scope=all 不含边界 / GeoJSON 字段",
      all(not any(k in x for k in ("geometry", "coordinates", "polygon", "geojson"))
          for x in _ga16["regions"]))
_, _r16def = gateway.api(app, "GET", "/api/geodist", "", b"")
check("/api/geodist 默认口径为 all", _r16def["data"]["scope"] == "all")
_, _r16all = gateway.api(app, "GET", "/api/geodist", "scope=all", b"")
check("/api/geodist 放行 scope=all", _r16all["data"]["scope"] == "all")
check("gateway 放行三种 scope", '("cn", "overseas", "all")' in _g16)
check("预热只算一份全球地域分布",
      's.geo_distribution("24h", "all", 40, _ttl=ttl)' in _g16 and
      's.geo_distribution("24h", "cn", 40' not in _g16)
check("首页内联全球 IP 来源分布",
      "全球 IP 来源分布" in _html16 and 'id="geoCard"' in _html16)
check("首页内联访问统计与排名",
      "访问统计与排名" in _html16 and 'id="rankCard"' in _html16 and
      'id="rankSum"' in _html16)
check("地图去掉境内 / 全球切换",
      "geoSeg" not in _html16 and "geoScopeTag" not in _html16 and
      "geoSeg" not in _j16)
check("地图右侧重复统计与排名已移除",
      "geoBars" not in _html16 and "geoTip" not in _html16 and
      "geoSum" not in _html16 and "geoBars" not in _j16)
check("全页只保留一处境内 / 境外双榜",
      _html16.count('id="rankCn"') == 1 and _html16.count('id="rankOs"') == 1 and
      _html16.count("境内访问排名") == 1 and _html16.count("境外访问排名") == 1)
check("前端固定请求 scope=all",
      _j16.count("&scope=all&limit=40") >= 2 and "geoScope: 'all'" in _j16)
check("地图固定全球投影",
      "var b = WORLD_BOUNDS;" in _j16 and
      "var step = 30, lng, lat, x, y;" in _j16 and
      "S.geoScope === 'cn' ? CN_BOUNDS" not in _j16)
check("排名条目支持点击下钻",
      "function renderRank(elId, list, cls, scope)" in _j16 and
      "data-region=" in _j16 and "['rankCn', 'rankOs']" in _j16 and
      "openRegionProfile(el.getAttribute('data-region')" in _j16)
# 1.1.7 起 loadHeavy 逐接口包了一层 {ok,data}，数据多取一层 .data
check("双榜与地图下钻口径正确",
      "renderRank('rankCn', r[1].data.data.cn, '', 'cn')" in _j16 and
      "renderRank('rankOs', r[1].data.data.overseas, 'os', 'overseas')" in _j16)
check("统计卡与提示搬到合并模块",
      "$('rankSum').innerHTML" in _j16 and "$('rankTip').textContent" in _j16 and
      "国家 / 地区" in _j16)
check("样式支持全宽地图与双榜",
      ".rank-cols{display:grid;grid-template-columns:1fr 1fr" in _c16 and
      ".rank-col{" in _c16 and ".rank-row[data-region]" in _c16 and
      ",.rank-cols{grid-template-columns:1fr}" in _c16)
check("预览 mock 同步全球口径",
      "var geoAll=" in _p16 and "scope:'all'" in _p16 and
      "data:geoAll" in _p16 and "#rank-detail" in _p16)
check("预览 mock 不再引用旧控件",
      "geoCn" not in _p16 and "geoOs" not in _p16 and
      "geoSeg" not in _p16 and ".geo-bar[data-region]" not in _p16)
check("更新日志只用三种 emoji",
      not any(x in _ch16 for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("端口敲门仍保持只观测", "只观测" in _rd16 and "只观测" in _ch16)
print("\n=== 17. 五卡交互放大与条目下钻（1.1.3） ===")
_s17 = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
_g17 = open(os.path.join(SERVER, "gateway.py"), encoding="utf-8").read()
_j17 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_h17 = open(os.path.join(UI, "index.html"), encoding="utf-8").read()
_c17 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_p17 = open(os.path.join(ROOT, "tools", "make_preview.py"), encoding="utf-8").read()
_m17 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()
_ch17 = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rd17 = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_dc17 = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
_html17 = gateway.render_index().decode("utf-8")

check("当前版本已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m17 and
      "**1.1.14（当前版本）**" in _ch17 and
      "**1.1.14（当前版本）**" in _rd17 and "1.1.14" in _dc17 and
      "build/ipsense_1.1.14_all.fpk" in _rd17)
_, _rh17 = gateway.api(app, "GET", "/api/health", "", b"")
check("health 返回 1.1.14", _rh17.get("version") == "1.1.14")
check("后端定义五个下钻维度",
      "WEB_DIMS = {" in _s17 and
      all(('"%s":' % d) in _s17 for d in
          ("proto", "referer", "page", "entry", "device")))
check("路由放行 breakdown 且校验维度",
      '"/api/web/breakdown"' in _g17 and
      '("proto", "referer", "page", "entry", "device")' in _g17 and
      "缺少条目名称" in _g17)
_cb17, _rb17 = gateway.api(app, "GET", "/api/web/breakdown", "dim=bogus&name=x", b"")
check("非法维度返回 400", _cb17 == 400 and _rb17.get("ok") is False)
_ce17, _re17 = gateway.api(app, "GET", "/api/web/breakdown", "dim=page&name=", b"")
check("缺条目名返回 400", _ce17 == 400 and _re17.get("ok") is False)

_ov17 = app.store.web_overview("24h", 30)
_bd17 = {}
for _dim17, _field17 in (("proto", "protocols"), ("referer", "referrers"),
                         ("page", "pages"), ("entry", "entries"), ("device", "devices")):
    _lst17 = _ov17.get(_field17) or []
    if not _lst17:
        continue
    _it17 = _lst17[0]
    _bd17[_dim17] = (_it17, app.store.web_breakdown(_dim17, _it17["name"], "24h", 50))
check("五个维度都能下钻出来源 IP",
      len(_bd17) == 5 and all(v[1].get("ok") and v[1].get("ip_list")
                              for v in _bd17.values()),
      str({k: len(v[1].get("ip_list", [])) for k, v in _bd17.items()}))
check("卡片次数与下钻汇总一致（口径同源）",
      all(v[0]["count"] == v[1]["requests"] for v in _bd17.values()),
      str({k: (v[0]["count"], v[1]["requests"]) for k, v in _bd17.items()}))
check("下钻返回首末次与最近动作",
      all(v[1].get("first_ts") and v[1].get("recent") for v in _bd17.values()))
check("IP 明细带归属与范围字段",
      all(all(k in x for k in ("ip", "n", "country", "scope", "verdict", "last_ts"))
          for v in _bd17.values() for x in v[1]["ip_list"]))
check("入口页下钻走会话首条 JOIN", "MIN(id) mid" in _s17 and "e.id = s.mid" in _s17)
check("哨兵值 - / unknown 还原成空串条件",
      "referer='-'" in _s17 and "proto='unknown'" in _s17)
check("下钻复用相同归一化函数与静态资源过滤",
      all(x in _s17 for x in ("_ref_name", "_clean_path", "_ua_name", "STATIC_PATH_RE")))
check("SQL 用参数化 IN，不把展示名拼进语句",
      '",".join("?" * len(real_keys))' in _s17 and "web_breakdown" in _s17)

check("首页内联放大面板结构",
      all(x in _html17 for x in
          ('id="cardZoom"', 'id="zoomMask"', 'id="zoomList"', 'id="zoomDetail"',
           'id="zoomClose"', "mini-expand", "data-dim=\"proto\"")))
check("五张卡都带 data-dim",
      all(('data-dim="%s"' % d) in _h17 for d in
          ("proto", "referer", "page", "entry", "device")))
check("前端实现无缝放大与收回",
      all(x in _j17 for x in ("function openCardZoom", "function closeCardZoom",
                              "void z.offsetWidth", "S.zoomFrom", "S.zoomOn")))
check("条目可点击下钻",
      all(x in _j17 for x in ("data-name=", "function openZoomItem",
                              "function renderZoomDetail", "api/web/breakdown")))
check("来源 IP 复用画像抽屉",
      "closeCardZoom(false, function () { openDetail(ip); })" in _j17)
check("放大用位置尺寸过渡，不拉伸文字",
      "z.style.width = w + 'px'" in _j17 and "transform: scale" not in _c17)
check("放大面板同步 aria-hidden 语义",
      "z.setAttribute('aria-hidden', 'false')" in _j17 and
      "z.setAttribute('aria-hidden', 'true')" in _j17 and
      'aria-hidden="true"' in _h17)
check("放大时关地图滚轮、面板内仍可滚动",
      "$('zoomMask').classList.contains('on')" in _j17 and
      "classList.contains('zoom-card')" in _j17 and "setMapScroll(false)" in _j17)
check("首屏取 30 条、卡片显示 8 条",
      "&limit=30" in _j17 and "slice(0, 8)" in _j17 and
      's.web_overview("24h", 30' in _g17)
check("Esc / 遮罩 / 关闭按钮均可收起",
      "e.key !== 'Escape'" in _j17 and "$('zoomMask').onclick" in _j17 and
      "$('zoomClose').onclick" in _j17)
check("预览 mock 含下钻详情与三个验收入口",
      all(x in _p17 for x in ("var breakdown=", "api/web/breakdown",
                              "#card-zoom", "#card-item", "#card-ip")))
check("样式含放大面板与响应式",
      all(x in _c17 for x in (".zoom-card{", ".zoom-body{", ".zoom-ip{",
                              "@media(max-width:820px)")))
check("更新日志只用三种 emoji",
      not any(x in _ch17.split("**1.1.2**")[0] for x in
              ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("端口敲门仍保持只观测", "只观测" in _rd17 and "只观测" in _ch17)
check("合规红线不变", "不产出任何边界" in _s17 and "不绘制国界" in _html17)


print("\n=== 18. 滚动条治理与卡片布局（1.1.4） ===")
_c18 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_ch18 = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rd18 = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_dc18 = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
_m18 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()
check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m18 and
      "**1.1.14（当前版本）**" in _ch18 and
      "**1.1.14（当前版本）**" in _rd18 and "1.1.14" in _dc18 and
      "build/ipsense_1.1.14_all.fpk" in _rd18)
check("小卡列表去掉 max-height 与 overflow-y:auto",
      ".mini-list{overflow:visible}" in _c18 and
      "max-height:224px;overflow-y:auto" not in _c18)
check("小卡行去掉负 margin，改用内边距",
      ".mini-row[data-dim]{border-radius:6px;padding:6px 5px;margin:0;" in _c18 and
      "margin:0 -5px" not in _c18)
check("页面主滚动条隐藏视觉但保留滚动",
      "html{scrollbar-width:none" in _c18 and
      "html::-webkit-scrollbar{width:0;height:0;display:none}" in _c18)
check("内部滚动区改用恒定细条，不再 hover 显隐（1.1.5 修订）",
      ":is(.live-list,.zoom-list,.zoom-detail,.drawer-body,.table-wrap,.zoom-body)" in _c18 and
      "scrollbar-width:thin" in _c18 and "scrollbar-gutter:stable" in _c18 and
      "width:6px;height:6px" in _c18 and
      "hover::-webkit-scrollbar-thumb" not in _c18)
check("放大面板与画像抽屉仍保留滚动能力",
      ".zoom-list{overflow-y:auto" in _c18 and ".drawer-body{" in _c18)
check("五卡 flex 列布局与说明贴底",
      ".mini-card{display:flex;flex-direction:column}" in _c18 and
      ".mini-sub{margin-top:auto}" in _c18)
check("放大面板与响应式样式未被破坏",
      all(x in _c18 for x in (".zoom-card{", ".zoom-body{", ".zoom-ip{",
                              "@media(max-width:820px)")))
check("使用说明含 1.1.4 章节与 FAQ",
      "### 滚动条与卡片布局（1.1.4）" in _dc18 and
      "**1.1.4 去掉滚动条后，内容多的时候还能滚吗？**" in _dc18)
check("更新日志 1.1.4 只用三种 emoji",
      not any(x in _ch18.split("**1.1.2**")[0] for x in
              ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("端口敲门仍保持只观测", "只观测" in _rd18 and "只观测" in _ch18)
check("合规红线不变", "不产出任何边界" in _m18 and "不产出任何国界" in _dc18)


print("\n=== 19. 设置抽屉滚动稳定性（1.1.5） ===")
_c19 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_j19 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_ch19 = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rd19 = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_dc19 = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
_m19 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()
check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m19 and
      "**1.1.14（当前版本）**" in _ch19 and
      "**1.1.14（当前版本）**" in _rd19 and "1.1.14" in _dc19 and
      "build/ipsense_1.1.14_all.fpk" in _rd19)
check("内部滚动区 scrollbar-width 恒定为 thin",
      "scrollbar-width:thin;" in _c19 and "scrollbar-color:" in _c19)
check("彻底删除 hover 切换 scrollbar-width（抖动根因）",
      ":hover{\n  scrollbar-width:thin" not in _c19 and
      "):hover{\n  scrollbar-width" not in _c19 and
      _c19.count("scrollbar-width:none") == 1)   # 只剩 html 主滚动条那条
check("scrollbar-gutter:stable 恒定预留槽位",
      "scrollbar-gutter:stable" in _c19)
check("滚动条槽宽恒定 6px 且 thumb 常显淡色",
      "width:6px;height:6px" in _c19 and
      "background:rgba(130,160,210,.16);border-radius:9999px" in _c19 and
      "background:transparent;border-radius:9999px" not in _c19)
check("hover 只加深颜色、不改变布局",
      "::-webkit-scrollbar-thumb:hover{\n  background:rgba(130,160,210,.5)}" in _c19)
check(".drawer-body 补 min-height:0",
      ".drawer-body{padding:20px 22px 40px;overflow-y:auto;flex:1;min-height:0;" in _c19)
check(".zoom-list / .zoom-detail 补 min-height:0",
      ".zoom-list{overflow-y:auto;flex:1;min-height:0;" in _c19 and
      ".zoom-detail{overflow-y:auto;min-height:0;" in _c19)
check("遮罩去掉 backdrop-filter，改纯半透明",
      ".mask{position:fixed;inset:0;background:rgba(3,8,18,.78)" in _c19 and
      ".zoom-mask{position:fixed;inset:0;background:rgba(3,8,18,.8)" in _c19 and
      "backdrop-filter:blur(4px)" not in _c19)
check("抽屉独立合成层", "backface-visibility:hidden" in _c19)
check("滚轮拦截改父链遍历，不依赖 Element.closest",
      "function inOverlayScroll(t)" in _j19 and "t.classList.contains('drawer')" in _j19 and
      "inOverlayScroll(e.target)" in _j19 and "t.closest &&" not in _j19)
check("1.1.4 五卡零滚动条未回归",
      ".mini-list{overflow:visible}" in _c19 and "max-height:224px;overflow-y:auto" not in _c19)
check("放大面板 / 下钻 / 画像抽屉未回归",
      all(x in _c19 for x in (".zoom-card{", ".zoom-body{", ".zoom-ip{")) and
      "/api/web/breakdown" in _j19 and "openDetail(ip)" in _j19)
check("使用说明含 1.1.5 章节与 FAQ",
      "### 设置抽屉滚动与文字稳定性（1.1.5）" in _dc19 and
      "**1.1.5 设置界面之前为什么会抖，现在还会不会？**" in _dc19)
check("旧描述已订正，不再说淡显 5px 细条",
      "淡显一条 5px 细条" not in _dc19 and "淡显 5px 的半透明细条" not in _dc19)
check("更新日志 1.1.5 只用三种 emoji",
      not any(x in _ch19.split("**1.1.4**")[0] for x in
              ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("端口敲门仍保持只观测", "只观测" in _rd19 and "只观测" in _ch19)
check("合规红线不变", "不产出任何边界" in _m19 and "不产出任何国界" in _dc19)

print("\n=== 20. 浮层外滚轮重定向（1.1.6） ===")
_j20 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_c20 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_p20 = open(os.path.join(ROOT, "tools", "make_preview.py"), encoding="utf-8").read()
_ch20 = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rd20 = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_dc20 = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
_m20 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()
check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m20 and
      "**1.1.14（当前版本）**" in _ch20 and
      "**1.1.14（当前版本）**" in _rd20 and "1.1.14" in _dc20 and
      "build/ipsense_1.1.14_all.fpk" in _rd20)
check("新增浮层滚动容器选择函数",
      "function overlayScrollCandidates(e)" in _j20 and
      "document.querySelector('.drawer.on .drawer-body')" in _j20 and
      "$('zoomMask').classList.contains('on')" in _j20)
check("放大面板按鼠标左右位置选列表 / 详情",
      "e.clientX >= r.left + r.width / 2" in _j20 and
      "[$('zoomDetail'), $('zoomList')]" in _j20 and
      "[$('zoomList'), $('zoomDetail')]" in _j20)
check("不可滚容器才回退，不做滚到底连锁",
      "el.scrollHeight - el.clientHeight <= 1) continue" in _j20 and
      "if (el.scrollTop !== before)" not in _j20)
check("滚轮量重定向到 scrollTop",
      "function redirectWheel(e)" in _j20 and "el.scrollTop += d" in _j20 and
      "redirectWheel(e);" in _j20)
check("deltaMode 按行 / 按页换算",
      "e.deltaMode === 1 ? unit * 16" in _j20 and
      "e.deltaMode === 2 ? unit * el.clientHeight : unit" in _j20)
check("浮层内部仍走原生滚动",
      "function inOverlayScroll(t)" in _j20 and
      "if (inOverlayScroll(e.target)) return;" in _j20 and
      "t.closest &&" not in _j20)
check("浮层外仍 preventDefault 并挡住 SDK 手势",
      "e.preventDefault();" in _j20 and "e.stopImmediatePropagation();" in _j20 and
      "{ passive: false, capture: true }" in _j20)
check("地图滚轮缩放开关未回归",
      "function setMapScroll(on)" in _j20 and "setMapScroll(false)" in _j20 and
      "setMapScroll(true)" in _j20)
check("CSS 恒定细条与可收缩布局未回归",
      "scrollbar-width:thin;" in _c20 and "scrollbar-gutter:stable" in _c20 and
      "min-height:0" in _c20 and "backdrop-filter:blur(4px)" not in _c20)
check("预览页含两个新验收入口",
      "#settings-wheel" in _p20 and "#card-wheel" in _p20)
check("使用说明含 1.1.6 章节与 FAQ",
      "### 浮层外滚轮也能滚动（1.1.6）" in _dc20 and
      "**1.1.6 设置界面打开后，鼠标停在地图上滚轮没反应？**" in _dc20)
check("旧 FAQ 已订正为重定向口径",
      "抽屉外的滚轮改成重定向" in _dc20 and
      "抽屉外的滚轮统一拦截" not in _dc20)
check("README 详版含重定向说明", "浮层外的滚轮改为**重定向**" in _rd20)
# 1.1.7：manifest 的 changelog 单行滚动到最新版，desc 里 1.1.6 说明仍保留
check("manifest 历史 desc 说明保留（1.1.6 / 1.1.7）",
      "1.1.6 起浮层外的滚轮不再被吞掉" in _m20 and
      "1.1.7 起状态标分三级" in _m20)
check("更新日志 1.1.6 只用三种 emoji",
      not any(x in _ch20.split("**1.1.5**")[0] for x in
              ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("五卡放大 / 下钻 / 画像抽屉未回归",
      "function openCardZoom" in _j20 and "/api/web/breakdown" in _j20 and
      "openDetail(ip)" in _j20)
check("端口敲门仍保持只观测", "只观测" in _rd20 and "只观测" in _ch20)
check("合规红线不变", "不产出任何边界" in _m20 and "不产出任何国界" in _dc20)

print("\n=== 21. 连接状态与缓存击穿治理（1.1.7） ===")
_j21 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_c21 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_s21 = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
_p21 = open(os.path.join(ROOT, "tools", "make_preview.py"), encoding="utf-8").read()
_ch21 = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rd21 = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_dc21 = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
_m21 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()
check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m21 and
      "**1.1.14（当前版本）**" in _ch21 and
      "**1.1.14（当前版本）**" in _rd21 and "1.1.14" in _dc21 and
      "build/ipsense_1.1.14_all.fpk" in _rd21)
check("缓存改为 stale-while-revalidate",
      "stale-while-revalidate" in _s21 and
      "if hit:" in _s21 and "return hit[2]" in _s21 and
      "def _refresh_cache(self, key, fn, life, guard)" in _s21)
check("每 key 独立后台刷新锁，防并发穿透",
      "self._cache_busy = {}" in _s21 and "guard.acquire(False)" in _s21 and
      "threading.Thread(target=self._refresh_cache" in _s21 and
      "guard.release()" in _s21)
check("后台重算全局限流，避免锁风暴",
      "self._cache_refresh_sem = threading.Semaphore(1)" in _s21 and
      "if not self._cache_refresh_sem.acquire(False)" in _s21 and
      "self._cache_refresh_sem.release()" in _s21)
check("重算异常保留旧值下轮重试",
      "# 重算失败不动旧值" in _s21 and "except Exception:" in _s21)
# 功能性验证：过期请求不等冷聚合，且只有一个后台线程重算
_calls = {"n": 0}
def _slow():
    _calls["n"] += 1
    time.sleep(0.30)
    return "v%d" % _calls["n"]
app.store.clear_cache()
_t0 = time.time()
_v1 = app.store.cached("swr-probe", _slow, ttl=0.05)
_d1 = time.time() - _t0
time.sleep(0.08)
_t0 = time.time()
_v2 = app.store.cached("swr-probe", _slow, ttl=0.05)
_d2 = time.time() - _t0
check("缓存过期立即返回旧值，不等冷聚合",
      _v1 == "v1" and _v2 == _v1 and _d2 < 0.10,
      "首次 %.3fs / 过期 %.3fs" % (_d1, _d2))
time.sleep(0.55)
_v3 = app.store.cached("swr-probe", _slow, ttl=0.05)
check("后台重算写入新值", _v3 != _v1 and _calls["n"] >= 2,
      "%s -> %s, calls=%d" % (_v1, _v3, _calls["n"]))
import threading as _th
_calls2 = {"n": 0}
def _slow2():
    _calls2["n"] += 1
    time.sleep(0.25)
    return _calls2["n"]
app.store.clear_cache()
app.store.cached("swr-conc", _slow2, ttl=0.05)
time.sleep(0.08)
_ts = [_th.Thread(target=lambda: app.store.cached("swr-conc", _slow2, ttl=0.05))
       for _ in range(8)]
for _t in _ts: _t.start()
for _t in _ts: _t.join()
time.sleep(0.40)
check("并发过期只触发一次后台重算", _calls2["n"] == 2,
      "calls=%d" % _calls2["n"])
# 多 key 同时过期：全局信号量保证同一时刻只有一个冷聚合在跑
_active = {"cur": 0, "max": 0}
_probe_lock = _th.Lock()
def _slow3():
    with _probe_lock:
        _active["cur"] += 1
        _active["max"] = max(_active["max"], _active["cur"])
    time.sleep(0.20)
    with _probe_lock:
        _active["cur"] -= 1
    return 1
app.store.clear_cache()
for _i in range(6):
    app.store.cached("swr-multi-%d" % _i, _slow3, ttl=0.01)
time.sleep(0.05)
for _i in range(6):
    app.store.cached("swr-multi-%d" % _i, _slow3, ttl=0.01)
time.sleep(0.40)
check("多 key 同时过期也只有一个后台重算", _active["max"] == 1,
      "max concurrent=%d" % _active["max"])
check("前端逐接口 settle 容错",
      "function settle(p, label)" in _j21 and
      "function badNames(rs, names)" in _j21 and
      "settle(api('api/status" in _j21 and "settle(api('api/trend" in _j21)
check("旧版一损俱损的 catch 已移除",
      "console.warn('heavy', e)" not in _j21 and
      "$('statusPill').querySelector('span').textContent = '连接失败'" not in _j21)
check("events 失败时实时列表退回 live",
      "else if (r[2].ok) renderLive(r[2].data.data)" in _j21 and
      "var evs = r[1].ok ? (r[1].data.data.events || []) : []" in _j21)
check("单接口失败只跳过自己那块渲染",
      "if (r[0].ok) renderTrend(r[0].data.data)" in _j21 and
      "if (r[4].ok) renderWebCards(r[4].data.data)" in _j21 and
      "if (r[5].ok) renderGeoDist(r[5].data.data)" in _j21)
check("状态标三级且不受指纹短路影响",
      "function updateLinkPill()" in _j21 and
      "markLightResult(bad);" in _j21 and "markHeavyResult(bad);" in _j21 and
      "cls += ' warn'" in _j21 and "txt = '部分数据异常'" in _j21 and
      "txt = '连接失败'" in _j21 and "txt = '归属库异常'" in _j21)
check("红色仅在连续两轮全部失败",
      "S.lightFails >= 2 || S.heavyFails >= 2" in _j21 and
      "bad.length >= 3) S.lightFails++" in _j21 and
      "if (!bad.length) { S.lightFails = 0;" in _j21)
check("失败接口名可定位",
      "tip = '未响应：' + bad.join('、')" in _j21 and
      "console.warn('api ' + label + ' failed: '" in _j21 and
      "toast('部分数据加载失败：' + bad.join('、'))" in _j21)
check("CSS 新增琥珀态", ".status-pill.warn{" in _c21 and
      ".status-pill.warn i{" in _c21)
check("预览页含 #conn-fail 验收入口",
      "#conn-fail" in _p21 and "window.__connFailOnce" in _p21)
check("使用说明含 1.1.7 章节与 FAQ",
      "### 顶部「连接失败」提示（1.1.7）" in _dc21 and
      "**1.1.7 数据都正常，为什么顶部还显示「连接失败」？**" in _dc21)
check("README 详版含根因与修复说明",
      "stale-while-revalidate" in _rd21 and "7.75 秒" in _rd21 and
      "逐接口独立容错" in _rd21)
check("manifest desc 保留 1.1.7 并追加 1.1.8 说明",
      "1.1.7 起状态标分三级" in _m21 and
      "1.1.8 起设置界面预置" in _m21)
check("更新日志 1.1.7 只用三种 emoji",
      not any(x in _ch21.split("**1.1.8**")[1].split("**1.1.6**")[0]
              for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("1.1.6 浮层外滚轮重定向未回归",
      "function redirectWheel(e)" in _j21 and
      "function overlayScrollCandidates(e)" in _j21 and
      "scrollbar-gutter:stable" in _c21)
check("五卡放大 / 下钻 / 画像抽屉未回归",
      "function openCardZoom" in _j21 and "/api/web/breakdown" in _j21 and
      "openDetail(ip)" in _j21)
check("端口敲门仍保持只观测", "只观测" in _rd21 and "只观测" in _ch21)
check("合规红线不变", "不产出任何边界" in _m21 and "不产出任何国界" in _dc21)

print("\n=== 22. 地图服务预设与自定义接口（1.1.8） ===")
_j22 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_c22 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_h22 = open(os.path.join(UI, "index.html"), encoding="utf-8").read()
_s22 = open(os.path.join(SERVER, "settings.py"), encoding="utf-8").read()
_mp22 = open(os.path.join(SERVER, "map_providers.py"), encoding="utf-8").read()
_g22 = open(os.path.join(SERVER, "gateway.py"), encoding="utf-8").read()
_st22 = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
_p22 = open(os.path.join(ROOT, "tools", "make_preview.py"), encoding="utf-8").read()
_ch22 = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rd22 = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_dc22 = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
_m22 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()

import map_providers as _mp
from settings import Settings as _Settings118

check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m22 and
      "**1.1.14（当前版本）**" in _ch22 and
      "**1.1.14（当前版本）**" in _rd22 and "1.1.14" in _dc22 and
      "build/ipsense_1.1.14_all.fpk" in _rd22)
_pids = [p["id"] for p in _mp.MAP_PROVIDERS]
check("预设仅四家合规服务商", _pids == ["tencent", "amap", "baidu", "tianditu"], str(_pids))
check("预设 SDK 只含 {key} 占位符、不含任何有效密钥",
      all(p["sdk"].count("{key}") == 1 for p in _mp.MAP_PROVIDERS) and
      all(("请" in p["key_placeholder"] or "替换" in p["key_placeholder"])
          for p in _mp.MAP_PROVIDERS) and "请" in _mp.MAP_KEY_PLACEHOLDER)
check("合规域名白名单与违规关键词齐备",
      "map.qq.com" in _mp22 and "webapi.amap.com" in _mp22 and
      "api.map.baidu.com" in _mp22 and "api.tianditu.gov.cn" in _mp22 and
      "openstreetmap" in _mp22.lower() and "mapbox" in _mp22.lower())
_bad_ok, _bad_flag, _ = _mp.compliance_of(
    "https://tile.openstreetmap.org/{z}/{x}/{y}.png?key={key}")
check("OpenStreetMap 来源判定为违规", (not _bad_ok) and _bad_flag == "blocked")
_good_ok, _good_flag, _ = _mp.compliance_of("https://webapi.amap.com/maps?v=2.0&key={key}")
check("高德官方域名判定为合规", _good_ok and _good_flag == "allowed")
try:
    _mp.validate_custom([{"id": "osm", "name": "OSM", "engine": "tmap",
                          "sdk": "https://tile.openstreetmap.org/{z}/{x}/{y}.png?key={key}",
                          "key": "x"}])
    check("自定义接口拒绝未获资质来源", False)
except ValueError:
    check("自定义接口拒绝未获资质来源", True)
try:
    _mp.validate_custom([{"id": "tencent", "name": "撞 id", "engine": "tmap",
                          "sdk": "https://map.qq.com/api/gljs?v=1.exp&key={key}", "key": "x"}])
    check("自定义接口拒绝与内置 id 冲突", False)
except ValueError:
    check("自定义接口拒绝与内置 id 冲突", True)

_s118 = _Settings118(os.path.join(tmp, "map118.json"))
check("默认服务商为腾讯且未配置",
      _s118.current_provider()["id"] == "tencent" and not _s118.map_configured())
_s118.update({"map_provider": "amap",
              "map_keys": {"amap": "AMAP_KEY_12345678", "tencent": "TENCENT_KEY_12345678"}})
check("切换服务商并按家分别取 KEY",
      _s118.current_provider()["id"] == "amap" and
      _s118.provider_key() == "AMAP_KEY_12345678" and
      _s118.provider_key("tencent") == "TENCENT_KEY_12345678")
check("map_configured 按当前服务商判定",
      _s118.map_configured() and _s118.map_configured("tencent") and
      not _s118.map_configured("baidu"))
check("SDK URL 随服务商切换", "webapi.amap.com" in _s118.current_sdk_url("cb"))
_s118.update({"map_custom": [{"id": "myproxy", "name": "自建代理", "engine": "tmap",
                              "sdk": "https://map.qq.com/api/gljs?v=1.exp&key={key}",
                              "key": "MYPROXY_KEY_12345678"}]})
check("自定义接口持久化并可选中",
      len(_s118.get("map_custom")) == 1 and
      _mp.provider_by_id("myproxy", _s118.get("map_custom"))["name"] == "自建代理")
_s118b = _Settings118(os.path.join(tmp, "map118b.json"))
_s118b.update({"map_key": "LEGACY_TENCENT_KEY_12345678"})
check("旧版单个 map_key 自动沿用为腾讯密钥",
      _s118b.map_configured() and _s118b.provider_key() == "LEGACY_TENCENT_KEY_12345678")
check("后端下发预设表与只读接口",
      'cfg["map_providers"]' in _g22 and '"/api/map/providers"' in _g22 and
      "map_keys" in _s22 and "validate_custom" in _s22)

check("四家引擎适配器齐全",
      "var MAP_ENGINES = {" in _j22 and
      all((e + ": {") in _j22 for e in ("tmap", "amap", "bmapgl", "tianditu")) and
      "ns: 'TMap'" in _j22 and "ns: 'AMap'" in _j22 and
      "ns: 'BMapGL'" in _j22 and "ns: 'T'" in _j22)
check("统一 SDK 兼容层六件套",
      "return { Map: Map, LatLng: LatLng, MultiPolyline: MultiPolyline," in _j22 and
      "MultiMarker: MultiMarker, PolylineStyle: PolylineStyle, MarkerStyle: MarkerStyle };" in _j22)
check("绘制层不再硬编码 TMap，全部走 SDK",
      _j22.count("new TMap.") == 0 and _j22.count("new SDK.") >= 20)
check("GeoLayer 增量同步接口齐全",
      "function GeoLayer(" in _j22 and
      all(("GeoLayer.prototype." + m) in _j22 for m in
          ("setGeometries", "add", "updateGeometries", "remove", "getGeometries", "on")))
check("MapView 统一销毁/缩放/滚轮接口",
      "function MapView(" in _j22 and "MapView.prototype.destroy" in _j22 and
      "MapView.prototype.resize" in _j22 and "MapView.prototype.setScrollable" in _j22)
check("坐标系按引擎转换",
      "function gcjToBd(" in _j22 and "function gcjToWgs(" in _j22 and
      "gcjToBd(lat, lng)" in _j22 and "gcjToWgs(lat, lng)" in _j22)
check("切换服务商销毁旧引擎再重建",
      "function rebuildMap()" in _j22 and "SDK = null;" in _j22 and
      "initTMap('', true)" in _j22 and "mapChanged" in _j22)
check("百度 SDK 用 callback 异步加载", "window[cb] = once" in _j22 and "{callback}" in _j22)
check("设置界面四家预设与自定义接口表单",
      "function mapServiceHtml()" in _j22 and 'data-act="pick"' in _j22 and
      'data-act="save"' in _j22 and "data-mk=" in _j22 and "data-cf=" in _j22)
check("按家分别收集 KEY 与自定义列表",
      "patch.map_keys = mk;" in _j22 and "patch.map_custom = mapCustomList();" in _j22 and
      "function captureMapKeys()" in _j22)
check("前端也拦截未获资质来源",
      "禁止接入 Google Maps" in _j22 and "合规限制：禁止接入" in _j22)
check("底图诊断与页脚随服务商动态",
      "['当前服务商'" in _j22 and "['引擎 / 坐标系'" in _j22 and
      'id="footMap"' in _h22 and "function updateFooterMap()" in _j22)
check("CSS 新增服务商卡片与自定义表单样式",
      ".prov-card.on{" in _c22 and ".prov-form{" in _c22 and ".prov-grid{" in _c22)
check("预览页含 #map-provider / #map-custom 验收入口",
      "#map-provider" in _p22 and "#map-custom" in _p22 and "map_provider:'tencent'" in _p22)
check("使用说明含 1.1.8 章节与 FAQ",
      "### 地图服务切换与自定义接口（1.1.8）" in _dc22 and
      "**1.1.8 切换地图服务商会丢之前填的 key 吗？**" in _dc22 and
      "四家合规底图" in _dc22)
check("README 详版含适配层设计说明",
      "SDK 兼容层" in _rd22 and "GeoLayer" in _rd22 and "rebuildMap()" in _rd22)
check("更新日志 1.1.8 只用三种 emoji",
      not any(x in _ch22.split("**1.1.8**")[1].split("**1.1.7**")[0]
              for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("1.1.7 三级状态标与 SWR 缓存未回归",
      "function updateLinkPill()" in _j22 and "stale-while-revalidate" in _st22)
check("1.1.6 浮层外滚轮重定向未回归",
      "function redirectWheel(e)" in _j22 and "scrollbar-gutter:stable" in _c22)
check("五卡放大 / 下钻 / 画像抽屉未回归",
      "function openCardZoom" in _j22 and "/api/web/breakdown" in _j22 and "openDetail(ip)" in _j22)
check("合规红线与端口敲门口径不变",
      "不产出任何边界" in _m22 and "不产出任何国界" in _dc22 and
      "只观测" in _rd22 and "只观测" in _ch22)


print("\n=== 23. 软件汇总日志与 fnOS 原生文件夹选择器（1.1.9） ===")
_j23 = open(os.path.join(UI, "app.js"), encoding="utf-8").read()
_c23 = open(os.path.join(UI, "style.css"), encoding="utf-8").read()
_h23 = open(os.path.join(UI, "index.html"), encoding="utf-8").read()
_s23 = open(os.path.join(SERVER, "settings.py"), encoding="utf-8").read()
_sm23 = open(os.path.join(SERVER, "summary.py"), encoding="utf-8").read()
_g23 = open(os.path.join(SERVER, "gateway.py"), encoding="utf-8").read()
_st23 = open(os.path.join(SERVER, "store.py"), encoding="utf-8").read()
_p23 = open(os.path.join(ROOT, "tools", "make_preview.py"), encoding="utf-8").read()
_ch23 = open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
_rd23 = open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()
_dc23 = open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
_m23 = open(os.path.join(ROOT, "src", "manifest"), encoding="utf-8").read()

import summary as _sm

check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m23 and
      "**1.1.14（当前版本）**" in _ch23 and
      "**1.1.14（当前版本）**" in _rd23 and "1.1.14" in _dc23 and
      "build/ipsense_1.1.14_all.fpk" in _rd23)
check("汇总日志模块可导入且核心组件齐备",
      all(hasattr(_sm, x) for x in ("build_summary", "write_summary", "validate_dir",
                                    "path_allowed", "SummaryWriter", "LATEST_NAME",
                                    "ARCHIVE_PREFIX")))
check("目录四层校验函数齐备",
      all(hasattr(_sm, x) for x in ("_norm", "_in_allowed", "_is_denied")) and
      "os.path.realpath(rp)" in _sm23 and "path_allowed(real)" in _sm23 and
      "os.path.isdir(real)" in _sm23 and
      "os.access(real, os.W_OK | os.X_OK)" in _sm23)
check("目录白名单允许 /vol 用户目录与 /home /mnt /media",
      all(_sm.path_allowed(x) for x in
          ("/vol1/1000/AIlogs", "/vol2/share", "/vol10/x",
           "/home/user/logs", "/mnt/usb/logs", "/media/d/logs")))
check("目录白名单拒绝系统区 / 应用数据区 / 相对路径 / 穿越",
      not any(_sm.path_allowed(x) for x in
              ("/etc", "/usr/share", "/proc/self", "/bin", "/var/log",
               "/vol1/@appdata/ipsense", "/vol2/@appcenter/x",
               "relative/path", "/vol1/../../etc", "", "C:\\Windows")))
check("汇总日志含 0~8 共九个章节",
      all(('section("%d. ' % i) in _sm23 for i in range(0, 9)))
check("汇总日志含只观测 / 免责 / AI 处置提示",
      "不自动修改防火墙" in _sm23 and "不封禁 IP" in _sm23 and
      "请人工确认" in _sm23 and "给 AI 的分析与处置建议提示" in _sm23 and
      "不上传任何数据" in _sm23)
check("固定 latest 覆盖与按天归档",
      "ipsense-summary-latest.md" in _sm23 and
      "ipsense-summary-" in _sm23 and "os.replace(tmp, latest)" in _sm23)
check("SummaryWriter 后台线程且改设置无需重启",
      "class SummaryWriter" in _sm23 and
      "self.summary = SummaryWriter(self)" in _g23)
check("配置新增四项汇总配置并纳入类型分组",
      all(('"%s"' % x) in _s23 for x in
          ("summary_dir", "summary_enabled", "summary_interval", "summary_range")) and
      "BOOL_KEYS" in _s23 and "INT_KEYS" in _s23 and "STR_KEYS" in _s23)
check("summary_dir 落盘前过白名单校验", "path_allowed(v)" in _s23)
check("summary_range 只接受五种窗口",
      '("1h", "24h", "7d", "30d", "all")' in _s23)
check("网关新增 5 个 /api/summary/* 路由",
      all(('/api/summary/%s"' % x) in _g23 for x in
          ("status", "preview", "validate", "generate", "download")))
check("/api/config 下发 summary 状态块", 'cfg["summary"]' in _g23)
check("保存配置后汇总项变化立即后台生成", "ipsense-summary-now" in _g23)
check("manifest 声明原生选择器所需权限",
      "micro_app                  = true" in _m23 and
      "disable_authorization_path = false" in _m23)
check("manifest desc 保留 1.1.8 / 1.1.9 并追加 1.1.13 说明",
      "1.1.8 起设置界面预置" in _m23 and "1.1.9 起设置界面新增" in _m23 and
      "1.1.14 起" in _m23)
check("前端通道 A 检测 TrimApp 并调 pickUserFile",
      "window.TrimApp" in _j23 and "pickUserFile" in _j23 and
      "directory: true" in _j23)
check("前端通道 B 已弃用独立窗口，改走桌面桥 / 应用内卡片",
      "/app-auth/pick-file" in _j23 and
      "window.open(target" not in _j23 and "PICK_WIN_FEATURES" not in _j23 and
      "fnosBridge" in _j23 and "openPickerCard" in _j23)
check("原生选择器 URL 参数齐备（含 creatable / okText=选择）",
      all(("q.set('%s'" % x) in _j23 for x in
          ("appName", "redirectUri", "state", "directory", "sidebarGroup",
           "creatable", "title", "okText")) and
      "q.set('okText', '选择')" in _j23)
check("redirectUri 用 new URL 保留查询串并追加回跳标记",
      "new URL(location.href)" in _j23 and
      "back.searchParams.set(PICK_CB_FLAG, '1')" in _j23 and
      "back.hash = ''" in _j23)
check("state 校验与 300s 超时",
      "PICK_TIMEOUT = 300000" in _j23 and "gotState !== rec.state" in _j23 and
      "Date.now() - rec.at" in _j23)
check("回传 path 按 JSON 数组解析",
      "JSON.parse(raw)" in _j23 and "Array.isArray(paths)" in _j23)
check("status 三态与异常分支齐备",
      "status !== 'success'" in _j23 and "已取消选择" in _j23 and
      "选择结果已过期或校验未通过" in _j23 and "没有拿到目录路径" in _j23)
check("回跳清理参数但保留其它查询串",
      "history.replaceState" in _j23 and "p.delete(k)" in _j23 and
      "location.hash" in _j23)
check("离线 mock 仅 file:// 生效（真机不启用）",
      "location.protocol === 'file:'" in _j23 and "__ipsensePickerMock" in _j23)
check("路径一律交后端四层校验，前端不信任选择器",
      "不信任选择器回传" in _j23 and "api/summary/validate" in _j23)
check("设置界面含汇总日志区块与原生选择按钮",
      "summaryServiceHtml" in _j23 and "软件汇总日志（1.1.14）" in _j23 and
      "btnPickFolder" in _j23 and "选择文件夹（飞牛原生）" in _j23)
check("设置界面含手填路径兜底",
      "cfgSummaryDir" in _j23 and "手动填写 NAS 绝对路径" in _j23)
check("设置界面含立即生成 / 预览 / 复制 / 下载",
      all(x in _j23 for x in
          ("btnSumGenerate", "btnSumPreview", "btnSumCopy", "btnSumDownload")))
check("设置界面渲染汇总状态行与统计窗口",
      "renderSummaryStatus" in _j23 and "sumStatusBox" in _j23 and
      "summaryRangeOptions" in _j23)
check("CSS 新增汇总日志样式",
      ".sum-path{" in _c23 and ".sum-preview{" in _c23)
check("首页页脚含 1.1.14 汇总日志说明",
      "1.1.14 可在设置里接入敲门网关请求日志" in _h23)
check("预览页含 #summary 验收入口",
      "#summary" in _p23 and "summaryServiceBox" in _p23)
check("预览页含 #picker-* 模拟回跳",
      "#picker-" in _p23 and "__ipsensePickerMock" in _p23)
check("预览页 mock 五个汇总接口",
      all(('api/summary/%s' % x) in _p23 for x in
          ("status", "preview", "validate", "generate", "download")))
check("使用说明含 1.1.9 章节与 FAQ",
      "### 软件汇总日志与飞牛原生文件夹选择器（1.1.9）" in _dc23 and
      "**1.1.9 点「选择文件夹」没弹出" in _dc23 and
      "**1.1.9 这份日志会自动封禁可疑 IP 吗？**" in _dc23)
check("README 详版含原生选择器协议与四层校验",
      "pick-user-file" in _rd23 and "四层校验" in _rd23 and
      "micro_app" in _rd23 and "SummaryWriter" in _rd23)
check("更新日志 1.1.14 只用三种 emoji",
      not any(x in _ch23.split("**1.1.14（当前版本）**")[1].split("**1.1.8**")[0]
              for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("应用仍只观测 / 不改防火墙 / 不封禁 / 不上传",
      "不自动修改防火墙" in _sm23 and "不封禁 IP" in _sm23 and
      "不上传任何数据" in _sm23 and "只观测" in _rd23)
check("不产出自绘边界 / 国界",
      "不产出任何边界" in _m23 and "不产出任何国界" in _dc23)
check("1.1.8 地图服务切换与自定义接口无回归",
      "map_provider" in _j23 and "rebuildMap" in _j23 and "SDK 兼容层" in _rd23)
check("1.1.7 三级状态标与 SWR 缓存未回归",
      "function updateLinkPill()" in _j23 and "stale-while-revalidate" in _st23)
check("1.1.6 浮层外滚轮重定向未回归",
      "function redirectWheel(e)" in _j23 and "scrollbar-gutter:stable" in _c23)
check("五卡放大 / 下钻 / 画像抽屉未回归",
      "function openCardZoom" in _j23 and "/api/web/breakdown" in _j23 and
      "openDetail(ip)" in _j23)
check("合规红线与端口敲门 L0 只观测口径不变",
      "只观测" in _rd23 and "只观测" in _ch23)


print("\n=== 24. 保存位置改为 750×630 小卡片（1.1.10） ===")
_j24 = _j23
_p24 = _p23
_h24 = _h23
_c24 = _c23
_m24 = _m23
_ch24 = _ch23
_rd24 = _rd23
_dc24 = _dc23

check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m24 and
      "**1.1.14（当前版本）**" in _ch24 and
      "**1.1.14（当前版本）**" in _rd24 and "1.1.14" in _dc24 and
      "build/ipsense_1.1.14_all.fpk" in _rd24)
check("1.1.10 的 window.open 开窗实现已移除",
      "PICK_WIN_FEATURES" not in _j24 and
      "window.open(target, '_blank'" not in _j24)
check("取证注释记录 1.1.9 整页跳转根因",
      "1.1.9 用 location.assign 整页跳转" in _j24)
check("原生授权页 URL 补齐 creatable 与 okText=选择",
      all(("q.set('%s'" % x) in _j24 for x in
          ("appName", "redirectUri", "state", "directory", "sidebarGroup",
           "creatable", "title", "okText")) and
      "q.set('creatable', 'true')" in _j24 and "q.set('okText', '选择')" in _j24)
check("redirectUri 保留查询串并追加 fnosPickerCallback",
      "new URL(location.href)" in _j24 and
      "back.searchParams.set(PICK_CB_FLAG, '1')" in _j24 and
      "back.hash = ''" in _j24 and
      "var PICK_CB_FLAG = 'fnosPickerCallback'" in _j24)
check("watchPicker 三路收结果且不再依赖子窗口",
      "function watchPicker(state)" in _j24 and
      "window.addEventListener('message', onMsg)" in _j24 and
      "PICK_MSG_TYPE" in _j24 and "PICK_RESULT_KEY" in _j24 and
      "}, 600);" in _j24 and "win.closed" not in _j24 and
      "PICK_TIMEOUT);" in _j24 and "等待超时（5 分钟）" in _j24)
check("postMessage 校验 origin / type / state",
      "ev.origin !== location.origin" in _j24 and
      "d.type !== PICK_MSG_TYPE" in _j24 and "d.state !== state" in _j24)
check("回跳页把结果交给 opener 与 sessionStorage",
      "window.opener.postMessage(payload, location.origin)" in _j24 and
      "sessionStorage.setItem(PICK_RESULT_KEY, JSON.stringify(payload))" in _j24)
check("state 用 crypto.randomUUID 兜底且带 ips- 前缀",
      "crypto.randomUUID" in _j24 and "'ips-' + rnd" in _j24)
check("主通道改为 penpal 桥调用路径选择方法",
      "bridge.call(method, opts)" in _j24 and
      "'pickFile'" in _j24 and
      "creatable: true" in _j24 and "var PENPAL" in _j24)
check("设置界面说明改为应用窗口内卡片且不新开窗口",
      "当前应用窗口内" in _j24 and "不新开浏览器窗口、当前页面不跳走" in _j24 and
      "软件汇总日志（1.1.14）" in _j24)
check("首页页脚含 1.1.14 应用内卡片说明",
      "1.1.14 可在设置里接入敲门网关请求日志" in _h24 and
      "点开保存位置会在应用窗口内弹出飞牛原生卡片" in _h24)
check("预览页记录 window.open 但不再用它弹卡片",
      "window.open=function(u,name,features)" in _p24 and
      "__windowOpenCalls" in _p24 and
      "location.protocol!=='file:'" in _p24 and "#picker-card" in _p24)
check("预览页 file:// 专属渲染器与同构原生 UI",
      "__ipsensePickerCardRender" in _p24 and
      all(x in _p24 for x in
          ("我的文件", "他人共享", "我的收藏",
           "新建文件夹", "pk-cancel", "pk-ok")))
check("预览页卡片通过 MessageEvent 与 sessionStorage 回传",
      "new MessageEvent('message'" in _p24 and
      "sessionStorage.setItem('ipsense.fnos.picker.result'" in _p24)
check("预览页 health 版本 1.1.14", "version:'1.1.14'" in _p24)
check("使用说明含 1.1.14 小卡片章节与 FAQ",
      "### 保存位置改为小卡片弹出（1.1.10）" in _dc24 and
      "**1.1.10 点「选择文件夹」还是没弹出卡片？**" in _dc24)
check("README 详版含官方 SDK 取证与小卡片口径",
      "window.open(url, '_blank', 'width=750,height=630')" in _rd24 and
      "class Eoe" in _rd24 and "watchPicker" in _rd24 and
      "fnosPickerCallback" in _rd24)
check("更新日志 1.1.14 只用三种 emoji",
      not any(x in _ch24.split("**1.1.14（当前版本）**")[1].split("**1.1.10**")[0]
              for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("manifest 权限声明与 desc 追加 1.1.14",
      "micro_app                  = true" in _m24 and
      "disable_authorization_path = false" in _m24 and
      "1.1.14 起" in _m24)
check("目录四层校验与只观测口径未变",
      "def validate_dir" in _sm23 and "不自动修改防火墙" in _sm23 and
      "不封禁 IP" in _sm23 and "不上传任何数据" in _sm23)
check("1.1.9 汇总日志五个接口与 SummaryWriter 未回归",
      all(('/api/summary/%s"' % x) in _g23 for x in
          ("status", "preview", "validate", "generate", "download")) and
      "self.summary = SummaryWriter(self)" in _g23)
check("1.1.8 / 1.1.7 / 1.1.6 无回归",
      "map_provider" in _j24 and "rebuildMap" in _j24 and
      "function updateLinkPill()" in _j24 and
      "function redirectWheel(e)" in _j24 and
      "scrollbar-gutter:stable" in _c24)

print("\n=== 25. 保存位置改为应用内模态卡片 / penpal 主通道（1.1.11） ===")
_j25 = _j24
_p25 = _p24
_h25 = _h24
_c25 = _c24
_m25 = _m24
_ch25 = _ch24
_rd25 = _rd24
_dc25 = _dc24
_cb25 = open(os.path.join(UI, "picker-cb.html"), encoding="utf-8").read()

check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m25 and
      "**1.1.14（当前版本）**" in _ch25 and
      "**1.1.14（当前版本）**" in _rd25 and "1.1.14" in _dc25 and
      "build/ipsense_1.1.14_all.fpk" in _rd25)
check("取证注释写明 1.1.10 误用 standalone 降级通道",
      "1.1.10 误把 N7e 当主通道" in _j25 and
      "connectToChild" in _j25 and "I7e() 主通道" in _j25)
check("penpal 协议常量齐备",
      "var PENPAL" in _j25 and
      all(x in _j25 for x in ("syn: 'syn'", "synAck: 'synAck'", "ack: 'ack'",
                              "call: 'call'", "reply: 'reply'",
                              "fulfilled: 'fulfilled'", "rejected: 'rejected'")))
check("fnosBridge 复刻 syn / synAck / ack / call / reply",
      "function fnosBridge()" in _j25 and
      "penpal: PENPAL.syn" in _j25 and
      "d.penpal === PENPAL.synAck" in _j25 and
      "penpal: PENPAL.ack" in _j25 and
      "penpal: PENPAL.call" in _j25 and
      "d.penpal === PENPAL.reply" in _j25 and
      "ev.source !== window.parent" in _j25)
check("握手超时 1.5s 且启动时预热",
      "PICK_BRIDGE_TIMEOUT = 1500" in _j25 and
      "getBridge().catch(function () {})" in _j25 and
      "var bridgePromise = null" in _j25)
check("主通道调用路径选择方法且参数齐全",
      "bridge.call(method, opts)" in _j25 and
      "var opts = {" in _j25 and
      all(x in _j25 for x in ("directory: true", "multiple: false",
                              "title: PICK_CARD_TITLE", "okText: '选择'",
                              "creatable: true", "accept: []",
                              "sidebarGroup: PICK_SIDEBAR.slice()")))
check("finishBridge 归一化处理成功 / 取消 / 失败三类返回",
      "function finishBridge(r)" in _j25 and
      "function pickPathsFrom(r)" in _j25 and
      "function pickIsCancel(r)" in _j25 and
      "Number(r.code) === -1" in _j25 and
      "saveSummaryDir(paths[0])" in _j25)
check("应用内模态卡片 DOM 齐备",
      "function openPickerCard(reason)" in _j25 and
      all(x in _j25 for x in ("pick-mask", "pick-card", "pick-card-head",
                              "pick-card-body", "pick-card-foot", "pickClose")))
check("iframe 内嵌原生授权页且不自绘目录树",
      "/app-auth/pick-file" in _j25 and
      "createElement('iframe')" in _j25 and
      "fr.src = src" in _j25 and
      "fr.className = 'pick-frame'" in _j25)
check("redirectUri 指向同源静态回调页并保留查询串",
      "'/picker-cb.html'" in _j25 and
      "back.searchParams.set(PICK_CB_FLAG, '1')" in _j25 and
      "back.hash = ''" in _j25 and
      "new URL(location.href)" in _j25)
check("原生授权页 URL 补齐参数与 creatable / okText",
      all(("q.set('%s'" % x) in _j25 for x in
          ("appName", "redirectUri", "state", "directory", "sidebarGroup",
           "creatable", "title", "okText")) and
      "q.set('creatable', 'true')" in _j25 and "q.set('okText', '选择')" in _j25)
check("卡片可关闭：按钮 / 遮罩 / ESC",
      "$('pickClose').onclick" in _j25 and
      "mask.onclick" in _j25 and
      "function pickerKeyHandler(e)" in _j25 and
      "e.key === 'Escape'" in _j25 and
      "function closePickerCard(byUser)" in _j25)
check("watchPicker 三路收结果 + 卡片关闭收口",
      "function watchPicker(state)" in _j25 and
      "pickerWatcher = { finish: finish }" in _j25 and
      "window.addEventListener('message', onMsg)" in _j25 and
      "}, 600);" in _j25 and "PICK_TIMEOUT);" in _j25 and
      "win.closed" not in _j25 and "function watchPicker(win, state)" not in _j25)
check("postMessage 仍校验 origin / type / state",
      "ev.origin !== location.origin" in _j25 and
      "d.type !== PICK_MSG_TYPE" in _j25 and "d.state !== state" in _j25)
check("全程不再 window.open 开窗",
      "window.open(target" not in _j25 and
      "PICK_WIN_FEATURES" not in _j25 and
      "location.assign(location.origin" not in _j25)
check("CSS 新增 .pick-* 模态卡片且 750×630",
      all(x in _c25 for x in (".pick-mask", ".pick-card", ".pick-card-head",
                              ".pick-card-body", ".pick-frame", ".pick-card-foot")) and
      "width:750px" in _c25 and "height:630px" in _c25 and
      "z-index:20000" in _c25)   # 1.1.14 随 UI 浮层统一抬到 1000 以上
check("静态回调页 picker-cb.html 存在且同源回传",
      "ipsense:fnos-picker" in _cb25 and
      "sessionStorage.setItem('ipsense.fnos.picker.result'" in _cb25 and
      "window.parent.postMessage(payload, location.origin)" in _cb25 and
      "JSON.parse(raw)" in _cb25)
check("预览页双仿真：主通道桥与卡片渲染器",
      "__ipsenseMockBridge" in _p25 and
      "__ipsensePickerCardRender" in _p25 and
      "__ipsenseForcePickerCard" in _p25 and
      "#picker-bridge" in _p25 and "#picker-modal" in _p25)
check("预览页 window.open 只记录不渲染，卡片改由渲染器负责",
      "__windowOpenCalls" in _p25 and "return null;" in _p25 and
      "window.open=function(u,name,features)" in _p25 and
      "__ipsensePickerCardRender" in _p25)
check("预览页 health 版本 1.1.14", "version:'1.1.14'" in _p25)
check("设置界面 1.1.14 说明",
      "软件汇总日志（1.1.14）" in _j25 and
      "当前应用窗口内" in _j25 and
      "不新开浏览器窗口、当前页面不跳走" in _j25)
check("首页页脚 1.1.14 应用内卡片说明",
      "1.1.14 可在设置里接入敲门网关请求日志" in _h25 and
      "点开保存位置会在应用窗口内弹出飞牛原生卡片" in _h25)
check("CHANGELOG 1.1.14 章节与历史 1.1.10 并存",
      "**1.1.14（当前版本）**" in _ch25 and "**1.1.10**" in _ch25 and
      "penpal 握手走桌面桥" in _ch25)
check("CHANGELOG 1.1.14 只用三种 emoji",
      not any(x in _ch25.split("**1.1.14（当前版本）**")[1].split("**1.1.10**")[0]
              for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊", "🔧", "⚡")))
check("README 能力对照表与详版 1.1.14",
      "| 11 |" in _rd25 and "1.1.14" in _rd25 and
      "**1.1.14（当前版本）**" in _rd25 and
      "connectToParent" in _rd25 and "picker-cb.html" in _rd25)
check("使用说明 1.1.11 章节与 3 条 FAQ",
      "### 保存位置改为应用内卡片弹出（1.1.11）" in _dc25 and
      "**1.1.11 点「选择文件夹」还会新开一个窗口吗？**" in _dc25 and
      "**1.1.11 卡片是谁画的？**" in _dc25 and
      "**1.1.11 选完目录后要刷新页面吗？**" in _dc25)
check("manifest 1.1.14 与权限声明不变",
      "version                    = 1.1.14" in _m25 and
      "micro_app                  = true" in _m25 and
      "disable_authorization_path = false" in _m25 and
      "1.1.14 起" in _m25)
check("目录四层校验与只观测口径未变",
      "def validate_dir" in _sm23 and "不自动修改防火墙" in _sm23 and
      "不封禁 IP" in _sm23 and "不上传任何数据" in _sm23)
check("1.1.9 汇总日志五个接口与 SummaryWriter 未回归",
      all(('/api/summary/%s"' % x) in _g23 for x in
          ("status", "preview", "validate", "generate", "download")) and
      "self.summary = SummaryWriter(self)" in _g23)
check("1.1.8 / 1.1.7 / 1.1.6 无回归",
      "map_provider" in _j25 and "rebuildMap" in _j25 and
      "function updateLinkPill()" in _j25 and
      "function redirectWheel(e)" in _j25 and
      "scrollbar-gutter:stable" in _c25)


print("\n=== 26. 地图 SDK 层级隔离，按钮不再被吃掉点击（1.1.12） ===")
_j26 = _j25
_p26 = _p25
_h26 = _h25
_c26 = _c25
_m26 = _m25
_ch26 = _ch25
_rd26 = _rd25
_dc26 = _dc25
_sm26 = open(os.path.join(SERVER, "summary.py"), encoding="utf-8").read()

check("两个地图容器均创建层叠上下文",
      _c26.count("isolation:isolate") >= 2 and
      ".map-wrap{position:relative;isolation:isolate;" in _c26 and
      ".geo-map-wrap{position:relative;isolation:isolate;" in _c26)
check("UI 浮层全部抬到 1000 以上",
      all(x in _c26 for x in (
          "z-index:1100;", "z-index:1200;", "z-index:1300;", "z-index:1350;",
          "z-index:1400;", "z-index:1500;", "z-index:20000;")))
check("容器内蒙版 / 图注 / 图例高于 SDK 的 z=1000",
      ".map-wrap.tmap-on:after{content:\"\";position:absolute;inset:0;pointer-events:none;z-index:1100;" in _c26 and
      ".geo-map-wrap.tmap-on:after{content:\"\";position:absolute;inset:0;pointer-events:none;z-index:1100;" in _c26 and
      ".map-note,.map-stat{z-index:1101;pointer-events:none}" in _c26 and
      ".heat-legend{position:absolute;right:12px;bottom:11px;z-index:1102;" in _c26 and
      ".geo-legend{position:absolute;left:12px;bottom:11px;z-index:1102;" in _c26)
check("修复注释写明 z=1000 根因与隔离方案",
      "1.1.12 层叠上下文隔离" in _c26 and "z=1000" in _c26 and
      "锁死" in _c26)
check("旧的低层级数值已全部移除",
      not any(x in _c26 for x in (
          "z-index:20;", "z-index:40;", "z-index:44;", "z-index:45;",
          "z-index:50;", "z-index:80;", "z-index:12000;")))
check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m26 and
      "**1.1.14（当前版本）**" in _ch26 and
      "**1.1.14（当前版本）**" in _rd26 and "1.1.14" in _dc26 and
      "build/ipsense_1.1.14_all.fpk" in _rd26)
check("首页页脚 / 设置标题 / 预览页 health 均标注 1.1.14",
      "1.1.14 可在设置里接入敲门网关请求日志" in _h26 and
      "软件汇总日志（1.1.14）" in _j26 and
      "version:'1.1.14'" in _p26)
check("CHANGELOG 1.1.14 只用三种 emoji",
      not any(x in _ch26.split("**1.1.14（当前版本）**")[1].split("**1.1.11**")[0]
              for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊")))
check("README 详版含根因取证与能力表第 12 行",
      "| 12 |" in _rd26 and "elementFromPoint" in _rd26 and
      "isolation:isolate" in _rd26)
check("使用说明含 1.1.12 章节与 3 条 FAQ",
      "### 修复按钮点不动（1.1.12）" in _dc26 and
      "**1.1.12 为什么按钮在地图上方就点不动？**" in _dc26 and
      "**1.1.12 修复后地图还能拖动、点圆点吗？**" in _dc26 and
      "**1.1.12 升级后需要重新配置地图 KEY 吗？**" in _dc26)
check("1.1.11 应用内卡片 / penpal 主通道无回归",
      "fnosBridge" in _j26 and "openPickerCard" in _j26 and
      "picker-cb.html" in _j26 and "summaryServiceHtml" in _j26 and
      "window.open(target" not in _j26 and "PICK_WIN_FEATURES" not in _j26)
check("1.1.9 汇总日志五个接口与只观测口径无回归",
      all(('/api/summary/%s"' % x) in _g23 for x in
          ("status", "preview", "validate", "generate", "download")) and
      "不自动修改防火墙" in _sm26 and "不封禁 IP" in _sm26)
check("1.1.8 / 1.1.7 / 1.1.6 / 1.1.5 无回归",
      "map_provider" in _j26 and "rebuildMap" in _j26 and
      "function updateLinkPill()" in _j26 and
      "function redirectWheel(e)" in _j26 and
      "scrollbar-gutter:stable" in _c26)


print("\n=== 27. 选择文件夹不再误报「已取消选择」（1.1.13） ===")
_j27 = _j26
_p27 = _p26
_h27 = _h26
_c27 = _c26
_m27 = _m26
_ch27 = _ch26
_rd27 = _rd26
_dc27 = _dc26
_pc27 = open(os.path.join(UI, "picker-cb.html"), encoding="utf-8").read()
_sm27 = _sm26

check("penpal call 的 args 已数组化（父窗口 .apply 展开）",
      "args: [args || {}]" in _j27 and "t[methodName].apply(t, args)" in _j27 and
      "args: args || []" not in _j27)
check("主通道优先 pickFile，pickUserFile 仅作回退",
      "names.indexOf('pickFile') >= 0 ? 'pickFile' : 'pickUserFile'" in _j27 and
      "addUserAuthorizationPath" in _j27 and "W7=e=>" in _j27)
check("结果归一化覆盖多形态返回",
      "function pickPathsFrom(r)" in _j27 and
      "Array.isArray(r.data)" in _j27 and "r.data.paths" in _j27 and
      "v.path || v.filePath || v.fullPath" in _j27 and
      "function pickIsCancel(r)" in _j27 and "function pickErrMsg(r)" in _j27)
check("空路径 / code=1 不再一律误报「已取消选择」",
      "Number(r.code) === -1" in _j27 and
      "toast('选择失败：' + (pickErrMsg(r)" in _j27 and
      "if ((r && r.code === 1) || !paths.length)" not in _j27)
check("失败提示给出真实原因与手填路径兜底",
      _j27.count("可手动填写 NAS 绝对路径") >= 3)
check("调用级 reject 不再盲目重弹卡片",
      "return bridge.call(method, opts).then(" in _j27 and
      "openPickerCard((e && e.message) || '')" in _j27)
check("降级路由改 /app-auth/pick-file 且 redirectUri 双写",
      "'/app-auth/pick-file?'" in _j27 and "q.set('redirect_uri'" in _j27 and
      "'/app-auth/pick-user-file?'" not in _j27)
check("consumePickerCallback 方法白名单补 pickFile / pick-file",
      "method !== 'pickFile'" in _j27 and "method !== 'pick-file'" in _j27)
check("回调页宽容解析 path 与 status",
      "p.get('path') || p.get('paths')" in _pc27 and
      "v.path || v.filePath || v.fullPath" in _pc27 and
      "status === 'ok' || status === '1' || status === 'true'" in _pc27 and
      "ipsense 1.1.13" in _pc27)
check("watchPicker / consumePickerCallback 只有明确 cancel 才提示取消",
      "status === 'cancel'" in _j27 and
      "toast('已取消选择' + (err" not in _j27 and
      "status !== 'success'" in _j27)
check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m27 and
      "**1.1.14（当前版本）**" in _ch27 and
      "**1.1.14（当前版本）**" in _rd27 and "1.1.14" in _dc27 and
      "build/ipsense_1.1.14_all.fpk" in _rd27)
check("首页页脚 / 设置标题 / 预览页 health 均标注 1.1.14",
      "1.1.14 可在设置里接入敲门网关请求日志" in _h27 and
      "软件汇总日志（1.1.14）" in _j27 and
      "version:'1.1.14'" in _p27)
check("CHANGELOG 1.1.14 只用三种 emoji",
      not any(x in _ch27.split("**1.1.14（当前版本）**")[1].split("**1.1.12**")[0]
              for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊")))
check("README 详版含取证链与能力表第 13 行",
      "| 13 |" in _rd27 and "B$e" in _rd27 and
      "addUserAuthorizationPath" in _rd27 and "pickPathsFrom()" in _rd27)
check("使用说明含 1.1.13 章节与 3 条 FAQ",
      "### 修复「选择文件夹后显示已取消选择」（1.1.13）" in _dc27 and
      "**1.1.13 为什么之前选中文件夹还提示「已取消选择」？**" in _dc27 and
      "**1.1.13 升级后需要重新选择一次文件夹吗？**" in _dc27 and
      "**1.1.13 选择失败时会提示什么？**" in _dc27)
check("1.1.12 层叠隔离 / 1.1.11 应用内卡片无回归",
      "isolation:isolate" in _c27 and "z-index:20000" in _c27 and
      "fnosBridge" in _j27 and "openPickerCard" in _j27 and
      "picker-cb.html" in _j27 and
      "window.open(target" not in _j27 and "PICK_WIN_FEATURES" not in _j27)
check("1.1.9 汇总日志五个接口与只观测口径无回归",
      all(('/api/summary/%s"' % x) in _g23 for x in
          ("status", "preview", "validate", "generate", "download")) and
      "不自动修改防火墙" in _sm27 and "不封禁 IP" in _sm27)
check("1.1.8 / 1.1.7 / 1.1.6 / 1.1.5 无回归",
      "map_provider" in _j27 and "rebuildMap" in _j27 and
      "function updateLinkPill()" in _j27 and
      "function redirectWheel(e)" in _j27 and
      "scrollbar-gutter:stable" in _c27)


print("\n=== 28. 敲门网关请求日志接入（1.1.14） ===")
_j28 = _j27
_p28 = _p27
_h28 = _h27
_c28 = _c27
_m28 = _m27
_ch28 = _ch27
_rd28 = _rd27
_dc28 = _dc27
_sm28 = _sm27
_cl28 = open(os.path.join(SERVER, "collector.py"), encoding="utf-8").read()
_st28 = open(os.path.join(SERVER, "settings.py"), encoding="utf-8").read()
_ix28 = open(os.path.join(UI, "index.html"), encoding="utf-8").read()
import collector as _cm28

check("版本 1.1.14 已同步到六处",
      gateway.VERSION == "1.1.14" and
      "version                    = 1.1.14" in _m28 and
      "**1.1.14（当前版本）**" in _ch28 and
      "**1.1.14（当前版本）**" in _rd28 and "1.1.14" in _dc28 and
      "build/ipsense_1.1.14_all.fpk" in _rd28)
check("首页页脚 / 设置标题 / 预览页 health 均标注 1.1.14",
      "1.1.14 可在设置里接入敲门网关请求日志" in _h28 and
      "软件汇总日志（1.1.14）" in _j28 and
      "version:'1.1.14'" in _p28)
check("CHANGELOG 1.1.14 只用三种 emoji",
      not any(x in _ch28.split("**1.1.14（当前版本）**")[1].split("**1.1.13**")[0]
              for x in ("✨", "⌨️", "🧹", "📦", "🛡️", "📊")))
check("README 能力表第 14 行与详版取证链",
      "| 14 | 接入外部敲门网关日志" in _rd28 and
      "| 13 | 选择文件夹能真正回填路径" in _rd28 and
      "KnockDirTailer" in _rd28 and "client_ip" in _rd28 and
      "按天把结构化 JSON" in _rd28)
check("使用说明含 3b 接入章节与 3 条 FAQ",
      "### 3b) 敲门网关请求日志（1.1.14，默认关闭）" in _dc28 and
      "**装了端口敲门，为什么 IP 动态感知里一条敲门记录都没有？**" in _dc28 and
      "**接入敲门网关日志后，应用会自动封禁攻击 IP 吗？**" in _dc28 and
      "**为什么日志里看不到 `127.0.0.1` 的请求，或者少了几条？**" in _dc28)
check("collector 字段白名单来自真机取证",
      all(x in _cl28 for x in (
          "KNOCK_IP_KEYS", "KNOCK_TS_KEYS", "KNOCK_TEXT_KEYS",
          "KNOCK_SCHEME_KEYS", '"client_ip"', '"auth_decision"',
          '"waf_action"', '"logged_time"', '"status_code"')))
check("IP 严格校验用 inet_pton，时间戳不会被当成地址",
      "socket.inet_pton(fam, s)" in _cl28 and
      "IP_ANY.fullmatch(s)" not in _cl28 and
      "def knock_ip(v)" in _cl28)
check("时间兼容 ISO8601 / epoch 秒 / epoch 毫秒 / 文本",
      "datetime.datetime.fromisoformat(s)" in _cl28 and
      "if x > 1e12:" in _cl28 and "%Y-%m-%d %H:%M:%S" in _cl28)
check("新增目录级增量扫描器 KnockDirTailer",
      "class KnockDirTailer(object)" in _cl28 and
      "st.st_ino" in _cl28 and "64 * 1024" in _cl28 and
      "def poll(self)" in _cl28 and "def backfill(self, flush" in _cl28 and
      "def targets(self)" in _cl28 and "max_files" in _cl28)
check("扫描器只接 JSON / JSONL / LOG / TXT 分片",
      'EXTS = (".json", ".jsonl", ".log", ".txt")' in _cl28)
check("解析方法按四类动作区分且不硬猜协议",
      "def parse_knock_app(self, line)" in _cl28 and
      '"WAF / 策略拦截"' in _cl28 and '"认证被拒"' in _cl28 and
      '"认证通过"' in _cl28 and '"网关请求"' in _cl28 and
      'proto = "web"' in _cl28 and '"source=knock_app"' not in _cl28)
check("采集器已接入目录扫描 / 回补 / 状态",
      "self.knock_dir_tailer = KnockDirTailer(" in _cl28 and
      "self.knock_dir_tailer.poll()" in _cl28 and
      "self.knock_dir_tailer.backfill(self._flush)" in _cl28 and
      '"knock_app_enabled":' in _cl28 and '"knock_app_files":' in _cl28)
check("settings 三个新键与白名单齐全",
      '"source_knock_app": False' in _st28 and
      '"knock_app_dir": "/vol1/@appdata/fn-knock-lite/gateway/logs"' in _st28 and
      '"knock_app_port": 8999' in _st28 and
      '"source_knock_app"' in _st28 and '"knock_app_port")' in _st28 and
      '"knock_app_dir",' in _st28)
check("汇总日志新增 3.1 敲门网关与授信时间线",
      'section("3.1 敲门网关与授信时间线", s3k)' in _sm28 and
      "source='knock_app'" in _sm28 and
      '"knock_app": "敲门网关请求日志"' in _sm28 and
      "不等于攻击定性" in _sm28 and "未启用（默认关闭）" in _sm28)
check("只观测口径：不改对方配置 / 防火墙 / 不自动处置",
      "不会替你打开对方日志开关" in _sm28 and
      "不修改防火墙、不封禁 IP" in _sm28 and
      "本应用不会替你打开这个开关" in _dc28 and
      "只读对方落盘日志" in _rd28)
check("前端设置开关 / 目录 / 端口与来源筛选",
      "sw('source_knock_app', '敲门网关 · 请求日志'" in _j28 and
      "fld('knock_app_dir', '敲门网关日志目录'" in _j28 and
      "fld('knock_app_port', '敲门网关入口端口'" in _j28 and
      "knock_app: '敲门网关'" in _j28 and
      'value="knock_app">敲门网关</option>' in _ix28)
check("预览页 mock 同步新配置与状态字段",
      "source_knock_app:false" in _p28 and
      "knock_app_port:8999" in _p28 and "knock_app_enabled:false" in _p28)

_o28 = Collector.__new__(Collector)
_o28.cfg = {"knock_app_port": 8999}
_cases28 = [
    ('{"logged_time":"2026-11-14T11:20:31.123Z","client_ip":"45.155.205.113",'
     '"auth_decision":"unauthorized","status_code":401,"host":"nas.cn",'
     '"path":"/login","scheme":"https"}', "45.155.205.113", "认证被拒", "https"),
    ('{"time":1794655258,"client_ip":"220.205.86.196","auth_decision":"session",'
     '"status_code":200,"forwarded_proto":"https"}', "220.205.86.196", "认证通过", "https"),
    ('{"ts":1794655258000,"ip":"8.8.8.8","waf_action":"block","status":403}',
     "8.8.8.8", "WAF / 策略拦截", "web"),
    ('{"client_ip":"203.0.113.9","action":"allow","host":"x.cn","path":"/"}',
     "203.0.113.9", "认证通过", "web"),
    ("2026-11-14 11:20:31 45.155.205.113 GET /probe 404",
     "45.155.205.113", "网关请求", "web"),
    ('{"client_ip":"2001:db8::8a2e:370:7334","event":"auth_failed"}',
     "2001:db8::8a2e:370:7334", "认证被拒", "web"),
]
check("运行时：六种日志形态都能解析出正确客户端 IP / 动作 / 协议",
      all((lambda e, c: e and e["ip"] == c[1] and c[2] in e["action"]
           and e["proto"] == c[3] and e["source"] == "knock_app"
           and e["verdict"] == "knock")(_o28.parse_knock_app(c[0]), c)
          for c in _cases28))
check("运行时：无 IP / 纯时间戳 / 坏 JSON 不入脏数据",
      _o28.parse_knock_app("no ip here") is None and
      _o28.parse_knock_app("2026-11-14 11:20:31 12:00:00") is None and
      _o28.parse_knock_app("{broken json") is None)
check("历史能力无回归（1.1.13 / 1.1.12 / 1.1.9 / 1.1.8）",
      "args: [args || {}]" in _j28 and "pickPathsFrom" in _j28 and
      "isolation:isolate" in _c28 and "z-index:20000" in _c28 and
      "fnosBridge" in _j28 and "openPickerCard" in _j28 and
      "def build_summary" in _sm28 and
      "map_provider" in _j28 and "rebuildMap" in _j28 and
      "function redirectWheel(e)" in _j28)

print("\n=== 结果：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
if fail:
    print("失败项：" + ", ".join(fail))
app.close()
shutil.rmtree(tmp, ignore_errors=True)
sys.exit(1 if fail else 0)
