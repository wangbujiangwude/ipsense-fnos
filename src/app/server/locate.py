# -*- coding: utf-8 -*-
"""本机出口 IP 定位。

设计要点：
1. 应用不再假设本机位置，定位由用户在设置页主动触发，不会常驻对外请求；
2. 直连回显源取宽带真实出口，代理回显源用于识别 clash/TUN 分流带来的第二个出口；
3. 归属用在线源交叉，并与随包 ip2region 离线库对照，差异如实展示；
4. 结果写入 settings，升级 / 重装不丢。
"""
import ipaddress
import json
import re
import time
import urllib.request

UA = "Mozilla/5.0 (compatible; ipsense/1.0.3; local-nas-app)"

DIRECT_URL = "https://myip.ipip.net"
PROXY_URLS = ("https://ifconfig.me/ip", "https://api.ipify.org")
GEO_URLS = (
    ("ipwho.is", "https://ipwho.is/{ip}"),
    ("ip.sb", "https://api.ip.sb/geoip/{ip}"),
)

_IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_GEO_RE = re.compile(r"来自于\s*[：:]\s*(.+)")

_CN_SPECIAL = {
    "hong kong": "中国香港", "hongkong": "中国香港",
    "macao": "中国澳门", "macau": "中国澳门",
    "taiwan": "中国台湾",
}

_FALLBACK = {
    "北京市": (39.90, 116.41), "上海市": (31.23, 121.47),
    "天津市": (39.13, 117.20), "重庆市": (29.56, 106.55),
    "安徽省": (31.82, 117.23), "广东省": (23.13, 113.26),
    "江苏省": (32.06, 118.80), "浙江省": (30.27, 120.15),
    "河北省": (38.04, 114.51), "甘肃省": (36.06, 103.83),
}


def _http(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")[:8192]


def _first_ip(text):
    if not text:
        return ""
    for m in _IP_RE.finditer(text):
        try:
            ipaddress.IPv4Address(m.group(1))
            return m.group(1)
        except ValueError:
            continue
    return ""


def _geo_text(text):
    m = _GEO_RE.search(text or "")
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _norm_special(s):
    low = (s or "").strip().lower()
    for k, v in _CN_SPECIAL.items():
        if low == k or low.startswith(k + " "):
            return v
    return ""


def _online_geo(ip):
    """返回 (归一化在线归属, 用过的源名列表)；在线源只用来取经纬度与文字归属。"""
    used = []
    for name, tpl in GEO_URLS:
        try:
            d = json.loads(_http(tpl.format(ip=ip)))
            used.append(name)
            if d.get("success") is False:
                continue
            country = str(d.get("country") or d.get("country_name") or "").strip()
            region = str(d.get("region") or "").strip()
            city = str(d.get("city") or "").strip()
            lat = d.get("latitude") or d.get("lat")
            lng = d.get("longitude") or d.get("lng")
            special = _norm_special(country) or _norm_special(region)
            if special:
                country, region = "中国", special
            if country.lower() in ("cn", "china"):
                country = "中国"
            return ({
                "country": country, "region": region, "city": city,
                "lat": float(lat) if lat else None,
                "lng": float(lng) if lng else None,
                "source": name,
            }, used)
        except Exception:
            continue
    return (None, used)


def _label(geo_text, online, local):
    if geo_text:
        base = geo_text.replace(" ", "")
        for k, v in (("中国香港", "中国香港"), ("中国澳门", "中国澳门"),
                     ("中国台湾", "中国台湾")):
            base = base.replace(k, v)
    elif online:
        base = "".join([x for x in (online["country"], online["region"],
                                    online["city"]) if x])
    else:
        base = (local.get("label") or "本机").replace("·", "")
    base = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff]", "", base)[:32]
    return "本机 · " + (base or "本机") + "（出口 IP）"


def _mismatch(online, local):
    if not online:
        return False
    if local.get("scope") == "overseas":
        return bool(local.get("country") and online.get("country") and
                    local["country"] != online["country"])
    lr = str(local.get("province") or "")
    orr = str(online.get("region") or "")
    if not lr or not orr:
        return False
    a = orr.replace("省", "").replace("市", "").replace("Sheng", "").strip()
    b = lr.replace("省", "").replace("市", "").strip()
    return not (a in b or b in a or a == b)


def current(app):
    s = app.settings
    return {
        "ip": s.get("home_ip", ""),
        "proxy_ip": s.get("home_proxy_ip", ""),
        "geo": s.get("home_geo", ""),
        "source": s.get("home_source", "default"),
        "located_at": s.get("home_locate_at", 0),
        "home": {"lat": s.get("home_lat"), "lng": s.get("home_lng"),
                 "label": s.get("home_label")},
    }


def run(app, timeout=6):
    """执行一次定位，成功写入配置并返回完整诊断。"""
    res = {"ok": False, "msg": "", "sources": []}
    direct_text = ""
    try:
        direct_text = _http(DIRECT_URL, timeout)
        res["sources"].append("myip.ipip.net")
    except Exception as e:
        res["msg"] = "直连回显服务不可达：%s" % e

    ip = _first_ip(direct_text)
    geo_text = _geo_text(direct_text)
    if not ip:
        for u in PROXY_URLS:
            try:
                t = _http(u, timeout)
                ip = _first_ip(t)
                if ip:
                    res["sources"].append(u.split("/")[2])
                    res["msg"] = "直连回显不可用，已退回备用源（可能经过代理）"
                    break
            except Exception:
                continue
    if not ip:
        res["msg"] = res["msg"] or "未能获取出口 IP，请检查设备联网，或在上方手动填写经纬度"
        return res

    # 识别 clash / TUN 分流产生的第二个出口
    proxy_ip = ""
    for u in PROXY_URLS:
        try:
            cand = _first_ip(_http(u, timeout))
            if cand and cand != ip:
                proxy_ip = cand
                res["sources"].append(u.split("/")[2] + "(代理)")
                break
        except Exception:
            continue

    online, geo_used = _online_geo(ip)
    res["sources"].extend(geo_used)
    local = app.geo.lookup(ip)

    if online and online["lat"] is not None and online["lng"] is not None:
        lat, lng = online["lat"], online["lng"]
        coord_src = online["source"]
    elif local.get("lat") is not None:
        lat, lng = local["lat"], local["lng"]
        coord_src = "本地 ip2region 库（在线源不可用）"
    else:
        province = str(local.get("province") or "")
        lat, lng = _FALLBACK.get(province, (35.86, 104.20))
        coord_src = "内置省会坐标（降级）"

    label = _label(geo_text, online, local)
    if geo_text:
        geo = geo_text
    elif online:
        geo = " ".join([x for x in (online["country"], online["region"],
                                    online["city"]) if x])
    else:
        geo = local.get("label", "")

    patch = {
        "home_ip": ip,
        "home_geo": geo,
        "home_proxy_ip": proxy_ip,
        "home_source": "auto",
        "home_locate_at": time.time(),
        "home_lat": round(float(lat), 4),
        "home_lng": round(float(lng), 4),
        "home_label": label,
    }
    changed = app.settings.update(patch)
    res.update({
        "ok": True,
        "ip": ip,
        "proxy_ip": proxy_ip,
        "has_proxy": bool(proxy_ip),
        "geo_text": geo_text,
        "online": online,
        "local": {k: local.get(k) for k in
                  ("country", "province", "city", "label", "lat", "lng", "scope")},
        "mismatch": _mismatch(online, local),
        "coord_source": coord_src,
        "home": {"lat": patch["home_lat"], "lng": patch["home_lng"],
                 "label": patch["home_label"]},
        "changed": changed,
    })
    return res
