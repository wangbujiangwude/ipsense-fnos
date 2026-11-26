# -*- coding: utf-8 -*-
"""IP 归属核验（1.0.8 新增，1.1.30 改口径）。

历史背景：1.0.8 引入三家在线源 + 本地库共 4 票多数派裁决，
用来订正 ip2region 对运营商网段重分配的滞后。

1.1.30 实测结论：ip-api.com / ipinfo.io 对国内省市的判定反而不如随包
离线库稳定（同一 IP 常给出济南 / 东营两套结果），继续参与多数派只会把
离线库的正确结果带偏。因此去掉这两家，改成：

  - ip2region(本地)  主裁决：国家 / 省 / 市 / 运营商 / 区县全部以它为准
  - ip.sb(参考)      只补坐标与空缺字段，不参与主裁决、不改归属
  - 独立区级源        ip9.com.cn / 用户自定义接口，只补 district

设计约束：
  1. 纯标准库 urllib，强制直连（ProxyHandler({})），与 locate.py 一致；
  2. 结果落 SQLite geo_cache，TTL 默认 30 天，遵守在线源限流；
  3. 后台低频队列校验高频公网 IP，不阻塞采集与 HTTP 响应；
  4. 在线参考不可用时完全回退离线库，归属结果不受影响；
  5. 核验后回写 events 表，让地图/排名/记录立即使用最新归属。
"""
import json
import time
import queue
import hashlib
import threading
import urllib.request
import urllib.parse
import concurrent.futures

UA = "Mozilla/5.0 (compatible; ipsense/1.0.8; local-nas-app)"

# 1.1.30：源列表即前端「归属信息源」展示顺序。第一项是主裁决，
# 其余只作参考；不再有任何在线源能改写国家 / 省 / 市。
SOURCES = ("ip2region(本地)", "ip.sb(参考)")
# 区级补充源只用来补 district，不参与归属裁决。
# 1.1.30 起 ip-api.com 已被移除，这里只留 ip9.com.cn 与用户自定义接口。
DISTRICT_SOURCES = ("ip9.com.cn",)

ISO_CN = {
    "CN": "中国", "US": "美国", "JP": "日本", "KR": "韩国", "DE": "德国",
    "GB": "英国", "FR": "法国", "NL": "荷兰", "RU": "俄罗斯", "SG": "新加坡",
    "IN": "印度", "CA": "加拿大", "AU": "澳大利亚", "BR": "巴西", "IT": "意大利",
    "ES": "西班牙", "UA": "乌克兰", "TR": "土耳其", "VN": "越南", "TH": "泰国",
    "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾", "PK": "巴基斯坦",
    "IR": "伊朗", "MX": "墨西哥", "AR": "阿根廷", "ZA": "南非", "EG": "埃及",
    "NG": "尼日利亚", "SE": "瑞典", "NO": "挪威", "FI": "芬兰", "PL": "波兰",
    "CH": "瑞士", "AT": "奥地利", "BE": "比利时", "DK": "丹麦", "IE": "爱尔兰",
    "PT": "葡萄牙", "GR": "希腊", "CZ": "捷克", "RO": "罗马尼亚", "HU": "匈牙利",
    "IL": "以色列", "SA": "沙特阿拉伯", "AE": "阿联酋", "KZ": "哈萨克斯坦",
    "MN": "蒙古", "KH": "柬埔寨", "MM": "缅甸", "BD": "孟加拉国",
    "NZ": "新西兰", "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁",
    "BG": "保加利亚", "HR": "克罗地亚", "RS": "塞尔维亚", "LT": "立陶宛",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "IS": "冰岛", "LU": "卢森堡",
    "CY": "塞浦路斯", "MU": "毛里求斯", "HK": "中国香港", "MO": "中国澳门",
    "TW": "中国台湾",
}

EN_CN = {
    "china": "中国", "united states": "美国", "japan": "日本", "korea": "韩国",
    "germany": "德国", "united kingdom": "英国", "france": "法国",
    "netherlands": "荷兰", "russia": "俄罗斯", "singapore": "新加坡",
    "india": "印度", "canada": "加拿大", "australia": "澳大利亚",
    "brazil": "巴西", "italy": "意大利", "spain": "西班牙", "ukraine": "乌克兰",
    "turkey": "土耳其", "vietnam": "越南", "thailand": "泰国",
    "indonesia": "印度尼西亚", "malaysia": "马来西亚", "philippines": "菲律宾",
    "pakistan": "巴基斯坦", "iran": "伊朗", "mexico": "墨西哥",
    "argentina": "阿根廷", "south africa": "南非", "egypt": "埃及",
    "nigeria": "尼日利亚", "sweden": "瑞典", "norway": "挪威", "finland": "芬兰",
    "poland": "波兰", "switzerland": "瑞士", "austria": "奥地利",
    "belgium": "比利时", "denmark": "丹麦", "ireland": "爱尔兰",
    "portugal": "葡萄牙", "greece": "希腊", "czechia": "捷克",
    "czech republic": "捷克", "romania": "罗马尼亚", "hungary": "匈牙利",
    "israel": "以色列", "saudi arabia": "沙特阿拉伯",
    "united arab emirates": "阿联酋", "kazakhstan": "哈萨克斯坦",
    "mongolia": "蒙古", "cambodia": "柬埔寨", "myanmar": "缅甸",
    "bangladesh": "孟加拉国", "new zealand": "新西兰", "chile": "智利",
    "colombia": "哥伦比亚", "peru": "秘鲁", "bulgaria": "保加利亚",
    "croatia": "克罗地亚", "serbia": "塞尔维亚", "lithuania": "立陶宛",
    "latvia": "拉脱维亚", "estonia": "爱沙尼亚", "iceland": "冰岛",
    "luxembourg": "卢森堡", "cyprus": "塞浦路斯", "mauritius": "毛里求斯",
    "hong kong": "中国香港", "hongkong": "中国香港", "香港": "中国香港",
    "macao": "中国澳门", "macau": "中国澳门", "澳门": "中国澳门",
    "taiwan": "中国台湾", "台湾": "中国台湾",
}

EN_PROV = {
    "anhui": "安徽", "hebei": "河北", "tianjin": "天津", "guangdong": "广东",
    "inner mongolia": "内蒙古", "nei mongol": "内蒙古", "gansu": "甘肃",
    "shanghai": "上海", "henan": "河南", "beijing": "北京",
    "zhejiang": "浙江", "jiangsu": "江苏", "shandong": "山东", "sichuan": "四川",
    "hubei": "湖北", "hunan": "湖南", "fujian": "福建", "jiangxi": "江西",
    "liaoning": "辽宁", "jilin": "吉林", "heilongjiang": "黑龙江",
    "shanxi": "山西", "shaanxi": "陕西", "yunnan": "云南", "guizhou": "贵州",
    "guangxi": "广西", "hainan": "海南", "xinjiang": "新疆", "tibet": "西藏",
    "ningxia": "宁夏", "qinghai": "青海", "chongqing": "重庆",
    "heilongjiang sheng": "黑龙江", "xinjiang uyghur": "新疆",
}

# 常见英文/拼音城市名 → 中文（1.0.9）。
# ip.sb / ipinfo.io 返回 Hefei、Guangzhou，ip-api.com 返回「合肥」「广州」，
# 若不归一，多数派投票会把同一座城市当成两个候选，英文名可能以 2:1 胜出，
# 导致同省 IP 在排名/画像里一会儿「合肥」一会儿「Hefei」。
CITY_CN = {
    "hefei": "合肥", "guangzhou": "广州", "shenzhen": "深圳",
    "beijing": "北京", "peking": "北京", "shanghai": "上海",
    "tianjin": "天津", "chongqing": "重庆", "hangzhou": "杭州",
    "nanjing": "南京", "wuhan": "武汉", "chengdu": "成都",
    "xian": "西安", "zhengzhou": "郑州", "jinan": "济南",
    "qingdao": "青岛", "shenyang": "沈阳", "dalian": "大连",
    "changsha": "长沙", "fuzhou": "福州", "xiamen": "厦门",
    "kunming": "昆明", "guiyang": "贵阳", "nanchang": "南昌",
    "shijiazhuang": "石家庄", "taiyuan": "太原", "harbin": "哈尔滨",
    "changchun": "长春", "lanzhou": "兰州", "xining": "西宁",
    "yinchuan": "银川", "urumqi": "乌鲁木齐", "wulumuqi": "乌鲁木齐",
    "nanning": "南宁", "haikou": "海口", "suzhou": "苏州",
    "wuxi": "无锡", "ningbo": "宁波", "dongguan": "东莞",
    "foshan": "佛山", "zhuhai": "珠海", "hong kong": "中国香港",
    "hongkong": "中国香港", "macao": "中国澳门", "macau": "中国澳门",
    "taipei": "中国台湾", "singapore": "新加坡", "port louis": "路易港",
    "tokyo": "东京", "seoul": "首尔", "london": "伦敦",
    "paris": "巴黎", "sydney": "悉尼", "toronto": "多伦多",
    "los angeles": "洛杉矶", "san jose": "圣何塞",
    "frankfurt": "法兰克福", "amsterdam": "阿姆斯特丹",
}


def norm_country(s):
    s = (s or "").strip()
    if not s:
        return ""
    if s.upper() in ISO_CN:
        return ISO_CN[s.upper()]
    return EN_CN.get(s.lower(), s)


def norm_prov(s):
    s = (s or "").strip()
    if not s:
        return ""
    s = EN_PROV.get(s.lower(), s)
    for suf in ("维吾尔自治区", "壮族自治区", "回族自治区", "特别行政区",
                "自治区", "省", "市", "sheng", "shi"):
        s = s.replace(suf, "")
    return s.strip()


def norm_city(s):
    """城市名归一：去「市 / city」后缀，并把英文/拼音名映射为中文（1.0.9）。"""
    s = (s or "").strip()
    if s.endswith("市"):
        s = s[:-1]
    if s.lower().endswith(" city"):
        s = s[:-5]
    s = s.strip()
    return CITY_CN.get(s.lower(), s)


def norm_district(s):
    """区县名归一：去 0 / - / 未知 等哨兵值，保留「蜀山区」原样。"""
    v = (s or "").strip() if isinstance(s, str) else ""
    return "" if v in ("", "0", "-", "未知", "unknown", "None") else v


def _http(url, data=None, timeout=6):
    """直连请求（绕过系统代理），返回解码后的文本。"""
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": UA, "Accept": "*/*",
        "Content-Type": "application/json" if data else "text/plain",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")[:16384]


# 1.1.30：ip-api.com / ipinfo.io 取数函数已移除。
# 只保留 ip.sb 一家在线源，且它的结果不再进入 vote() 的归属裁决，
# 仅用于补坐标与运营商等空缺字段（见 vote / verify）。
def fetch_ipsb(ip):
    d = json.loads(_http("https://api.ip.sb/geoip/" + urllib.parse.quote(ip, safe="")))
    return {
        "source": "ip.sb", "country": norm_country(d.get("country")),
        "province": norm_prov(d.get("region")), "city": norm_city(d.get("city")),
        "district": "",
        "isp": (d.get("isp") or d.get("asn_organization") or "").strip(),
        "lat": d.get("latitude"), "lng": d.get("longitude"),
    }


def fetch_custom_district(ip, settings):
    """1.1.16：用户自定义区级接口，URL 用 {ip} 占位，按点号路径取区县。

    安全边界（防止设备变成任意 URL 代理）：只接受 https、必须含 {ip} 占位、
    禁止回环 / 内网 / 云元数据 / IPv6 主机、5 秒超时、结果只取字符串并截断。
    失败一律返回 None，不影响主裁决流程。
    """
    if not settings.get("geo_district_api_enabled", False):
        return None
    tpl = (settings.get("geo_district_api") or "").strip()
    if not tpl or "{ip}" not in tpl:
        return None
    u = tpl.replace("{ip}", urllib.parse.quote(str(ip), safe=""))
    p = urllib.parse.urlparse(u)
    h = (p.hostname or "").lower()
    if p.scheme != "https" or not h or ":" in h:
        return None
    blocked = ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254",
               "metadata.google.internal", "metadata", "[::1]")
    if h in blocked or h.startswith(("127.", "10.", "192.168.", "169.254.")):
        return None
    if any(h.startswith("172.%d." % i) for i in range(16, 32)):
        return None
    obj = json.loads(_http(u, timeout=5))
    path = (settings.get("geo_district_field") or "district").strip()
    cur = obj
    for seg in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(seg)
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return None
    if not isinstance(cur, str):
        return None
    return norm_district(cur)[:40] or None


def fetch_ip9(ip):
    """国内区县级补充源（1.1.15）：只取 area 作为 district。

    实测该源对 220.205.91.142 等网段给的是「广东/广州」，与三家国际源和
    用户实测的「安徽/合肥」冲突，因此刻意不进 FETCHERS、不参与 4 票裁决。
    """
    d = json.loads(_http("https://ip9.com.cn/get?ip=" +
                         urllib.parse.quote(ip, safe=""), timeout=5))
    if d.get("ret") != 200:
        return None
    x = d.get("data") or {}
    return {"source": "ip9.com.cn(区县)",
            "country": norm_country(x.get("country")),
            "province": norm_prov(x.get("prov")),
            "city": norm_city(x.get("city")),
            "district": norm_district(x.get("area")),
            "isp": (x.get("isp") or "").strip(),
            "lat": x.get("lat"), "lng": x.get("lng")}


# 1.1.30：只剩 ip.sb 一家在线参考源。并行度 1，结果只用于补坐标 /
# 运营商 / 区县，绝不改写离线库给出的国家 / 省 / 市。
FETCHERS = (("ip.sb", fetch_ipsb),)


def _most_common(values):
    vals = [v for v in values if v]
    if not vals:
        return "", 0
    best, cnt = "", 0
    for v in set(vals):
        c = vals.count(v)
        if c > cnt or (c == cnt and v > best):
            best, cnt = v, c
    return best, cnt


def vote(local, online):
    """1.1.30 裁决：离线库主裁决 + 在线源仅作参考。

    local  : GeoResolver.lookup_uncached() 的完整结果（唯一归属依据）
    online : 在线参考源结果列表（当前最多 1 条 ip.sb），不改归属

    返回 (geo_dict, verification_dict)。verification["sources"] 仍保留
    两行明细供前端「归属核验」面板展示，用 role 区分主裁决 / 参考。
    """
    from geoip import PROVINCE_COORDS

    # ---- 主裁决：国家 / 省 / 市 / 运营商 / 区县全部以离线库为准 ----
    country = norm_country(local.get("country"))
    province = norm_prov(local.get("province"))
    city = norm_city(local.get("city"))
    district = norm_district(local.get("district"))
    isp = (local.get("isp") or "").strip()
    if country in ("中国香港", "中国澳门", "中国台湾"):
        if not province:
            province = country
        country = "中国"
    is_cn = country in ("中国", "中国香港", "中国澳门", "中国台湾")
    if province and is_cn and province not in ("中国香港", "中国澳门", "中国台湾"):
        # 补全「省/市」后缀，与 PROVINCE_COORDS 对齐
        for k in PROVINCE_COORDS:
            if norm_prov(k) == norm_prov(province):
                province = k
                break

    main_vote = {
        "source": "ip2region(本地)", "role": "主裁决",
        "country": country, "province": province, "city": city,
        "district": district, "isp": isp,
        "lat": local.get("lat"), "lng": local.get("lng"),
    }
    ref = None
    for o in online:
        if o and o.get("country"):
            ref = dict(o)
            break
    if ref:
        ref["role"] = "参考"
        # 参考源只在主裁决缺字段时补位，绝不覆盖已有归属
        if not isp and ref.get("isp"):
            isp = ref["isp"]
        if not district and ref.get("district"):
            district = ref["district"]

    # ---- 坐标：必须与最终裁决的省份自洽 ----
    center = PROVINCE_COORDS.get(province) if country == "中国" else None
    lat = lng = None
    if center:
        # 中国境内优先取「省份与主裁决一致」的参考源城市级坐标
        if ref and norm_prov(ref.get("province") or "") == norm_prov(province) \
                and ref.get("lat") is not None and ref.get("lng") is not None:
            try:
                lat, lng = float(ref["lat"]), float(ref["lng"])
            except (TypeError, ValueError):
                lat = lng = None
        if lat is None:
            lat, lng = center
            h = int(hashlib.md5(str(local.get("ip") or "").encode()).hexdigest()[:6], 16)
            lat += ((h % 100) / 100.0 - 0.5) * 1.2
            lng += (((h // 100) % 100) / 100.0 - 0.5) * 1.6
    else:
        # 海外 / 无明确省份：优先参考源坐标，否则用本地库坐标
        if ref and ref.get("lat") is not None and ref.get("lng") is not None:
            try:
                lat, lng = float(ref["lat"]), float(ref["lng"])
            except (TypeError, ValueError):
                lat = lng = None
        if lat is None:
            lat, lng = local.get("lat"), local.get("lng")

    # ---- 分歧与置信度：反映「参考源与离线库是否一致」，不反映在线源数量 ----
    disagree = False
    if ref:
        rc = norm_country(ref.get("country"))
        if rc in ("中国香港", "中国澳门", "中国台湾"):
            rc = "中国"
        rp = norm_prov(ref.get("province") or "")
        disagree = bool((rc and rc != country) or
                        (is_cn and rp and province and rp != norm_prov(province)))
    valid_local = bool(country) and country != "未知"
    if not valid_local:
        confidence = "offline"
    elif ref and disagree:
        confidence = "medium"
    else:
        # 离线库本身即可定论；参考源缺失 / 一致都不降低可信度
        confidence = "high"

    scope = "cn" if (country == "中国" or province in
                     ("中国香港", "中国澳门", "中国台湾")) else "overseas"
    label = "·".join([x for x in (country, province, city, district) if x]) or "未知归属"
    geo = {
        "ip": local.get("ip"), "country": country, "province": province,
        "city": city, "district": district, "isp": isp,
        "scope": scope, "label": label,
        "lat": round(lat, 4) if isinstance(lat, (int, float)) else None,
        "lng": round(lng, 4) if isinstance(lng, (int, float)) else None,
        "ipver": local.get("ipver", 4),
    }
    sources = [main_vote] + ([ref] if ref else [])
    verification = {
        "confidence": confidence, "disagree": disagree,
        "online_sources": len(online), "province_votes": 1 if province else 0,
        "checked_at": time.time(), "sources": sources,
        "country_votes": sorted({c["country"] for c in sources if c.get("country")}),
        "province_candidates": sorted({c["province"] for c in sources
                                       if c.get("province") and c["province"] != "中国"}),
        "primary_source": "ip2region(本地)",
    }
    return geo, verification


class GeoVerifier(object):
    """多源校验器：缓存 + 后台低频队列 + 回写事件表。"""

    def __init__(self, store, geo, settings, log=None):
        self.store = store
        self.geo = geo
        self.settings = settings
        self.log = log or (lambda m: None)
        # 1.1.15：新 IP 首次出现也会入队，队列必须有界 + 去重，
        # 否则扫描高峰期会把在线源打爆。
        self.q = queue.Queue(maxsize=512)
        self._pending = set()
        self.stats_lock = threading.Lock()
        self.source_stat = {}
        self.verified = 0
        self.failed = 0
        self.stop_evt = threading.Event()
        self.worker = threading.Thread(target=self._loop, name="geo-verify", daemon=True)
        self.worker.start()
        try:
            self.geo.attach(self)
        except AttributeError:
            pass

    # ---- 缓存 ----
    def _ttl(self):
        try:
            return int(self.settings.get("geo_verify_days", 30) or 30) * 86400
        except (TypeError, ValueError):
            return 30 * 86400

    def cached(self, ip):
        if not self.settings.get("geo_verify_enabled", True):
            return None
        r = self.store.get_geo_cache(ip)
        if not r:
            return None
        if time.time() - float(r.get("checked_at") or 0) > self._ttl():
            return None
        try:
            sources = json.loads(r.get("sources") or "[]")
        except (TypeError, ValueError):
            sources = []
        g = {
            "ip": ip, "country": r.get("country", ""), "province": r.get("province", ""),
            "city": r.get("city", ""), "district": r.get("district", ""),
            "isp": r.get("isp", ""),
            "scope": r.get("scope", "cn"), "label": r.get("label", ""),
            "lat": r.get("lat"), "lng": r.get("lng"), "ipver": r.get("ipver", 4),
            "verified": True, "verification": {
                "confidence": r.get("confidence", "low"),
                "disagree": bool(r.get("disagree")),
                "online_sources": r.get("online_sources", 0),
                "checked_at": r.get("checked_at"), "sources": sources,
                "country_votes": [], "province_candidates": [],
                "district_source": r.get("district_source", ""),
            },
        }
        return g

    def details(self, ip):
        """给前端的完整核验信息（含本地库对照）。"""
        r = self.store.get_geo_cache(ip)
        if not r:
            return None
        try:
            sources = json.loads(r.get("sources") or "[]")
        except (TypeError, ValueError):
            sources = []
        return {
            "ip": ip, "country": r.get("country", ""), "province": r.get("province", ""),
            "city": r.get("city", ""), "district": r.get("district", ""),
            "isp": r.get("isp", ""),
            "lat": r.get("lat"), "lng": r.get("lng"),
            "district_source": r.get("district_source", ""),
            "local": {"country": r.get("local_country", ""),
                      "province": r.get("local_province", ""),
                      "city": r.get("local_city", "")},
            "confidence": r.get("confidence", "low"),
            "disagree": bool(r.get("disagree")),
            "online_sources": r.get("online_sources", 0),
            "checked_at": r.get("checked_at"), "sources": sources,
        }

    # ---- 在线校验 ----
    def verify(self, ip, force=False):
        if not self.settings.get("geo_verify_enabled", True):
            return {"ok": False, "msg": "在线归属校验已在设置中关闭", "ip": ip}
        if not force:
            hit = self.cached(ip)
            if hit:
                return {"ok": True, "cached": True, "ip": ip,
                        "geo": hit, "verification": hit.get("verification")}
        # 1.1.30：离线库是唯一归属依据，不再读取历史上「在线多数派订正」
        # 固化下来的 local_fix，避免旧的在线判定继续覆盖离线库结果。
        local = self.geo.lookup_uncached(ip)
        online, errors = [], []

        def run(item):
            name, fn = item
            try:
                return name, fn(ip), None
            except Exception as e:
                return name, None, "%s: %s" % (name, str(e)[:80])

        # 1.1.30：只查一家在线参考源，不阻塞主裁决；失败一律忽略。
        with concurrent.futures.ThreadPoolExecutor(1) as ex:
            for name, o, err in ex.map(run, FETCHERS):
                if o and o.get("country"):
                    online.append(o)
                    with self.stats_lock:
                        self.source_stat[name] = self.source_stat.get(name, 0) + 1
                if err:
                    errors.append(err)
        geo, vf = vote(local, online)
        # 1.1.16：区级补充探测（独立源，不进裁决；失败不影响主流程）。
        # 1.1.30：保留的 ip.sb 不返回 district，ip9.com.cn 的 area 对多个
        # 国内 IP 也常为空，所以自动区级补充拿不到数据是常态；
        # 优先让用户填自己的 JSON 接口，或在画像里手工补充。
        if not geo.get("district") and geo.get("country") == "中国" and \
                self.settings.get("geo_district_enabled", True):
            try:
                dc = fetch_custom_district(ip, self.settings)
                if dc:
                    geo["district"] = dc
                    geo["label"] = "·".join(
                        [x for x in (geo["country"], geo["province"],
                                     geo["city"], geo["district"]) if x])
                    vf["district_source"] = "custom"
            except Exception as e:
                errors.append("custom-district: %s" % str(e)[:80])
            if not geo.get("district"):
                try:
                    d9 = fetch_ip9(ip)
                    if d9 and d9.get("district"):
                        geo["district"] = d9["district"]
                        geo["label"] = "·".join(
                            [x for x in (geo["country"], geo["province"],
                                         geo["city"], geo["district"]) if x])
                        vf["district_source"] = "ip9.com.cn"
                except Exception as e:
                    errors.append("ip9: %s" % str(e)[:80])
        vf["errors"] = errors
        vf["local"] = {"country": local.get("country"), "province": local.get("province"),
                       "city": local.get("city"), "isp": local.get("isp")}
        self.store.set_geo_cache(ip, geo, vf, local)
        # 裁决结果回写历史事件，让地图/排名/记录立即生效
        try:
            updated = self.store.apply_geo(ip, geo)
        except Exception as e:
            updated = 0
            self.log("apply_geo %s: %s" % (ip, e))
        # 1.1.30：不再把在线参考源的分歧固化进 geo_local_fix。
        # 归属只由离线库决定，参考源不一致时仅在核验面板提示（disagree）。
        self.geo.invalidate(ip)
        with self.stats_lock:
            self.verified += 1
            if not online:
                self.failed += 1
        return {"ok": True, "cached": False, "ip": ip, "geo": geo,
                "verification": vf, "events_updated": updated, "errors": errors}

    def enqueue(self, ip):
        """新 IP / 高频 IP 统一入队；已缓存、已在队列、队列满时不重复提交。"""
        if not ip or not self.settings.get("geo_verify_enabled", True):
            return False
        if self.cached(ip):
            return False
        with self.stats_lock:
            if ip in self._pending:
                return False
            self._pending.add(ip)
        try:
            self.q.put_nowait(ip)
        except queue.Full:
            with self.stats_lock:
                self._pending.discard(ip)
            return False
        return True

    def set_district(self, ip, district):
        """用户在 IP 画像里手工补充区县，回写事件与缓存。"""
        d = norm_district(district)[:40]
        n = self.store.set_district(ip, d)
        try:
            self.geo.invalidate(ip)
        except Exception:
            pass
        return n

    def _loop(self):
        while not self.stop_evt.is_set():
            try:
                ip = self.q.get(timeout=2.0)
            except queue.Empty:
                continue
            if not ip:
                continue
            try:
                if not self.cached(ip):
                    self.verify(ip)
            except Exception as e:
                self.log("geo verify %s: %s" % (ip, e))
            finally:
                with self.stats_lock:
                    self._pending.discard(ip)
            # 在线源限流：每次至少间隔 1.5 s
            self.stop_evt.wait(1.5)

    def queue_top(self, limit=60):
        ips = self.store.top_public_ips(limit)
        for ip in ips:
            self.enqueue(ip)
        return len(ips)

    def stats(self):
        with self.stats_lock:
            src = dict(self.source_stat)
            v, f = self.verified, self.failed
        return {"enabled": bool(self.settings.get("geo_verify_enabled", True)),
                "cached": self.store.geo_cache_count(),
                "verified": v, "failed": f, "queue": self.q.qsize(),
                "sources": src, "source_names": list(SOURCES),
                "ttl_days": int(self.settings.get("geo_verify_days", 30) or 30)}
