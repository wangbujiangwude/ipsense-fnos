# -*- coding: utf-8 -*-
"""多源 IP 归属交叉校验（1.0.8 新增）。

背景：随包 ip2region xdb 是单一来源，对运营商网段重分配更新滞后
（实测 220.205.0.0/16 多个 IP 被误判到河北/天津/内蒙古/甘肃）。
本模块引入三家在线权威源 + 本地库共 4 票，按国家/省份/城市多数派裁决：

  - ip-api.com  中文，返回国家/省/市/运营商/经纬度
  - ip.sb       英文，返回国家/省/市/ASN
  - ipinfo.io   ISO 码 + loc 坐标
  - 本地 xdb    离线兜底

设计约束：
  1. 纯标准库 urllib，强制直连（ProxyHandler({})），与 locate.py 一致；
  2. 结果落 SQLite geo_cache，TTL 默认 30 天，遵守在线源限流；
  3. 后台低频队列校验高频公网 IP，不阻塞采集与 HTTP 响应；
  4. 在线不可用时自动回退本地库，标记 verified=false；
  5. 裁决后回写 events 表，让地图/排名/记录立即使用更准的归属。
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

SOURCES = ("ip-api.com", "ip.sb", "ipinfo.io", "ip2region(本地)")
# 1.1.15：区级补充源只用来补 district，不参与 4 票裁决，
# 避免把国内库的省级偏差带进多数派结果（实测 220.205.91.142 国内源误判广东）。
DISTRICT_SOURCES = ("ip-api.com", "ip9.com.cn")

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


def fetch_ipapi(ip):
    d = json.loads(_http("http://ip-api.com/json/%s?lang=zh-CN&fields="
                         "status,message,country,countryCode,regionName,city,district,"
                         "isp,lat,lon,query"
                         % urllib.parse.quote(ip, safe="")))
    if d.get("status") != "success":
        return None
    return {
        "source": "ip-api.com", "country": norm_country(d.get("country") or d.get("countryCode")),
        "province": norm_prov(d.get("regionName")), "city": norm_city(d.get("city")),
        "district": norm_district(d.get("district")),
        "isp": (d.get("isp") or "").strip(),
        "lat": d.get("lat"), "lng": d.get("lon"),
    }


def fetch_ipsb(ip):
    d = json.loads(_http("https://api.ip.sb/geoip/" + urllib.parse.quote(ip, safe="")))
    return {
        "source": "ip.sb", "country": norm_country(d.get("country")),
        "province": norm_prov(d.get("region")), "city": norm_city(d.get("city")),
        "district": "",
        "isp": (d.get("isp") or d.get("asn_organization") or "").strip(),
        "lat": d.get("latitude"), "lng": d.get("longitude"),
    }


def fetch_ipinfo(ip):
    d = json.loads(_http("https://ipinfo.io/%s/json" % urllib.parse.quote(ip, safe="")))
    lat = lng = None
    if d.get("loc") and "," in d["loc"]:
        try:
            a, b = d["loc"].split(",", 1)
            lat, lng = float(a), float(b)
        except (TypeError, ValueError):
            pass
    return {
        "source": "ipinfo.io", "country": norm_country(d.get("country")),
        "province": norm_prov(d.get("region")), "city": norm_city(d.get("city")),
        "district": "",
        "isp": (d.get("org") or "").strip(), "lat": lat, "lng": lng,
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


FETCHERS = (("ip-api.com", fetch_ipapi), ("ip.sb", fetch_ipsb),
            ("ipinfo.io", fetch_ipinfo))


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
    """4 票多数派裁决，返回 (geo_dict, verification_dict)。

    local  : GeoResolver.lookup() 的完整结果
    online : 各在线源归一化结果列表
    """
    candidates = []
    for o in online:
        if o and o.get("country"):
            candidates.append(o)
    local_vote = {
        "source": "ip2region(本地)", "country": norm_country(local.get("country")),
        "province": norm_prov(local.get("province")), "city": norm_city(local.get("city")),
        "district": norm_district(local.get("district")),
        "isp": (local.get("isp") or "").strip(),
        "lat": local.get("lat"), "lng": local.get("lng"),
    }
    if local_vote["country"] and local_vote["country"] != "未知":
        candidates.append(local_vote)

    country, country_cnt = _most_common([c["country"] for c in candidates])
    country = country or "未知"
    is_cn = country in ("中国", "中国香港", "中国澳门", "中国台湾")
    if country in ("中国香港", "中国澳门", "中国台湾"):
        country = "中国"

    # 省份：仅中国境内参与投票，且各源需给出省份
    prov_votes = [c["province"] for c in candidates
                  if c["country"] in ("中国", "中国香港", "中国澳门", "中国台湾")
                  and c["province"]]
    province, prov_cnt = _most_common(prov_votes)
    if province in ("中国香港", "中国澳门", "中国台湾"):
        # 港澳台作为省级标注，国家仍为中国
        pass
    elif province and is_cn:
        # 补全「省/市」后缀，与现有 PROVINCE_COORDS 对齐
        from geoip import PROVINCE_COORDS
        for k in PROVINCE_COORDS:
            if norm_prov(k) == norm_prov(province):
                province = k
                break

    city_votes = [c["city"] for c in candidates if c["city"]]
    city, _ = _most_common(city_votes)
    isp, _ = _most_common([c["isp"] for c in candidates])
    # 1.1.15：区级单独投票，缺字段的源不参与（不把空串当一票）。
    district, _ = _most_common([c.get("district", "") for c in candidates])

    # 坐标（1.0.9）：必须与最终裁决的省份一致。
    # 旧逻辑取「第一个有坐标的在线源」，在线源缺坐标时回退本地库，
    # 结果 112.28.131.131 被裁决为安徽省，却沿用本地库广东坐标画到了广州。
    # 现在中国境内优先取「省份与裁决一致」的那票坐标；都没有时用省级中心点
    # 并按 IP 轻微散开，保证地图点位与省份标注自洽。
    from geoip import PROVINCE_COORDS
    center = PROVINCE_COORDS.get(province) if country == "中国" else None
    lat = lng = None
    if center:
        for c in candidates:
            if c["source"] == "ip2region(本地)":
                continue
            if norm_prov(c.get("province") or "") == norm_prov(province) \
                    and c.get("lat") is not None and c.get("lng") is not None:
                try:
                    lat, lng = float(c["lat"]), float(c["lng"])
                    break
                except (TypeError, ValueError):
                    continue
        if lat is None:
            lat, lng = center
            h = int(hashlib.md5(str(local.get("ip") or "").encode()).hexdigest()[:6], 16)
            lat += ((h % 100) / 100.0 - 0.5) * 1.2
            lng += (((h // 100) % 100) / 100.0 - 0.5) * 1.6
    else:
        # 海外 / 无明确省份：优先在线源城市级坐标，否则用本地库
        for c in candidates:
            if c["source"] != "ip2region(本地)" and c.get("lat") is not None \
                    and c.get("lng") is not None:
                try:
                    lat, lng = float(c["lat"]), float(c["lng"])
                    break
                except (TypeError, ValueError):
                    continue
        if lat is None:
            lat, lng = local.get("lat"), local.get("lng")

    # 分歧与置信度
    countries = {c["country"] for c in candidates if c["country"]}
    provs = {c["province"] for c in candidates
             if c["province"] and c["province"] != "中国"}
    disagree = len(countries) > 1 or len(provs) > 1
    n_online = len(online)
    if n_online >= 2 and country_cnt >= 2 and (not prov_votes or prov_cnt >= 2):
        confidence = "high"
    elif n_online >= 2:
        confidence = "medium"
    elif n_online == 1:
        confidence = "low"
    else:
        confidence = "offline"

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
    verification = {
        "confidence": confidence, "disagree": disagree,
        "online_sources": n_online, "province_votes": prov_cnt,
        "checked_at": time.time(), "sources": candidates,
        "country_votes": sorted(countries), "province_candidates": sorted(provs),
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
        local = self.geo.lookup_uncached(ip)
        # 1.1.16：离线库省级脏值被在线多数派订正后要固化下来，否则每次
        # force 核验都会把「重庆市」重新带进本地票、local_* 展示与地域聚合。
        try:
            fix = self.store.local_fix(ip) if hasattr(self.store, "local_fix") else None
            if fix:
                local = fix
        except Exception as e:
            self.log("local_fix %s: %s" % (ip, e))
        online, errors = [], []

        def run(item):
            name, fn = item
            try:
                return name, fn(ip), None
            except Exception as e:
                return name, None, "%s: %s" % (name, str(e)[:80])

        # 三家源并行查询：总耗时约等于最慢的一家，避免超过网关 20 s 连接超时
        with concurrent.futures.ThreadPoolExecutor(3) as ex:
            for name, o, err in ex.map(run, FETCHERS):
                if o and o.get("country"):
                    online.append(o)
                    with self.stats_lock:
                        self.source_stat[name] = self.source_stat.get(name, 0) + 1
                if err:
                    errors.append(err)
        geo, vf = vote(local, online)
        # 1.1.16：区级补充探测（独立源，不进裁决；失败不影响主流程）。
        # 实测 ip-api.com / ip.sb / ipinfo.io 免费版都不返回 district，
        # ip9.com.cn 的 area 对多个国内 IP 也全为空，所以 1.1.15 的自动
        # 区级补充实际上拿不到数据；优先让用户填自己的 JSON 接口。
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
        # 在线多数派与离线库冲突时固化裁决结果，杜绝脏值反复回流。
        if vf.get("disagree") and vf.get("online_sources", 0) >= 2:
            try:
                self.store.put_local_fix(ip, dict(geo, ip=ip))
            except Exception as e:
                self.log("put_local_fix %s: %s" % (ip, e))
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
