# -*- coding: utf-8 -*-
"""离线 IP 归属地查询（ip2region v3 xdb，纯标准库，零外部依赖）。

数据文件随应用分发，不联网。xdb 索引段每条 14 字节：
    sip(u32 LE) | eip(u32 LE) | data_len(u16 LE) | data_ptr(u32 LE)
数据区字符串格式：国家|区域|省份|城市|运营商，"0" 表示空。

合规说明：香港、澳门、台湾均属中国，统一归入「境内」并以
「中国香港 / 中国澳门 / 中国台湾」标注，绝不作为国家或境外地区展示。
"""
import os
import re
import ipaddress
import struct
import hashlib

XDB_NAME = "ip2region_v4.xdb"
HEADER_LEN = 256
INDEX_LEN = 14

# 国家/地区中心点（纬度, 经度）。仅用于点位标注，不绘制任何国界。
COUNTRY_COORDS = {
    "中国": (35.86, 104.20), "美国": (39.83, -98.58), "日本": (36.20, 138.25),
    "韩国": (36.50, 127.90), "德国": (51.17, 10.45), "英国": (54.00, -2.00),
    "法国": (46.60, 2.50), "荷兰": (52.13, 5.29), "俄罗斯": (61.52, 105.32),
    "新加坡": (1.35, 103.82), "印度": (22.00, 79.00), "加拿大": (56.13, -106.35),
    "澳大利亚": (-25.27, 133.78), "巴西": (-14.24, -51.93), "意大利": (42.83, 12.57),
    "西班牙": (40.46, -3.75), "乌克兰": (48.38, 31.17), "土耳其": (38.96, 35.24),
    "越南": (16.00, 107.50), "泰国": (15.87, 100.99), "印度尼西亚": (-2.55, 118.02),
    "马来西亚": (4.21, 101.98), "菲律宾": (12.88, 121.77), "巴基斯坦": (30.38, 69.35),
    "伊朗": (32.43, 53.69), "墨西哥": (23.63, -102.55), "阿根廷": (-38.42, -63.62),
    "南非": (-30.56, 22.94), "埃及": (26.82, 30.80), "尼日利亚": (9.08, 8.68),
    "瑞典": (60.13, 18.64), "挪威": (60.47, 8.87), "芬兰": (61.92, 25.75),
    "波兰": (51.92, 19.15), "瑞士": (46.82, 8.23), "奥地利": (47.52, 14.55),
    "比利时": (50.50, 4.47), "丹麦": (56.26, 9.50), "爱尔兰": (53.41, -8.24),
    "葡萄牙": (39.40, -8.22), "希腊": (39.07, 23.73), "捷克": (49.82, 15.47),
    "罗马尼亚": (45.94, 24.97), "匈牙利": (47.16, 19.50), "以色列": (31.05, 34.85),
    "沙特阿拉伯": (23.89, 45.08), "阿联酋": (23.42, 53.85), "哈萨克斯坦": (48.02, 66.92),
    "蒙古": (46.86, 103.85), "朝鲜": (40.34, 127.51), "柬埔寨": (12.57, 104.99),
    "缅甸": (21.92, 95.96), "老挝": (19.86, 102.50), "孟加拉国": (23.68, 90.36),
    "尼泊尔": (28.39, 84.12), "斯里兰卡": (7.87, 80.77), "新西兰": (-40.90, 174.89),
    "智利": (-35.68, -71.54), "哥伦比亚": (4.57, -74.30), "秘鲁": (-9.19, -75.02),
    "委内瑞拉": (6.42, -66.59), "摩洛哥": (31.79, -7.09), "阿尔及利亚": (28.03, 2.63),
    "肯尼亚": (-0.02, 37.91), "埃塞俄比亚": (9.15, 40.49), "刚果": (-1.50, 23.50),
    "立陶宛": (55.17, 23.88), "拉脱维亚": (56.88, 24.60), "爱沙尼亚": (58.60, 25.01),
    "塞尔维亚": (44.02, 21.01), "克罗地亚": (45.10, 15.20), "保加利亚": (42.73, 25.49),
    "斯洛伐克": (48.67, 19.70), "斯洛文尼亚": (46.15, 14.99), "白俄罗斯": (53.71, 27.95),
    "冰岛": (64.96, -19.02), "卢森堡": (49.82, 6.13), "塞浦路斯": (35.13, 33.43),
    "卡塔尔": (25.35, 51.18), "科威特": (29.31, 47.48), "巴林": (25.93, 50.64),
    "阿曼": (21.47, 55.98), "约旦": (30.59, 36.24), "黎巴嫩": (33.85, 35.86),
    "伊拉克": (33.22, 43.68), "叙利亚": (34.80, 38.99), "阿富汗": (33.94, 67.71),
    "乌兹别克斯坦": (41.38, 64.59), "吉尔吉斯斯坦": (41.20, 74.77), "塔吉克斯坦": (38.86, 71.01),
    "阿塞拜疆": (40.14, 47.58), "格鲁吉亚": (42.32, 43.36), "亚美尼亚": (40.07, 45.04),
    "突尼斯": (33.89, 9.54), "利比亚": (26.34, 17.23), "苏丹": (12.86, 30.22),
    "加纳": (7.95, -1.02), "坦桑尼亚": (-6.37, 34.89), "乌干达": (1.37, 32.29),
    "津巴布韦": (-19.02, 29.15), "赞比亚": (-13.13, 27.85), "安哥拉": (-12.29, 17.54),
    "巴拿马": (8.54, -80.78), "哥斯达黎加": (9.75, -83.75), "古巴": (21.52, -79.92),
    "多米尼加": (18.74, -70.16), "厄瓜多尔": (-1.83, -78.18), "玻利维亚": (-16.29, -63.59),
    "乌拉圭": (-32.52, -55.77), "巴拉圭": (-23.44, -58.44),
}

# 中国省级行政区中心点（纬度, 经度）
PROVINCE_COORDS = {
    "北京市": (39.90, 116.41), "天津市": (39.08, 117.20), "上海市": (31.23, 121.47),
    "重庆市": (29.56, 106.55), "河北省": (38.04, 114.51), "山西省": (37.87, 112.55),
    "辽宁省": (41.80, 123.43), "吉林省": (43.82, 125.32), "黑龙江省": (45.80, 126.53),
    "江苏省": (32.06, 118.80), "浙江省": (30.27, 120.15), "安徽省": (31.82, 117.23),
    "福建省": (26.07, 119.30), "江西省": (28.68, 115.86), "山东省": (36.65, 117.12),
    "河南省": (34.75, 113.63), "湖北省": (30.58, 114.30), "湖南省": (28.23, 112.94),
    "广东省": (23.13, 113.26), "海南省": (20.04, 110.20), "四川省": (30.57, 104.07),
    "贵州省": (26.65, 106.63), "云南省": (25.04, 102.71), "陕西省": (34.34, 108.94),
    "甘肃省": (36.06, 103.83), "青海省": (36.62, 101.78), "台湾省": (23.70, 120.96),
    "内蒙古自治区": (40.84, 111.75), "广西壮族自治区": (22.82, 108.32),
    "西藏自治区": (29.65, 91.13), "宁夏回族自治区": (38.49, 106.23),
    "新疆维吾尔自治区": (43.83, 87.62), "中国香港": (22.32, 114.17),
    "中国澳门": (22.20, 113.54), "中国台湾": (23.70, 120.96),
}

# 常见 IPv6 前缀粗归属（v4 xdb 不覆盖 IPv6，仅做运营商/国家级判断）
CN_V6_PREFIX = (
    ("2408", "中国", "中国移动"), ("2409", "中国", "中国联通"),
    ("240a", "中国", "中国电信"), ("240e", "中国", "中国电信"),
    ("2001:da8", "中国", "教育网"),
)

# xdb 的最后一列是 ISO 国家码，用它做中文名归一，避免境外显示英文名
ISO_TO_CN = {
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
    "MN": "蒙古", "KP": "朝鲜", "KH": "柬埔寨", "MM": "缅甸", "LA": "老挝",
    "BD": "孟加拉国", "NP": "尼泊尔", "LK": "斯里兰卡", "NZ": "新西兰",
    "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁", "VE": "委内瑞拉",
    "MA": "摩洛哥", "DZ": "阿尔及利亚", "KE": "肯尼亚", "ET": "埃塞俄比亚",
    "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚", "RS": "塞尔维亚",
    "HR": "克罗地亚", "BG": "保加利亚", "SK": "斯洛伐克", "SI": "斯洛文尼亚",
    "BY": "白俄罗斯", "IS": "冰岛", "LU": "卢森堡", "CY": "塞浦路斯",
    "QA": "卡塔尔", "KW": "科威特", "BH": "巴林", "OM": "阿曼", "JO": "约旦",
    "LB": "黎巴嫩", "IQ": "伊拉克", "SY": "叙利亚", "AF": "阿富汗",
    "UZ": "乌兹别克斯坦", "KG": "吉尔吉斯斯坦", "TJ": "塔吉克斯坦",
    "AZ": "阿塞拜疆", "GE": "格鲁吉亚", "AM": "亚美尼亚", "TN": "突尼斯",
    "LY": "利比亚", "SD": "苏丹", "GH": "加纳", "TZ": "坦桑尼亚", "UG": "乌干达",
    "ZW": "津巴布韦", "ZM": "赞比亚", "AO": "安哥拉", "PA": "巴拿马",
    "CR": "哥斯达黎加", "CU": "古巴", "DO": "多米尼加", "EC": "厄瓜多尔",
    "BO": "玻利维亚", "UY": "乌拉圭", "PY": "巴拉圭",
    "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾",
    "MU": "毛里求斯",
}

# 部分 xdb 记录的国家字段是英文且 ISO 列为空，这里兜底成中文，避免境外显示英文
COUNTRY_ALIAS = {
    "china": "中国", "united states": "美国", "united kingdom": "英国",
    "japan": "日本", "south korea": "韩国", "korea": "韩国",
    "germany": "德国", "france": "法国", "netherlands": "荷兰",
    "russia": "俄罗斯", "singapore": "新加坡", "india": "印度",
    "canada": "加拿大", "australia": "澳大利亚", "brazil": "巴西",
    "italy": "意大利", "spain": "西班牙", "ukraine": "乌克兰",
    "turkey": "土耳其", "vietnam": "越南", "thailand": "泰国",
    "indonesia": "印度尼西亚", "malaysia": "马来西亚",
    "philippines": "菲律宾", "poland": "波兰", "bulgaria": "保加利亚",
    "sweden": "瑞典", "norway": "挪威", "finland": "芬兰",
    "switzerland": "瑞士", "austria": "奥地利", "belgium": "比利时",
    "denmark": "丹麦", "ireland": "爱尔兰", "portugal": "葡萄牙",
    "greece": "希腊", "czechia": "捷克", "czech republic": "捷克",
    "romania": "罗马尼亚", "hungary": "匈牙利", "israel": "以色列",
    "saudi arabia": "沙特阿拉伯", "united arab emirates": "阿联酋",
    "kazakhstan": "哈萨克斯坦", "mongolia": "蒙古", "cambodia": "柬埔寨",
    "myanmar": "缅甸", "bangladesh": "孟加拉国", "new zealand": "新西兰",
    "chile": "智利", "colombia": "哥伦比亚", "peru": "秘鲁",
    "mauritius": "毛里求斯", "south africa": "南非", "egypt": "埃及",
    "nigeria": "尼日利亚", "hong kong": "中国香港", "hongkong": "中国香港",
    "macao": "中国澳门", "macau": "中国澳门", "taiwan": "中国台湾",
    "香港": "中国香港", "澳门": "中国澳门", "台湾": "中国台湾",
}

_CN_ALIAS = {"香港": "中国香港", "澳门": "中国澳门", "台湾": "中国台湾",
             "香港特别行政区": "中国香港", "澳门特别行政区": "中国澳门",
             "台湾省": "中国台湾", "中国香港特别行政区": "中国香港",
             "中国澳门特别行政区": "中国澳门", "中国台湾省": "中国台湾"}

_PRIVATE_RE = re.compile(
    r"^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|"
    r"0\.|255\.|224\.|::1$|fc|fd|fe80)", re.I)


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return bool(_PRIVATE_RE.match(ip or ""))


class XdbSearcher(object):
    """只读、线程安全的 ip2region xdb 二分查找器（整库 mmap 式载入内存）。"""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.buf = f.read()
        if len(self.buf) < HEADER_LEN + INDEX_LEN:
            raise ValueError("xdb 文件过小或损坏: %s" % path)
        ver, policy, created, self.start, self.end = struct.unpack_from("<HHIII", self.buf, 0)
        self.version = ver
        self.count = (self.end - self.start) // INDEX_LEN
        if self.count <= 0 or self.end > len(self.buf):
            raise ValueError("xdb 索引段异常: start=%s end=%s size=%s" % (self.start, self.end, len(self.buf)))

    def search_raw(self, ip):
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        lo, hi = 0, self.count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            off = self.start + mid * INDEX_LEN
            sip, eip, dlen, dptr = struct.unpack_from("<IIHI", self.buf, off)
            if n < sip:
                hi = mid - 1
            elif n > eip:
                lo = mid + 1
            else:
                if dptr + dlen > len(self.buf):
                    return None
                return self.buf[dptr:dptr + dlen].decode("utf-8", "replace")
        return None


class GeoResolver(object):
    def __init__(self, data_dir):
        self.searcher = None
        path = os.path.join(data_dir, XDB_NAME)
        if os.path.isfile(path):
            try:
                self.searcher = XdbSearcher(path)
            except Exception as e:
                self.searcher = None
                self.error = str(e)
        else:
            self.error = "离线库缺失: %s" % path
        self.cache = {}
        self.verifier = None
        self.ready = self.searcher is not None

    @staticmethod
    def _clean(v):
        return "" if not v or v == "0" or v == "内网IP" else v.strip()

    @staticmethod
    def _province_key(name):
        if not name:
            return ""
        name = _CN_ALIAS.get(name, name)
        for key in PROVINCE_COORDS:
            if key == name:
                return key
        # "广东" -> "广东省"；"内蒙古" -> "内蒙古自治区"
        for key in PROVINCE_COORDS:
            short = key.replace("省", "").replace("市", "").replace("自治区", "") \
                       .replace("壮族", "").replace("回族", "").replace("维吾尔", "").replace("特别行政", "")
            if name.startswith(short) or short.startswith(name.replace("省", "").replace("市", "")):
                return key
        return name

    def attach(self, verifier):
        """接入多源校验器，命中缓存时优先用裁决后的归属（1.0.8）。"""
        self.verifier = verifier

    def lookup_uncached(self, ip):
        """只走本地库，供多源校验器取「本地票」，避免与缓存结果循环。"""
        return self._lookup_uncached((ip or "").strip())

    def invalidate(self, ip):
        self.cache.pop((ip or "").strip(), None)

    def lookup(self, ip):
        ip = (ip or "").strip()
        if not ip:
            return self._empty(ip)
        hit = self.cache.get(ip)
        if hit is not None:
            return hit
        # 已通过多源裁决的 IP，全站统一使用更准的结果
        if self.verifier is not None:
            c = self.verifier.cached(ip)
            if c:
                if len(self.cache) > 30000:
                    self.cache.clear()
                self.cache[ip] = c
                return c
        r = self._lookup_uncached(ip)
        if len(self.cache) > 30000:
            self.cache.clear()
        self.cache[ip] = r
        return r

    def _empty(self, ip):
        return {"ip": ip, "country": "", "province": "", "city": "",
                "district": "", "isp": "",
                "scope": "private" if is_private(ip) else "unknown",
                "label": "内网地址" if is_private(ip) else "未知归属",
                "lat": None, "lng": None, "ipver": 6 if ":" in ip else 4}

    def _lookup_uncached(self, ip):
        if is_private(ip):
            return self._empty(ip)
        country = province = city = district = isp = ""
        if ":" in ip:
            low = ip.lower()
            for pre, cn, carrier in CN_V6_PREFIX:
                if low.startswith(pre):
                    country, isp = "中国", carrier
                    break
            else:
                country = "境外"
            # IPv6 仅做国家级粗判，不再把 province 写成「中国」污染省份排名
            lat, lng = COUNTRY_COORDS["中国"] if country == "中国" else (20.0, 0.0)
            return {"ip": ip, "country": country, "province": "", "city": "",
                    "district": "", "isp": isp,
                    "scope": "cn" if country == "中国" else "overseas",
                    "label": ("中国·" + isp) if (country == "中国" and isp) else "境外·IPv6",
                    "lat": lat, "lng": lng, "ipver": 6}
        raw = self.searcher.search_raw(ip) if self.searcher else None
        iso = ""
        if raw:
            parts = raw.split("|")
            parts += [""] * (6 - len(parts))
            # 国家 | 省/州 | 城市 | 运营商或机构 | ISO 国家码 | 区县(可选)
            # 1.1.15：部分离线库带第 6 段区县；没有就留空，绝不猜测。
            country = self._clean(parts[0])
            province = self._clean(parts[1])
            city = self._clean(parts[2])
            isp = self._clean(parts[3])
            iso = self._clean(parts[4]).upper()
            district = self._clean(parts[5])
            if iso in ISO_TO_CN:
                country = ISO_TO_CN[iso]
        country = _CN_ALIAS.get(country, country)
        if country and country not in ("中国", "境外") and country.lower() in COUNTRY_ALIAS:
            country = COUNTRY_ALIAS[country.lower()]
        if country in ("中国香港", "中国澳门", "中国台湾"):
            province, country = country, "中国"
        if province:
            province = self._province_key(province)
        if province in ("中国香港", "中国澳门", "中国台湾"):
            country = "中国"
        is_cn = (iso == "CN" or country == "中国")
        if is_cn:
            country = "中国"
        if is_cn:
            scope = "cn"
            lat, lng = PROVINCE_COORDS.get(province, COUNTRY_COORDS["中国"])
            # 同城不同 IP 轻微散开，避免所有点重叠
            h = int(hashlib.md5(ip.encode()).hexdigest()[:6], 16)
            lat += ((h % 100) / 100.0 - 0.5) * 1.2
            lng += (((h // 100) % 100) / 100.0 - 0.5) * 1.6
            label = "·".join([x for x in ("中国", province, city, district) if x])
        else:
            scope = "overseas"
            lat, lng = COUNTRY_COORDS.get(country, (20.0, 0.0))
            h = int(hashlib.md5(ip.encode()).hexdigest()[:6], 16)
            lat += ((h % 100) / 100.0 - 0.5) * 3.0
            lng += (((h // 100) % 100) / 100.0 - 0.5) * 4.0
            label = "·".join([x for x in (country or "境外", province, city,
                                         district) if x])
        return {"ip": ip, "country": country or "未知", "province": province,
                "city": city, "district": district, "isp": isp,
                "scope": scope, "label": label,
                "lat": round(lat, 4), "lng": round(lng, 4), "ipver": 4}
