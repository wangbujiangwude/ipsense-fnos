# -*- coding: utf-8 -*-
"""地图服务商预设与合规白名单（1.1.8）。

合规红线（不可放宽）：
- 只允许腾讯地图 / 高德地图 / 百度地图 / 天地图四家具备资质的底图服务；
- 禁止 Google Maps / Apple Maps / Bing 海外版 / OpenStreetMap 直连瓦片 /
  Mapbox / Leaflet + OSM 等未获资质来源；
- 本文件绝不内置任何有效 KEY：key 一律用各家开放平台的申请占位符，
  由用户在设置界面自行申请并填入，配置只落在本机 TRIM_PKGVAR。
- 应用本身不产出任何国界 / 区划轮廓数据，边界一律以官方底图为准。
"""
import re

# 腾讯 key 占位符（1.0.x 起沿用，gateway.py 会重新导出给前端做兼容提示）
MAP_KEY_PLACEHOLDER = "请到腾讯位置服务开放平台申请自己的 key 并替换此占位符"

# 引擎 id 与前端 MAP_ENGINES 一一对应
ENGINES = ("tmap", "amap", "bmapgl", "tianditu")

# 官方 SDK 地址模板：{key} 由用户填写；百度需要 {callback} 才能异步加载。
# 注意各家参数名不同（key / ak / tk），模板里已经写死，不在代码里猜测。
MAP_PROVIDERS = [
    {
        "id": "tencent",
        "name": "腾讯地图 GL JS",
        "engine": "tmap",
        "sdk": "https://map.qq.com/api/gljs?v=1.exp&key={key}",
        "apply_url": "https://lbs.qq.com/dev/console/application/mine",
        "apply_text": "腾讯位置服务控制台",
        "coord": "GCJ-02",
        "key_label": "key",
        "key_placeholder": MAP_KEY_PLACEHOLDER,
        "note": "需勾选「WebGL JavaScript GL」产品，并配置 Referer 白名单。",
        "builtin": True,
    },
    {
        "id": "amap",
        "name": "高德地图 JS API 2.0",
        "engine": "amap",
        "sdk": "https://webapi.amap.com/maps?v=2.0&key={key}",
        "apply_url": "https://console.amap.com/dev/key/app",
        "apply_text": "高德开放平台控制台",
        "coord": "GCJ-02",
        "key_label": "key",
        "key_placeholder": "请到高德开放平台申请自己的 key 并替换此占位符",
        "note": "需创建「Web端 (JS API)」Key，并配置域名白名单。",
        "builtin": True,
    },
    {
        "id": "baidu",
        "name": "百度地图 GL v1.0",
        "engine": "bmapgl",
        "sdk": "https://api.map.baidu.com/api?type=webgl&v=1.0&ak={key}&callback={callback}",
        "apply_url": "https://lbsyun.baidu.com/apiconsole/key",
        "apply_text": "百度地图开放平台控制台",
        "coord": "BD-09（自动转换）",
        "key_label": "ak",
        "key_placeholder": "请到百度地图开放平台申请自己的 ak 并替换此占位符",
        "note": "需创建「浏览器端」AK 并配置 Referer 白名单；坐标由 GCJ-02 自动转 BD-09。",
        "builtin": True,
    },
    {
        "id": "tianditu",
        "name": "天地图 4.0",
        "engine": "tianditu",
        "sdk": "https://api.tianditu.gov.cn/api?v=4.0&tk={key}",
        "apply_url": "https://console.tianditu.gov.cn/apikey",
        "apply_text": "天地图开发平台",
        "coord": "CGCS2000 / EPSG:4326",
        "key_label": "tk",
        "key_placeholder": "请到天地图开发平台申请自己的 tk 并替换此占位符",
        "note": "需申请「浏览器端」key（tk）；底图瓦片由官方服务提供。",
        "builtin": True,
    },
]

PROVIDER_IDS = tuple(p["id"] for p in MAP_PROVIDERS)

# 合规域名白名单：自定义接口指向这些域名时判定为「合规来源」。
# 自建 / 内网代理不在名单内，允许保存但会在设置界面标注需自行确保数据源合规。
ALLOWED_HOSTS = (
    "map.qq.com", "lbs.qq.com", "mapapi.qq.com", "gtimg.com", "qq.com",
    "webapi.amap.com", "restapi.amap.com", "amap.com", "autonavi.com",
    "api.map.baidu.com", "map.baidu.com", "baidu.com",
    "api.tianditu.gov.cn", "tianditu.gov.cn", "tianditu.com",
)

# 明确违规的地图来源关键词：命中即拒绝保存，并给出合规替代建议。
BLOCKED_HINTS = (
    "google", "gstatic", "googleapis", "apple", "maps.apple", "bing.com",
    "virtualearth", "openstreetmap", "osm.org", "tile.osm", "mapbox",
    "maptiler", "carto", "leaflet", "arcgisonline", "esri", "here.com",
    "tomtom", "yandex", "wikimedia",
)

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}$")


def builtin_by_id(pid):
    for p in MAP_PROVIDERS:
        if p["id"] == pid:
            return p
    return None


def provider_by_id(pid, custom=None):
    """预设优先，其次自定义列表；找不到返回 None。"""
    p = builtin_by_id(pid)
    if p:
        return p
    for c in (custom or []):
        if isinstance(c, dict) and c.get("id") == pid:
            return c
    return None


def public_providers():
    """下发给前端的预设表：剔除任何可能被误当成内置 key 的字段。"""
    out = []
    for p in MAP_PROVIDERS:
        q = dict(p)
        q.pop("key_placeholder", None)  # 占位符仍由 cfg.map_key_placeholder / 前端常量提供
        out.append(q)
    return out


def host_of(url):
    m = re.match(r"^https?://([^/:?#]+)", (url or "").strip(), re.I)
    return (m.group(1) or "").lower() if m else ""


def compliance_of(url):
    """返回 (是否放行, 合规标记, 说明)。明确违规来源直接拒。"""
    u = (url or "").strip()
    low = u.lower()
    for bad in BLOCKED_HINTS:
        if bad in low:
            return False, "blocked", (
                "检测到未获资质的地图来源（%s）。按合规要求只能使用腾讯地图 / "
                "高德地图 / 百度地图 / 天地图，或其官方自建代理。" % bad)
    h = host_of(u)
    if not h:
        return True, "custom", "未识别域名，请自行确认底图数据源合规。"
    for suf in ALLOWED_HOSTS:
        if h == suf or h.endswith("." + suf):
            return True, "allowed", "官方合规域名。"
    if (h in ("localhost", "127.0.0.1", "::1") or h.startswith("192.168.")
            or h.startswith("10.") or h.startswith("172.")):
        return True, "custom", "本机 / 内网自建服务，请自行确保底图数据源合规。"
    return True, "custom", "自定义域名，请自行确保底图数据源合规。"


def validate_custom(items):
    """清洗并返回自定义服务商列表；不合规项抛 ValueError 说明原因。

    限制：最多 8 项；id 不与预设冲突且全局唯一；engine 必须在白名单；
    SDK 地址必须是 http(s)、含 {key} 占位、且不含明确违规地图来源。
    """
    if not isinstance(items, list):
        raise ValueError("自定义接口必须是列表")
    if len(items) > 8:
        raise ValueError("自定义接口最多 8 个")
    out, seen = [], set()
    for raw in items:
        if not isinstance(raw, dict):
            continue
        pid = str(raw.get("id", "")).strip().lower()
        name = str(raw.get("name", "")).strip()[:32]
        engine = str(raw.get("engine", "")).strip()
        sdk = str(raw.get("sdk", "")).strip()[:400]
        key = str(raw.get("key", ""))[:400]
        apply_url = str(raw.get("apply_url", ""))[:400]
        note = str(raw.get("note", ""))[:200]
        coord = str(raw.get("coord", ""))[:40]
        if not pid or not name or not sdk:
            raise ValueError("自定义接口缺少名称 / id / SDK 地址")
        if not _ID_RE.match(pid) or pid in PROVIDER_IDS or pid in seen:
            raise ValueError("自定义接口 id 非法或与已有项重复：" + pid)
        if engine not in ENGINES:
            raise ValueError("自定义接口引擎类型不在支持范围内：" + engine)
        if not re.match(r"^https?://", sdk, re.I):
            raise ValueError("SDK 地址必须以 http(s):// 开头")
        if "{key}" not in sdk:
            raise ValueError("SDK 地址必须包含 {key} 占位符，运行时替换为你的密钥")
        okc, flag, why = compliance_of(sdk)
        if not okc:
            raise ValueError(why)
        seen.add(pid)
        out.append({
            "id": pid, "name": name, "engine": engine, "sdk": sdk, "key": key,
            "apply_url": apply_url, "note": note or why, "coord": coord,
            "compliance": flag, "builtin": False,
            "key_label": "key", "key_placeholder": "请填写你自己申请的 API 密钥",
            "apply_text": "自定义接口",
        })
    return out


def sdk_url(provider, key, callback=""):
    """把模板里的 {key} / {callback} 换成实际值；不回显任何内置密钥。"""
    if not provider:
        return ""
    u = str(provider.get("sdk", ""))
    u = u.replace("{key}", key or "")
    u = u.replace("{callback}", callback or "")
    # 百度无 callback 时移除空参数，避免 URL 里留 &callback=
    u = re.sub(r"([?&])callback=&", r"\1", u)
    u = re.sub(r"[?&]callback=$", "", u)
    return u


def key_configured(key):
    """判断用户填的 key 是否为真实密钥（排除占位符 / 明显提示语）。"""
    if not key or not isinstance(key, str):
        return False
    k = key.strip()
    if len(k) < 8 or "请" in k or "替换此占位符" in k or k.startswith("填写"):
        return False
    return True
