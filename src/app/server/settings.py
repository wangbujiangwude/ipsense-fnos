# -*- coding: utf-8 -*-
"""应用配置（JSON，落在 TRIM_PKGVAR 数据目录，升级/重装不丢）。"""
import os
import json
import threading

from map_providers import (                                   # noqa: E402
    MAP_KEY_PLACEHOLDER, MAP_PROVIDERS, PROVIDER_IDS,
    provider_by_id, public_providers, validate_custom,
    sdk_url, key_configured,
)
from summary import path_allowed                              # noqa: E402

DEFAULTS = {
    # 数据源
    "source_local_auth": True,
    "source_local_web": True,
    "source_router_syslog": True,
    "source_knock": False,
    # 1.1.14：fn-knock-lite 网关请求日志（只观测，不改对方配置 / 防火墙）
    "source_knock_app": False,
    "knock_app_dir": "/vol1/@appdata/fn-knock-lite/gateway/logs",
    "knock_app_port": 8999,
    "source_fnos_audit": True,      # fnOS TRIMEVENT 结构化登录审计
    "source_auth_rotated": True,    # 回填 auth.log.1 / .gz 轮转日志
    "auth_rotated_max": 2,
    "lan_separate": True,           # 内网地址单独归类，不污染公网排名
    "syslog_port": 5514,
    "inbox_dir": "/vol1/@appdata/ipsense/inbox",
    "auth_log": "/var/log/auth.log",
    "web_log": "/usr/trim/nginx/logs/access.log",
    "kern_log": "/var/log/kern.log",
    "knock_marker": "/etc/ipsense/knock.enabled",
    "web_port": 5666,
    "ssh_port": 22,
    # Web 协议推断：combined 日志不含 scheme，留空时只信同站来路，不硬猜。
    # 可手动填 https / http 覆盖全部 Web 事件，置信度标 manual。
    "web_scheme_override": "",
    "ignore_ips": ["127.0.0.1", "::1"],
    "keep_days": 30,
    # 地图（1.1.8：四家合规预设 + 自定义接口，KEY 按服务商分别保存）
    # 合规：这里只有占位符，绝不内置任何有效 KEY；用户自申请后写入本机配置。
    "map_key": MAP_KEY_PLACEHOLDER,      # 兼容旧版：仍作为 tencent 的默认 key
    "map_provider": "tencent",          # 当前选中的服务商 id
    "map_keys": {},                     # {provider_id: key}，切换服务商不丢各自 KEY
    "map_custom": [],                   # 用户自定义接口列表
    # 本机位置：不再写死城市，未定位时用中国中心，由设置页「自动定位本机」写入
    "home_lat": 35.86,
    "home_lng": 104.20,
    "home_label": "本机 · 未定位",
    "home_ip": "",
    "home_geo": "",
    "home_proxy_ip": "",
    "home_source": "default",
    "home_locate_at": 0.0,
    "map_refresh": 3,
    "map_heavy_refresh": 12,
    "map_arc_limit": 16,
    "map_arc_bend": 0.12,
    "map_arc_animate": True,
    "chart_range": "24h",
    # 归属信息源：多源交叉校验（1.0.8）
    "geo_verify_enabled": True,
    "geo_verify_days": 30,
    "geo_verify_batch": 60,
    # 1.1.9：软件汇总日志（交给 AI 做设备防护分析）
    # 保存目录由设置界面的 fnOS 原生文件夹选择器选定；这里只存路径，
    # 不内置任何默认目录，也不预设用户数据位置。
    "summary_dir": "",
    "summary_enabled": True,         # 后台按间隔自动生成
    "summary_interval": 5,           # 分钟
    "summary_range": "24h",          # 汇总统计窗口
}

BOOL_KEYS = ("source_local_auth", "source_local_web", "source_router_syslog",
             "source_knock", "source_knock_app", "source_fnos_audit",
             "source_auth_rotated",
             "lan_separate", "geo_verify_enabled", "map_arc_animate",
             "summary_enabled")
INT_KEYS = ("syslog_port", "web_port", "ssh_port", "keep_days", "map_refresh",
            "map_heavy_refresh", "map_arc_limit", "auth_rotated_max",
            "geo_verify_days", "geo_verify_batch", "summary_interval",
            "knock_app_port")
FLOAT_KEYS = ("home_lat", "home_lng", "home_locate_at", "map_arc_bend")
STR_KEYS = ("inbox_dir", "auth_log", "web_log", "kern_log", "knock_marker",
            "knock_app_dir",
            "map_key", "map_provider", "home_label", "chart_range",
            "web_scheme_override", "home_ip", "home_geo", "home_proxy_ip",
            "home_source", "summary_dir", "summary_range")
DICT_KEYS = ("map_keys",)
LIST_KEYS = ("map_custom",)


class Settings(object):
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.data = dict(DEFAULTS)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                if isinstance(saved, dict):
                    self.data.update({k: v for k, v in saved.items() if k in DEFAULTS})
        except Exception:
            pass
        self._save_locked()

    def _save_locked(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def all(self):
        with self.lock:
            return dict(self.data)

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def update(self, patch):
        changed = []
        patch = patch or {}
        with self.lock:
            # 1.1.8：自定义列表与「当前服务商」可能在同一 patch 里，
            # 先算出最终自定义列表，才能一致地校验 provider id 与 map_keys 的键。
            final_custom = patch.get("map_custom", self.data.get("map_custom", []))
            if "map_custom" in patch:
                final_custom = validate_custom(final_custom)
            valid_ids = set(PROVIDER_IDS) | set(
                c["id"] for c in final_custom if isinstance(c, dict))
            for k, v in patch.items():
                if k not in DEFAULTS:
                    continue
                if k in BOOL_KEYS:
                    v = bool(v) if not isinstance(v, str) else v.lower() in ("1", "true", "yes", "on")
                elif k in INT_KEYS:
                    try:
                        v = int(v)
                    except (TypeError, ValueError):
                        continue
                elif k in FLOAT_KEYS:
                    try:
                        v = float(v)
                    except (TypeError, ValueError):
                        continue
                elif k in DICT_KEYS:
                    if not isinstance(v, dict):
                        continue
                    v = {str(kk)[:32]: str(vv)[:400]
                         for kk, vv in v.items() if str(kk) in valid_ids}
                elif k in LIST_KEYS:
                    v = final_custom
                elif k == "map_provider":
                    v = str(v)[:32]
                    if v not in valid_ids:
                        continue
                elif k == "summary_dir":
                    # 1.1.9：只接受合规的 NAS 数据目录；越权路径静默忽略，
                    # 前端另有 /api/summary/validate 给出可读原因。
                    v = str(v).strip()[:400]
                    if v and not path_allowed(v):
                        continue
                elif k == "summary_range":
                    v = str(v)[:16]
                    if v not in ("1h", "24h", "7d", "30d", "all"):
                        continue
                elif k == "ignore_ips":
                    v = [str(x)[:64] for x in (v if isinstance(v, list) else [])][:50]
                if self.data.get(k) != v:
                    self.data[k] = v
                    changed.append(k)
            self._save_locked()
        return changed

    # ---- 1.1.8 地图服务 ----
    def provider_list(self):
        """预设（合规白名单四家）+ 用户自定义接口。"""
        return public_providers() + list(self.get("map_custom", []) or [])

    def current_provider(self):
        pid = self.get("map_provider", "tencent") or "tencent"
        p = provider_by_id(pid, self.get("map_custom", []))
        return p or MAP_PROVIDERS[0]

    def provider_key(self, pid=None):
        """取某服务商的 KEY；兼容 1.1.7 及更早版本只有单个 map_key 的配置。"""
        pid = pid or self.get("map_provider", "tencent") or "tencent"
        keys = self.get("map_keys", {}) or {}
        k = keys.get(pid, "")
        if not k and pid == "tencent":
            k = self.get("map_key", "")
        return k or ""

    def current_sdk_url(self, callback=""):
        p = self.current_provider()
        return sdk_url(p, self.provider_key(p.get("id")), callback)

    def map_configured(self, pid=None):
        """按当前（或指定）服务商判断 KEY 是否已配置，切换服务商不误判。"""
        return key_configured(self.provider_key(pid))
