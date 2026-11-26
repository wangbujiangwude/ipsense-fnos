# -*- coding: utf-8 -*-
"""多路数据采集：本机日志 / 路由器 syslog / 端口敲门 / 敲门网关请求日志（1.1.14）。

- 本机日志：auth.log（SSH 认证）、nginx access.log（Web 访问）、kern.log（内核敲门日志）
- 路由器日志：UDP syslog 接收 + 指定目录的日志文件导入
- 端口敲门：kern.log 中带 IPSENSE-KNOCK 前缀的记录，默认未安装/未启用
- 敲门网关：fn-knock-lite 按天分片的 JSON 请求日志，只读增量扫描，默认关闭

所有解析结果进入统一队列，由写线程批量落 SQLite，避免高频日志拖垮数据库。
"""
import os
import re
import time
import glob
import json
import gzip
import queue
import socket
import hashlib
import threading
import datetime
import collections

from store import Store
from geoip import is_private


# ---------- 1.1.18 · 目标端口 / 协议推断 ----------
# 已知端口 → scheme 映射只用于「有显式目标端口」时补协议，标注 conf=port，
# 不把无法确认的请求硬猜成 http/https。
TLS_PORTS = frozenset((443, 8443, 9443, 10443, 5667, 8448))
PLAIN_PORTS = frozenset((80, 8080, 8000, 8888, 5666, 5000, 3000))
PORT_TAIL = re.compile(r'"\s+(\d{2,5})\s*$')
PORT_FIELD = re.compile(
    r'(?i)["\']?(?:server_port|dst_port|target_port|serverPort)["\']?\s*[:=]\s*"?(\d{2,5})"?'
    r'|["\']port["\']\s*:\s*"?(\d{2,5})"?')
ABS_URL_PORT = re.compile(
    r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+https?://[^/\s"\']+:(\d{2,5})(?:[/\s"])',
    re.I)
SAME_SITE_PORT = re.compile(r"^(https?)://([^/:]+):(\d{2,5})(?:/|$)", re.I)


def _valid_port(v):
    try:
        p = int(str(v).strip())
        return p if 0 < p < 65536 else 0
    except (TypeError, ValueError):
        return 0


def _port_map(cfg):
    """解析设置页「Web 日志端口映射」：每行『日志路径=端口』，也支持分号分隔。"""
    out = {}
    for item in re.split(r"[;\n]+", str((cfg or {}).get("web_port_map", "") or "")):
        item = item.strip()
        if "=" not in item:
            continue
        path, _, val = item.rpartition("=")
        p = _valid_port(val)
        if path.strip() and p:
            out[path.strip()] = p
    return out


def web_log_port(line, referer="", cfg=None, log_path=""):
    """1.1.18：多级读取「目标端口」，返回 (port, source)。

    Nginx combined 标准格式根本不含目标端口，这是「端口未记录」的根本原因；
    Docker 容器 / fnOS 反代的访问日志同样是 combined，所以也不会有端口。

    1.1.16 曾把应用自身 web_port 直接填进 port（每条都是 5666），又无条件
    从 Referer 取端口且不标来源，两次都被真机回归否定。1.1.18 改为
    「有证据才填、并明确标注来源」，优先级从高到低：

      1. log_tail    日志行尾自定义 log_format 追加的 $server_port（最可信）
      2. log_field   行内结构化端口字段 server_port= / "port": 等
      3. request_url $request 为绝对 URL 时自带的端口
      4. log_cfg     设置页「Web 日志端口映射」按日志文件指定的监听端口
      5. referer     同站来路里写明的端口（低置信度推断，可在设置里关闭）

    绝不把应用自身监听端口硬塞进去；读不到就 (0, "")，前端显示「未记录」。
    """
    cfg = cfg or {}
    s = (line or "").rstrip()
    m = PORT_TAIL.search(s)
    if m:
        p = _valid_port(m.group(1))
        if p:
            return p, "log_tail"
    m = PORT_FIELD.search(s)
    if m:
        p = _valid_port(m.group(1) or m.group(2))
        if p:
            return p, "log_field"
    m = ABS_URL_PORT.search(s)
    if m:
        p = _valid_port(m.group(1))
        if p:
            return p, "request_url"
    if log_path:
        base = os.path.basename(log_path)
        for k, v in _port_map(cfg).items():
            if k == log_path or os.path.basename(k) == base:
                return v, "log_cfg"
    if cfg.get("web_port_infer_referer", True):
        m = SAME_SITE_PORT.match((referer or "").strip())
        if m and LOCAL_HOST.match(m.group(2)):
            p = _valid_port(m.group(3))
            if p:
                return p, "referer"
    return 0, ""

ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))")
NGINX_TS = re.compile(r"\[([^\]]+)\]")
# 1.1.0：fnOS 的 nginx 本来就是 combined 格式，$request / $status / $http_referer /
# $http_user_agent 全在同一行里。这里把整行拆开，不需要改动系统 nginx 配置
# （改了也会被 fnOS 升级覆盖）。末两段可选，兼容自定义 log_format 缺字段的日志。
NGINX_COMBINED = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?')
NGINX_LINE = NGINX_COMBINED          # 保留旧名，兼容既有调用
PROTO_HINT = re.compile(r"\bPROTO=([A-Za-z0-9]+)")
# 同站来路才可用于推断当前请求的 scheme；外部站点 referer 不可用来猜协议
LOCAL_HOST = re.compile(r"^(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)", re.I)
AUTH_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")
AUTH_INVALID = re.compile(r"Invalid user (\S+) from (\S+) port (\d+)")
AUTH_ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)")
AUTH_CLOSED = re.compile(r"Connection (?:closed|reset) by (?:authenticating )?user (\S+) (\S+) port (\d+)")
TRIMEVENT = re.compile(r"TRIMEVENT:(\{.*\})")
SRC_DPT = re.compile(r"\bSRC=([0-9a-fA-F.:]+).*?\bDPT=(\d+)")
IP_ANY = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:.]*\b")

SCAN_PATH = re.compile(
    r"(?i)(\.env|\.git|wp-login|wp-admin|phpmyadmin|pma|/admin|\.php$|\.\./|"
    r"/shell|/cgi-bin|/actuator|boaform|/HNAP1|/setup\.cgi|/vendor/|/xmlrpc|"
    r"\.aws|\.ssh|/manager/html|/solr|/jenkins|\.sql$|\.bak$|/console|"
    r"echo\.php|/wls-wsat|/dubbo|/config\.json|/npm/|/owa/|/ecp/|/remote/|"
    r"/cgi/|\.asp$|\.jsp$|/login\.cgi|/sdk|/debug|/probe|/test\.php)", re.I)
STATIC_PATH = re.compile(r"(?i)\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map|webp)(\?|$)")

# ---------- 1.1.30 · 过滤软件自身访问 ----------
# fnOS 把 /app/ipsense/* 转发给本应用，这些页面与 API 轮询都会写进共享的
# /usr/trim/nginx/logs/access.log。它们是应用自己的心跳，不是外部来访，
# 却会挤进协议构成、来路 TOP、受访页、入口页与总量指标。
SELF_WEB_PREFIX = "/app/ipsense"
REF_PATH = re.compile(r"^[a-z]+://[^/]+(/[^?#\s]*)", re.I)


def is_self_web(path, referer, prefix=SELF_WEB_PREFIX):
    """path 或来路的路径命中应用自身前缀即为自身访问。

    与 src/app/ui/config 的 gatewayPrefix 保持一致；只比路径部分，
    不把域名里恰好带这些字样的外部来路误判为自身请求。
    """
    def hit(p):
        p = (p or "").split("?", 1)[0].split("#", 1)[0]
        return p == prefix or p.startswith(prefix + "/")

    if hit(path):
        return True
    r = (referer or "").strip()
    if not r:
        return False
    m = REF_PATH.match(r)
    return hit(m.group(1)) if m else (r.startswith("/") and hit(r))
SENSITIVE_PORTS = {21, 22, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 3389,
                   5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017}



# ---------- 1.1.14 · 敲门网关（fn-knock-lite）请求日志 ----------
# 字段白名单来自真机取证：Go 网关二进制的 json tag + 官方「请求分析」文档。
# 网关按天把结构化 JSON 写到运行目录 logs/，逐笔含客户端 IP / 认证状态 /
# WAF 动作 / 状态码 / 耗时。这里只做只读提取，字段缺失一律留空，绝不猜值。
KNOCK_IP_KEYS = ("client_ip", "real_client_ip", "remote_ip", "ip",
                 "src_ip", "host_ip")
KNOCK_TS_KEYS = ("logged_time", "accessed_time", "processed_time", "original_time",
                 "time", "timestamp", "ts", "start_time", "date")
KNOCK_TEXT_KEYS = ("auth_decision", "waf_action", "action", "decision", "event",
                   "reason_code", "status_detail", "level")
KNOCK_HOST_KEYS = ("host", "authority", "forwarded_host")
KNOCK_PATH_KEYS = ("path", "request_uri", "normalized_path", "uri", "current_path")
KNOCK_UA_KEYS = ("user_agent", "ua", "http_user_agent")
KNOCK_REF_KEYS = ("referer", "referrer")
KNOCK_METHOD_KEYS = ("method", "http_method")
KNOCK_STATUS_KEYS = ("status_code", "status", "http_status")
KNOCK_PORT_KEYS = ("host_port", "server_port", "port")
KNOCK_SCHEME_KEYS = ("scheme", "forwarded_proto", "protocol")

# ---------- 2.0.0 B5 · lucky 日志解析器框架（D 路径：占位骨架） ----------
# 真机只读取证（docs/lucky_probe_result.md）：lucky 3.8.2 为 fnOS 原生应用，
# /var/log/apps/Lucky.log 为 0 字节、反代 Web 访问日志不落盘、*.lkcf 为二进制配置。
# 因此本批次不接 LogTailer、不接后台 API、不把任何臆测行格式写死进产品。
# 这里只提供「宽松键值提取 + 严格 IP 校验 + 保守字段映射」的解析器框架，
# 并配基于占位样例的单测；拿到后台「日志中心」原始文本后，再按
# docs/lucky_log_research.md 5.6 清单校准 LUCKY_LEVEL / LUCKY_MODULE 白名单。
LUCKY_SOURCES = ("lucky_web", "lucky_sys")
# 占位：时间戳文本宽松识别（统一交给 knock_to_ts() 转换，不另写一套时间解析）
LUCKY_TS = re.compile(
    r"(?<!\d)(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[+-]\d{2}:?\d{2}|Z)?)")
# 占位：仅 MAIN 有用户截图证据，其余模块名待真实样例补全
LUCKY_LEVEL = re.compile(r"(?i)\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b")
LUCKY_MODULE = re.compile(r"(?i)\b(MAIN)\b")
# 占位：文本里的 键=值 / 键:值；字段缺失一律留空，绝不猜值
LUCKY_KV = re.compile(r"([a-z_][a-z0-9_]*)\s*[:=]\s*([^\s,;{}\[\]]+)", re.I)
LUCKY_IP_KEYS = ("client_ip", "clientip", "real_client_ip", "remote_ip",
                 "remoteip", "src_ip", "ip", "x_forwarded_for", "x_real_ip")
LUCKY_TS_KEYS = ("time", "timestamp", "ts", "logged_time", "date", "datetime")
LUCKY_HOST_KEYS = ("host", "authority", "forwarded_host", "server_name")
LUCKY_PATH_KEYS = ("path", "request_uri", "uri", "request_path", "url")
LUCKY_STATUS_KEYS = ("status_code", "status", "http_status", "code")
LUCKY_METHOD_KEYS = ("method", "http_method", "request_method")
LUCKY_UA_KEYS = ("user_agent", "useragent", "ua", "http_user_agent")
LUCKY_REF_KEYS = ("referer", "referrer")
LUCKY_PORT_KEYS = ("host_port", "server_port", "port")
LUCKY_TEXT_KEYS = ("action", "decision", "event", "reason", "message", "msg")


def lucky_pick(d, keys):
    """按字段白名单取值；缺失 / 脏值一律返回空串，不猜值。"""
    for k in keys:
        v = d.get(k)
        if v is None or isinstance(v, (dict, list, bool)):
            continue
        s = str(v).strip()
        if s and s.lower() not in ("-", "null", "none"):
            return s
    return ""


def lucky_fields(line):
    """宽松提取行内键值：JSON 对象优先，再叠加文本键值。字段缺失一律留空。

    这里只做「通用键值框架」，不代表 lucky 真实日志格式；没有样例前
    不写死任何分隔符 / 级别 / 模块名。
    """
    d = {}
    raw = (line or "").strip()
    if "{" in raw:
        try:
            obj = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
            if isinstance(obj, dict):
                d.update({str(k).lower(): v for k, v in obj.items()})
        except Exception:
            pass
    norm = raw.replace('"', " ").replace("'", " ")
    for m in LUCKY_KV.finditer(norm):
        k = m.group(1).lower()
        v = (m.group(2) or "").strip()
        if k not in d and v:
            d[k] = v
    return d



def knock_pick(d, keys):
    for k in keys:
        v = d.get(k)
        if v is None or isinstance(v, (dict, list, bool)):
            continue
        s = str(v).strip()
        if s and s.lower() not in ("-", "null", "none", "0", "false"):
            return s
    return ""


def knock_ip(v):
    # 严格校验：IP_ANY 的 IPv6 分支会把 "11:20:31" 这类时间戳误判成地址，
    # 所以字段值与文本兜底都必须过 inet_pton，IPv4 / IPv6 各自单独判。
    s = str(v or "").strip()
    if not s or len(s) > 64:
        return ""
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, s)
            return s
        except (OSError, ValueError):
            pass
    return ""


def knock_to_ts(v):
    """ISO8601 / epoch 秒 / epoch 毫秒 / 常见文本时间；无法确认返回 0。"""
    if v in (None, "", 0, "0"):
        return 0
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.match(r"^\d{10,16}$", v)):
        try:
            x = float(v)
            if x > 1e12:
                x /= 1000.0
            if 946684800 < x < 4102444800:
                return x
        except Exception:
            pass
    s = str(v).strip().replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt).timestamp()
        except Exception:
            pass
    return 0

def to_ts(iso_text):
    try:
        s = iso_text.replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:
        return time.time()


def to_ts_nginx(text):
    try:
        return datetime.datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except Exception:
        return time.time()


def session_id(ip, ua, ts):
    """入口页会话：ip + UA + 30 分钟时间桶，纯本地计算不落任何隐私标识。"""
    raw = "%s|%s|%d" % (ip, (ua or "")[:120], int(ts) // 1800)
    return hashlib.md5(raw.encode("utf-8", "replace")).hexdigest()[:16]


def infer_scheme(referer, cfg, port=0):
    """推断 Web 请求的 scheme，返回 (scheme, confidence)。

    combined 日志的 $request 只含 HTTP/1.1，不含 scheme，也拿不到 X-Forwarded-Proto。
    这就是「Web 未识别」的成因：没有可信信号就不硬猜。1.1.18 增加一条证据来源，
    延续「标置信度、不伪造」原则，优先级从高到低：
      - 设置页手动覆盖 → manual；
      - 同站来路（内网 / localhost）带 scheme → medium；
      - 1.1.18：已读到目标端口且命中已知 TLS / 明文端口 → port（低置信度）；
      - 外部站点 referer / 无 referer / 无端口 → 不猜，返回空 + none。
    """
    override = str(cfg.get("web_scheme_override", "") or "").strip().lower()
    if override in ("https", "http"):
        return override, "manual"
    r = (referer or "").strip()
    if r and r != "-":
        m = re.match(r"^(https?)://([^/:]+)", r, re.I)
        if m and LOCAL_HOST.match(m.group(2)):
            return m.group(1).lower(), "medium"
    if cfg.get("web_scheme_by_port", True) and port:
        if port in TLS_PORTS:
            return "https", "port"
        if port in PLAIN_PORTS:
            return "http", "port"
    return "", "none"


def tail_lines(path, max_lines=6000, max_bytes=6 * 1024 * 1024):
    """只读地取文件尾部若干行，用于首次安装的历史回填。"""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - max_bytes))
            data = f.read()
        lines = data.decode("utf-8", "replace").splitlines()
        if size > max_bytes and lines:
            lines = lines[1:]
        return lines[-max_lines:]
    except Exception:
        return []


class LogTailer(object):
    """按 inode + offset 增量跟踪文件，自动处理日志轮转。"""

    def __init__(self, name, path, parser, emit):
        self.name = name
        self.path = path
        self.parser = parser
        self.emit = emit
        self.pos = 0
        self.inode = None
        self.initialized = False
        self.last_read = 0
        self.count = 0
        self.error = ""

    def _read_new(self, from_start=False):
        try:
            st = os.stat(self.path)
        except OSError as e:
            self.error = str(e)
            return
        rotated = (self.inode is not None and st.st_ino != self.inode)
        if not self.initialized or rotated or st.st_size < self.pos:
            self.pos = 0 if (not self.initialized or rotated) else self.pos
            self.inode = st.st_ino
            self.initialized = True
            # 首次跟踪只从尾部 64KB 开始，避免把全部历史灌进实时队列
            if not rotated:
                self.pos = max(0, st.st_size - 64 * 1024)
        if st.st_size <= self.pos:
            return
        try:
            with open(self.path, "rb") as f:
                f.seek(self.pos)
                data = f.read(min(st.st_size - self.pos, 2 * 1024 * 1024))
            self.pos += len(data)
        except Exception as e:
            self.error = str(e)
            return
        self.error = ""
        self.last_read = time.time()
        for line in data.decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            ev = self.parser(line)
            if ev:
                self.count += 1
                self.emit(ev)

    def info(self):
        return {"name": self.name, "path": self.path,
                "exists": os.path.isfile(self.path), "count": self.count,
                "last_read": self.last_read, "error": self.error}



class KnockDirTailer(object):
    # 1.1.14：只读增量扫描按天分片的网关请求日志目录。
    # 与 LogTailer 的区别：目标可以是目录，文件按天新增 / 滚动删除；
    # 用 inode + offset 记住读取位置，首次只从尾部 64KB 开始，
    # 不把保留期内的全部历史灌进实时队列。
    EXTS = (".json", ".jsonl", ".log", ".txt")

    def __init__(self, name, path, parser, emit, max_files=12):
        self.name = name
        self.path = path
        self.parser = parser
        self.emit = emit
        self.max_files = max_files
        self.state = {}
        self.count = 0
        self.error = ""
        self.last_read = 0

    def targets(self):
        try:
            if os.path.isfile(self.path):
                return [self.path]
            if not os.path.isdir(self.path):
                self.error = "日志目录不存在或不可读"
                return []
            out = []
            for pat in ("*", "*/*"):
                for f in glob.glob(os.path.join(self.path, pat)):
                    if os.path.isfile(f) and f.lower().endswith(self.EXTS):
                        out.append(f)
            out = sorted(set(out), key=lambda x: os.path.getmtime(x), reverse=True)
            self.error = ""
            return out[:self.max_files]
        except Exception as e:
            self.error = str(e)
            return []

    def _read(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return []
        prev = self.state.get(path)
        if prev is None:
            pos = max(0, st.st_size - 64 * 1024)
        elif prev[0] != st.st_ino or st.st_size < prev[1]:
            pos = 0
        else:
            pos = prev[1]
        if st.st_size <= pos:
            self.state[path] = (st.st_ino, pos)
            return []
        try:
            with open(path, "rb") as f:
                f.seek(pos)
                data = f.read(min(st.st_size - pos, 2 * 1024 * 1024))
        except Exception as e:
            self.error = str(e)
            return []
        self.state[path] = (st.st_ino, pos + len(data))
        self.last_read = time.time()
        return data.decode("utf-8", "replace").splitlines()

    def poll(self):
        for p in self.targets():
            for line in self._read(p):
                if not line.strip():
                    continue
                ev = self.parser(line)
                if ev:
                    self.count += 1
                    self.emit(ev)

    def backfill(self, flush, max_lines=1500):
        lines = []
        for p in self.targets():
            lines.extend(tail_lines(p, max_lines, 512 * 1024))
            if len(lines) >= max_lines:
                break
        batch = []
        for line in lines[:max_lines]:
            ev = self.parser(line)
            if ev:
                batch.append(ev)
        for i in range(0, len(batch), 200):
            flush(batch[i:i + 200])
        return len(batch)

    def info(self):
        return {"name": self.name, "path": self.path,
                "exists": os.path.exists(self.path),
                "files": len(self.state), "count": self.count,
                "last_read": self.last_read, "error": self.error}

class Collector(object):
    def __init__(self, store, geo, cfg, log=None):
        self.store = store
        self.geo = geo
        self.cfg = cfg
        self.log = log or (lambda m: None)
        self.verifier = None          # 1.1.15：由 App 在启动采集器时注入
        self.queue = queue.Queue(maxsize=20000)
        self.recent = collections.deque(maxlen=600)
        self.lock = threading.Lock()
        self.stop_evt = threading.Event()
        self.threads = []
        self.source_hits = collections.Counter()
        self.syslog_ok = False
        self.syslog_error = ""
        self.started = time.time()
        self.tailers = []
        self.knock_dir_tailer = None
        self._build_tailers()

    # ---------- 解析 ----------
    @staticmethod
    def _base(ts, source, ip, port, service, action, verdict, path, raw):
        # 1.1.0 新增的协议 / 来路 / 会话字段统一给默认值，历史解析器无需逐个改
        return {"ts": ts, "source": source, "ip": ip, "port": port,
                "service": service, "action": action, "verdict": verdict,
                "path": path, "raw": raw[:600],
                "layer": "", "proto": "", "scheme_conf": "",
                "method": "", "status": 0, "referer": "", "ua": "", "sess_id": "",
                "port_src": ""}

    @staticmethod
    def _tag(ev, layer, proto, scheme_conf=""):
        """给非 Web 事件补协议维度：SSH 认证 / 网络层 / 端口敲门。"""
        if ev:
            ev["layer"] = layer
            ev["proto"] = proto
            ev["scheme_conf"] = scheme_conf
        return ev

    def parse_auth(self, line):
        m = ISO_TS.match(line)
        ts = to_ts(m.group(1)) if m else time.time()
        low = line.lower()
        if "pam_unix(sudo" in low or "pam_env" in low or "systemd-logind" in low:
            return None   # 过滤本地 sudo / 会话噪声
        m = AUTH_FAILED.search(line)
        if m:
            return self._tag(self._base(ts, "local_auth", m.group(2), int(m.group(3)),
                                        "SSH", "密码认证失败 · 用户 %s" % m.group(1),
                                        "attack", "", line), "auth", "ssh")
        m = AUTH_INVALID.search(line)
        if m:
            return self._tag(self._base(ts, "local_auth", m.group(2), int(m.group(3)),
                                        "SSH", "不存在的用户 %s" % m.group(1),
                                        "attack", "", line), "auth", "ssh")
        m = AUTH_ACCEPT.search(line)
        if m:
            return self._tag(self._base(ts, "local_auth", m.group(3), int(m.group(4)),
                                        "SSH", "登录成功 · 用户 %s" % m.group(2),
                                        "normal", "", line), "auth", "ssh")
        m = AUTH_CLOSED.search(line)
        if m:
            return self._tag(self._base(ts, "local_auth", m.group(2), int(m.group(3)),
                                        "SSH", "认证前断开", "scan", "", line), "auth", "ssh")
        return None

    def parse_trimevent(self, line):
        """fnOS 自带的结构化登录审计事件（1.0.8 新增可靠来源）。

        形如：TRIMEVENT:{"from":"user","eventId":"SshdLoginSucc",
              "data":{"IP":"192.168.3.38","user":"..."},"datetime":1794275225}
        字段是 JSON，比正则匹配 sshd 文本可靠，且能明确区分成功 / 失败。
        """
        m = TRIMEVENT.search(line)
        if not m:
            return None
        try:
            d = json.loads(m.group(1))
        except (ValueError, TypeError):
            return None
        eid = str(d.get("eventId") or "")
        data = d.get("data") or {}
        ip = str(data.get("IP") or data.get("ip") or "")
        if not ip:
            return None
        if eid == "SshdLogonout":
            return None       # 登出不是访问来源
        user = str(data.get("user") or "")
        try:
            ts = float(d.get("datetime") or 0)
            if not ts:
                raise ValueError
        except (TypeError, ValueError):
            m2 = ISO_TS.match(line)
            ts = to_ts(m2.group(1)) if m2 else time.time()
        if eid == "SshdLoginAuthFail":
            verdict, action = "attack", "SSH 认证失败 · 用户 %s" % (user or "未知")
        elif eid == "SshdLoginSucc":
            verdict, action = "normal", "SSH 登录成功 · 用户 %s" % (user or "未知")
        else:
            verdict, action = "normal", "fnOS 审计事件 · %s" % eid
        return self._tag(self._base(ts, "fnos_audit", ip, int(self.cfg.get("ssh_port", 22) or 22),
                                   "fnOS 审计", action, verdict, "", line), "auth", "ssh")

    def parse_auth_any(self, line):
        """TRIMEVENT 优先，非结构化行仍走 sshd 文本解析（含轮转日志里的历史失败登录）。"""
        if self.cfg.get("source_fnos_audit", True):
            ev = self.parse_trimevent(line)
            if ev:
                return ev
        return self.parse_auth(line)

    def parse_web(self, line, log_path=""):
        """解析 Nginx combined 行，一次取回协议 / 来路 / 受访页 / 会话所需字段。

        $request 形如 "GET /app/xxx?a=1 HTTP/1.1"，用 split 拆比正则更耐受畸形行；
        末两段 referer / UA 是可选组，缺字段的自定义日志也不会整行丢弃。
        静态资源仍照常入库（保证访问总量口径不变），只在「受访页 / 入口页」聚合时剔除；
        1.1.30 起应用自身 /app/ipsense/ 路径与来路在采集侧直接丢弃，不入库。
        """
        m = NGINX_COMBINED.match(line)
        if not m:
            return None
        ip, tstext, request, status = m.group(1), m.group(2), m.group(3), m.group(4)
        referer = (m.group(6) or "").strip()
        ua = (m.group(7) or "").strip()
        parts = request.split()
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else ""
        # 1.1.30：软件自身 /app/ipsense/ 的页面与 API 轮询也落在共享
        # access.log 里，量级远超真实外部访问（实测单日数万条），会把
        # 协议构成 / 来路 TOP / 受访页 / 入口页全部带偏。采集侧直接丢弃，
        # 不入库、不进任何统计；历史存量由 store.purge_self_web() 清理。
        if self.cfg.get("filter_self_web", True) and is_self_web(path, referer):
            return None
        ts = to_ts_nginx(tstext)
        st = int(status)
        # 1.1.18：目标端口按「日志显式字段 → 端口映射 → 同站来路」多级读取，
        # 并把来源写进 port_src，前端可如实标注置信度。
        port, port_src = web_log_port(line, referer, self.cfg, log_path)
        scheme, conf = infer_scheme(referer, self.cfg, port)
        proto = scheme or "web"          # 无证据时标 web，不硬猜 http/https
        is_scan = bool(SCAN_PATH.search(path))
        if not is_scan and st >= 400 and not STATIC_PATH.search(path):
            is_scan = True
        action = ("扫描探测 · %s %s → %s" % (method, status, path)) if is_scan \
                 else ("正常访问 · %s %s" % (method, status))
        ev = self._base(ts, "local_web", ip, port,
                        "fnOS Web", action, "scan" if is_scan else "normal",
                        path, line)
        ev.update({
            "layer": "web", "proto": proto, "scheme_conf": conf,
            "method": method[:16], "status": st,
            "referer": referer[:300], "ua": ua[:300],
            "sess_id": session_id(ip, ua, ts), "port_src": port_src,
        })
        return ev

    def parse_kern(self, line):
        if "IPSENSE-KNOCK" not in line and "SRC=" not in line:
            return None
        m = SRC_DPT.search(line)
        if not m:
            return None
        ip, dpt = m.group(1), int(m.group(2))
        knock = "IPSENSE-KNOCK" in line
        m2 = ISO_TS.match(line)
        ts = to_ts(m2.group(1)) if m2 else time.time()
        pm = PROTO_HINT.search(line)
        proto = (pm.group(1).lower() if pm else "tcp")
        if proto not in ("tcp", "udp", "icmp"):
            proto = "tcp"
        return self._tag(self._base(ts, "knock" if knock else "local_kern", ip, dpt,
                                   "端口敲门" if knock else "内核转发",
                                   ("敲门序列命中 · 端口 %s" % dpt) if knock else "端口访问",
                                   "knock" if knock else ("scan" if dpt in SENSITIVE_PORTS else "normal"),
                                   "", line), "knock" if knock else "net", proto)

    def parse_router(self, line, source="router_syslog"):
        m = SRC_DPT.search(line)
        dpt = 0
        if m:
            ip, dpt = m.group(1), int(m.group(2))
        else:
            ips = IP_ANY.findall(line)
            cand = [x for x in ips if not x.startswith("127.") and not x.startswith("0.")]
            if not cand:
                return None
            ip = cand[0]
        m2 = ISO_TS.match(line)
        ts = to_ts(m2.group(1)) if m2 else time.time()
        scan = dpt in SENSITIVE_PORTS or bool(re.search(r"(?i)drop|reject|deny|block|attack|invalid", line))
        pm = PROTO_HINT.search(line)
        proto = (pm.group(1).lower() if pm else "tcp")
        if proto not in ("tcp", "udp", "icmp"):
            proto = "tcp"
        return self._tag(self._base(ts, source, ip, dpt, "路由器日志",
                                   ("拦截/转发 · 目标端口 %s" % dpt) if dpt else "路由器转发记录",
                                   "scan" if scan else "normal", "", line), "net", proto)


    def parse_knock_app(self, line):
        """1.1.14：解析敲门网关按天分片的 JSON 请求日志；非 JSON 行退回 IP 兜底。"""
        raw = line.strip()
        if not raw:
            return None
        d = {}
        if "{" in raw:
            try:
                obj = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
                if isinstance(obj, dict):
                    d = obj
            except Exception:
                d = {}
        ip = ""
        for k in KNOCK_IP_KEYS:
            ip = knock_ip(d.get(k))
            if ip:
                break
        if not ip:
            for cand in IP_ANY.findall(raw):
                if cand.startswith(("127.", "0.")):
                    continue
                ip = knock_ip(cand)
                if ip:
                    break
        if not ip:
            return None
        ts = 0
        for k in KNOCK_TS_KEYS:
            ts = knock_to_ts(d.get(k))
            if ts:
                break
        if not ts:
            m = ISO_TS.match(raw)
            ts = to_ts(m.group(1)) if m else time.time()
        txt = " ".join(str(d.get(k) or "") for k in KNOCK_TEXT_KEYS).lower()
        status = knock_pick(d, KNOCK_STATUS_KEYS)
        if re.search(r"waf|block|denied|deny|reject|forbidden", txt) or status == "403":
            kind = "WAF / 策略拦截"
        elif re.search(r"unauthor|unauthenticated|login_failure|failed|invalid|401|rejected", txt):
            kind = "认证被拒"
        elif re.search(r"allow|pass|granted|success|session|whitelist|authenticated|exempt|permit", txt):
            kind = "认证通过"
        else:
            kind = "网关请求"
        host = knock_pick(d, KNOCK_HOST_KEYS)
        path = knock_pick(d, KNOCK_PATH_KEYS)
        target = ((host + (path if path.startswith("/") else "/" + path)) if path
                  else host) if host else (path or "—")
        proto = knock_pick(d, KNOCK_SCHEME_KEYS).lower()
        if proto not in ("http", "https"):
            proto = "web"
        port = 0
        pv = knock_pick(d, KNOCK_PORT_KEYS)
        if pv.isdigit():
            port = int(pv)
        if not port:
            try:
                port = int(self.cfg.get("knock_app_port", 0) or 0)
            except Exception:
                port = 0
        ev = self._base(ts, "knock_app", ip, port, "敲门网关",
                        "敲门网关 · " + kind, "knock", target, raw)
        ev["method"] = knock_pick(d, KNOCK_METHOD_KEYS)[:16]
        try:
            ev["status"] = int(str(status)[:3]) if str(status).isdigit() else 0
        except Exception:
            ev["status"] = 0
        ev["ua"] = knock_pick(d, KNOCK_UA_KEYS)[:300]
        ev["referer"] = knock_pick(d, KNOCK_REF_KEYS)[:300]
        return self._tag(ev, "knock", proto)

    def parse_lucky_web(self, line, log_path=""):
        """2.0.0 B5：lucky 反代 Web 访问日志解析框架（D 路径占位骨架）。

        只依赖「行内键值 + 严格 IP 校验」，不写死任何臆测的 lucky 行格式；
        无合法 IP 一律丢弃，避免把时间戳 / 模块名误判成地址。
        字段缺失留空、无 scheme 证据标 web、自身访问不入库。
        """
        raw = (line or "").strip()
        if not raw:
            return None
        d = lucky_fields(raw)
        ip = ""
        for k in LUCKY_IP_KEYS:
            ip = knock_ip(d.get(k))
            if ip:
                break
        if not ip:
            for cand in IP_ANY.findall(raw):
                if cand.startswith(("127.", "0.")):
                    continue
                ip = knock_ip(cand)
                if ip:
                    break
        if not ip:
            return None
        ts = 0
        for k in LUCKY_TS_KEYS:
            ts = knock_to_ts(d.get(k))
            if ts:
                break
        if not ts:
            m = LUCKY_TS.search(raw)
            ts = knock_to_ts(m.group(1)) if m else time.time()
        host = lucky_pick(d, LUCKY_HOST_KEYS)
        path = lucky_pick(d, LUCKY_PATH_KEYS)
        referer = lucky_pick(d, LUCKY_REF_KEYS)
        target = ((host + (path if path.startswith("/") else "/" + path)) if path
                  else host) if host else (path or "—")
        # 与 parse_web 一致：软件自身 /app/ipsense 访问不进统计
        if self.cfg.get("filter_self_web", True) and is_self_web(target, referer):
            return None
        status = lucky_pick(d, LUCKY_STATUS_KEYS)
        try:
            st = int(status[:3]) if status.isdigit() else 0
        except Exception:
            st = 0
        txt = " ".join(lucky_pick(d, (k,)) for k in LUCKY_TEXT_KEYS).lower()
        verdict = "scan" if (SCAN_PATH.search(path) or st in (401, 403, 404) or
                             re.search(r"block|deny|denied|reject|forbidden|拦截", txt)) else "normal"
        port = 0
        pv = lucky_pick(d, LUCKY_PORT_KEYS)
        if pv.isdigit():
            port = int(pv)
        ua = lucky_pick(d, LUCKY_UA_KEYS)[:300]
        ev = self._base(ts, "lucky_web", ip, port, "Lucky 反代",
                        "Lucky 反代 · " + ("拦截 / 异常路径" if verdict == "scan" else "正常访问"),
                        verdict, target, raw)
        ev["method"] = lucky_pick(d, LUCKY_METHOD_KEYS)[:16]
        ev["status"] = st
        ev["ua"] = ua
        ev["referer"] = referer[:300]
        ev["sess_id"] = session_id(ip, ua, ts)
        # 键值 / combined 日志都没有 scheme 证据：proto=web、scheme_conf=none，绝不硬猜
        return self._tag(ev, "web", "web")

    def parse_lucky_sys(self, line, log_path=""):
        """2.0.0 B5：lucky 系统运行日志解析框架（D 路径占位骨架）。

        系统日志没有「扫描探测 / 端口敲门」语义，verdict 一律 normal；
        级别 / 模块只进 action 文本，未匹配到就留空，绝不猜值。
        """
        raw = (line or "").strip()
        if not raw:
            return None
        d = lucky_fields(raw)
        ip = ""
        for k in LUCKY_IP_KEYS:
            ip = knock_ip(d.get(k))
            if ip:
                break
        if not ip:
            for cand in IP_ANY.findall(raw):
                if cand.startswith(("127.", "0.")):
                    continue
                ip = knock_ip(cand)
                if ip:
                    break
        if not ip:
            return None
        ts = 0
        for k in LUCKY_TS_KEYS:
            ts = knock_to_ts(d.get(k))
            if ts:
                break
        if not ts:
            m = LUCKY_TS.search(raw)
            ts = knock_to_ts(m.group(1)) if m else time.time()
        lv = LUCKY_LEVEL.search(raw)
        mod = LUCKY_MODULE.search(raw)
        level = lv.group(1).upper() if lv else ""
        module = mod.group(1).upper() if mod else ""
        action = "Lucky 系统" + ((" · " + level) if level else "") + ((" " + module) if module else "")
        ev = self._base(ts, "lucky_sys", ip, 0, "Lucky 系统", action, "normal", "", raw)
        return self._tag(ev, "system", "")

    def set_verifier(self, verifier):
        """注入在线校验器，让新出现的公网 IP 首次入库即进入后台核验队列。"""
        self.verifier = verifier

    # ---------- 事件入口 ----------
    def emit(self, ev):
        ip = ev.get("ip", "")
        if not ip or ip in self.cfg.get("ignore_ips", []):
            return
        try:
            self.queue.put_nowait(ev)
        except queue.Full:
            pass

    def writer_loop(self):
        batch = []
        while True:
            try:
                batch.append(self.queue.get(timeout=0.35))
                if len(batch) >= 200:
                    self._flush(batch)
                    batch = []
            except queue.Empty:
                if batch:
                    self._flush(batch)
                    batch = []
                if self.stop_evt.is_set():
                    break
        if batch:
            self._flush(batch)

    def _flush(self, batch):
        full = []
        ignore = set(self.cfg.get("ignore_ips", []) or [])
        separate = bool(self.cfg.get("lan_separate", True))
        for ev in batch:
            ip = ev.get("ip", "")
            # 修复：backfill 此前直接调 _flush，绕过了 emit() 的 ignore_ips 过滤
            if ip in ignore:
                continue
            g = self.geo.lookup(ip)
            d = dict(ev)
            d.update({"ipver": g["ipver"], "country": g["country"],
                      "province": g["province"], "city": g["city"],
                      "district": g.get("district", ""), "isp": g["isp"],
                      "scope": g["scope"], "lat": g["lat"], "lng": g["lng"]})
            # 内网设备单独归类，不再以「无归属公网来源」污染地图 / 排名
            if separate and is_private(ip):
                d.update({"scope": "lan", "country": "", "province": "",
                          "city": "", "isp": "", "lat": None, "lng": None})
            full.append(d)
        try:
            n = self.store.insert_batch(full)
        except Exception as e:
            self.log("writer error: %s" % e)
            return
        # 1.1.15：入库成功后再入队，避免校验回写与插入抢顺序。
        # 去重 / 缓存命中 / 队列上限都由 verifier.enqueue() 负责；
        # 内网地址不查在线源，离线库判错的新 IP 会在数秒内自动订正。
        if self.verifier and self.cfg.get("geo_verify_auto", True):
            for d in full:
                if d.get("scope") in ("cn", "overseas"):
                    try:
                        self.verifier.enqueue(d.get("ip", ""))
                    except Exception:
                        pass
        with self.lock:
            for i, d in enumerate(full):
                self.source_hits[d["source"]] += 1
            self.recent.extend(full[-120:])

    # ---------- 数据源 ----------
    def _build_tailers(self):
        if self.cfg.get("source_local_auth", True):
            self.tailers.append(LogTailer("本机 · SSH 认证", self.cfg.get("auth_log", "/var/log/auth.log"),
                                          self.parse_auth_any, self.emit))
        if self.cfg.get("source_local_web", True):
            web_path = self.cfg.get("web_log", "/usr/trim/nginx/logs/access.log")
            self.tailers.append(LogTailer("本机 · Web 访问", web_path,
                lambda ln, p=web_path: self.parse_web(ln, p), self.emit))
        if self.cfg.get("source_knock", False):
            self.tailers.append(LogTailer("端口敲门 · 内核日志", self.cfg.get("kern_log", "/var/log/kern.log"),
                                          self.parse_kern, self.emit))
        if self.cfg.get("source_knock_app", False):
            self.knock_dir_tailer = KnockDirTailer(
                "敲门网关 · 请求日志",
                self.cfg.get("knock_app_dir",
                            "/vol1/@appdata/fn-knock-lite/gateway/logs"),
                self.parse_knock_app, self.emit)

    def tailer_loop(self):
        while not self.stop_evt.wait(1.0):
            for t in self.tailers:
                t._read_new()
            if self.knock_dir_tailer:
                self.knock_dir_tailer.poll()
            self.store.cleanup()

    def syslog_loop(self):
        if not self.cfg.get("source_router_syslog", True):
            return
        port = int(self.cfg.get("syslog_port", 5514) or 5514)
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.settimeout(1.0)
            self.syslog_ok = True
            self.syslog_error = ""
        except Exception as e:
            self.syslog_ok = False
            self.syslog_error = str(e)
            self.log("syslog bind failed: %s" % e)
            return
        while not self.stop_evt.is_set():
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode("utf-8", "replace")
            for line in text.splitlines():
                if not line.strip():
                    continue
                ev = self.parse_router(line)
                if ev:
                    ev["raw"] = "[%s] %s" % (addr[0], line[:500])
                    self.emit(ev)
        try:
            s.close()
        except Exception:
            pass
        self.syslog_ok = False

    def inbox_loop(self):
        d = self.cfg.get("inbox_dir", "")
        if not d:
            return
        seen = set()
        try:
            os.makedirs(d, exist_ok=True)
            for p in glob.glob(os.path.join(d, "*.log")) + glob.glob(os.path.join(d, "*.txt")):
                seen.add(p)
        except Exception:
            pass
        while not self.stop_evt.wait(5.0):
            try:
                files = glob.glob(os.path.join(d, "*.log")) + glob.glob(os.path.join(d, "*.txt"))
            except Exception:
                continue
            for p in files:
                if p in seen:
                    continue
                seen.add(p)
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        for i, line in enumerate(f):
                            if i > 20000:
                                break
                            ev = self.parse_router(line, "router_file")
                            if ev:
                                self.emit(ev)
                    self.log("inbox imported: %s" % p)
                except Exception as e:
                    self.log("inbox error %s: %s" % (p, e))

    def rotated_paths(self, base):
        """列出 auth.log.1 / .2.gz ... 轮转文件，按序号取最近 N 个。"""
        try:
            cand = [p for p in glob.glob(base + ".*") if os.path.isfile(p)]
        except Exception:
            return []
        def num(p):
            m = re.search(r"\.(\d+)(?:\.gz)?$", p)
            return int(m.group(1)) if m else 9999
        cand.sort(key=num)
        return cand[:max(0, int(self.cfg.get("auth_rotated_max", 2) or 2))]

    def read_rotated(self, path, max_lines=20000, max_bytes=24 * 1024 * 1024):
        """只读地取轮转日志尾部；.gz 用 gzip 顺序解压并限流。"""
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rb") as f:
                    data = f.read(max_bytes)
                lines = data.decode("utf-8", "replace").splitlines()[-max_lines:]
            else:
                size = os.path.getsize(path)
                with open(path, "rb") as f:
                    f.seek(max(0, size - max_bytes))
                    data = f.read()
                lines = data.decode("utf-8", "replace").splitlines()
                if size > max_bytes and lines:
                    lines = lines[1:]
                lines = lines[-max_lines:]
            return lines
        except Exception:
            return []

    def backfill(self, force=False):
        """回填历史日志，让界面立刻有真实数据。

        首次（或手动强制）读取最近 24MB / 12 万行，覆盖公网访问分布；
        之后每次启动只读尾部 1500 行，避免反复全量扫描大日志。
        事件表有 dedup 唯一键，重复导入不会产生重复记录。
        """
        total = 0
        do_full = force or self.store.get_meta("backfill_full") != "1"
        for t in self.tailers:
            if not t.name.startswith("本机"):
                continue
            if do_full:
                lines = tail_lines(t.path, 120000 if "Web" in t.name else 20000,
                                   24 * 1024 * 1024)
            else:
                lines = tail_lines(t.path, 1500, 512 * 1024)
            batch = []
            for line in lines:
                ev = t.parser(line)
                if ev:
                    batch.append(ev)
            for i in range(0, len(batch), 200):
                self._flush(batch[i:i + 200])
            total += len(batch)
            self.log("backfill %s: %d lines (full=%s)" % (t.name, len(batch), do_full))
        # 轮转日志（1.0.8）：auth.log.1 / .2.gz 里往往有上万条历史失败登录
        if do_full and self.cfg.get("source_auth_rotated", True):
            base = self.cfg.get("auth_log", "/var/log/auth.log")
            for rp in self.rotated_paths(base):
                rlines = self.read_rotated(rp)
                rbatch = []
                for line in rlines:
                    ev = self.parse_auth_any(line)
                    if ev:
                        rbatch.append(ev)
                for i in range(0, len(rbatch), 200):
                    self._flush(rbatch[i:i + 200])
                total += len(rbatch)
                self.log("backfill rotated %s: %d events" % (rp, len(rbatch)))
        if self.knock_dir_tailer:
            n = self.knock_dir_tailer.backfill(self._flush)
            total += n
            self.log("backfill 敲门网关请求日志: %d events" % n)
        if do_full:
            self.store.set_meta("backfill_full", "1")
        self.log("backfill done: %d events" % total)
        return total

    def start(self, do_backfill=True):
        if do_backfill:
            t = threading.Thread(target=self.backfill, name="backfill", daemon=True)
            t.start()
            self.threads.append(t)
        for name, target in (("writer", self.writer_loop), ("tailer", self.tailer_loop),
                             ("syslog", self.syslog_loop), ("inbox", self.inbox_loop)):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.stop_evt.set()

    def status(self):
        return {
            "started": self.started,
            "queue": self.queue.qsize(),
            "syslog_port": int(self.cfg.get("syslog_port", 5514) or 5514),
            "syslog_ok": self.syslog_ok,
            "syslog_error": self.syslog_error,
            "knock_enabled": bool(self.cfg.get("source_knock", False)),
            "knock_installed": os.path.isfile(self.cfg.get("knock_marker", "/etc/ipsense/knock.enabled")),
            "knock_app_enabled": bool(self.cfg.get("source_knock_app", False)),
            "knock_app_dir": str(self.cfg.get("knock_app_dir", "")),
            "lucky_web_enabled": bool(self.cfg.get("source_lucky_web", False)),
            "lucky_sys_enabled": bool(self.cfg.get("source_lucky_sys", False)),
            "knock_app_files": (self.knock_dir_tailer.info()
                                if self.knock_dir_tailer else None),
            "fnos_audit": bool(self.cfg.get("source_fnos_audit", True)),
            "auth_rotated": bool(self.cfg.get("source_auth_rotated", True)),
            "lan_separate": bool(self.cfg.get("lan_separate", True)),
            "lan": self.store.lan_stat(),
            "tailers": [t.info() for t in self.tailers],
            "hits": dict(self.source_hits),
            "geo_ready": self.geo.ready,
            "geo_error": getattr(self.geo, "error", ""),
        }

    def live(self, limit=80):
        with self.lock:
            return list(self.recent)[-limit:]
