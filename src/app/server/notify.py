# -*- coding: utf-8 -*-
"""2.0.0 B3 · 预警通知统一适配层（纯外发 · 零第三方依赖）。

红线：本模块只负责「把一条消息发出去」。
  · 不读 / 不写提交单与密钥授权状态文件
  · 不调用处置通道、不执行系统命令、不改防火墙、不自动处置
  · 所有 HTTP 出口统一经 http_json()（自检可 monkeypatch）
  · SMTP 走标准库 smtplib，是唯一非 HTTP 通道

渠道共 10 个：企业微信群机器人 / 钉钉 / 飞书 / Bark / PushPlus /
魔法推送 / SMTP / 企业微信应用 / 通用 Webhook / MeoW。
接口依据见 docs/notify_channels_research.md（2026-11-26 只读查证）。
"""
import base64
import hashlib
import hmac
import json
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

# 出站契约版本：与运行时包版本解耦，最终滚 2.0.0 时两者一致。
PAYLOAD_VERSION = "2.0.0"
UA = "ipsense-notify/1.0 (+fnOS)"
MASK = "******"
DEFAULT_TIMEOUT = 8
DEFAULT_PREFIX = "[ipsense]"

# 云厂商元数据 / 明确恶意的内网别名：拒绝。私有网段（10./192.168./172.16）
# 放行，因为 MagicPush 是自托管，用户很可能把 NAS 内网地址填进来。
_BLOCK_HOSTS = (
    "169.254.169.254", "169.254.169.253", "169.254.169.250",
    "100.100.100.200",                       # 阿里云 metadata
    "metadata.google.internal", "metadata",  # GCP / 通用别名
)
_BLOCK_SUFFIX = (".internal", ".localdomain")


# ---------------------------------------------------------------- 渠道元信息
# 每个字段：key / label / type / secret / placeholder / default / options /
# required / hint。前端据此动态生成表单，后端据此做校验与脱敏。
def _f(key, label, type="text", secret=False, placeholder="", default="",
       options=None, required=False, hint=""):
    return {"key": key, "label": label, "type": type, "secret": bool(secret),
            "placeholder": placeholder, "default": default,
            "options": options or [], "required": bool(required), "hint": hint}


CHANNELS = [
    {"id": "wecom_bot", "label": "企业微信群机器人", "group": "群机器人",
     "docs": "https://developer.work.weixin.qq.com/document/path/91770",
     "note": "群「消息推送」完整 Webhook URL 即凭证（含 key），仅内部群可用；20 条/分钟。",
     "fields": [
         _f("webhook_url", "Webhook URL（含 key）", "text", True,
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...", "", None, True),
     ]},
    {"id": "dingtalk", "label": "钉钉群机器人", "group": "群机器人",
     "docs": "https://open.dingtalk.com/document/orgapp/custom-robots-send-group-messages",
     "note": "安全设置三选一：关键词 / 加签 / IP 白名单。开启加签填 SEC 开头 secret；"
             "开启关键词请统一标题前缀加入关键词列表，否则消息会被静默丢弃。20 条/分钟。",
     "fields": [
         _f("webhook_url", "Webhook URL（含 access_token）", "text", True,
            "https://oapi.dingtalk.com/robot/send?access_token=...", "", None, True),
         _f("secret", "加签 Secret（可选）", "password", True, "SECxxxxxxxx", ""),
         _f("keyword", "关键词（可选，注入正文）", "text", False, "留空则用统一标题前缀", ""),
     ]},
    {"id": "feishu", "label": "飞书自定义机器人", "group": "群机器人",
     "docs": "https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot",
     "note": "签名校验与钉钉加签算法不同（秒级时间戳 / body 顶层 / 不做 urlEncode），"
             "本模块已分开实现。100 次/分钟、5 次/秒。",
     "fields": [
         _f("webhook_url", "Webhook URL", "text", True,
            "https://open.feishu.cn/open-apis/bot/v2/hook/...", "", None, True),
         _f("secret", "签名校验 Secret（可选）", "password", True, "", ""),
         _f("keyword", "关键词（可选，注入正文）", "text", False, "留空则用统一标题前缀", ""),
     ]},
    {"id": "bark", "label": "Bark", "group": "个人推送",
     "docs": "https://github.com/Finb/bark-server/blob/master/docs/API_V2.md",
     "note": "唯一以 iOS/APNs 为终点的渠道。官方公共服务 api.day.app 无 SLA，"
             "敏感场景建议自建并填自己的 base_url。",
     "fields": [
         _f("base_url", "服务地址", "text", False, "", "https://api.day.app", None, True),
         _f("device_key", "Device Key", "password", True, "", "", None, True),
         _f("basic_user", "Basic Auth 用户名（可选）", "text", False, "", ""),
         _f("basic_pass", "Basic Auth 密码（可选）", "password", True, "", ""),
         _f("sound", "提示音（可选）", "text", False, "minuet", ""),
     ]},
    {"id": "pushplus", "label": "PushPlus（推送加）", "group": "个人推送",
     "docs": "https://www.pushplus.plus/doc/guide/api.html",
     "note": "未实名返回 905、额度 0，需先实名。接口异步：code=200 只代表收到、不代表送达。"
             "实名用户 1 分钟 5 次 / 200 次每天，相同内容 1 小时 3 条。",
     "fields": [
         _f("token", "Token", "password", True, "", "", None, True),
         _f("template", "内容模板", "select", False, "", "markdown",
            ["html", "txt", "markdown", "json"]),
         _f("channel", "推送渠道", "select", False, "", "wechat",
            ["wechat", "webhook", "cp", "mail", "clawbot", "app", "qq", "sms", "voice"]),
         _f("topic", "群组编码 topic（可选）", "text", False, "", ""),
     ]},
    {"id": "magicpush", "label": "魔法推送（MagicPush）", "group": "自托管",
     "docs": "https://github.com/magiccode1412/magicpush",
     "note": "自托管服务，官方无统一 SaaS 地址。请填自己 Docker/懒猫部署的 base URL"
             "（到 /api 一级）与「接口管理」生成的推送 Token。",
     "fields": [
         _f("base_url", "服务 Base URL（必填）", "text", False,
            "https://your-domain.com/api", "", None, True),
         _f("push_token", "推送 Token", "password", True, "", "", None, True),
         _f("type", "消息类型", "select", False, "", "markdown",
            ["text", "markdown", "html"]),
     ]},
    {"id": "smtp", "label": "SMTP 邮件", "group": "邮件",
     "docs": "https://docs.python.org/3/library/smtplib.html",
     "note": "唯一非 HTTP 通道。国内邮箱通常用「授权码」而非登录密码。"
             "465=SSL、587=STARTTLS、25=明文。",
     "fields": [
         _f("host", "SMTP 主机", "text", False, "smtp.qq.com", "", None, True),
         _f("port", "端口", "number", False, "", "465", None, True),
         _f("security", "加密方式", "select", False, "", "ssl",
            ["ssl", "starttls", "none"]),
         _f("username", "账号", "text", False, "", "", None, True),
         _f("password", "密码 / 授权码", "password", True, "", "", None, True),
         _f("from_addr", "发件人", "text", False, "", ""),
         _f("to_addrs", "收件人（逗号分隔）", "text", False, "", "", None, True),
     ]},
    {"id": "wecom_app", "label": "企业微信应用消息", "group": "企业应用",
     "docs": "https://developer.work.weixin.qq.com/document/90002/90151/90854",
     "note": "与群机器人完全不同的接口：corpid+corpsecret 换 access_token（缓存 7200s）"
             "再发应用消息。需在后台配好应用可见范围与可信 IP。",
     "fields": [
         _f("corpid", "CorpID", "text", False, "", "", None, True),
         _f("corpsecret", "CorpSecret", "password", True, "", "", None, True),
         _f("agentid", "AgentID", "text", False, "1000002", "", None, True),
         _f("touser", "接收成员", "text", False, "@all", "@all", None, True),
     ]},
    {"id": "webhook", "label": "通用 Webhook", "group": "自定义",
     "docs": "",
     "note": "自定义 POST。支持自定义 headers、body 模板与鉴权头；"
             "可对接 Home Assistant / n8n / Grafana，或把 MagicPush 当统一分发入口。",
     "fields": [
         _f("url", "目标 URL", "text", True, "https://your-endpoint/hook", "", None, True),
         _f("method", "方法", "select", False, "", "POST", ["POST", "PUT"]),
         _f("auth_type", "鉴权方式", "select", False, "", "none",
            ["none", "bearer", "basic"]),
         _f("auth_token", "Bearer Token / Basic 串", "password", True, "", ""),
         _f("headers", "额外请求头（JSON 对象）", "textarea", False, '{"X-Token":"..."}', "{}"),
         _f("body_template", "body 模板（可选）", "textarea", False,
            '留空用默认负载；占位符 {{title}} {{text}} {{event}} {{timestamp}}', ""),
         _f("success_matcher", "成功判定（可选）", "text", False,
            "留空=HTTP 2xx；或填 body 必须包含的关键字", ""),
     ]},
    {"id": "meow", "label": "MeoW", "group": "个人推送",
     "docs": "https://www.chuckfang.com/MeoW/api_doc.html",
     "note": "无 token：用「用户昵称」当接收识别码（须已在 App 注册、不含斜杠）。"
             "成功判定看业务码 status==200，不能只看 HTTP 200。非会员 3 秒 1 条。",
     "fields": [
         _f("base_url", "服务地址", "text", False, "", "https://api.chuckfang.com", None, True),
         _f("nickname", "接收昵称", "password", True, "", "", None, True),
         _f("category", "分类（≤10 字，可选）", "text", False, "服务器告警", ""),
         _f("msg_type", "消息类型", "select", False, "", "text", ["text", "html"]),
     ]},
]

CHANNEL_IDS = tuple(c["id"] for c in CHANNELS)
CHANNEL_MAP = {c["id"]: c for c in CHANNELS}
# 所有敏感字段（下发配置时打码，日志里也不落明文）
SECRET_KEYS = tuple(sorted({f["key"] for c in CHANNELS for f in c["fields"]
                            if f["secret"]}))
FIELD_KEYS = tuple(sorted({f["key"] for c in CHANNELS for f in c["fields"]}))
COMMON_KEYS = ("id", "channel", "enabled", "title_prefix", "timeout", "retry")


def public_channels():
    """给前端的渠道元信息（与 CHANNELS 同源，去掉内部字段）。"""
    return [{"id": c["id"], "label": c["label"], "group": c["group"],
             "docs": c.get("docs", ""), "note": c.get("note", ""),
             "fields": [dict(f) for f in c["fields"]]} for c in CHANNELS]


def mask(v):
    """敏感字段统一打码；空值保持空，便于 UI 判断「未填写」。"""
    return MASK if v not in (None, "", MASK) else (v or "")


def is_masked(v):
    return v == MASK


# ---------------------------------------------------------------- 公共助手
def validate_url(url, label="URL"):
    """SSRF 基础防护：只放行 http/https、拒绝云元数据地址与明显恶意别名。

    私有网段（10./192.168./172.16）与 loopback 放行 —— MagicPush 是自托管，
    用户很可能把 NAS 内网地址填进来，一刀切会误伤。返回 (ok, reason)。
    """
    p = urllib.parse.urlparse((url or "").strip())
    if p.scheme not in ("http", "https"):
        return False, "%s 协议只允许 http/https" % label
    if not p.hostname:
        return False, "%s 缺少主机" % label
    host = p.hostname.lower().strip(".")
    if host in _BLOCK_HOSTS or host.endswith(_BLOCK_SUFFIX):
        return False, "%s 指向禁止访问的元数据地址" % label
    return True, ""


def http_json(url, payload, headers=None, timeout=DEFAULT_TIMEOUT, method="POST"):
    """统一 HTTP 出口。返回 (status:int, raw:str)。自检可 monkeypatch 本函数。"""
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    h = {"Content-Type": "application/json; charset=utf-8", "User-Agent": UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(4096).decode("utf-8", "replace")


def _json(raw):
    try:
        j = json.loads(raw or "")
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


def _res(ok, channel, msg, raw=None, retryable=False):
    return {"ok": bool(ok), "channel": channel, "msg": msg,
            "raw": raw, "retryable": bool(retryable)}


def _content(title, text, c):
    """统一正文：注入标题前缀，满足钉钉/飞书「关键词」安全设置。"""
    prefix = (c.get("title_prefix") or "").strip() or DEFAULT_PREFIX
    keyword = (c.get("keyword") or "").strip()
    head = (prefix + " " + (keyword or "")).strip()
    return "%s %s\n%s" % (head, title or "", text or "")


def _timeout(c):
    try:
        t = int(c.get("timeout") or DEFAULT_TIMEOUT)
        return 3 if t < 3 else (30 if t > 30 else t)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT


def _payload(event="", title="", text="", detail=None):
    """2.0.0 稳定出站契约（通用 Webhook / MagicPush 的模板变量来源）。"""
    return {"source": "ipsense", "version": PAYLOAD_VERSION, "event": event,
            "title": title, "text": text,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "detail": detail or {}}


def _render_template(tpl, title, text, event="", detail=None):
    """把 {{title}} 等占位符替换成转义后的 JSON 字符串片段。"""
    p = _payload(event, title, text, detail)
    out = tpl
    for k, v in p.items():
        out = out.replace("{{%s}}" % k, json.dumps(v, ensure_ascii=False)[1:-1]
                          if isinstance(v, str) else json.dumps(v, ensure_ascii=False))
    return out


# ---------------------------------------------------------------- 加签算法
def dingtalk_sign(secret):
    """钉钉加签：毫秒时间戳 / secret 作 HMAC key / query / urlEncode。

    string_to_sign = timestamp(ms) + "\\n" + secret
    sign = quote_plus(base64(HmacSHA256(key=secret, msg=string_to_sign)))
    """
    ts = str(round(time.time() * 1000))
    s = "%s\n%s" % (ts, secret)
    h = hmac.new(secret.encode("utf-8"), s.encode("utf-8"),
                 digestmod=hashlib.sha256).digest()
    return ts, urllib.parse.quote_plus(base64.b64encode(h).decode("ascii"))


def feishu_sign(secret, ts=None):
    """飞书签名校验：秒级时间戳 / 拼接串作 HMAC key / 对空串签名 / body / 不编码。

    key = timestamp(s) + "\\n" + secret，msg = b""
    sign = base64(HmacSHA256(key, b""))  （不再 urlEncode）
    """
    ts = str(int(ts if ts is not None else time.time()))
    s = "%s\n%s" % (ts, secret)
    h = hmac.new(s.encode("utf-8"), b"", digestmod=hashlib.sha256).digest()
    return ts, base64.b64encode(h).decode("ascii")


# ---------------------------------------------------------------- 10 个 adapter
def _wecom_bot(title, text, c):
    url = (c.get("webhook_url") or "").strip()
    ok, why = validate_url(url)
    if not ok:
        return _res(False, "wecom_bot", why)
    st, raw = http_json(url, {"msgtype": "text",
                              "text": {"content": _content(title, text, c)}},
                        timeout=_timeout(c))
    j = _json(raw)
    if j.get("errcode") == 0 and 200 <= st < 300:
        return _res(True, "wecom_bot", "已发送", raw)
    return _res(False, "wecom_bot", "errcode=%s errmsg=%s" %
                (j.get("errcode"), j.get("errmsg")), raw, 500 <= st < 600)


def _dingtalk(title, text, c):
    url = (c.get("webhook_url") or "").strip()
    ok, why = validate_url(url)
    if not ok:
        return _res(False, "dingtalk", why)
    secret = (c.get("secret") or "").strip()
    if secret:
        ts, sign = dingtalk_sign(secret)
        glue = "&" if urllib.parse.urlparse(url).query else "?"
        url = "%s%stimestamp=%s&sign=%s" % (url, glue, ts, sign)
    st, raw = http_json(url, {"msgtype": "text",
                              "text": {"content": _content(title, text, c)}},
                        timeout=_timeout(c))
    j = _json(raw)
    if j.get("errcode") == 0 and 200 <= st < 300:
        return _res(True, "dingtalk", "已发送", raw)
    return _res(False, "dingtalk", "errcode=%s errmsg=%s" %
                (j.get("errcode"), j.get("errmsg")), raw, 500 <= st < 600)


def _feishu(title, text, c):
    url = (c.get("webhook_url") or "").strip()
    ok, why = validate_url(url)
    if not ok:
        return _res(False, "feishu", why)
    body = {"msg_type": "text", "content": {"text": _content(title, text, c)}}
    secret = (c.get("secret") or "").strip()
    if secret:
        ts, sign = feishu_sign(secret)
        body["timestamp"], body["sign"] = ts, sign
    st, raw = http_json(url, body, timeout=_timeout(c))
    j = _json(raw)
    if (j.get("code") == 0 or j.get("StatusCode") == 0) and 200 <= st < 300:
        return _res(True, "feishu", "已发送", raw)
    return _res(False, "feishu", "code=%s msg=%s" %
                (j.get("code"), j.get("msg")), raw, 500 <= st < 600)


def _bark(title, text, c):
    base = (c.get("base_url") or "https://api.day.app").strip().rstrip("/")
    url = base + "/push"
    ok, why = validate_url(url)
    if not ok:
        return _res(False, "bark", why)
    body = {"device_key": c.get("device_key") or "", "title": title,
            "body": _content(title, text, c), "group": "ipsense"}
    if c.get("sound"):
        body["sound"] = c["sound"]
    headers = {}
    if c.get("basic_user"):
        tok = "%s:%s" % (c.get("basic_user") or "", c.get("basic_pass") or "")
        headers["Authorization"] = "Basic " + base64.b64encode(
            tok.encode("utf-8")).decode("ascii")
    st, raw = http_json(url, body, headers=headers, timeout=_timeout(c))
    if 200 <= st < 300:
        return _res(True, "bark", "已发送", raw)
    return _res(False, "bark", "HTTP %s" % st, raw, 500 <= st < 600)


def _pushplus(title, text, c):
    url = "https://www.pushplus.plus/send"
    body = {"token": c.get("token") or "", "title": title,
            "content": _content(title, text, c),
            "template": c.get("template") or "markdown",
            "channel": c.get("channel") or "wechat"}
    if c.get("topic"):
        body["topic"] = c["topic"]
    st, raw = http_json(url, body, timeout=_timeout(c))
    j = _json(raw)
    if j.get("code") == 200:
        # 异步接口：code=200 只代表「收到请求」，不是送达确认。
        return _res(True, "pushplus", "已受理（异步，非送达确认）流水号=%s" %
                    j.get("data"), raw)
    code = j.get("code")
    hint = "（未实名认证，需先实名）" if code == 905 else ""
    return _res(False, "pushplus", "code=%s msg=%s%s" %
                (code, j.get("msg"), hint), raw, 500 <= st < 600)


def _magicpush(title, text, c):
    base = (c.get("base_url") or "").strip().rstrip("/")
    ok, why = validate_url(base or "http://", "服务地址")
    if not ok:
        return _res(False, "magicpush", why)
    url = base if base.endswith("/push") else base + "/push"
    body = {"title": title, "content": _content(title, text, c),
            "type": c.get("type") or "markdown"}
    headers = {"Authorization": "Bearer %s" % (c.get("push_token") or "")}
    st, raw = http_json(url, body, headers=headers, timeout=_timeout(c))
    j = _json(raw)
    if j.get("success") is True and int(j.get("failedCount") or 0) == 0:
        return _res(True, "magicpush", "已发送 %s/%s 渠道" %
                    (j.get("successCount"), j.get("total")), raw)
    return _res(False, "magicpush", "success=%s failedCount=%s" %
                (j.get("success"), j.get("failedCount")), raw, 500 <= st < 600)


def _smtp(title, text, c):
    host = (c.get("host") or "").strip()
    if not host:
        return _res(False, "smtp", "缺少 SMTP 主机")
    try:
        port = int(c.get("port") or 465)
    except (TypeError, ValueError):
        port = 465
    sec = c.get("security") or "ssl"
    msg = EmailMessage()
    msg["From"] = (c.get("from_addr") or c.get("username") or "").strip()
    msg["To"] = (c.get("to_addrs") or "").strip()
    msg["Subject"] = "%s %s" % ((c.get("title_prefix") or DEFAULT_PREFIX), title)
    msg.set_content(_content(title, text, c))
    ctx = ssl.create_default_context()
    if sec == "ssl":
        s = smtplib.SMTP_SSL(host, port, timeout=_timeout(c), context=ctx)
    else:
        s = smtplib.SMTP(host, port, timeout=_timeout(c))
        if sec == "starttls":
            s.starttls(context=ctx)
    with s:
        if c.get("username"):
            s.login(c["username"], c.get("password") or "")
        s.send_message(msg)
    return _res(True, "smtp", "已发送")


_TOKEN_CACHE = {}
_TOKEN_LOCK = threading.Lock()
_WECOM_TOKEN_URL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
_WECOM_SEND_URL = "https://qyapi.weixin.qq.com/cgi-bin/message/send"


def wecom_access_token(corpid, secret, timeout=DEFAULT_TIMEOUT):
    """企业微信应用 access_token：按 (corpid, agentid) 缓存 7200s，提前 300s 刷新。"""
    key = "%s|%s" % (corpid, secret[:8])
    with _TOKEN_LOCK:
        ent = _TOKEN_CACHE.get(key)
        if ent and ent["exp"] > time.time() + 300:
            return ent["tok"], ""
    url = _WECOM_TOKEN_URL + "?" + urllib.parse.urlencode(
        {"corpid": corpid, "corpsecret": secret})
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        j = _json(r.read(4096).decode("utf-8", "replace"))
    if j.get("errcode") != 0 or not j.get("access_token"):
        return "", "gettoken errcode=%s errmsg=%s" % (
            j.get("errcode"), j.get("errmsg"))
    exp = time.time() + int(j.get("expires_in") or 7200)
    with _TOKEN_LOCK:
        _TOKEN_CACHE[key] = {"tok": j["access_token"], "exp": exp}
    return j["access_token"], ""


def _wecom_app(title, text, c):
    tok, err = wecom_access_token(c.get("corpid") or "",
                                  c.get("corpsecret") or "", _timeout(c))
    if not tok:
        return _res(False, "wecom_app", err or "取 access_token 失败")
    url = _WECOM_SEND_URL + "?" + urllib.parse.urlencode({"access_token": tok})
    body = {"touser": c.get("touser") or "@all", "msgtype": "text",
            "agentid": c.get("agentid") or "", "safe": 0,
            "text": {"content": _content(title, text, c)}}
    st, raw = http_json(url, body, timeout=_timeout(c))
    j = _json(raw)
    if j.get("errcode") == 0:
        return _res(True, "wecom_app", "已发送", raw)
    return _res(False, "wecom_app", "errcode=%s errmsg=%s" %
                (j.get("errcode"), j.get("errmsg")), raw, 500 <= st < 600)


def _webhook(title, text, c):
    url = (c.get("url") or "").strip()
    ok, why = validate_url(url)
    if not ok:
        return _res(False, "webhook", why)
    method = (c.get("method") or "POST").upper()
    if method not in ("POST", "PUT"):
        method = "POST"
    headers = {}
    try:
        extra = json.loads(c.get("headers") or "{}")
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
    except Exception:
        pass
    at = c.get("auth_type") or "none"
    if at == "bearer" and c.get("auth_token"):
        headers["Authorization"] = "Bearer " + c["auth_token"]
    elif at == "basic" and c.get("auth_token"):
        headers["Authorization"] = "Basic " + c["auth_token"]
    tpl = (c.get("body_template") or "").strip()
    if tpl:
        try:
            body = json.loads(_render_template(tpl, title, text))
        except Exception as e:
            return _res(False, "webhook", "body 模板不是合法 JSON: %s" % e)
    else:
        body = _payload(event="alert", title=title, text=text)
    st, raw = http_json(url, body, headers=headers, timeout=_timeout(c),
                        method=method)
    matcher = (c.get("success_matcher") or "").strip()
    ok2 = 200 <= st < 300
    if ok2 and matcher:
        ok2 = matcher in (raw or "")
    if ok2:
        return _res(True, "webhook", "已发送（HTTP %s）" % st, raw)
    return _res(False, "webhook", "HTTP %s / 判定未通过" % st, raw,
                500 <= st < 600)


def _meow(title, text, c):
    base = (c.get("base_url") or "https://api.chuckfang.com").strip().rstrip("/")
    nick = (c.get("nickname") or "").strip()
    if not nick or "/" in nick:
        return _res(False, "meow", "昵称不能为空且不能包含斜杠")
    url = base + "/" + urllib.parse.quote(nick, safe="")
    body = {"title": title, "msg": _content(title, text, c)}
    if c.get("category"):
        body["category"] = c["category"]
    params = {}
    if c.get("msg_type") == "html":
        params["msgType"] = "html"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    st, raw = http_json(url, body, timeout=_timeout(c))
    j = _json(raw)
    if j.get("status") == 200:
        return _res(True, "meow", "已发送", raw)
    hint = {404: "昵称未注册", 429: "频率超限", 403: "内容策略禁止"}.get(
        j.get("status"), "")
    return _res(False, "meow", "业务码=%s msg=%s %s" %
                (j.get("status"), j.get("msg"), hint), raw, 500 <= st < 600)


ADAPTERS = {
    "wecom_bot": _wecom_bot, "dingtalk": _dingtalk, "feishu": _feishu,
    "bark": _bark, "pushplus": _pushplus, "magicpush": _magicpush,
    "smtp": _smtp, "wecom_app": _wecom_app, "webhook": _webhook,
    "meow": _meow,
}


def send(channel, title, text, cfg):
    """统一入口。cfg 至少含 channel；返回 SendResult dict。

    retry 仅对 retryable（网络错误 / 5xx / 限流）生效；参数错误不重试。
    """
    c = dict(cfg or {})
    c["channel"] = channel
    fn = ADAPTERS.get(channel)
    if not fn:
        return _res(False, channel, "未注册的渠道：%s" % channel)
    try:
        retries = int(c.get("retry") or 0)
    except (TypeError, ValueError):
        retries = 0
    retries = 0 if retries < 0 else (2 if retries > 2 else retries)
    last = None
    for i in range(retries + 1):
        try:
            last = fn(title, text, c)
        except Exception as e:
            last = _res(False, channel, "%s: %s" % (type(e).__name__, e),
                        retryable=True)
        if last["ok"] or not last.get("retryable") or i >= retries:
            return last
        time.sleep(1)
    return last
