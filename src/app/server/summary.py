# -*- coding: utf-8 -*-
"""1.1.9 · 软件汇总日志（交给 AI 做设备实时防护分析）。

设计边界（刻意收紧，避免把应用变成「自动防护」）：
- 日志只汇总 store 里已有的事实，不伪造、不新增数据源、不猜测未识别字段；
- 只观测、不自动修改防火墙 / 不封禁 IP，所有防护动作在文档里明确留给人工确认；
- 保存目录由用户在设置界面用 fnOS 原生文件夹选择器选定，后端做四层校验
  （绝对路径 / 归一化防穿越 / 真实目录 / 真实可写探针）后才落盘；
- 原子写 latest.md（固定路径，便于把同一个文件持续交给 AI）+ 按天归档，
  同天覆盖，不做任何自动删除，规避误删风险。
"""
import os
import re
import time
import threading

LATEST_NAME = "ipsense-summary-latest.md"
ARCHIVE_PREFIX = "ipsense-summary-"

# 只允许写到 NAS 数据区；应用目录 / 系统目录一律拒绝。
# 注意 fnOS 的卷是 /vol1、/vol2 …（不是 /vol/1），所以卷前缀要按 /vol\d+ 匹配。
ALLOWED_ROOTS = ("/home", "/mnt", "/media")
DENY_PREFIX = ("/etc", "/usr", "/bin", "/sbin", "/proc", "/sys", "/dev",
               "/boot", "/lib", "/opt", "/var/apps", "/var/lib", "/var/log")
_VOL_RE = re.compile(r"^/vol\d*(?:/|$)")
_APPDIR_RE = re.compile(r"^/vol\d*/@")

RANGE_NAME = {"1h": "近 1 小时", "24h": "近 24 小时", "7d": "近 7 天",
              "30d": "近 30 天", "all": "全部历史"}
SCOPE_NAME = {"cn": "境内", "overseas": "境外", "private": "内网",
              "lan": "局域网设备", "unknown": "未知"}
VERDICT_NAME = {"normal": "正常访问", "scan": "扫描探测",
                "attack": "认证攻击", "knock": "端口敲门"}
SRC_NAME = {"local_auth": "本机 SSH 认证", "local_web": "本机 Web 访问",
            "local_kern": "内核日志", "router_syslog": "路由器 syslog",
            "router_file": "路由器日志文件", "knock": "端口敲门",
            "knock_app": "敲门网关请求日志",
            "fnos_audit": "fnOS 结构化登录审计"}
PROTO_NAME = {"https": "HTTPS", "http": "HTTP", "web": "Web 未识别",
              "ssh": "SSH", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP",
              "unknown": "未识别"}


def _norm(p):
    """纯字符串归一化（折叠 // / . / ..），平台无关，便于离线自检。
    不解析符号链接——真实软链由 validate_dir 里的 realpath 复核。"""
    parts = []
    for seg in str(p).split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def _in_allowed(rp):
    if _VOL_RE.match(rp):
        return True
    return any(rp == r or rp.startswith(r + "/") for r in ALLOWED_ROOTS)


def _is_denied(rp):
    if any(rp == d or rp.startswith(d + "/") for d in DENY_PREFIX):
        return True
    # 任何卷下的 @appdata / @appcenter / @appconf 等系统区都不写
    return _APPDIR_RE.match(rp) is not None


def path_allowed(p):
    """四层校验的第 1~2 层（纯字符串，不碰文件系统，跨平台可自检）。"""
    if not isinstance(p, str):
        return False
    s = p.strip()
    if not s or len(s) > 400 or "\x00" in s or not s.startswith("/"):
        return False
    rp = _norm(s)
    if not rp or not _in_allowed(rp) or _is_denied(rp):
        return False
    return True


def validate_dir(directory, check_write=True):
    """四层校验，返回 (ok, reason, normalized_path)。

    1) 绝对路径 + 长度 / NUL 检查
    2) 归一化防 `..` 穿越 + 目录白名单 / 系统目录黑名单
    3) 真实是目录（realpath 后再跑一次白名单，防软链指到系统区）
    4) os.access + 实际写探针（真机以 package 用户跑，ACL 的最终真相）
    """
    if not isinstance(directory, str) or not directory.strip():
        return False, "保存位置不能为空", ""
    raw = directory.strip()
    if not path_allowed(raw):
        return False, ("只允许保存到 NAS 数据目录（/vol、/home、/mnt、/media 下），"
                       "且不能是应用或系统目录"), ""
    rp = _norm(raw)
    real = os.path.realpath(rp)
    if not path_allowed(real):
        return False, "目录的真实路径越出了允许范围（软链指向系统区）", ""
    if not os.path.isdir(real):
        return False, "目录不存在，请先在飞牛文件管理器里创建，或重新选择", ""
    if check_write:
        if not os.access(real, os.W_OK | os.X_OK):
            return False, ("应用对该目录没有写入权限；请在「系统设置 → 应用 → "
                           "IP 动态感知 → 访问权限」里授权该文件夹"), ""
        probe = os.path.join(real, ".ipsense-write-probe-%d" % os.getpid())
        try:
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)
        except Exception as e:
            try:
                os.remove(probe)
            except Exception:
                pass
            return False, "目录写入测试失败：%s" % e, ""
    return True, "可写", real


# ---------------- Markdown 生成 ----------------
def _ts(v):
    if not v:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(v)))
    except Exception:
        return "—"


def _cell(v, limit=150):
    return (str(v if v is not None else "")
            .replace("|", "\\|").replace("\n", " ").strip()[:limit]) or "—"


def _table(head, rows):
    out = ["| " + " | ".join(head) + " |",
           "| " + " | ".join(["---"] * len(head)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(_cell(x) for x in r) + " |")
    return out


def _geo(r):
    return " / ".join(str(x) for x in (r.get("country"), r.get("province"),
                                       r.get("city"), r.get("isp"))
                      if x and str(x) != "0") or "未知"


def build_summary(app, rng="24h", top_ips=20, top_events=30):
    """生成一份结构化 Markdown。每段独立容错：某段读失败就明说，不伪造数据。"""
    st = app.store
    now = time.time()
    L = []
    A = L.append

    def section(title, fn):
        A("")
        A("## " + title)
        A("")
        try:
            fn()
        except Exception as e:
            A("> 本节数据读取失败（%s），已如实标注，未填充任何推测值。" % e)

    A("# IP 动态感知 · 设备访问汇总日志")
    A("")
    A("> **用途**：把本文件直接交给 AI，让它分析这台设备的访问态势并给出防护建议。  ")
    A("> **口径**：本应用只观测、不自动修改防火墙、不封禁 IP；"
      "下列所有封禁 / 限流 / 加固动作都请人工确认后再执行。  ")
    A("> **数据来自本机日志**，不含任何边界 / 国界 / 行政区划轮廓数据。")
    A("")
    A("```text")
    A("建议提问：以下是我 NAS / 设备的访问汇总日志。请判断哪些来源 IP 属于扫描、")
    A("爆破或异常高频访问，是否有突发峰值或集中时段，给出按优先级排序的处置建议")
    A("（封禁网段、限制 SSH、调整端口、加强口令 / 密钥、检查特定受访页等），")
    A("并明确哪些结论只是线索、需要我进一步核实。不要假设日志里没写的字段。")
    A("```")

    # ---- 0. 生成信息 ----
    def s0():
        cfg = app.settings.all()
        allst = st.status("all")
        src = st.sources_stat() or {}
        rows = [
            ["生成时间", _ts(now) + "（设备本地时间）"],
            ["应用", "IP 动态感知 / ipsense"],
            ["统计窗口", RANGE_NAME.get(rng, rng)],
            ["保存位置", str(cfg.get("summary_dir") or "（未设置）")],
            ["自动生成", ("开启 · 每 %s 分钟" % cfg.get("summary_interval", 5))
             if cfg.get("summary_enabled", True) else "关闭"],
            ["库内记录总数", "%s 条" % allst.get("total", 0)],
            ["最早记录", _ts(allst.get("oldest"))],
            ["数据源", "、".join(SRC_NAME.get(k, k) for k in src.keys()) or "（暂无）"],
            ["归属库", "内置 ip2region 离线库" + (
                " + 在线多源交叉校验" if cfg.get("geo_verify_enabled", True) else "")],
        ]
        L.extend(_table(["项", "值"], rows))
    section("0. 生成信息", s0)

    # ---- 1. 态势总览 ----
    def s1():
        d = st.status(rng)
        total = d.get("total", 0) or 0
        bad = (d.get("scan", 0) or 0) + (d.get("attack", 0) or 0) + (d.get("knock", 0) or 0)
        inner = (d.get("private", 0) or 0) + (d.get("lan", 0) or 0)
        rows = [
            ["访问总量", "%s 次" % total],
            ["独立来源 IP", "%s 个" % d.get("unique_ip", 0)],
            ["境内 / 境外", "%s / %s 次" % (d.get("cn", 0), d.get("overseas", 0))],
            ["内网 / 局域网", "%s 次（单独归类，不污染公网排名）" % inner],
            ["正常访问", "%s 次" % d.get("normal", 0)],
            ["扫描 / 攻击 / 敲门", "%s 次（占比 %.1f%%）" % (
                bad, (100.0 * bad / total) if total else 0.0)],
            ["每分钟速率", "%s 次" % d.get("per_minute", 0)],
            ["最近一条", _ts((d.get("last") or {}).get("ts"))],
        ]
        L.extend(_table(["指标", "数值"], rows))
        A("")
        if bad > 0:
            A("**关注点**：窗口内出现 %s 次扫描 / 认证攻击 / 端口敲门观测，"
              "请重点看第 3 节的逐条明细。" % bad)
        else:
            A("**关注点**：窗口内没有标记为扫描 / 攻击 / 敲门的事件；"
              "这不代表绝对安全，仅表示当前判定口径下未识别到异常。")
    section("1. 态势总览（%s）" % RANGE_NAME.get(rng, rng), s1)

    # ---- 2. 高频来源 IP ----
    def s2():
        start, _ = st._range(rng)
        with st.lock:
            rows = st.conn.execute(
                "SELECT ip, COUNT(*) n, MAX(ts) last_ts, "
                "SUM(CASE WHEN verdict IN ('scan','attack','knock') THEN 1 ELSE 0 END) bad, "
                "MAX(country) country, MAX(province) province, MAX(city) city, "
                "MAX(scope) scope, MAX(port) port, MAX(proto) proto, MAX(verdict) verdict "
                "FROM events WHERE ts>=? GROUP BY ip ORDER BY n DESC LIMIT ?",
                (start, top_ips)).fetchall()
        out = []
        for r in rows:
            out.append([r["ip"],
                        " / ".join(str(x) for x in (r["country"], r["province"], r["city"])
                                  if x and str(x) != "0") or "未知",
                        SCOPE_NAME.get(r["scope"], r["scope"] or "未知"),
                        r["n"], r["bad"] or 0,
                        PROTO_NAME.get(r["proto"], r["proto"] or "未识别"),
                        r["port"] or "—", _ts(r["last_ts"])])
        L.extend(_table(["来源 IP", "归属", "范围", "访问次数", "异常次数",
                         "协议", "目标端口", "最近时间"], out))
        A("")
        A("> `异常次数` 为该 IP 被判定为扫描 / 攻击 / 敲门的事件数；"
          "判定依据来自日志特征，不是威胁情报结论。")
    section("2. 高频来源 IP（前 %d 个）" % top_ips, s2)

    # ---- 3. 可疑 / 异常事件 ----
    def s3():
        hits = []
        for v in ("attack", "scan", "knock"):
            try:
                rec = st.records(page=1, size=top_events, rng=rng, verdict=v)
                for r in rec.get("rows", []):
                    hits.append(r)
            except Exception:
                continue
        hits.sort(key=lambda r: r.get("ts") or 0, reverse=True)
        hits = hits[:top_events]
        if not hits:
            A("窗口内没有标记为扫描 / 认证攻击 / 端口敲门的事件。")
            return
        out = []
        for r in hits:
            out.append([_ts(r.get("ts")), r.get("ip"),
                        " / ".join(str(x) for x in (r.get("country"), r.get("province"),
                                                    r.get("city")) if x and str(x) != "0") or "未知",
                        VERDICT_NAME.get(r.get("verdict"), r.get("verdict") or "—"),
                        PROTO_NAME.get(r.get("proto"), r.get("proto") or "未识别"),
                        r.get("port") or "—",
                        (r.get("action") or r.get("path") or "—"),
                        SRC_NAME.get(r.get("source"), r.get("source") or "—")])
        L.extend(_table(["时间", "来源 IP", "归属", "判定", "协议", "端口",
                         "动作 / 路径", "来源通道"], out))
    section("3. 可疑 / 异常事件明细（最多 %d 条，按时间倒序）" % top_events, s3)

    # ---- 3.1 敲门网关与授信时间线（1.1.14） ----
    def s3k():
        cfg = app.settings.all()
        on = bool(cfg.get("source_knock_app", False))
        A("数据源：%s ｜ 日志目录：`%s`" % (
            "已启用" if on else "未启用（默认关闭）",
            str(cfg.get("knock_app_dir") or "（未设置）")))
        A("")
        if not on:
            A("> 敲门网关请求日志当前未接入。该通道只读第三方网关落盘的结构化 JSON，"
              "不会替你打开对方日志开关、不修改对方配置，也不改防火墙。")
            return
        with st.lock:
            rows = st.conn.execute(
                "SELECT ts, ip, action, path, proto, status, port, "
                "country, province, city FROM events "
                "WHERE ts>=? AND source='knock_app' ORDER BY ts DESC LIMIT ?",
                (st._range(rng)[0], top_events)).fetchall()
            kinds = st.conn.execute(
                "SELECT action, COUNT(*) n FROM events "
                "WHERE ts>=? AND source='knock_app' GROUP BY action ORDER BY n DESC",
                (st._range(rng)[0],)).fetchall()
        # sqlite3.Row 没有 .get()，_geo() 与表格都要 dict；先转换再渲染。
        rows = [dict(x) for x in rows]
        kinds = [dict(x) for x in kinds]
        A("窗口内共 %d 条网关请求观测。" % len(rows))
        A("")
        if kinds:
            L.extend(_table(["网关动作", "次数"],
                            [[k["action"], k["n"]] for k in kinds]))
            A("")
        if not rows:
            A("窗口内没有敲门网关请求记录。若对方日志开关未开启、日志已被保留期清理，"
              "或测试流量来自 127.0.0.1，这里都会是空的，属于正常现象而非采集故障。")
            return
        L.extend(_table(["时间", "客户端 IP", "归属", "网关动作", "Host / 路径",
                         "协议", "状态码"],
                        [[_ts(r["ts"]), r["ip"], _geo(r), r["action"],
                          r["path"] or "—",
                          PROTO_NAME.get(r["proto"], r["proto"] or "未识别"),
                          r["status"] or "—"] for r in rows]))
        A("")
        A("> 以上只记录网关观测到的事实。认证被拒 / WAF 拦截不等于攻击定性，"
          "授信与后续访问是否相关请结合第 2、3 节同一 IP 的时间线人工判断；"
          "应用不自动封禁、不自动处置。")
    section("3.1 敲门网关与授信时间线", s3k)


    # ---- 4. 地域来源分布 ----
    def s4():
        rk = st.ranking(rng, 10)
        gd = st.geo_distribution(rng, "all", 15)
        A("**境内按省级行政区（前 10）**")
        A("")
        L.extend(_table(["地区", "访问次数", "独立 IP"],
                        [[x["name"], x["count"], x["ips"]] for x in rk.get("cn", [])]))
        A("")
        A("**境外按国家 / 地区（前 10）**")
        A("")
        L.extend(_table(["地区", "访问次数", "独立 IP"],
                        [[x["name"], x["count"], x["ips"]] for x in rk.get("overseas", [])]))
        A("")
        A("**全球合并视图（前 15，境内统一归并为「中国」）**")
        A("")
        L.extend(_table(["地区", "访问次数", "独立 IP"],
                        [[x["name"], x["count"], x["ips"]] for x in gd.get("regions", [])]))
        A("")
        A("> 地域分布只有聚合数字与内置中心点，不含任何边界 / 区划轮廓；"
          "国界与行政区划一律以官方合规底图为准。港澳台计入境内口径。")
    section("4. 地域来源分布", s4)

    # ---- 5. Web 访问画像 ----
    def s5():
        ov = st.web_overview(rng, 10)
        sm = ov.get("summary", {})
        A("Web 请求 %s 次 · 独立 IP %s 个 · 会话 %s 个。" % (
            sm.get("requests", 0), sm.get("ips", 0), sm.get("sessions", 0)))
        A("")
        A("**访问协议构成**")
        A("")
        L.extend(_table(["协议", "次数", "独立 IP", "手动指定", "推断"],
                        [[PROTO_NAME.get(x["name"], x["name"]), x["count"], x["ips"],
                          x.get("manual", 0), x.get("inferred", 0)]
                         for x in ov.get("protocols", [])]))
        for label, key in (("来路", "referrers"), ("受访页", "pages"),
                           ("入口页", "entries"), ("终端设备", "devices")):
            A("")
            A("**%s（前 10）**" % label)
            A("")
            L.extend(_table(["条目", "次数", "独立 IP"],
                            [[x.get("name"), x.get("count"), x.get("ips")]
                             for x in ov.get(key, [])]))
        A("")
        A("> combined 日志不含 scheme，`Web 未识别` 表示没有可靠信号，"
          "应用不硬猜协议；入口页按会话首条请求统计。")
    section("5. Web 访问画像", s5)

    # ---- 6. 频率趋势与峰值 ----
    def s6():
        t = st.trend(rng)
        pts = t.get("points", [])
        if not pts:
            A("窗口内没有趋势数据。")
            return
        peak = max(pts, key=lambda x: x.get("all", 0))
        bad_peak = max(pts, key=lambda x: x.get("scan", 0))
        A("时间桶 %s 秒 · 共 %s 个桶。" % (t.get("bucket"), len(pts)))
        A("")
        A("- 总量峰值：%s，该桶 %s 次（其中扫描 / 攻击 %s 次）" % (
            _ts(peak.get("t")), peak.get("all", 0), peak.get("scan", 0)))
        A("- 异常峰值：%s，该桶 %s 次" % (
            _ts(bad_peak.get("t")), bad_peak.get("scan", 0)))
        A("")
        A("**最近 12 个时间桶**")
        A("")
        L.extend(_table(["时间", "总量", "境内", "境外", "内网", "扫描 / 攻击"],
                        [[_ts(x.get("t")), x.get("all", 0), x.get("cn", 0),
                          x.get("overseas", 0), x.get("private", 0), x.get("scan", 0)]
                         for x in pts[-12:]]))
    section("6. 访问频率趋势与峰值", s6)

    # ---- 7. 数据口径与免责声明 ----
    def s7():
        cfg = app.settings.all()
        A("- **出口 IP 归属不等于设备物理位置**；本机位置由用户在设置页按需定位，"
          "未定位时不写死城市。")
        A("- IP 归属以内置 ip2region 离线库为基础，可选启用 ip-api.com / ip.sb / "
          "ipinfo.io 三家在线源做多源交叉裁决（当前%s），结果本地缓存、可关闭；"
          "离线库对运营商网段重分配存在滞后。" % (
              "已启用" if cfg.get("geo_verify_enabled", True) else "已关闭"))
        A("- 内网 / 局域网设备单独归类，不污染公网排名，但完整保留在记录表里。")
        A("- 访问协议与判定是两个独立维度；协议无法确认时明确标「未识别」，不伪造。")
        A("- 端口敲门为预留观测能力，默认未安装；应用不修改防火墙、不封禁 IP、"
          "不做自动阻断。")
        A("- 1.1.14 敲门网关通道只读第三方网关落盘的结构化 JSON，按字段白名单提取；"
          "字段缺失留空、协议无法确认标「未识别」，不猜测、不补齐。")
        A("- 认证被拒 / WAF 拦截 / 授信通过都只是网关记录的事实，不是威胁情报结论；"
          "是否构成攻击需结合同一 IP 的后续行为人工判断。")
        A("- 本日志只包含本设备日志产生的事实数据，不含任何自绘边界 / 国界 / "
          "行政区划轮廓，也不上传任何数据。")
        A("- 统计窗口 %s；所有数字来自本机 SQLite 聚合，"
          "刷新瞬间可能因滑动窗口与缓存存在小幅差异。" % RANGE_NAME.get(rng, rng))
    section("7. 数据口径与免责声明", s7)

    # ---- 8. 给 AI 的处置建议模板 ----
    def s8():
        A("1. 先看第 1 节确认异常占比，再对照第 3 节逐条判断是否真是攻击"
          "（把正常爬虫、健康检查、自己人的登录失败排除掉）。")
        A("2. 第 2 节里「异常次数」高、且归属与业务无关、集中在少数端口的 IP，"
          "优先列为可疑来源。")
        A("3. 第 6 节的峰值时间若与第 3 节时间戳吻合，考虑是集中扫描 / 爆破；"
          "若只是平稳高频，更可能是常态访问。")
        A("4. 结论里请区分「日志可直接证明」与「需要我进一步核实」两类，"
          "不要替我下确定性判断。")
        A("5. **任何封禁 / 改端口 / 改防火墙的操作，请输出为建议命令由我确认，"
          "本应用不会自动执行。**")
    section("8. 给 AI 的分析与处置建议提示", s8)

    A("")
    A("---")
    A("")
    A("文件由 IP 动态感知自动生成 · 生成于 %s · 只观测，不处置。" % _ts(now))
    return "\n".join(L) + "\n"


# ---------------- 落盘 ----------------
def write_summary(app, directory, text):
    """原子写 latest.md + 按天归档（同天覆盖，不自动删除任何历史文件）。"""
    ok, reason, real = validate_dir(directory)
    if not ok:
        raise ValueError(reason)
    data = text.encode("utf-8")
    latest = os.path.join(real, LATEST_NAME)
    tmp = latest + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, latest)
    arc = os.path.join(real, ARCHIVE_PREFIX + time.strftime("%Y%m%d") + ".md")
    atmp = arc + ".tmp"
    with open(atmp, "wb") as f:
        f.write(data)
    os.replace(atmp, arc)
    return {"dir": real, "latest": latest, "archive": arc,
            "bytes": len(data), "at": time.time(),
            "name": LATEST_NAME}


class SummaryWriter(object):
    """后台定时自动生成。检查周期 30 秒，真正写入间隔由配置决定。"""

    def __init__(self, app):
        self.app = app
        self.lock = threading.Lock()
        self.stop_evt = threading.Event()
        self.last_at = 0.0
        self.last_file = ""
        self.last_size = 0
        self.last_error = ""
        self.writes = 0
        threading.Thread(target=self._loop, name="ipsense-summary", daemon=True).start()

    def stop(self):
        self.stop_evt.set()

    def _interval(self, cfg):
        try:
            return max(1, min(1440, int(cfg.get("summary_interval", 5) or 5))) * 60
        except Exception:
            return 300

    def _loop(self):
        while not self.stop_evt.is_set():
            if self.stop_evt.wait(30):
                break
            try:
                cfg = self.app.settings.all()
                if not cfg.get("summary_enabled", True):
                    continue
                d = str(cfg.get("summary_dir", "") or "").strip()
                if not d:
                    continue
                if time.time() - self.last_at < self._interval(cfg):
                    continue
                self.generate(d, cfg.get("summary_range", "24h"))
            except Exception as e:
                with self.lock:
                    self.last_error = str(e)

    def generate(self, directory, rng="24h"):
        text = build_summary(self.app, rng)
        info = write_summary(self.app, directory, text)
        with self.lock:
            self.last_at = info["at"]
            self.last_file = info["latest"]
            self.last_size = info["bytes"]
            self.last_error = ""
            self.writes += 1
        return info

    def mark(self, info, err=""):
        with self.lock:
            if err:
                self.last_error = err
            elif info:
                self.last_at = info.get("at", 0)
                self.last_file = info.get("latest", "")
                self.last_size = info.get("bytes", 0)
                self.last_error = ""

    def status(self, cfg):
        d = str(cfg.get("summary_dir", "") or "").strip()
        ok, reason, real = (False, "尚未设置保存位置", "")
        if d:
            ok, reason, real = validate_dir(d)
        with self.lock:
            return {
                "dir": d, "dir_ok": ok, "dir_reason": reason, "real_dir": real,
                "enabled": bool(cfg.get("summary_enabled", True)),
                "interval": max(1, min(1440, int(cfg.get("summary_interval", 5) or 5))),
                "range": cfg.get("summary_range", "24h"),
                "latest": os.path.join(d, LATEST_NAME) if d else "",
                "latest_name": LATEST_NAME,
                "last_at": self.last_at, "last_file": self.last_file,
                "last_size": self.last_size, "last_error": self.last_error,
                "writes": self.writes,
                "next_at": (self.last_at + self._interval(cfg))
                           if (d and ok and cfg.get("summary_enabled", True)
                               and self.last_at) else 0,
            }
