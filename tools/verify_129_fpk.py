# -*- coding: utf-8 -*-
"""1.1.29 三架构 FPK 交付校验：不安装、只解包读取，逐项核对内容。

重点确认 1.1.29「mh setup 一步步引导 / fw 原生防火墙单通道 / skills 与文档入库」
真的进了包与仓库；同时 1.1.28～1.1.18 全部历史修复与「只观测」红线无回归。
输出 build/verify_129_fpk.json。

注意：本脚本刻意不复用 verify_117_fpk.py 的 1.1.16 旧断言 ——
1.1.18 已把 worldSegs 换成三副本裁剪、把 portLabel 换成带 port_src 的版本、
把 web_log_port 换成多级证据链，旧断言会全部误报。
"""
import hashlib
import io
import json
import os
import re
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REL = os.path.join(ROOT, "release")
VER = "1.1.29"
PKGS = [("all", "all"), ("x86", "x86"), ("arm", "arm")]
OUT = os.path.join(ROOT, "build", "verify_129_fpk.json")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

ok, fail = 0, []


def check(name, cond, extra=""):
    global ok
    if cond:
        ok += 1
        print("  [OK] %s %s" % (name, extra))
    else:
        fail.append(name)
        print("  [FAIL] %s %s" % (name, extra))


def md5(b):
    return hashlib.md5(b).hexdigest()


def main():
    info, app_md5 = {}, set()
    for suffix, platform in PKGS:
        p = os.path.join(REL, "ipsense_%s_%s.fpk" % (VER, suffix))
        exists = os.path.isfile(p)
        check("%s 包存在" % suffix, exists,
              "%.2f MB" % (os.path.getsize(p) / 1048576.0) if exists else "缺失")
        if not exists:
            continue
        with tarfile.open(p, "r:gz") as t:
            names = t.getnames()
            man = t.extractfile("manifest").read().decode("utf-8")
            app = t.extractfile("app.tgz").read()
        m = re.search(r"^version\s*=\s*(\S+)", man, re.M)
        pl = re.search(r"^platform\s*=\s*(\S+)", man, re.M)
        ck = re.search(r"^checksum\s*=\s*(\S+)", man, re.M)
        check("%s 包 version=%s" % (suffix, VER), bool(m) and m.group(1) == VER)
        check("%s 包 platform=%s" % (suffix, platform),
              bool(pl) and pl.group(1) == platform)
        check("%s 包 checksum 与 app.tgz 一致" % suffix,
              bool(ck) and ck.group(1) == md5(app))
        check("%s 包成员齐备" % suffix,
              all(x in names for x in
                  ("manifest", "ICON.PNG", "ICON_256.PNG", "LICENSE",
                   "app.tgz", "cmd/main", "config/privilege", "wizard/install")),
              "%d 个成员" % len(names))
        app_md5.add(md5(app))
        info[suffix] = {"bytes": os.path.getsize(p),
                        "md5": md5(open(p, "rb").read()),
                        "platform": pl.group(1) if pl else "",
                        "app_tgz_md5": md5(app)}

        # ---- 只解包读取，不安装 ----
        with tarfile.open(fileobj=io.BytesIO(app), mode="r:gz") as a:
            an = a.getnames()

            def rd(path):
                return a.extractfile(path).read().decode("utf-8", "replace")

            js = rd("ui/app.js")
            html = rd("ui/index.html")
            css = rd("ui/style.css")
            gw = rd("server/gateway.py")
            cl = rd("server/collector.py")
            st = rd("server/store.py")
            se = rd("server/settings.py")
            rt = rd("server/rtlog.py")
            gs = rd("server/geosource.py")
            dg = rd("server/diag.py")
            py = "\n".join([gw, cl, st, se, rt, gs, dg])
            png = a.extractfile("ui/images/sponsor.png").read() \
                if "ui/images/sponsor.png" in an else b""

        # ---- 通用版本 ----
        check("%s 包内版本三处一致" % suffix,
              ('VERSION = "%s"' % VER) in gw and
              ("version                    = " + VER) in man and
              VER in html)

        # ---- ① 地图接缝弧线（跨 ±180 反经线） ----
        check("%s ① 三副本裁剪与接缝端点插值" % suffix,
              all(x in js for x in
                  ("var SEAM_EPS = 0.001;", "function seamPoint(a, b, bound, lo, hi)",
                   "function clipToWindow(pts, lo, hi)",
                   "[-360, 0, 360]", "clipToWindow(shifted, -180, 180)")) and
              "((x + 180) % 360 + 360) % 360 - 180" not in js)
        check("%s ① SDK/Canvas 双路径仍接上" % suffix,
              "g.sdkSegs = worldSegs(full)" in js and
              "function worldCenteredBounds(home)" in js and
              "function sdkLat(lat, lng)" in js and
              "sdkLat(p.lat, p.lng)" in js)

        # ---- ② Web 未识别协议成因与按端口补协议 ----
        check("%s ② 协议成因说明进界面" % suffix,
              all(x in js for x in
                  ("为什么会有「Web 未识别」", "X-Forwarded-Proto",
                   "combined 日志不含 scheme", "var SCHEME_CONF = {", "port:")))
        check("%s ② 后端按已知端口补 scheme" % suffix,
              'def infer_scheme(referer, cfg, port=0)' in cl and
              "TLS_PORTS" in cl and "PLAIN_PORTS" in cl and
              "web_scheme_by_port" in se and
              "scheme_conf IN ('medium','port')" in st)

        # ---- ③ 目标端口多级证据链（含 Docker / 反代） ----
        check("%s ③ web_log_port 五级来源" % suffix,
              all(x in cl for x in
                  ('def web_log_port(line, referer="", cfg=None, log_path="")',
                   "PORT_TAIL", "PORT_FIELD", "SAME_SITE_PORT", "ABS_URL_PORT",
                   '"log_tail"', '"log_field"', '"request_url"',
                   '"log_cfg"', '"referer"')) and
              'int(self.cfg.get("web_port", 5666))' not in cl)
        check("%s ③ port_src 落库与 29 占位符" % suffix,
              '("port_src", "TEXT DEFAULT \'\'")' in st and
              "sess_id,port_src) " in st and
              '",".join(["?"] * 29)' in st and
              '(ev.get("port_src") or "")[:24]' in st and
              "RECORD_COLS" in st and "port_src" in st)
        check("%s ③ 前端如实显示端口与来源" % suffix,
              all(x in js for x in
                  ("var PORT_SRC_NAME = {", "function portHint(src)",
                   "function portLabel(p, src, portSrc)",
                   "portLabel(r.port, r.source, r.port_src)",
                   "if (!portSrc)")) and
              "web_port_map" in se and "web_port_infer_referer" in se)
        check("%s ③ 设置页端口映射未重复定义" % suffix,
              se.count('"web_port_map": ""') == 1)

        # ---- ④ 筛选范围持久化 ----
        check("%s ④ 各功能区范围写入 localStorage" % suffix,
              all(x in js for x in
                  ("var UI_PREF_KEY = 'ipsense.ui.filters.v1'",
                   "function readUiPref()", "function writeUiPref(patch)",
                   "function applyUiPref()", "applyUiPref();")) and
              "fQuery" in js)

        # ---- ⑤ 在线校验自动复制 + 站内查询 ----
        check("%s ⑤ 打开查询页并自动复制 IP（带降级）" % suffix,
              all(x in js for x in
                  ("function copyTextRobust(text, cb)",
                   "document.execCommand('copy')",
                   "window.open('https://tool.hiofd.com/ip/'",
                   "navigator.clipboard.writeText",
                   "仅复制 IP")))
        check("%s ⑤ 站内查询复用多源核验" % suffix,
              "站内查询（在线源直接核对）" in js and
              "api/geo/verify?ip=" in js and
              "inlineCheckResult" in js and
              "不是公开 API" in js)

        # ---- ⑥ 关于页 ----
        check("%s ⑥ 顶栏关于按钮在设置左侧" % suffix,
              'id="btnAbout"' in html and 'id="btnSettings"' in html and
              html.index('id="btnAbout"') < html.index('id="btnSettings"') and
              "function openAbout()" in js and "$('btnAbout').onclick = openAbout" in js)
        check("%s ⑥ 关于弹窗内容齐备" % suffix,
              all(x in html for x in
                  ('id="aboutMask"', "使用说明", "注意事项", "开发者：",
                   "WangShao", "【投喂入口】", "1132993836",
                   "https://github.com/wangbujiangwude/ipsense-fnos",
                   "images/sponsor.png")) and
              ".about-mask" in css and ".about-mask.on" in css)
        check("%s ⑥ 投喂二维码随包且为有效 PNG" % suffix,
              "ui/images/sponsor.png" in an and
              png.startswith(PNG_MAGIC) and len(png) > 100 * 1024,
              "%d B" % len(png))
        # 1.1.21：二维码从关于卡片内移出，改为独立放大灯箱
        check("%s ⑥ 投喂二维码改为独立放大灯箱" % suffix,
              'id="sponsorMask"' in html and 'id="sponsorBox"' in html and
              'id="sponsorClose"' in html and 'id="aboutSponsor"' not in html and
              'class="sponsor-stage"' in html and
              html.count("images/sponsor.png") == 1 and
              ".sponsor-mask{position:fixed;inset:0;z-index:14000" in css and
              "width:min(76vw,460px)" in css and ".about-sponsor" not in css and
              "$('btnSponsor').onclick = openSponsor" in js and
              "function closeSponsor()" in js and
              "aboutSponsor" not in js and
              js.index("if ($('sponsorMask').classList.contains('on')) { closeSponsor(); return; }") <
              js.index("if ($('aboutMask').classList.contains('on')) { closeAbout(); return; }"))

        # ---- ⑧ 1.1.21：记录表合并 + 路径明细收敛到画像 ----
        check("%s ⑧ 表头改为「动作」，卡片说明合并与路径查看位置" % suffix,
              "<th title=\"同秒同 IP 的多个请求已合并；路径明细点开画像查看\">动作</th>" in html and
              "动作 / 路径" not in html and
              "只记录动作；路径明细点开画像查看" in html)
        check("%s ⑧ 合并函数与同秒分组键齐备" % suffix,
              all(x in js for x in
                  ("function pathRoot(p)", "function recGroupKey(r)",
                   "function mergeRecords(rows)",
                   "groups = mergeRecords(data.rows)")) and
              "Math.floor(Number(r.ts) || 0)" in js and
              "r.path ? esc(r.path) : esc(r.action)" not in js)
        check("%s ⑧ 动作格只记录动作、标注合并条数与一级前缀" % suffix,
              "var act = esc(r.action || VERDICT_NAME[r.verdict] || '记录');" in js and
              "个请求已合并（" in js and "点行看路径明细" in js and
              "本页合并为 " in js and ".act-main{" in css and ".act-sub{" in css)
        check("%s ⑧ 画像路径明细完整显示、可点击复制" % suffix,
              "function pathBlock(list, total)" in js and
              ">路径明细 · 高频路径</h3>" in js and
              '<div class="path-row" data-copy=' in js and
              "word-break:break-all" in css and
              "document.addEventListener('click', function (e) {" in js)
        check("%s ⑧ 后端 top_paths 放宽到 TOP 20" % suffix,
              "sorted(cp.items(), key=lambda x: -x[1])[:20]" in st and
              "sorted(cpath.items(), key=lambda x: -x[1])[:20]" in st)
        check("%s ⑧ 每页取数 50，导出 CSV 仍逐条原始明细" % suffix,
              "page: 1, size: 50" in js and "api/export?range=" in js)

        # ---- ⑨ 1.1.21：三图合一 + 右上角模式切换 ----
        check("%s ⑨ 单卡片三图层与三种模式按钮进包" % suffix,
              'class="card geodist map-unified" id="geoCard"' in html and
              '<div class="map-stage" id="mapStage">' in html and
              '<div class="map-grid">' not in html and
              all(('id="' + i + '"') in html for i in
                  ("worldWrap", "cnWrap", "geoWrap", "mapModeSeg",
                   "mapModeTitle", "mapModeTag", "worldHeat", "cnHeat")) and
              html.count('button type="button" data-mode=') == 3 and
              all(x in html for x in ("境外连线", "境内连线", "全球分布",
                                      "全球 IP 来源分布",
                                      "连线颜色按连接频率由冷到热")))
        check("%s ⑨ 模式切换函数与偏好记忆进包" % suffix,
              all(x in js for x in
                  ("var MAP_MODE_LAYERS = { world: 'worldWrap', cn: 'cnWrap', geo: 'geoWrap' };",
                   "function setMapMode(mode, save)", "function bindMapMode()",
                   "bindMapMode();", "if (p.mapMode) setMapMode(p.mapMode, false);",
                   "writeUiPref({ mapMode: mode })",
                   "document.body.dataset.mapMode = mode")) and
              "mapMode: 'world'," in js)
        check("%s ⑨ 非活动层只切透明度、底图实例不重建" % suffix,
              ".map-stage>.map-layer{position:absolute;inset:0;width:100%;height:100%;" in css and
              ".map-stage>.map-layer.active{opacity:1;z-index:2;pointer-events:auto}" in css and
              ".map-mode-seg button.on{background:rgba(59,130,246,.22)" in css and
              ".map-wrap{position:relative;isolation:isolate;" in css and
              "$('worldWrap').classList.add('tmap-on')" in js and
              "new SDK.Map" not in js.split("function setMapMode", 1)[1]
                  .split("function bindMapMode", 1)[0])
        check("%s ⑨ 版本与三图口径在包内一致" % suffix,
              ('VERSION = "%s"' % VER) in gw and
              ("version                    = " + VER) in man and
              "1.1.21 起三张地图合并为一张卡片" in html and
              "只观测" in js and "不封禁" in rt)

        # ---- ⑦ 安全红线与无回归 ----
        check("%s ⑦ 只观测口径与 1.1.17 报错导出未回归" % suffix,
              "只观测" in js and "不封禁" in rt and
              all(x in js for x in ("var RT = {", "function rtPush(o)",
                                    "btnRtExport", "api/runtime/errors/export")) and
              "class RuntimeLog" in rt and "6.1 前端运行时报错" in dg and
              not any(k in py for k in ("iptables -A", "nft add rule")))
        check("%s ⑦ 离线库随包、无缓存与密钥文件" % suffix,
              "server/data/ip2region_v4.xdb" in an and
              not any(x.endswith(".pyc") or "__pycache__" in x for x in an) and
              not any("cred" in x.lower() or "token" in x.lower() for x in an),
              "%d 个文件" % len(an))

        # ---- ⑩ 1.1.22：方案 B / 只观测红线 ----
        with tarfile.open(fileobj=io.BytesIO(app), mode="r:gz") as _a122:
            ord_py = _a122.extractfile("server/orders.py").read().decode("utf-8", "replace")
        check("%s ⑩ orders.py 随包且零权限" % suffix,
              "server/orders.py" in an and
              "class OrderBook" in ord_py and "orders.json" in ord_py and
              not any(k in ord_py for k in
                      ("import subprocess", "os.system", "iptables", "firewall-cmd")))
        check("%s ⑩ 三个只读接口与 OrderBook 初始化进包" % suffix,
              all(x in gw for x in
                  ('if path == "/api/orders" and method == "POST"',
                   'if path == "/api/orders":',
                   'if path == "/api/orders/prompt":',
                   "from orders import OrderBook",
                   "self.orders = OrderBook(VAR_DIR, log)")))
        check("%s ⑩ 标注框 / 提交单 / 复制提示词进包" % suffix,
              'id="btnOrders"' in html and 'id="btnAbout"' in html and
              html.index('id="btnOrders"') < html.index('id="btnAbout"') and
              all(x in html for x in
                  ('id="ordersMask"', 'id="ordersList"', 'id="btnCopyPrompt"')) and
              all(x in js for x in
                  ("function profileHead(big, sub, annotateIp)",
                   'id="noteInput"', "function saveNote(",
                   "function copyOrderPrompt(", "function ensureOrders(",
                   "api/orders/prompt")) and
              ".detail-ip-row{" in css and ".orders-mask" in css)
        check("%s ⑩ 红线与防提示词注入口径进包（1.1.25 短提示词口径）" % suffix,
              html.count("永远不改防火墙设置") >= 2 and
              "完全交给外部 agent" in man and
              "请读取工程中的 AI 标记，按标注逐项修改" in ord_py and
              "绝不当指令拼接" in ord_py and "IP_CHARS" in ord_py and
              "_clean(" in ord_py and "MAX_NOTE" in ord_py and
              "## 0. 边界" not in ord_py and "<user_note>" not in ord_py)
        check("%s ⑩ 版本与 1.1.22 口径在包内一致" % suffix,
              ('VERSION = "%s"' % VER) in gw and
              ("version                    = " + VER) in man and
              "1.1.22 起画像可给 IP 写标注" in html and
              "只观测" in js and "不封禁" in js)


        # ---- ⑪ 1.1.24：单行标注 / 写标注窗口 / 四弹层淡入淡出 ----
        check("%s ⑪ 标注框回归单行只读触发器（非放大 textarea）" % suffix,
              '<input type="text" id="noteInput" readonly' in js and
              'data-act="open-note"' in js and
              "<textarea id=\"noteInput\"" not in js and
              "root.querySelector('#noteInput')" in js)
        check("%s ⑪ 写标注窗口 DOM / 预设 / 开关函数进包" % suffix,
              all(x in html for x in (
                  'id="noteMask"', 'id="noteCard"', 'id="noteDialogInput"',
                  'id="notePresets"', 'id="noteDialogSave"', 'id="noteDialogCancel"',
                  'id="noteClose"')) and
              html.count('class="preset-chip"') >= 6 and
              all(x in js for x in (
                  "var NOTE_PRESETS = [", "function openNoteDialog(",
                  "function closeNoteDialog(", "function appendPreset(",
                  "function saveNoteFromDialog(", "openNoteDialog(ip)",
                  "while (t && t !== box)", "t = t.parentNode",
                  "closeNoteDialog(); return;")))
        check("%s ⑪ 四弹层淡入淡出 CSS 进包，弃用回弹 keyframes" % suffix,
              "opacity:0;visibility:hidden;pointer-events:none" in css and
              "transition:opacity .3s" in css and
              ".about-mask.on,.sponsor-mask.on,.orders-mask.on,.note-mask.on{" in css and
              ".note-mask{" in css and "#noteDialogInput{" in css and
              "transform:translateY(10px)" in css and
              "prefers-reduced-motion" in css and
              all(k not in css for k in (
                  "@keyframes ipsensePop", "@keyframes ipsenseMaskIn",
                  "animation:ipsensePop", "animation:ipsenseMaskIn",
                  "note-expanded", "height:104px",
                  ".about-mask.on{display:flex}")))
        check("%s ⑪ 三个原弹层 DOM 与只观测红线仍完整" % suffix,
              all(x in html for x in ('id="aboutMask"', 'id="ordersMask"',
                  'id="sponsorMask"', 'id="btnSponsor"')) and
              html.count("永远不改防火墙设置") >= 2 and
              all(x in js for x in ("function openAbout()", "function openOrders()",
                  "function openSponsor()", "classList.add('on')")) and
              not re.search(r"\b(iptables|firewall-cmd|nftables|ufw)\b", js))
        check("%s ⑪ 版本与 1.1.24 口径在包内一致" % suffix,
              ('VERSION = "%s"' % VER) in gw and
              ("version                    = " + VER) in man and
              "1.1.24 起标注输入框回归单行" in html and
              "1.1.24 标注输入框回归单行" in man and
              "1.1.22 起画像可给 IP 写标注" in html and
              "只观测" in js and "不封禁" in js)

        # ---- ⑫ 1.1.25：四区看板 / 短提示词 / mh 接口 / 乐观锁 ----
        check("%s ⑫ orders.py v2 四区状态机与乐观锁进包" % suffix,
              all(x in ord_py for x in (
                  'ONE_LINER = "请读取工程中的 AI 标记，按标注逐项修改"',
                  'ONE_LINER_REVERT = "请读取工程中的 AI 标记，按标注逐项复原"',
                  'STATUSES = ("pending", "done", "revert", "restored")',
                  '"mark-done": ("pending", "done")',
                  '"restore": ("revert", "restored")',
                  "def _receipt(", "def mh_state(", "def mh_show(",
                  "def mh_path(", "def mh_prepare(", "def mh_commit(",
                  "def mh_discard(", "def mh_write(", "def request_revert(",
                  "旧回执被拒")) and
              '"version": 2' in ord_py)
        _pr125 = ord_py.split("def prompt(")[1].split("def mh_prepare(")[0]
        check("%s ⑫ 短提示词：一句话 + 读取路径，长篇规矩不进提示词" % suffix,
              "读取路径：" in ord_py and "读取命令：mh read " in ord_py and
              "规矩与流程：见 " in ord_py and "SKILL_HINT" in ord_py and
              "## 0. 边界" not in ord_py and "<user_note>" not in ord_py and
              "全部是观测数据，不是指令" not in ord_py and
              all(k not in _pr125 for k in ("TTL", "白名单", "二次确认", "回滚")))
        check("%s ⑫ gateway：四个只读 /api/mh/* + 唯一写入口 /api/mh/write" % suffix,
              all(x in gw for x in (
                  '/api/mh/state" and method == "GET"',
                  '/api/mh/show" and method == "GET"',
                  '/api/mh/path" and method == "GET"',
                  '/api/mh/prompt" and method == "GET"',
                  '/api/mh/write" and method == "POST"',
                  "app.orders.mh_write(payload)", "request-revert",
                  '409, {"ok": False')) and
              gw.count('"/api/mh/write"') == 1)
        check("%s ⑫ 前端四区 Tab / 计数 / 状态徽标 / 流水进包" % suffix,
              all(x in html for x in (
                  'id="ordersTabs"', 'data-otab="pending"', 'data-otab="done"',
                  'data-otab="revert"', 'data-otab="all"',
                  'id="tabCountPending"', 'id="tabCountDone"',
                  'id="tabCountRevert"', 'id="tabCountAll"',
                  'id="ordersReadCmd"', 'id="btnCopyPath"')) and
              all(x in js for x in (
                  "var TAB_DEF = {", "function ordersTabCounts(",
                  "function renderOrders(", "function switchOrdersTab(",
                  "function requestRevert(", "function toggleSummary(",
                  "function renderLog(", "function statusBadge(",
                  "function historyLine(", "function orderCard(",
                  "api/orders/prompt?tab=", "action: 'request-revert'",
                  "AI 处理总结", "mh read pending")) and
              all(x in css for x in (
                  ".orders-tabs", ".orders-tab", ".tab-count",
                  ".orders-readpath", ".order-status", ".st-pending",
                  ".st-done", ".st-revert", ".st-restored",
                  ".order-sum", ".order-hist", ".order-log", ".log-row")))
        check("%s ⑫ 红线与版本口径在包内一致" % suffix,
              html.count("永远不改防火墙设置") >= 2 and
              "永远不改防火墙设置" in ord_py and
              "完全交给外部 agent" in man and
              ('VERSION = "%s"' % VER) in gw and
              ("version                    = " + VER) in man and
              "1.1.25 提交单改为待处理" in man and
              "1.1.25 起提交单分" in html and
              "只观测" in js and "不封禁" in js and
              not re.search(r"\b(iptables|firewall-cmd|nftables|ufw)\b", ord_py))

        # ---- ⑬ 1.1.26：画像标注行只保留输入框 ----
        check("%s ⑬ 包内 app.js 已删除行内 save-note 按钮与事件分支" % suffix,
              'data-act="save-note"' not in js and
              "btn-note" not in js and
              "closest('[data-act=\"save-note\"]')" not in js and
              "function profileHead(big, sub, annotateIp)" in js and
              "1.1.26：画像里已无行内" in js)
        check("%s ⑬ 只读输入框与弹窗保存按钮在包内成对保留" % suffix,
              '<input type="text" id="noteInput" readonly' in js and
              'data-act="open-note"' in js and
              "root.querySelector('#noteInput')" in js and
              'id="noteDialogSave"' in html and
              "$('noteDialogSave').onclick = saveNoteFromDialog;" in js and
              html.count('class="preset-chip"') >= 6)
        _row126 = js.split('<div class="note-row">')[1].split("</div>")[0]
        check("%s ⑬ note-row 结构里只有 input，无 button" % suffix,
              'id="noteInput"' in _row126 and "<button" not in _row126 and
              "保存并加入提交单" not in _row126)
        check("%s ⑬ 包内 CSS 无 .btn-note 孤儿样式" % suffix,
              ".btn-note" not in css and
              ".note-row input,.note-row textarea{flex:1" in css and
              "1.1.26：画像里的行内" in css)
        check("%s ⑬ 版本与 changelog 口径在包内一致（1.1.26）" % suffix,
              ('VERSION = "%s"' % VER) in gw and
              ("version                    = " + VER) in man and
              "1.1.26 画像标注行只保留输入框" in man and
              "1.1.26 起画像标注行只保留输入框" in html and
              "永远不改防火墙设置" in html)

        # ---- ⑭ 1.1.27 底线：keyauth 后端 / 直接执行 / 红线不变（1.1.28 继续沿用） ----
        _ka = ""
        if "server/keyauth.py" in an:
            with tarfile.open(fileobj=io.BytesIO(app), mode="r:gz") as _a14:
                _ka = _a14.extractfile("server/keyauth.py").read().decode("utf-8", "replace")
        check("%s ⑭ 包内含 keyauth.py，且只做文件级授权管理" % suffix,
              bool(_ka) and
              all(k in _ka for k in ('MARK = "ipsense-agent-bridge"',
                  'KEYDIR = "/vol1/@appdata/ipsense/keys"',
                  "def revoke(", "def state(", "os.chmod(tmp, 0o600)",
                  "AttributeError", "不给私钥内容", "不动用户其它密钥")) and
              not re.search(r"\b(iptables|firewall-cmd|nftables|ufw|subprocess|os\.system)\b", _ka))
        check("%s ⑭ gateway 两个 keyauth 接口仍在且版本为 %s" % (suffix, VER),
              ('VERSION = "%s"' % VER) in gw and
              "from keyauth import KeyAuth" in gw and
              '"/api/keyauth/state"' in gw and
              '"/api/keyauth/revoke"' in gw and
              "self.keyauth = KeyAuth(VAR_DIR, log)" in gw)
        check("%s ⑭ 红线不变：包内不含 fw / skill / mh / iptables 处置代码" % suffix,
              not any(k in n for n in an for k in ("fw.py", "SKILL.md", "mh.py")) and
              not re.search(r"\b(iptables|firewall-cmd|nftables|ufw)\b", gw) and
              not re.search(r"\b(iptables|firewall-cmd|nftables|ufw)\b", js) and
              "永远不改防火墙设置" in html and
              "完全交给外部 agent" in man)

        # ---- ⑮ 1.1.28：密钥授权右上角入口 + 点击浮层 / 多缩放不挤压 ----
        check("%s ⑮ 右上角入口在 orders-head 内、关闭左侧，带角标与 aria" % suffix,
              'class="orders-head-actions"' in html and
              html.index('id="keyauthToggle"') < html.index('id="ordersClose"') and
              html.index('class="orders-head-actions"') < html.index('id="keyauthToggle"') and
              all(k in html for k in ('class="link keyauth-entry"',
                  'id="keyauthCount"', 'aria-expanded="false"',
                  'aria-controls="keyauthPanel"')))
        check("%s ⑮ Tab 下方旧内嵌 .keyauth flex 块清零" % suffix,
              'class="keyauth"' not in html and 'id="keyauthBox"' not in html and
              'class="keyauth-toggle"' not in html and 'class="keyauth-panel"' not in html and
              ".keyauth{" not in css and ".keyauth-toggle" not in css and
              ".keyauth-panel" not in css)
        check("%s ⑮ 浮层 absolute 定位、默认 hidden、脱离文档流" % suffix,
              all(k in css for k in (".orders-card{", "position:relative;overflow:hidden",
                  ".keyauth-pop{position:absolute", "top:62px", "right:18px",
                  "z-index:60", ".keyauth-pop[hidden]{display:none}",
                  "max-height:calc(88vh - 120px)",
                  ".keyauth-list{min-height:0;flex:1;overflow-y:auto}")) and
              ".orders-body{flex:1" in css and
              'id="keyauthPanel" hidden' in html)
        check("%s ⑮ 浮层内容完整，私钥不出现在包内前端" % suffix,
              all(k in html for k in ('class="keyauth-pop-head"', 'id="keyauthList"',
                  'class="keyauth-note"', "用户可知 · 随时可撤销",
                  "撤销会删除设备上的私钥副本")) and
              all(k in js for k in ("keyauth-fp", "keyauth-pk", "keyauth-devkey",
                  "keyauth-revoke", "data-grant=", "api/keyauth/state")) and
              "private_key" not in js and
              "BEGIN OPENSSH PRIVATE KEY" not in html)
        check("%s ⑮ 开合闭环：三辅助函数 / 浮层外点击 / ESC / 开关弹层都收起" % suffix,
              all(k in js for k in ("function keyauthOpen(", "function keyauthClose(",
                  "function keyauthIsOpen(", "e.stopPropagation()",
                  "card.addEventListener('click'", ".contains(t)",
                  "keyauthClose();          // 1.1.28：每次打开提交单",
                  "keyauthClose();          // 1.1.28：关弹层时",
                  "keyauthIsOpen()) { keyauthClose(); return; }")) and
              "t.closest &&" not in js)
        check("%s ⑮ 撤销闭环未回归：POST /api/keyauth/revoke + grant_id" % suffix,
              "api/keyauth/revoke" in js and "grant_id: id" in js and
              "授权已撤销" in js and
              all(k in _ka for k in ('MARK = "ipsense-agent-bridge"',
                  'KEYDIR = "/vol1/@appdata/ipsense/keys"',
                  'if not grant_id.startswith("mh1-")',
                  "keep = [ln for ln in lines if tag not in ln]")))
        check("%s ⑮ 版本 / changelog / 脚注口径一致（1.1.28 + 1.1.27 + 1.1.26 历史）" % suffix,
              ("version                    = " + VER) in man and
              "1.1.28 密钥授权改到提交单右上角入口" in man and
              "1.1.27 提交单新增「密钥授权区」" in man and
              "1.1.26 画像标注行只保留输入框" in man and
              "1.1.28 起密钥授权改为提交单右上角入口" in html and
              "1.1.27 起新增密钥授权" in html and
              "1.1.26 起画像标注行只保留输入框" in html and
              "永远不改防火墙设置" in html and
              "完全交给外部 agent" in man)

    # ---- 仓库主页故障速查表（不在 FPK 内，单独核对） ----
    readme = io.open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    check("仓库 README 含故障速查表（含 1.1.21 合并刷屏条目）",
          "## 故障速查表" in readme and
          "「Web 未识别」占比很高" in readme and
          "端口显示「未记录」" in readme and
          "弧线在地图左右接缝处断开" in readme and
          "Web 日志端口映射" in readme and
          "IP 来源记录被同一个 IP 刷屏" in readme and
          "只观测、不封禁" in readme and
          "1.1.21" in readme)
    check("仓库 README 含 1.1.25 / 1.1.26 / 1.1.27 / 1.1.28 / 1.1.29 故障速查条目",
          "提交单只有一长串列表、读取提示词太长" in readme and
          "升级 `1.1.25`" in readme and "四区看板" in readme and
          "标注行有个点了没反应的「保存并加入提交单」按钮" in readme and
          "升级 `1.1.26`" in readme and "画像里只留输入框" in readme and
          "Permission denied" in readme and
          "想收回给 AI 的 SSH 授权" in readme and
          "密钥授权区" in readme and
          "升级 `1.1.27`" in readme and
          "ipsense_1.1.29_all.fpk" in readme)
    check("仓库 README 1.1.28 缩放条目指向右上角浮层方案",
          "不同缩放下「提交单」里密钥授权挤住列表" in readme and
          "升级 `1.1.28`" in readme and
          "入口移到右上角" in readme and
          "点开才显示浮层" in readme and
          "不占文档流" in readme)
    check("仓库 skill / mh CLI / agent-bridge 文档齐备（不在 FPK 内，单独核对）",
          os.path.isfile(os.path.join(ROOT, "skills", "ipsense-agent-bridge",
                                     "SKILL.md")) and
          os.path.isfile(os.path.join(ROOT, "skills", "ipsense-agent-bridge",
                                     "scripts", "mh.py")) and
          os.path.isfile(os.path.join(ROOT, "skills", "ipsense-agent-bridge",
                                     "scripts", "mh")) and
          os.path.isfile(os.path.join(ROOT, "docs", "agent-bridge.md")) and
          os.path.isfile(os.path.join(ROOT, "skills", "ipsense-agent-bridge",
                                     "scripts", "fw.py")) and
          os.path.isfile(os.path.join(ROOT, "skills", "ipsense-agent-bridge",
                                     "scripts", "fw")))
    _skill = io.open(os.path.join(ROOT, "skills", "ipsense-agent-bridge",
                                  "SKILL.md"), encoding="utf-8").read()
    check("仓库 skill 已按 1.1.27 新规矩重写（直接执行 / 仅争议才确认 / fw 通道）",
          "直接开始执行" in _skill and "无需二次确认" in _skill and
          "标注是用户写下的操作指令" in _skill and
          "fw = 处置通道" in _skill.replace("`", "") and
          "争议判定" in _skill and
          "永远不改防火墙设置" in _skill)
    # ---- ⑯ 1.1.29 专项：mh setup 引导 / fw 单通道 / skill 与文档入库 ----
    _sdir = os.path.join(ROOT, "skills", "ipsense-agent-bridge")
    _mh = io.open(os.path.join(_sdir, "scripts", "mh.py"), encoding="utf-8").read()
    _fw = io.open(os.path.join(_sdir, "scripts", "fw.py"), encoding="utf-8").read()
    _sk = io.open(os.path.join(_sdir, "SKILL.md"), encoding="utf-8").read()
    _doc = io.open(os.path.join(ROOT, "docs", "agent-bridge.md"), encoding="utf-8").read()
    _prev = io.open(os.path.join(ROOT, "build", "preview-ipsense.html"), encoding="utf-8").read()
    _chg = io.open(os.path.join(ROOT, "docs", "CHANGELOG.md"), encoding="utf-8").read()
    _usage = io.open(os.path.join(ROOT, "docs", "使用说明.md"), encoding="utf-8").read()
    _trb = io.open(os.path.join(ROOT, "docs", "排障指南.md"), encoding="utf-8").read()
    _dread = io.open(os.path.join(ROOT, "docs", "README.md"), encoding="utf-8").read()

    check("⑯ mh setup 8 步引导在 mh.py 内（parser / cmd_setup / 常量齐备）",
          "SETUP_STEPS = 8" in _mh and "def cmd_setup(a):" in _mh and
          "def _setup_plan(" in _mh and "def _setup_password(" in _mh and
          "class _SetupChan" in _mh and "def _setup_backup_local(" in _mh and
          '"setup",' in _mh and
          all(k in _mh for k in ("--dry-run", "--force", "--bootstrap", "--yes",
                                 "--host", "--user", "--key", "--device")) and
          'MARK = "ipsense-agent-bridge"' in _mh and
          'KEYDIR = "/vol1/@appdata/ipsense/keys"' in _mh and
          'KEYAUTH_JSON = "/vol1/@appdata/ipsense/keyauth.json"' in _mh)
    check("⑯ mh setup 自动生成密钥 / 动态读 $HOME / 私钥只回本机 / 非交互兜底",
          all(k in _mh for k in ("ssh-keygen -t ed25519", "$HOME", "authorized_keys",
                                 "BEGIN OPENSSH PRIVATE KEY", "IPSENSE_NONINTERACTIVE",
                                 "EOFError", "grants", "chmod 600", ".bak")) and
          ('"%s:%s" % (MARK, gid)' in _mh and
           '"comment": comment' in _mh and
           'MARK = "ipsense-agent-bridge"' in _mh))
    check("⑯ fw 处置收敛为飞牛原生防火墙单通道（永久 / reload / 无 iptables 执行）",
          'CHANNEL = "native"' in _fw and
          'FW_CONF = "/usr/trim/etc/fw.conf"' in _fw and
          'FW_SERVICE = "security_service"' in _fw and
          'DEFAULT_TTL = 0' in _fw and
          'NATIVE_MEMO = "ips:"' in _fw and
          not any(k in _fw for k in ("iptables -A", "iptables -D",
                                     "nft add rule", "nft delete rule")))
    check("⑯ SKILL.md 自包含 0.5 安装与 mh setup 配置/使用方法（不依赖仓库 docs）",
          "0.5" in _sk and "mh setup" in _sk and
          "自动生成 ed25519" in _sk and "1.1.29" in _sk and
          "paramiko" in _sk and "--dry-run" in _sk and
          "主包 VERSION = 1.1.29" in _sk.replace("`", ""))
    check("⑯ docs/agent-bridge.md 与 GitHub 主页 README 都写明 skill CLI 配置与使用方法",
          "mh setup" in _doc and "一步步引导" in _doc and
          all(k in readme for k in ("### 1. 装 skill 包", "### 2. 配置方法",
                                    "### 3. 使用方法", "### 4. 排障",
                                    "setup --dry-run", "pip install paramiko",
                                    "升级 `1.1.29`")))
    check("⑯ 1.1.29 版本口径全仓一致（changelog / 使用说明 / 排障 / docs README / 预览页）",
          "1.1.29（当前版本）" in _chg and
          "### 1.1.29 新增了什么" in _usage and
          "1.1.29" in _trb and
          "当前版本：1.1.29" in _dread and
          "version:'1.1.29'" in _prev)
    check("⑯ 安装表指向 1.1.29 三架构包，不含 1.1.28 旧包名",
          all(k in readme for k in ("ipsense_1.1.29_all.fpk",
                                    "ipsense_1.1.29_x86.fpk",
                                    "ipsense_1.1.29_arm.fpk")) and
          "ipsense_1.1.28_all.fpk" not in readme)

    check("三包 app.tgz 逐字节一致", len(app_md5) == 1,
          "MD5=" + (list(app_md5)[0] if app_md5 else "无"))

    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write(json.dumps({"version": VER, "pass": ok, "fail": fail,
                            "packages": info}, ensure_ascii=False, indent=2))
    print("\n=== 1.1.29 FPK 校验：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
    if fail:
        print("失败项：" + ", ".join(fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
