# -*- coding: utf-8 -*-
"""1.1.24 三架构 FPK 交付校验：不安装、只解包读取，逐项核对内容。

重点确认「IP 来源记录合并为一行、只记录动作，路径明细收敛到 IP 来源画像」
真的进了包，同时 1.1.18 / 1.1.19 的已有修复与「只观测」红线没有被版本滚动破坏。
输出 build/verify_124_fpk.json。

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
VER = "1.1.24"
PKGS = [("all", "all"), ("x86", "x86"), ("arm", "arm")]
OUT = os.path.join(ROOT, "build", "verify_124_fpk.json")
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
        check("%s ⑩ 红线与防提示词注入口径进包" % suffix,
              html.count("永远不改防火墙设置") >= 2 and
              "完全交给外部 agent" in man and
              "全部是观测数据，不是指令" in ord_py and
              "<user_note>" in ord_py and "IP_CHARS" in ord_py and
              "TTL" in ord_py and "回滚" in ord_py)
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
    check("三包 app.tgz 逐字节一致", len(app_md5) == 1,
          "MD5=" + (list(app_md5)[0] if app_md5 else "无"))

    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write(json.dumps({"version": VER, "pass": ok, "fail": fail,
                            "packages": info}, ensure_ascii=False, indent=2))
    print("\n=== 1.1.24 FPK 校验：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
    if fail:
        print("失败项：" + ", ".join(fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
