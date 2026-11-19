# -*- coding: utf-8 -*-
"""1.1.19 三架构 FPK 交付校验：不安装、只解包读取，逐项核对内容。

重点确认用户 1.1.19 的七项反馈真的都进了包，且「只观测」红线与 1.1.17
运行时报错导出没有被版本滚动破坏。输出 build/verify_119_fpk.json。

注意：本脚本刻意不复用 verify_117_fpk.py 的 1.1.16 旧断言 ——
1.1.19 已把 worldSegs 换成三副本裁剪、把 portLabel 换成带 port_src 的版本、
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
VER = "1.1.19"
PKGS = [("all", "all"), ("x86", "x86"), ("arm", "arm")]
OUT = os.path.join(ROOT, "build", "verify_119_fpk.json")
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
        # 1.1.19：二维码从关于卡片内移出，改为独立放大灯箱
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

    # ---- 仓库主页故障速查表（不在 FPK 内，单独核对） ----
    readme = io.open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    check("仓库 README 含故障速查表（15 类现象）",
          "## 故障速查表" in readme and
          "「Web 未识别」占比很高" in readme and
          "端口显示「未记录」" in readme and
          "弧线在地图左右接缝处断开" in readme and
          "Web 日志端口映射" in readme and
          "只观测、不封禁" in readme and
          "1.1.19" in readme)
    check("三包 app.tgz 逐字节一致", len(app_md5) == 1,
          "MD5=" + (list(app_md5)[0] if app_md5 else "无"))

    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write(json.dumps({"version": VER, "pass": ok, "fail": fail,
                            "packages": info}, ensure_ascii=False, indent=2))
    print("\n=== 1.1.19 FPK 校验：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
    if fail:
        print("失败项：" + ", ".join(fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
