# -*- coding: utf-8 -*-
"""1.1.16 三架构 FPK 交付校验：不安装、只解包读取，逐项核对内容。

在 1.1.15 校验基础上，重点核对本版六项真机反馈修复确实进了包：
  ① SDK 弧线合法经度窗口（worldSegs 归一化 / sdkLat / 无 ±360 副本）
  ② 设置开关可点击（sw 的 label[for] + CSS input 铺满）
  ③ 离线库重庆误判固化订正（geo_local_fix / normalize_local_geo）
  ④ 目标端口不再冒充 5666（web_log_port / portLabel / normalize_web_ports）
  ⑤ 区级归属可回填（districtBlock / extcheck / 自定义接口）
  ⑥ 版本、三包 app.tgz 逐字节一致、无缓存与密钥
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
VER = "1.1.16"
PKGS = [("all", "all"), ("x86", "x86"), ("arm", "arm")]
OUT = os.path.join(ROOT, "build", "verify_116_fpk.json")

ok = 0
fail = []


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
    info = {}
    app_md5 = set()
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
        check("%s 包 version=%s" % (suffix, VER),
              bool(m) and m.group(1) == VER, m.group(1) if m else "无")
        check("%s 包 platform=%s" % (suffix, platform),
              bool(pl) and pl.group(1) == platform, pl.group(1) if pl else "无")
        check("%s 包 checksum 与 app.tgz 一致" % suffix,
              bool(ck) and ck.group(1) == md5(app), ck.group(1) if ck else "无")
        check("%s 包成员齐备" % suffix,
              all(x in names for x in
                  ("manifest", "ICON.PNG", "ICON_256.PNG", "LICENSE",
                   "app.tgz", "cmd/main", "config/privilege", "wizard/install")),
              "%d 个成员" % len(names))
        app_md5.add(md5(app))
        info[suffix] = {"bytes": os.path.getsize(p),
                        "md5": md5(open(p, "rb").read()),
                        "platform": pl.group(1) if pl else "",
                        "checksum": ck.group(1) if ck else ""}
        if suffix != "all":
            continue

        # ---- all 包内 app.tgz 内容逐项核对 ----
        with tarfile.open(fileobj=io.BytesIO(app), mode="r:gz") as a:
            an = a.getnames()

            def rd(name):
                return a.extractfile(name).read().decode("utf-8")

            js = rd("ui/app.js")
            css = rd("ui/style.css")
            html = rd("ui/index.html")
            py = rd("server/gateway.py")
            st = rd("server/store.py")
            cl = rd("server/collector.py")
            gs = rd("server/geosource.py")
            se = rd("server/settings.py")
            dg = rd("server/diag.py")

        # ① 弧线
        check("① SDK 弧线：worldSegs 归一化到 [-180,180]",
              "((x + 180) % 360 + 360) % 360 - 180" in js)
        check("① SDK 弧线：sdkLat 钳制已接上折线",
              "function sdkLat(" in js and "sdkLat(p.lat, p.lng)" in js)
        check("① SDK 弧线：不再生成 ±360 世界副本",
              "[-360, 0, 360]" not in js and
              re.search(r"^  function sdkLat\(", js, re.M) is not None and
              re.search(r"^    function sdkLat\(", js, re.M) is None)
        check("① Canvas 本机中心连续窗口仍在",
              "function worldCenteredBounds(" in js and "worldSegs" in js)

        # ② 开关
        check("② 开关：sw() 生成 label[for] 与 input id",
              "var id = 'sw_' + key;" in js and 'for="' in js)
        check("② 开关：CSS input 铺满整个 .switch",
              ".switch input{position:absolute;inset:0;width:100%;height:100%" in css)
        check("② 开关：装饰滑块不吃点击",
              re.search(r"\.switch i\{[^}]*pointer-events:none", css) is not None)

        # ③ 重庆误判
        check("③ 离线库订正：geo_local_fix 表与读写",
              "CREATE TABLE IF NOT EXISTS geo_local_fix" in st and
              "def local_fix" in st and "def put_local_fix" in st)
        check("③ 离线库订正：升级幂等 normalize_local_geo",
              "def normalize_local_geo" in st and "normalize_local_geo" in py)
        check("③ 离线库订正：verify 优先取订正值",
              "self.store.local_fix(ip)" in gs and
              "put_local_fix(ip, dict(geo, ip=ip))" in gs)
        check("③ 归属回写后清聚合缓存", "self.clear_cache()" in st)

        # ④ 端口
        check("④ 端口：collector 用 web_log_port 而非 web_port",
              "def web_log_port(" in cl and
              'web_log_port(referer, line)' in cl and
              "Referer 语义上就不能用来推断" in cl)
        check("④ 端口：升级幂等订正历史 5666",
              "def normalize_web_ports" in st and
              "web_port_normalized_116" in st and
              "normalize_web_ports" in py)
        check("④ 端口：前端 portLabel 显示未记录",
              "function portLabel(" in js and "未记录" in js)

        # ⑤ 区级
        check("⑤ 区级：未核验 IP 也有补全入口 districtBlock",
              "function districtBlock(" in js and
              "districtBlock(null)" in js and "districtBlock(v)" in js)
        check("⑤ 区级：在线校验入口与 tool.hiofd.com",
              'data-act="extcheck"' in js and "tool.hiofd.com/ip/" in js and
              "cp.catch(function () {})" in js)
        check("⑤ 区级：自定义 JSON 接口与 SSRF 边界",
              "def fetch_custom_district" in gs and
              "geo_district_api_enabled" in se and
              "169.254.169.254" in gs)
        check("⑤ 区级：手工回填接口仍在包里",
              "api/geo/district" in js and '"/api/geo/district"' in py)

        # 版本 / 继承能力 / 卫生
        check("版本：" + VER + " 已同步到后端与首页",
              'VERSION = "' + VER + '"' in py and VER in html)
        check("继承：1.1.15 能力无回归",
              all(x in js for x in ("S.liveScope", "canonRegion", "sdkFailHint",
                                    "btnDiagExport", "< 0.02")) and
              "def build_bundle" in dg and "DROP_CFG_KEYS" in dg)
        check("继承：离线归属库随包", "server/data/ip2region_v4.xdb" in an)
        check("包内无编译缓存 / 密钥 / 临时产物",
              not any(x.endswith(".pyc") or "__pycache__" in x for x in an) and
              not any("cred" in x.lower() or "token" in x.lower() for x in an),
              "%d 个文件" % len(an))
        check("只观测口径未被改写",
              not any(k in py for k in ("iptables -A", "nft add rule")))

    check("三包 app.tgz 逐字节一致", len(app_md5) == 1,
          "MD5=" + (list(app_md5)[0] if app_md5 else "无"))

    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write(json.dumps({"version": VER, "pass": ok, "fail": fail,
                            "packages": info}, ensure_ascii=False, indent=2))
    print("\n=== 1.1.16 FPK 校验：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
    if fail:
        print("失败项：" + ", ".join(fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
