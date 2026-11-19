# -*- coding: utf-8 -*-
"""1.1.17 三架构 FPK 交付校验：不安装、只解包读取，逐项核对内容。

重点确认「运行时报错采集与一键导出」真的进了包，且 1.1.16 的六项真机修复
没有被版本滚动破坏。输出 build/verify_117_fpk.json。
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
VER = "1.1.17"
PKGS = [("all", "all"), ("x86", "x86"), ("arm", "arm")]
OUT = os.path.join(ROOT, "build", "verify_117_fpk.json")

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
        check("%s 包 version=%s" % (suffix, VER),
              bool(m) and m.group(1) == VER)
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
            gw = rd("server/gateway.py")
            dg = rd("server/diag.py")
            rt = rd("server/rtlog.py")
            cl = rd("server/collector.py")
            st = rd("server/store.py")
            gs = rd("server/geosource.py")
            py = "\n".join([gw, dg, rt, cl, st, gs])

        check("%s 包内新增 rtlog.py" % suffix,
              "server/rtlog.py" in an and "class RuntimeLog" in rt and
              "def build_export" in rt)
        check("%s 包内版本为 " % suffix + VER,
              ('VERSION = "%s"' % VER) in gw and
              ("version                    = " + VER) in man and
              VER in html)
        check("%s 包内三条运行报错路由" % suffix,
              '"/api/runtime/errors" and method == "POST"' in gw and
              '"/api/runtime/errors/export"' in gw and
              "self.rtlog = RuntimeLog(VAR_DIR)" in gw and
              "from rtlog import RuntimeLog" in gw)

        # ① 前端采集器
        check("%s ① 全局采集器与同因合并" % suffix,
              all(x in js for x in
                  ("var RT = {", "function rtPush(o)", "function rtFlush()",
                   "function rtDupWindow(kind)", "window.addEventListener('error'",
                   "unhandledrejection")))
        check("%s ① URL 参数值不落盘" % suffix,
              "function rtSafeUrl" in js and "?<参数名:" in js and
              "Math.min(60000, 5000 * RT.fails)" in js)
        check("%s ① 地图 SDK 失败单独记录" % suffix,
              "kind: 'map_sdk'" in js and "RT_HOST" in js and
              "S.tmapError" in js)
        check("%s ① 设置页两个新入口" % suffix,
              all(x in js for x in
                  ("btnRtExport", "btnRtView", "function exportRuntimeErrors()",
                   "function fetchRuntimeText()", "api/runtime/errors/export")))

        # ② 后端导出 / 诊断包 / 隐私
        check("%s ② 独立落盘与脱敏白名单" % suffix,
              "runtime_errors.jsonl" in rt and "STR_FIELDS = {" in rt and
              "from diag import scrub" in rt and "MAX_ITEMS = 500" in rt)
        check("%s ② 导出含地图 SDK 专项与明细" % suffix,
              "[2] 地图 SDK 专项" in rt and "[3] 逐条明细" in rt and
              "[4] 反馈时请一并提供" in rt)
        check("%s ② 诊断包并入 6.1 且心跳折叠" % suffix,
              "6.1 前端运行时报错" in dg and
              "from rtlog import format_section" in dg and
              "def tail_filtered" in dg and "HEARTBEAT_RE" in dg)
        check("%s ② 精确坐标 / 位置 / 私有目录剔除" % suffix,
              all(('"%s"' % k) in dg for k in
                  ("home_lat", "home_lng", "home_label", "summary_dir")))

        # ③ 1.1.16 六项修复无回归
        check("%s ③ 1.1.16 弧线 / 开关 / 端口 / 区级未回归" % suffix,
              "((x + 180) % 360 + 360) % 360 - 180" in js and
              "[-360, 0, 360]" not in js and
              "\n  function sdkLat(lat, lng)" in js and
              "function portLabel(p, src)" in js and
              "function districtBlock(" in js and
              "cp.catch(function () {})" in js and
              "def web_log_port(referer, line)" in cl and
              "def normalize_web_ports" in st and
              "CREATE TABLE IF NOT EXISTS geo_local_fix" in st)
        check("%s ③ 安全边界与只观测口径" % suffix,
              "169.254.169.254" in gs and
              "只观测" in js and "不封禁" in rt and
              not any(k in py for k in ("iptables -A", "nft add rule")))
        check("%s ③ 离线归属库随包、无缓存与密钥文件" % suffix,
              "server/data/ip2region_v4.xdb" in an and
              not any(x.endswith(".pyc") or "__pycache__" in x for x in an) and
              not any("cred" in x.lower() or "token" in x.lower() for x in an),
              "%d 个文件" % len(an))

    check("三包 app.tgz 逐字节一致", len(app_md5) == 1,
          "MD5=" + (list(app_md5)[0] if app_md5 else "无"))
    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write(json.dumps({"version": VER, "pass": ok, "fail": fail,
                            "packages": info}, ensure_ascii=False, indent=2))
    print("\n=== 1.1.17 FPK 校验：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
    if fail:
        print("失败项：" + ", ".join(fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
