# -*- coding: utf-8 -*-
"""1.1.15 三架构 FPK 交付校验：不安装、只解包读取，逐项核对内容。

校验点：
  * 三包存在且 manifest 的 version / platform / checksum 正确
  * checksum 等于包内 app.tgz 的真实 MD5
  * app.tgz 含 1.1.15 必须的新文件与新代码（diag.py / liveScope / worldSegs / district）
  * 三包 app.tgz 逐字节一致（纯 Python 应用不应有架构差异）
  * app.tgz 不含 __pycache__ / .pyc / 本地密钥与临时产物
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
VER = "1.1.15"
PKGS = [("all", "all"), ("x86", "x86"), ("arm", "arm")]
OUT = os.path.join(ROOT, "build", "verify_115_fpk.json")

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
        check("%s 包存在" % suffix, os.path.isfile(p),
              "%.2f MB" % (os.path.getsize(p) / 1048576.0)
              if os.path.isfile(p) else "缺失")
        if not os.path.isfile(p):
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
        info[suffix] = {"bytes": os.path.getsize(p), "md5": md5(open(p, "rb").read()),
                        "platform": pl.group(1) if pl else "",
                        "checksum": ck.group(1) if ck else ""}

        if suffix != "all":
            continue
        # all 包内 app.tgz 内容逐项核对
        with tarfile.open(fileobj=io.BytesIO(app), mode="r:gz") as a:
            an = a.getnames()
            check("app.tgz 含 1.1.15 新增 server/diag.py",
                  "server/diag.py" in an)
            js = a.extractfile("ui/app.js").read().decode("utf-8")
            html = a.extractfile("ui/index.html").read().decode("utf-8")
            py = a.extractfile("server/gateway.py").read().decode("utf-8")
            st = a.extractfile("server/store.py").read().decode("utf-8")
            dg = a.extractfile("server/diag.py").read().decode("utf-8")
        check("app.tgz 前端含长弧 / 同省 / 实时筛选 / 区级 / 诊断导出",
              all(x in js for x in
                  ("worldCenteredBounds", "worldSegs", "sdkSegs",
                   "d.dist > 90 ? 96 : 64", "< 0.02", "canonRegion",
                   "S.liveScope", "webapiamap", "sdkFailHint",
                   "exportDiag", "btnDiagExport", "api/geo/district")))
        check("app.tgz 首页含 liveScope 与 1.1.15 页脚",
              'id="liveScope"' in html and "1.1.15" in html)
        check("app.tgz 后端含 1.1.15 接口与版本",
              'VERSION = "1.1.15"' in py and
              '"/api/diag/export"' in py and '"/api/geo/district"' in py and
              "set_verifier(self.verifier)" in py)
        check("app.tgz 后端含按省细分与省份归一",
              "GeoResolver._province_key" in st and
              "COALESCE(NULLIF(province,''),'中国·未细分')" in st)
        check("app.tgz 诊断包含脱敏白名单与 scrub",
              "DROP_CFG_KEYS" in dg and "def scrub(text)" in dg)
        check("app.tgz 不含编译缓存 / 密钥 / 临时产物",
              not any(x.endswith((".pyc", "__pycache__")) or
                      "__pycache__" in x for x in an) and
              not any("cred" in x.lower() or "token" in x.lower()
                      for x in an), "%d 个文件" % len(an))

    check("三包 app.tgz 逐字节一致", len(app_md5) == 1,
          "MD5=" + (list(app_md5)[0] if app_md5 else "无"))

    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write(json.dumps({"version": VER, "pass": ok, "fail": fail,
                            "packages": info}, ensure_ascii=False, indent=2))
    print("\n=== FPK 校验：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
    if fail:
        print("失败项：" + ", ".join(fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
