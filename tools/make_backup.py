# -*- coding: utf-8 -*-
"""交付备份四件套：FPK / 源码包 / 数据资产包 / 更新日志 + MANIFEST。

本应用是 fnOS 原生 FPK、零容器，因此「Docker 镜像 tar」不适用；
以「数据资产包」（离线归属库 + 许可 + 校验）作为对应交付物，并在 MANIFEST 明示。
"""
import os
import re
import io
import time
import shutil
import tarfile
import hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
BUILD = os.path.join(ROOT, "build")
DOCS = os.path.join(ROOT, "docs")
BACKUP = os.path.join(ROOT, "backup")

ver = "1.0.3"
for line in open(os.path.join(SRC, "manifest"), encoding="utf-8"):
    m = re.match(r"^version\s*=\s*(\S+)", line)
    if m:
        ver = m.group(1)
        break
OUT = os.path.join(BACKUP, ver + "-all")
os.makedirs(OUT, exist_ok=True)
stamp = time.strftime("%Y-%m-%d %H:%M:%S")


def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()


def tar_selected(out, entries):
    n = 0
    with tarfile.open(out, "w:gz", compresslevel=6) as t:
        for base, rels in entries:
            for rel in rels:
                p = os.path.join(base, rel)
                if not os.path.exists(p):
                    continue
                if os.path.isfile(p):
                    arc = os.path.relpath(p, base)
                    ti = t.gettarinfo(p, arcname=arc)
                    ti.mode = 0o755 if (arc.endswith(".sh") or "/cmd/" in arc) else 0o644
                    with open(p, "rb") as f:
                        t.addfile(ti, f)
                    n += 1
                else:
                    for dp, ds, fs in os.walk(p):
                        ds.sort(); fs.sort()
                        for fn in fs:
                            if fn == "app.tgz" or fn.startswith("."):
                                continue
                            fp = os.path.join(dp, fn)
                            arc = os.path.relpath(fp, base)
                            ti = t.gettarinfo(fp, arcname=arc)
                            ti.mode = 0o755 if (fn.endswith(".sh") or "/cmd/" in arc) else 0o644
                            with open(fp, "rb") as f:
                                t.addfile(ti, f)
                            n += 1
    return n


print("=== 生成交付备份四件套 ===")
# 1. FPK
fpk_src = os.path.join(BUILD, "ipsense_%s_all.fpk" % ver)
fpk = os.path.join(OUT, os.path.basename(fpk_src))
shutil.copy2(fpk_src, fpk)
print("1) FPK          :", os.path.basename(fpk), "%.2f MB" % (os.path.getsize(fpk) / 1048576.0), md5(fpk))

# 2. 源码包
src_pkg = os.path.join(OUT, "ipsense_%s_src.tar.gz" % ver)
n_src = tar_selected(src_pkg, [
    (ROOT, ["src", "tools", "docs", ".gitattributes"]),
])
print("2) 源码包       :", os.path.basename(src_pkg), n_src, "个文件", md5(src_pkg))

# 3. 数据资产包（原生应用无 Docker 镜像 tar）
data_pkg = os.path.join(OUT, "ipsense_%s_data.tar.gz" % ver)
xdb = os.path.join(SRC, "app", "server", "data", "ip2region_v4.xdb")
note = ("IP 动态感知 %s · 数据资产\n"
        "================================\n"
        "ip2region_v4.xdb  IPv4 离线归属库，来源 https://github.com/lionsoul2014/ip2region\n"
        "大小: %d 字节  MD5: %s\n"
        "许可: 遵循 ip2region 项目原始许可证，权利归原作者所有；本项目仅随包分发，未修改内容。\n"
        "用途: 本地查询 IP 的国家/省/城市/运营商，运行时不联网、不上传日志。\n"
        "合规: 香港/澳门/台湾属中国，统一计入境内；地图底图由腾讯地图提供，需用户自备 key。\n"
        "生成时间: %s\n" % (ver, os.path.getsize(xdb), md5(xdb), stamp)).encode("utf-8")
with tarfile.open(data_pkg, "w:gz", compresslevel=6) as t:
    for name, data in (("ip2region_v4.xdb", open(xdb, "rb").read()),
                       ("LICENSE", open(os.path.join(SRC, "LICENSE"), "rb").read()),
                       ("README.txt", note)):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        ti.mode = 0o644
        ti.mtime = int(time.time())
        t.addfile(ti, io.BytesIO(data))
print("3) 数据资产包   :", os.path.basename(data_pkg), "3 个文件", md5(data_pkg))

# 4. 更新日志
chg = os.path.join(DOCS, "CHANGELOG.md")
chg_out = os.path.join(OUT, "CHANGELOG_%s.md" % ver)
shutil.copy2(chg, chg_out)
print("4) 更新日志     :", os.path.basename(chg_out))

# MANIFEST
man = os.path.join(OUT, "MANIFEST")
head = "# 交付备份清单 · ipsense\n# 说明: 本应用为 fnOS 原生 FPK、零容器，Docker 镜像 tar 不适用；以数据资产包对应。\n"
cols = "# 版本 | 大小(字节) | 文件数 | git tag | commit | 时间 | 一句话说明\n"
_chg = ""
for _l in open(os.path.join(SRC, "manifest"), encoding="utf-8"):
    _m = re.match(r"^changelog\s*=\s*(.+)$", _l)
    if _m:
        _chg = _m.group(1).strip()
        break
line = "%s | %d | %d | - | - | %s | %s\n" % (
    ver, os.path.getsize(fpk), 4, stamp, _chg or "版本更新")
with open(man, "w", encoding="utf-8", newline="\n") as f:
    f.write(head + cols + line)
    for p in (fpk, src_pkg, data_pkg, chg_out):
        f.write("# %s | %d | %s\n" % (os.path.basename(p), os.path.getsize(p), md5(p)))
print("\nMANIFEST:")
print(open(man, encoding="utf-8").read())

# 核对
assert md5(fpk) == md5(fpk_src), "FPK 副本 md5 不一致"
print("核对：FPK 与 build/ 原件 md5 一致 ✅")
