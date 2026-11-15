# -*- coding: utf-8 -*-
"""从已验证的 `platform=all` FPK 派生 x86 / arm 架构专用包。

依据 fnOS FPK 规范（V1.1.8+）：
  * `platform` 取值只有 x86 / arm / all，且**单值**，不支持多值；
  * `arch` 字段已废弃，不要再用；
  * 双架构原生应用应产出两个独立 FPK，文件名后缀为 `_{platform}.fpk`；
  * 纯脚本 / Docker 类应用可用 `all` 一个包覆盖全部架构。

ipsense 是纯 Python 标准库 + JS/CSS + ip2region 数据文件，没有任何架构相关
原生二进制，因此三种包的 app.tgz 完全一致；本脚本**只替换 manifest 的
platform 行**，其它成员逐字节原样复制（连同 tarinfo 权限 / 属主 / 时间）。

用法：先 `bash tools/build_fpk.sh` 产出 all 包，再 `python tools/build_multiarch.py`。
可重复执行；不会修改 src/manifest，也不会改动 all 包。
"""
import io
import os
import re
import sys
import gzip
import hashlib
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")
SRC_MANIFEST = os.path.join(ROOT, "src", "manifest")

VALID = ("x86", "arm", "all")
PLAT_RE = re.compile(r"^(platform\s*=\s*)(\S+)\s*$", re.M)


def md5(b):
    return hashlib.md5(b).hexdigest()


def read_version():
    for line in io.open(SRC_MANIFEST, encoding="utf-8"):
        m = re.match(r"^version\s*=\s*(\S+)", line)
        if m:
            return m.group(1)
    raise SystemExit("无法从 src/manifest 读取版本号")


def all_member_bytes(t):
    """收集 all 包所有成员，返回 [(TarInfo, bytes)]，顺序保持原样。"""
    out = []
    for m in t.getmembers():
        f = t.extractfile(m)
        data = f.read() if f is not None else b""
        out.append((m, data))
    return out


def patch_manifest(data, platform):
    """只改 platform 行的值，保留原有空格对齐与其它所有字节。"""
    text = data.decode("utf-8")
    hits = PLAT_RE.findall(text)
    if len(hits) != 1:
        raise SystemExit("manifest 里 platform 行不是唯一一条：%r" % (hits,))
    if hits[0][1] != "all":
        raise SystemExit("源 manifest 的 platform 必须是 all，实际为 %s" % hits[0][1])
    new = PLAT_RE.sub(lambda m: m.group(1) + platform, text, count=1)
    return new.encode("utf-8")


def write_fpk(path, members):
    """可复现构建：gzip header 固定 mtime=0，不写入当前时间。"""
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                          mtime=0, compresslevel=6) as gz:
            with tarfile.open(fileobj=gz, mode="w") as t:
                for info, data in members:
                    ti = tarfile.TarInfo(info.name)
                    ti.mode = info.mode
                    ti.uid, ti.gid = info.uid, info.gid
                    ti.uname, ti.gname = info.uname, info.gname
                    ti.mtime = info.mtime
                    ti.type = info.type
                    ti.linkname = info.linkname
                    ti.size = len(data)
                    t.addfile(ti, io.BytesIO(data))
    return md5(open(path, "rb").read())


def main():
    ver = read_version()
    src = os.path.join(BUILD, "ipsense_%s_all.fpk" % ver)
    if not os.path.isfile(src):
        raise SystemExit("缺少通用包：%s（请先执行 tools/build_fpk.sh）" % src)

    with tarfile.open(src, "r:gz") as t:
        members = all_member_bytes(t)

    idx = [i for i, (m, _) in enumerate(members) if m.name == "manifest"]
    if len(idx) != 1:
        raise SystemExit("all 包里 manifest 成员不唯一")
    mi = idx[0]
    src_manifest = members[mi][1]
    app_tgz_md5 = ""
    for m, data in members:
        if m.name == "app.tgz":
            app_tgz_md5 = md5(data)
    if not app_tgz_md5:
        raise SystemExit("all 包里没有 app.tgz")
    ck = re.search(r"^checksum\s*=\s*(\S+)\s*$",
                   src_manifest.decode("utf-8"), re.M)
    if not ck or ck.group(1) != app_tgz_md5:
        raise SystemExit("manifest checksum 与 app.tgz MD5 不一致：%s / %s" %
                         (ck.group(1) if ck else "无", app_tgz_md5))

    print("源包：%s" % src)
    print("版本：%s ｜ app.tgz MD5：%s ｜ 成员数：%d" %
          (ver, app_tgz_md5, len(members)))

    made = {}
    for platform in ("x86", "arm"):
        out = os.path.join(BUILD, "ipsense_%s_%s.fpk" % (ver, platform))
        patched = list(members)
        patched[mi] = (members[mi][0], patch_manifest(src_manifest, platform))
        digest = write_fpk(out, patched)
        made[platform] = (out, digest, patched)
        print("  -> %-28s platform=%-3s %d B  MD5=%s" %
              (os.path.basename(out), platform, os.path.getsize(out), digest))

    # 逐成员校验：除 manifest 外全部字节一致；manifest 只允许 platform 行不同
    bad = []
    for platform, (out, _, patched) in made.items():
        with tarfile.open(out, "r:gz") as t:
            got = all_member_bytes(t)
        if len(got) != len(members):
            bad.append("%s 成员数不一致" % platform)
            continue
        for (m0, d0), (m1, d1) in zip(members, got):
            if m0.name != m1.name:
                bad.append("%s 成员顺序/名字不一致：%s" % (platform, m0.name))
            elif m0.name == "manifest":
                a = PLAT_RE.sub(lambda m: m.group(1) + "<P>", d0.decode("utf-8"))
                b = PLAT_RE.sub(lambda m: m.group(1) + "<P>", d1.decode("utf-8"))
                if a != b:
                    bad.append("%s manifest 除 platform 外还有改动" % platform)
                if PLAT_RE.search(d1.decode("utf-8")).group(2) != platform:
                    bad.append("%s manifest platform 值不对" % platform)
            elif md5(d0) != md5(d1):
                bad.append("%s 成员 %s 字节被改动" % (platform, m0.name))
        # app.tgz 与 checksum 仍自洽
        man = dict((m.name, d) for m, d in got)["manifest"].decode("utf-8")
        at = dict((m.name, d) for m, d in got)["app.tgz"]
        c = re.search(r"^checksum\s*=\s*(\S+)\s*$", man, re.M)
        if not c or c.group(1) != md5(at):
            bad.append("%s checksum 与 app.tgz 不自洽" % platform)

    if bad:
        for x in bad:
            print("  [FAIL] " + x)
        return 1
    print("=== 多架构派生校验：全部通过（除 platform 行外逐字节一致）===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
