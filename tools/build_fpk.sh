#!/bin/bash
# 打包 fnOS FPK：统一 LF 行尾 → 语法自检 → app.tgz → checksum → .fpk
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"
OUT="$ROOT/build"
APP_TGZ="$SRC/app.tgz"
PY="${PY:-python3}"
mkdir -p "$OUT"

VER=$("$PY" -c "
import re,sys
for line in open(sys.argv[1],encoding='utf-8'):
    m=re.match(r'^version\s*=\s*(\S+)',line)
    if m: print(m.group(1)); break
" "$SRC/manifest")
FPK="$OUT/ipsense_${VER}_all.fpk"

echo "[1/6] 统一行尾为 LF"
find "$SRC" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.js' -o -name '*.css' \
    -o -name '*.html' -o -name '*.json' -o -name 'config' -o -name 'privilege' \
    -o -name 'resource' -o -name 'install' -o -name 'manifest' -o -name 'LICENSE' \) \
    -print0 | while IFS= read -r -d '' f; do
    "$PY" -c "
import sys
p=sys.argv[1]
b=open(p,'rb').read()
if b'\r\n' in b:
    open(p,'wb').write(b.replace(b'\r\n',b'\n'))
" "$f"
done

echo "[2/6] 补齐可执行位"
chmod +x "$SRC"/cmd/* "$SRC"/app/scripts/*.sh

echo "[3/6] Python 语法自检"
"$PY" -m py_compile "$SRC"/app/server/*.py "$ROOT"/tools/*.py
find "$SRC" "$ROOT/tools" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true

echo "[4/6] 生成 app.tgz"
rm -f "$APP_TGZ"                       # 必须删，否则旧包会被打进去
# 用 tarfile 显式写权限位：Windows/Git Bash 打包时 chmod +x 容易丢失
"$PY" - "$APP_TGZ" "$SRC/app" <<'PYEOF'
import os, sys, tarfile
out, root = sys.argv[1], sys.argv[2]
with tarfile.open(out, "w:gz", compresslevel=6) as t:
    for top in ("server", "ui", "scripts"):
        for dirpath, dirs, files in os.walk(os.path.join(root, top)):
            dirs.sort(); files.sort()
            for fn in files:
                p = os.path.join(dirpath, fn)
                arc = os.path.relpath(p, root).replace(os.sep, "/")
                ti = t.gettarinfo(p, arcname=arc)
                ti.mode = 0o755 if fn.endswith(".sh") else 0o644
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = "root"
                with open(p, "rb") as f:
                    t.addfile(ti, f)
PYEOF
"$PY" -c "
import tarfile,sys
t=tarfile.open(sys.argv[1])
names=t.getnames()
need=('server/gateway.py','server/data/ip2region_v4.xdb','ui/index.html','scripts/enable_knock.sh')
for n in need:
    assert any(x.endswith(n) for x in names), '缺少 '+n
print('  app.tgz 文件数:', len(names))
" "$APP_TGZ"

echo "[5/6] 写入 checksum"
CK=$("$PY" -c "import hashlib,sys;print(hashlib.md5(open(sys.argv[1],'rb').read()).hexdigest())" "$APP_TGZ")
"$PY" -c "
import re,sys
p,ck=sys.argv[1],sys.argv[2]
s=open(p,encoding='utf-8').read()
s=re.sub(r'^checksum\s*=.*$', 'checksum                   = '+ck, s, flags=re.M)
open(p,'w',encoding='utf-8',newline='\n').write(s)
print('  checksum =',ck)
" "$SRC/manifest" "$CK"

echo "[6/6] 打包 FPK"
"$PY" - "$FPK" "$SRC" <<'PYEOF'
import os, sys, tarfile
out, root = sys.argv[1], sys.argv[2]
files = ["manifest", "ICON.PNG", "ICON_256.PNG", "LICENSE", "app.tgz"]
dirs = ["cmd", "config", "wizard"]
with tarfile.open(out, "w:gz", compresslevel=6) as t:
    for rel in files:
        p = os.path.join(root, rel)
        ti = t.gettarinfo(p, arcname=rel)
        ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = 0o644, 0, 0, "root", "root"
        with open(p, "rb") as f:
            t.addfile(ti, f)
    for d in dirs:
        for dirpath, subdirs, names in os.walk(os.path.join(root, d)):
            subdirs.sort(); names.sort()
            for fn in names:
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                ti = t.gettarinfo(p, arcname=rel)
                ti.mode = 0o755 if d == "cmd" else 0o644
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = "root"
                with open(p, "rb") as f:
                    t.addfile(ti, f)
PYEOF
"$PY" -c "
import tarfile,hashlib,sys,os
p=sys.argv[1]
t=tarfile.open(p)
n=t.getnames()
for x in ('manifest','ICON.PNG','ICON_256.PNG','LICENSE','cmd/main','config/privilege','wizard/install','app.tgz'):
    assert x in n, 'FPK 缺少 '+x
print('  FPK:',p)
print('  大小: %.2f MB' % (os.path.getsize(p)/1048576))
print('  MD5 :',hashlib.md5(open(p,'rb').read()).hexdigest())
" "$FPK"
echo "完成: $FPK"

# 附加步骤：fnOS 的 platform 是单值（x86 | arm | all），双架构分发需要独立 FPK。
# 应用为纯 Python，三包 app.tgz 完全一致，只替换 manifest 的 platform 行。
# 只要 all 包，可用 SKIP_MULTIARCH=1 bash tools/build_fpk.sh 跳过。
if [ "${SKIP_MULTIARCH:-0}" != "1" ]; then
    echo "[附加] 派生 x86 / arm 架构专用包"
    "$PY" "$ROOT/tools/build_multiarch.py"
fi
