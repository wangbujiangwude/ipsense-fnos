#!/bin/sh
# ipsense 一键诊断收集脚本（只读 / 自动脱敏 / 自动打 tar.gz）
#
# 用法：  sh tools/diag_bundle.sh [输出目录]
# 例：    sh tools/diag_bundle.sh /vol1/1000/分享
#         sh tools/diag_bundle.sh                 # 默认输出到当前目录
#
# 设计红线：
#   - 全程只读：不改配置、不重启应用、不清理日志、不动数据库；
#   - 不读取 events.db 的原始事件行，只看文件大小与聚合行数；
#   - 所有文本逐份过脱敏：地图 KEY / 令牌 / 口令 / 邮箱抹除，
#     来访 IP 只保留前两段（例 220.205.*.*）；
#   - 每一步独立容错，缺文件 / 应用没启动都写明原因，不中断收集；
#   - 优先复用应用自带 diag.scrub()，旧版本没有时回退内嵌同规则实现。
#
# 产物：ipsense-diag-<时间戳>.tar.gz，直接贴到 GitHub Issue 即可。
# 注意：脚本不会上传任何内容，也不会替你提交 Issue。

set -u

APP_NAME="ipsense"
APP_DEST="${TRIM_APPDEST:-/var/apps/ipsense/target}"
VAR_DIR="${TRIM_PKGVAR:-/vol1/@appdata/ipsense}"
LOG_MAIN="/var/log/apps/ipsense.log"
LOG_FALLBACK="$VAR_DIR/app.log"
LOG_CMD="$VAR_DIR/cmd.log"
SOCK="$APP_DEST/app.sock"
SERVER="$APP_DEST/server"
OUTDIR="${1:-.}"
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown)"
NAME="ipsense-diag-$STAMP"

# 不能只看 command -v：Windows 上 python3 可能是 Microsoft Store 的占位 stub
# （存在但一执行就退出 49）。逐个候选真跑一次，取第一个可用的解释器。
PY=""
for c in python3 /usr/bin/python3 /usr/local/bin/python3 python; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys; sys.exit(0)' >/dev/null 2>&1; then
        PY="$c"; break
    fi
done

WORK="$(mktemp -d /tmp/ipsense-diag.XXXXXX 2>/dev/null)" || {
    echo "无法创建临时目录" >&2; exit 1;
}
BUNDLE="$WORK/$NAME"
mkdir -p "$BUNDLE" || { echo "无法创建收集目录" >&2; exit 1; }
mkdir -p "$OUTDIR" 2>/dev/null || OUTDIR="."
IPSENSE_SERVER="$SERVER"
export IPSENSE_SERVER

echo "== ipsense 诊断包收集 =="
echo "   应用目录  : $APP_DEST"
echo "   数据目录  : $VAR_DIR"
echo "   Python    : ${PY:-（未找到，命令类诊断会跳过）}"
echo "   输出目录  : $OUTDIR"
echo

# ---------------------------------------------------------------------
# 脱敏器：优先复用应用自带实现，缺失时回退内嵌同规则版本
# ---------------------------------------------------------------------
cat > "$WORK/scrub.py" <<'PYEOF'
# -*- coding: utf-8 -*-
import os
import re
import sys
import json

_scrub = None
_server = os.environ.get("IPSENSE_SERVER", "")
if _server and os.path.isfile(os.path.join(_server, "diag.py")):
    try:
        sys.path.insert(0, _server)
        import diag
        _scrub = diag.scrub
    except Exception:
        _scrub = None

if _scrub is None:
    IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
    IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F:]*\b")
    EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
    SECRET_RE = re.compile(
        r"(?i)(^|[?&\s;,'\"(])((?:[a-z0-9_\-]*_)?"
        r"(?:key|ak|tk|token|secret|password|passwd|authorization|cookie|"
        r"apikey|securityjscode))(\s*[:=]\s*)([\"']?)([^\s,;&\"']{4,})")
    BEARER_RE = re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]{6,}")
    PEM_RE = re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.S)
    DROP_CFG_KEYS = (
        "map_key", "map_keys", "map_custom", "home_ip", "home_proxy_ip",
        "home_geo", "home_source", "home_locate_at", "ignore_ips")

    def _scrub(text):
        s = str(text if text is not None else "")
        s = PEM_RE.sub("***PRIVATE KEY REDACTED***", s)
        s = BEARER_RE.sub("Bearer ***REDACTED***", s)
        s = SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + m.group(3) +
                          m.group(4) + "***REDACTED***", s)
        s = IPV6_RE.sub("***IPv6***", s)
        s = IPV4_RE.sub(lambda m: "%s.%s.*.*" % (m.group(1), m.group(2)), s)
        s = EMAIL_RE.sub("***@***", s)
        return s

mode = sys.argv[1] if len(sys.argv) > 1 else "text"
data = sys.stdin.read()
if mode == "config":
    try:
        obj = json.loads(data)
        if isinstance(obj, dict):
            for k in DROP_CFG_KEYS:
                obj.pop(k, None)
            data = json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        pass
sys.stdout.write(_scrub(data))
PYEOF

# 对某个文件逐份脱敏后写入收集目录
scrub_file() {
    _src="$1"; _dst="$BUNDLE/$2"; _mode="${3:-text}"
    if [ -n "$PY" ] && [ -f "$_src" ]; then
        "$PY" "$WORK/scrub.py" "$_mode" < "$_src" > "$_dst" 2>/dev/null ||
            echo "(脱敏处理失败，已跳过该文件内容)" > "$_dst"
    elif [ ! -f "$_src" ]; then
        echo "(未找到：$_src)" > "$_dst"
    else
        echo "(未找到 python3，无法安全脱敏，已跳过文件内容)" > "$_dst"
    fi
}

TAIL_N="${TAIL_N:-400}"
tail_log() {
    if command -v tail >/dev/null 2>&1; then
        tail -n "$TAIL_N" "$1" 2>/dev/null
    else
        sed -n '$p' "$1" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------
# 0. 说明文件
# ---------------------------------------------------------------------
cat > "$BUNDLE/00-README.txt" <<EOF
ipsense 运行日志诊断包
生成时间：$(date 2>/dev/null || echo unknown)
生成主机：$(uname -a 2>/dev/null || echo unknown)

本包由 tools/diag_bundle.sh 只读收集，已逐份自动脱敏：
  - 地图 KEY / 令牌 / 口令 / 邮箱已抹除；
  - 来访 IP 只保留前两段（例 220.205.*.*）；
  - 不含 events.db 原始事件行，不含原始日志全文；
  - 配置已剔除 map_key / map_keys / map_custom / 出口 IP 等敏感键。

文件说明：
  10-env.txt               版本与运行环境
  20-main-log.txt          主运行日志尾部（$LOG_MAIN）
  30-fallback-log.txt      兜底副本尾部（$LOG_FALLBACK）
  40-cmd-log.txt           生命周期日志尾部（$LOG_CMD）
  50-config-redacted.txt   配置（敏感键已剔除）
  60-health.txt            /api/health、/api/status、/api/sources
  70-probe-status.txt      gateway.py probe / status
  80-db-overview.txt       events.db 体积与聚合行数（不含事件明细）
  90-files.txt             关键文件清单与大小
  99-app-diag-export.txt   应用内 /api/diag/export（1.1.15+，最完整）

提交 Issue 前请再扫一眼：如果还有你不想公开的内网网段或主机名，
直接在文本里改掉即可。请不要另外附上未经脱敏的 config.json。
EOF

# ---------------------------------------------------------------------
# 1. 版本与运行环境
# ---------------------------------------------------------------------
{
    echo "收集时间      : $(date 2>/dev/null || echo unknown)"
    echo "内核 / 系统   : $(uname -a 2>/dev/null || echo unknown)"
    echo "架构          : $(uname -m 2>/dev/null || echo unknown)"
    echo "应用目录      : $APP_DEST"
    echo "数据目录      : $VAR_DIR"
    echo "Socket        : $SOCK ($( [ -S "$SOCK" ] && echo 存在 || echo 不存在 ))"
    echo "TRIM_APPDEST  : ${TRIM_APPDEST:-（未注入，使用默认路径）}"
    echo "TRIM_PKGVAR   : ${TRIM_PKGVAR:-（未注入，使用默认路径）}"
    echo "应用版本      : $(grep -m1 '^version' "$APP_DEST/manifest" 2>/dev/null || echo '（读不到 manifest）')"
    echo "gateway 版本  : $(grep -m1 '^VERSION' "$SERVER/gateway.py" 2>/dev/null || echo '（读不到 gateway.py）')"
    echo "fnOS 版本     : $(cat /etc/version 2>/dev/null || cat /etc/os-release 2>/dev/null | head -3 || echo '（读不到）')"
    echo "Python        : ${PY:-（未找到）}"
} > "$WORK/raw-env" 2>/dev/null
scrub_file "$WORK/raw-env" "10-env.txt"

# ---------------------------------------------------------------------
# 2. 三层日志（只读尾部，逐份脱敏）
# ---------------------------------------------------------------------
for pair in "$LOG_MAIN:20-main-log.txt" "$LOG_FALLBACK:30-fallback-log.txt" \
            "$LOG_CMD:40-cmd-log.txt"; do
    _src="${pair%%:*}"; _dst="${pair##*:}"
    if [ -f "$_src" ]; then
        tail_log "$_src" > "$WORK/raw-log" 2>/dev/null
        scrub_file "$WORK/raw-log" "$_dst"
    else
        echo "(未找到：$_src)" > "$BUNDLE/$_dst"
    fi
done

# ---------------------------------------------------------------------
# 3. 配置：先按键名剔除，再整体过脱敏
# ---------------------------------------------------------------------
scrub_file "$VAR_DIR/config.json" "50-config-redacted.txt" config

# ---------------------------------------------------------------------
# 4. 健康与状态接口
# ---------------------------------------------------------------------
if command -v curl >/dev/null 2>&1 && [ -S "$SOCK" ]; then
    for ep in api/health api/status api/sources; do
        echo "----- GET /$ep -----"
        curl -sS --max-time 8 --unix-socket "$SOCK" \
            "http://localhost/app/$APP_NAME/$ep" 2>&1 || echo "(请求失败)"
        echo
    done > "$WORK/raw-health" 2>/dev/null
else
    echo "(curl 不可用或 $SOCK 不存在，跳过接口采集)" > "$WORK/raw-health"
    echo "提示：应用未启动时可用「应用中心 → 启动」，或先跑 gateway.py status。" >> "$WORK/raw-health"
fi
scrub_file "$WORK/raw-health" "60-health.txt"

# ---------------------------------------------------------------------
# 5. gateway.py probe / status
# ---------------------------------------------------------------------
if [ -n "$PY" ] && [ -f "$SERVER/gateway.py" ]; then
    {
        echo "----- probe -----"
        "$PY" "$SERVER/gateway.py" probe 2>&1 || echo "(probe 失败)"
        echo
        echo "----- status -----"
        "$PY" "$SERVER/gateway.py" status 2>&1 || echo "(status 失败)"
    } > "$WORK/raw-probe" 2>/dev/null
else
    echo "(未找到 python3 或 $SERVER/gateway.py，跳过)" > "$WORK/raw-probe"
fi
scrub_file "$WORK/raw-probe" "70-probe-status.txt"

# ---------------------------------------------------------------------
# 6. 数据库概览：只看体积与聚合行数，绝不导原始事件
# ---------------------------------------------------------------------
{
    echo "events.db 三件套（WAL 模式，三者是一套，不要单独删除或复制）："
    for f in "$VAR_DIR/events.db" "$VAR_DIR/events.db-wal" "$VAR_DIR/events.db-shm"; do
        if [ -f "$f" ]; then
            echo "  $(basename "$f")  $(stat -c %s "$f" 2>/dev/null || stat -f %z "$f" 2>/dev/null || echo '?') bytes"
        else
            echo "  $(basename "$f")  （不存在）"
        fi
    done
    echo
    if [ -n "$PY" ] && [ -f "$VAR_DIR/events.db" ]; then
        "$PY" - "$VAR_DIR/events.db" <<'PY' 2>&1 || echo "(聚合行数读取失败)"
import sqlite3, sys
try:
    c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    for t in ("events", "geo_cache", "meta"):
        try:
            print("  %-12s %d 行" % (t, c.execute("SELECT COUNT(*) FROM " + t).fetchone()[0]))
        except Exception as e:
            print("  %-12s 读取失败：%s" % (t, e))
    c.close()
except Exception as e:
    print("  只读打开失败：%s" % e)
PY
    else
        echo "  （未找到 python3 或 events.db，跳过聚合行数）"
    fi
    echo
    echo "说明：诊断包不导出任何原始事件行、来访 IP 明细或原始日志全文。"
} > "$WORK/raw-db" 2>/dev/null
scrub_file "$WORK/raw-db" "80-db-overview.txt"

# ---------------------------------------------------------------------
# 7. 关键文件清单
# ---------------------------------------------------------------------
{
    for f in "$LOG_MAIN" "$LOG_FALLBACK" "$LOG_CMD" "$VAR_DIR/config.json" \
             "$VAR_DIR/app.log" "$VAR_DIR/ipsense.pid" "$SOCK" \
             "$VAR_DIR/ipsense-summary-latest.md"; do
        if [ -e "$f" ]; then
            echo "存在  $(stat -c '%s bytes  %y' "$f" 2>/dev/null || echo '? bytes')  $f"
        else
            echo "缺失  $f"
        fi
    done
} > "$WORK/raw-files" 2>/dev/null
scrub_file "$WORK/raw-files" "90-files.txt"

# ---------------------------------------------------------------------
# 8. 应用内一键导出（1.1.15+）：内容最完整，后端已自行脱敏
# ---------------------------------------------------------------------
if command -v curl >/dev/null 2>&1 && [ -S "$SOCK" ]; then
    curl -sS --max-time 20 --unix-socket "$SOCK" \
        "http://localhost/app/$APP_NAME/api/diag/export" \
        > "$WORK/raw-app-diag" 2>/dev/null || echo "(接口不可用，可能低于 1.1.15)" > "$WORK/raw-app-diag"
    if [ ! -s "$WORK/raw-app-diag" ]; then
        echo "(接口返回为空，可能低于 1.1.15)" > "$WORK/raw-app-diag"
    fi
else
    echo "(curl 不可用或应用未启动，跳过；1.1.15+ 也可在设置最底部点「导出运行日志」)" \
        > "$WORK/raw-app-diag"
fi
scrub_file "$WORK/raw-app-diag" "99-app-diag-export.txt"

# ---------------------------------------------------------------------
# 9. 打包
# ---------------------------------------------------------------------
TAR="$OUTDIR/$NAME.tar.gz"
if command -v tar >/dev/null 2>&1; then
    tar -czf "$TAR" -C "$WORK" "$NAME" 2>/dev/null
else
    echo "未找到 tar，只保留目录：$BUNDLE" >&2
    exit 1
fi

if [ -f "$TAR" ]; then
    echo "== 收集完成 =="
    echo "   诊断包  : $TAR"
    echo "   大小    : $(stat -c %s "$TAR" 2>/dev/null || stat -f %z "$TAR" 2>/dev/null || echo '?') bytes"
    echo "   未脱敏前原始文件仍在：$WORK（脚本不会删除，方便你复核）"
    echo
    echo "提交 Issue 前请确认："
    echo "  1) 已在设置 → 最底部导出运行日志，或附上本 tar.gz；"
    echo "  2) 没有另外附上未经脱敏的 config.json 或完整日志；"
    echo "  3) 已填全「诊断 6 件套」（见 docs/排障指南.md）。"
    exit 0
else
    echo "打包失败，收集目录：$BUNDLE" >&2
    exit 1
fi
