# -*- coding: utf-8 -*-
"""1.1.17 运行时报错专项冒烟（不连设备）。

覆盖：脱敏、字段白名单、环形上限、查询顺序、导出结构、心跳折叠、
坐标/位置配置剔除，以及 gateway 里新增的三条只读 / 上报路由。
"""
import io
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "src", "app", "server")
TMP = tempfile.mkdtemp(prefix="ipsense-rt117-")
os.environ["TRIM_PKGVAR"] = TMP
sys.path.insert(0, SERVER)

import diag        # noqa: E402
import rtlog       # noqa: E402
import gateway     # noqa: E402

ok, fail = 0, []


def chk(name, cond, extra=""):
    global ok
    if cond:
        ok += 1
        print("  [OK] %s %s" % (name, extra))
    else:
        fail.append(name)
        print("  [FAIL] %s %s" % (name, extra))


print("=== 1.1.17 运行时报错模块冒烟 ===")
r = rtlog.RuntimeLog(TMP)
chk("日志文件固定在 TRIM_PKGVAR 下",
    r.path == os.path.join(TMP, "runtime_errors.jsonl"))
chk("空日志 recent / count 均为 0", r.recent() == [] and r.count() == 0)

n = r.add([
    {"kind": "map_sdk", "level": "error",
     "msg": "底图未显示：高德 SDK 未就绪：KEY 无效",
     "src": "https://webapi.amap.com/maps?v=2.0&key=SUPERSECRET123456",
     "host": "webapi.amap.com", "provider": "amap",
     "mapState": "error", "stack": "Error at maps:1:1",
     "evil_field": "不应落盘"},
    {"kind": "js", "msg": "Uncaught TypeError client 220.205.91.142",
     "stack": "TypeError: x is undefined"},
    {"kind": "api", "msg": "接口失败 api/status：HTTP 500",
     "url": "api/status", "status": 500, "count": 3},
], {"ver": "1.1.17", "provider": "amap", "pill": "部分数据异常",
    "ua": "Chrome/138", "page": "/app/ipsense/"})
chk("批量落盘 3 条", n == 3 and r.count() == 3, "saved=%d" % n)
rows = r.recent()
chk("recent 最新在前", [x["kind"] for x in rows] == ["api", "js", "map_sdk"])
chk("白名单外字段被丢弃", "evil_field" not in rows[-1])
chk("上报 ctx 写入记录", rows[-1].get("provider") == "amap" and
    rows[-1].get("ver") == "1.1.17" and rows[-1].get("pill") == "部分数据异常")
chk("数值字段保留", rows[0].get("status") == 500 and rows[0].get("count") == 3)

text = rtlog.build_export(None, 200)
chk("导出文本非空且带版本", len(text) > 700 and "1.1.17" in text)
chk("导出含地图 SDK 专项与明细",
    "[2] 地图 SDK 专项" in text and "[3] 逐条明细" in text and
    "高德 SDK 未就绪" in text and "001" in text)
chk("导出含反馈清单", "[4] 反馈时请一并提供" in text and
    "运行日志诊断包" in text)
chk("导出不含地图 KEY 明文", "SUPERSECRET123456" not in text)
chk("导出不含完整来访 IP", "220.205.91.142" not in text and
    "220.205.*.*" in text)
chk("导出不含 URL 里的 key 值", "key=SUPERSECRET" not in text)
chk("SDK 域名保留便于定位", "webapi.amap.com" in text)

empty_txt = rtlog.build_export(rtlog.RuntimeLog(os.path.join(TMP, "empty")), 200)
chk("空日志也输出完整结构（不抛异常）",
    "[2] 地图 SDK 专项" in empty_txt and "本次记录里没有地图 SDK" in empty_txt)
chk("format_section 空记录有可读说明",
    "尚无前端运行时报错记录" in "\n".join(rtlog.format_section([])))

# 环形上限：多次写入，总数不超过 MAX_ITEMS
big = rtlog.RuntimeLog(os.path.join(TMP, "big"))
for i in range(14):
    big.add([{"kind": "js", "msg": "probe-%d-%d" % (i, j)} for j in range(50)])
cnt = big.count()
chk("环形上限 500 条生效", 0 < cnt <= rtlog.MAX_ITEMS, "%d 条" % cnt)
chk("被裁掉的是最旧记录", "probe-0-0" not in "\n".join(
    x["msg"] for x in big.recent(500)) and "probe-13-49" in "\n".join(
    x["msg"] for x in big.recent(500)))

# diag：精确坐标 / 位置描述 / 私有目录不再出现在配置导出里
cfg = diag.redact_config({
    "home_lat": 31.8639, "home_lng": 117.2808,
    "home_label": "中国安徽合肥联通", "summary_dir": "/vol1/1000/IPlog",
    "map_key": "SUPERSECRET123456", "keep_days": 30,
    "web_port": 5666, "other": "client 220.205.91.142"})
cfg_txt = json.dumps(cfg, ensure_ascii=False)
chk("精确坐标 / 本机位置 / 私有目录已剔除",
    cfg["home_lat"] == "<已移除>" and cfg["home_lng"] == "<已移除>" and
    cfg["home_label"] == "<已移除>" and cfg["summary_dir"] == "<已移除>" and
    "31.8639" not in cfg_txt and "中国安徽合肥联通" not in cfg_txt)
chk("数值型配置仍保留（排障有用）",
    cfg["keep_days"] == 30 and cfg["web_port"] == 5666)
chk("字符串值仍过 scrub", "220.205.*.*" in cfg["other"] and
    "SUPERSECRET123456" not in cfg_txt)

# 心跳折叠：真实故障行不能被 30 秒一次的 status 挤掉
hb = os.path.join(TMP, "cmd.log")
with io.open(hb, "w", encoding="utf-8") as f:
    f.write("[2026-11-19 09:00:00] main action=start\n")
    f.write("[2026-11-19 09:01:00] TRACEBACK collector crashed\n")
    for i in range(600):
        f.write("[2026-11-19 %02d:%02d:%02d] main action=status\n" %
                (9 + i // 120, (i // 2) % 60, i % 60))
    f.write("[2026-11-19 13:30:00] ERROR sdk load failed\n")
lines = diag.tail_filtered(hb, 50)
joined = "\n".join(lines)
chk("心跳被折叠且有计数说明", "已折叠" in joined and
    sum(1 for x in lines if "action=status" in x) <= 3)
chk("折叠后仍保留历史故障行", "TRACEBACK collector crashed" in joined and
    "ERROR sdk load failed" in joined and "main action=start" in joined)

# gateway 三条路由
class _Cfg(object):
    def get(self, k, d=None):
        return d


class FakeApp(object):
    version = "1.1.17"

    def __init__(self, rt):
        self.rtlog = rt
        self.settings = _Cfg()


app = FakeApp(rtlog.RuntimeLog(os.path.join(TMP, "api")))
body = json.dumps({"items": [
    {"kind": "js", "msg": "route probe 220.205.91.142"},
], "ctx": {"ver": "1.1.17"}}).encode("utf-8")
rp = gateway.api(app, "POST", "/api/runtime/errors", "", body)
chk("POST /api/runtime/errors 返回 200 与 saved",
    len(rp) == 2 and rp[0] == 200 and rp[1].get("saved") == 1, str(rp))
rg = gateway.api(app, "GET", "/api/runtime/errors", "limit=10", b"")
chk("GET /api/runtime/errors 返回最近记录",
    len(rg) == 2 and rg[0] == 200 and len(rg[1].get("data", [])) == 1 and
    "220.205.*.*" in rg[1]["data"][0]["msg"])
re_ = gateway.api(app, "GET", "/api/runtime/errors/export", "", b"")
chk("GET /api/runtime/errors/export 返回 text/plain 字节",
    len(re_) == 3 and re_[0] == 200 and "text/plain" in re_[2] and
    isinstance(re_[1], bytes) and "地图 SDK 专项" in re_[1].decode("utf-8"))
chk("导出接口不含完整 IP",
    "220.205.91.142" not in re_[1].decode("utf-8"))
chk("POST 非 JSON / 空体不抛异常",
    gateway.api(app, "POST", "/api/runtime/errors", "", b"not-json")[0] == 200)

# 诊断包里新增的 6.1 章节（完整 App 由 tools/selftest.py 构造验证）
_dg117 = io.open(os.path.join(SERVER, "diag.py"), encoding="utf-8").read()
chk("诊断包已并入 6.1 前端运行时报错章节",
    "6.1 前端运行时报错" in _dg117 and
    "from rtlog import format_section" in _dg117 and
    "tail_filtered(path" in _dg117)
chk("诊断包章节用延迟 import，避免 diag ↔ rtlog 循环依赖",
    _dg117.index("def runtime_errors()") < _dg117.index("from rtlog import format_section"))

shutil.rmtree(TMP, ignore_errors=True)
print("\n=== 结果：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
if fail:
    print("失败项：" + ", ".join(fail))
sys.exit(1 if fail else 0)
