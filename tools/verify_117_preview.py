# -*- coding: utf-8 -*-
"""1.1.17 离线预览页真实 Chrome 验收：运行时报错采集与导出全链路。

不连设备，用项目共用的 CDP 打开 build/preview-ipsense.html，真实制造
JS 异常 / Promise 拒绝 / script 加载失败，验证：
  采集 → 去重合并 → POST 上报 → 查询 → 界面查看 → 一键导出 → 脱敏。
输出 build/verify_117_preview.json。
"""
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "animation", "v4"))
from cdp import CDP                                       # noqa: E402

OUT = os.path.join(ROOT, "build")
RESULT = os.path.join(OUT, "verify_117_preview.json")
ok, fails, notes = 0, [], []


def check(name, cond, extra=""):
    global ok
    if cond:
        ok += 1
        print("  [OK] %s %s" % (name, extra))
    else:
        fails.append(name)
        print("  [FAIL] %s %s" % (name, extra))


def note(k, v):
    notes.append({"key": k, "value": str(v)})
    print("  [NOTE] %s = %s" % (k, str(v)[:160]))


def click_at(c, x, y):
    for t in ("mouseMoved", "mousePressed", "mouseReleased"):
        p = {"type": t, "x": x, "y": y, "button": "left", "clickCount": 1}
        if t == "mouseMoved":
            p.pop("button")
            p.pop("clickCount")
        c.cmd("Input.dispatchMouseEvent", p)


def click_sel(c, sel):
    """设置抽屉很长，按钮可能在视口外：先滚到视口中央，再按视口坐标实点。"""
    c.ev("(function(){var e=document.querySelector(%s);"
         "if(e&&e.scrollIntoView)e.scrollIntoView({block:'center'});"
         "return 1;})()" % json.dumps(sel))
    c.wait(350)
    r = center(c, sel)
    if not r.get("w"):
        return False
    click_at(c, r["x"], r["y"])
    return True


def center(c, sel):
    r = c.ev("(function(){var e=document.querySelector(%s);"
             "if(!e)return '';var b=e.getBoundingClientRect();"
             "return JSON.stringify({x:b.left+b.width/2,y:b.top+b.height/2,"
             "w:b.width,h:b.height});})()" % json.dumps(sel))
    try:
        return json.loads(r or "{}")
    except Exception:
        return {}


PROBE_INIT = r"""
window.__probeErrs=[];
window.addEventListener('error',function(e){
  window.__probeErrs.push(String((e&&e.message)||''));
},true);
"""


def main():
    c = CDP(9351, "verify117preview")
    result = {"ok": 0, "fails": [], "notes": []}
    try:
        c.start()
        c.cmd("Page.addScriptToEvaluateOnNewDocument", {"source": PROBE_INIT})
        c.load()
        check("预览页完整渲染（真实数据）",
              bool(c.ev("document.querySelector('#mTotal') && "
                        "document.querySelector('#mTotal').textContent.trim()")))

        # ---- 真实制造三类运行时错误 ----
        c.ev("setTimeout(function(){throw new Error('__rt_probe_117__')},0);1")
        c.wait(1400)
        c.ev("setTimeout(function(){Promise.reject(new Error('__rt_reject_117__'))},0);1")
        c.wait(1200)
        c.ev("(function(){var s=document.createElement('script');"
             "s.src='http://127.0.0.1:9/__rt_missing_sdk.js?key=SUPERSECRET123456';"
             "document.head.appendChild(s);return 1;})()")
        c.wait(1600)

        posted = json.loads(c.ev("JSON.stringify(window.__rtPosted||[])") or "[]")
        note("上报条数", len(posted))
        kinds = [x.get("kind") for x in posted]
        check("真实 JS 异常被全局捕获并上报",
              any(x.get("kind") == "js" and "__rt_probe_117__" in str(x.get("msg"))
                  for x in posted), str(kinds))
        check("真实 Promise 拒绝被捕获并上报",
              any(x.get("kind") == "rejection" and "__rt_reject_117__" in str(x.get("msg"))
                  for x in posted))
        check("真实 script 加载失败被捕获并上报",
              any(x.get("kind") == "resource" and
                  "__rt_missing_sdk.js" in str(x.get("src")) for x in posted))
        check("资源 URL 里的 KEY 明文不进入上报",
              all("SUPERSECRET123456" not in json.dumps(x, ensure_ascii=False)
                  for x in posted))
        check("资源 URL 保留域名与参数名供定位",
              any("__rt_missing_sdk.js" in str(x.get("src")) and
                  "参数名" in str(x.get("src")) for x in posted))
        check("每条上报都带时间戳与级别",
              all(x.get("ts") and x.get("level") for x in posted))

        # ---- 设置页：真实鼠标点开 ----
        st = center(c, "#btnSettings")
        check("设置按钮可点", st.get("w", 0) > 0 and st.get("h", 0) > 0, str(st))
        click_sel(c, "#btnSettings")
        c.wait(900)
        buttons = json.loads(c.ev(
            "(function(){var o={};['btnDiagExport','btnDiagView','btnRtExport',"
            "'btnRtView'].forEach(function(id){var e=document.getElementById(id);"
            "o[id]=!!(e&&e.getBoundingClientRect().width>0);});"
            "return JSON.stringify(o);})()") or "{}")
        check("设置页四个导出/查看按钮都在",
              all(buttons.values()), json.dumps(buttons, ensure_ascii=False))
        check("运行报错区块有说明文案",
              bool(c.ev("document.getElementById('settingsBody').innerText"
                        ".indexOf('地图 SDK 没正常加载')>=0")))

        check("「查看最近报错」按钮可点并已实点", click_sel(c, "#btnRtView"))
        c.wait(800)
        preview = c.ev("document.getElementById('diagPreview').textContent") or ""
        check("查看最近报错渲染出真实条目",
              "map_sdk" in preview and "高德 SDK 未就绪" in preview,
              preview[:110].replace("\n", " | "))

        check("「导出运行报错」按钮可点并已实点", click_sel(c, "#btnRtExport"))
        c.wait(800)
        hits = c.ev("window.__rtExportHits||0") or 0
        check("真实点击导出触发 /api/runtime/errors/export", hits >= 1,
              "hits=%s" % hits)
        export_txt = c.ev("fetch('api/runtime/errors/export').then(function(r)"
                          "{return r.text()})")
        check("导出文本含地图 SDK 专项与逐条明细",
              isinstance(export_txt, str) and "地图 SDK 专项" in export_txt and
              "逐条明细" in export_txt and "反馈时请一并提供" in export_txt)

        # ---- 回归：原运行日志诊断包预览仍工作，且带 6.1 章节 ----
        check("运行日志预览按钮已实点", click_sel(c, "#btnDiagView"))
        c.wait(800)
        diag_prev = c.ev("document.getElementById('diagPreview').textContent") or ""
        check("运行日志诊断包预览含 6.1 前端运行时报错章节",
              "6.1 前端运行时报错" in diag_prev)

        # ---- 无意外异常（故意注入的三类探针除外）----
        errs = json.loads(c.ev("JSON.stringify(window.__probeErrs||[])") or "[]")
        # 资源加载失败的 error 事件 message 为空字符串，属探针副产物，不算意外异常
        unexpected = [e for e in errs
                      if str(e).strip() and
                      "__rt_probe_117__" not in e and
                      "__rt_reject_117__" not in e and
                      "__rt_missing_sdk" not in e and
                      "Failed to load resource" not in e]
        check("除故意注入的探针外无其它 JS 异常",
              not unexpected, json.dumps(unexpected, ensure_ascii=False)[:200])
        note("探针异常数", len(errs))
    except Exception as e:
        check("验收脚本执行", False, repr(e))
    finally:
        c.close()

    result = {"ok": ok, "fails": fails, "notes": notes,
              "total": ok + len(fails)}
    with io.open(RESULT, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("\n=== 结果：%d 项通过 / %d 项失败 ===" % (ok, len(fails)))
    if fails:
        print("失败项：" + ", ".join(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
