# -*- coding: utf-8 -*-
"""1.1.15 离线预览页真实浏览器验收（Chrome CDP）。

不连真机，用 build/preview-ipsense.html 的离线 mock 在真实 Chrome 里跑，
验证本版八项需求里能在前端被观测到的部分：
  - 页脚版本、实时事件范围筛选（真实条数变化）
  - 设置最底部运行日志一键导出 / 预览（真实点击 + fetch mock）
  - 区级信息进入记录表
  - 地域图按省细分（气泡数据带 scope）
  - 全程无未捕获 JS 异常
输出 build/verify_115_home.png / build/verify_115_settings.png 与一份 JSON 结果。
"""
import base64
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "animation", "v4"))
from cdp import CDP                                       # noqa: E402

OUT = os.path.join(ROOT, "build")
RESULT = os.path.join(OUT, "verify_115_preview.json")
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


def save_png(c, name):
    b64 = c.shot(fmt="png", beyond=False)
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(base64.b64decode(b64))


def main():
    c = CDP(9339, "verify115")
    c.start()
    try:
        c.cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": ("window.__errs=[];"
                       "window.addEventListener('error',function(e){"
                       "window.__errs.push(String(e.message||e));});"
                       "window.addEventListener('unhandledrejection',function(e){"
                       "window.__errs.push('rejection:'+String(e.reason));});")})
        c.load()

        check("预览页完整渲染，指标卡有数据",
              c.ev("(document.querySelector('#mTotal')||{}).textContent.trim().length>0"))
        check("首页页脚标注 1.1.15",
              c.ev("document.querySelector('#footInfo').textContent.indexOf('1.1.15')>=0"))
        check("实时访问事件卡片存在 liveScope 下拉且 5 个选项",
              c.ev("!!document.querySelector('#liveScope') && "
                   "document.querySelector('#liveScope').options.length===5"))

        # 真实切换监控范围：列表条数必须减少，证明前端过滤生效
        before = c.ev("document.querySelectorAll('#liveList .live-item').length")
        c.ev("(function(){var s=document.querySelector('#liveScope');"
             "s.value='overseas';s.dispatchEvent(new Event('change',{bubbles:true}));"
             "return 1;})()")
        c.wait(300)
        after = c.ev("document.querySelectorAll('#liveList .live-item').length")
        check("切换「境外」后实时列表条数真实减少",
              isinstance(before, int) and isinstance(after, int) and
              before > 0 and after > 0 and after < before,
              "%s -> %s" % (before, after))
        c.ev("(function(){var s=document.querySelector('#liveScope');"
             "s.value='';s.dispatchEvent(new Event('change',{bubbles:true}));"
             "return 1;})()")

        check("记录表 / 实时列表出现区级信息（蜀山区）",
              c.ev("document.body.innerText.indexOf('蜀山区')>=0"))
        geo = c.ev(
            "fetch('api/geodist?scope=all&rng=24h&limit=40')"
            ".then(function(r){return r.json()})"
            ".then(function(d){var x=(d&&d.data)||d;return JSON.stringify("
            "(x.regions||[]).slice(0,3).map(function(y){return [y.name,y.scope]}))})")
        check("地域分布境内按省细分且每行带 scope",
              bool(geo) and "安徽省" in geo and '"cn"' in geo, geo or "接口无数据")
        check("地域图统计文案改为「国家 / 地区 · 省份」口径",
              c.ev("(document.querySelector('#geoStat')||{}).textContent||''")
              .find("省份") >= 0)

        save_png(c, "verify_115_home.png")

        # 打开设置抽屉，滚到最底部看问题反馈区
        c.ev("document.querySelector('#btnSettings').click()")
        c.wait(400)
        body = c.ev("document.querySelector('#settingsBody').innerText") or ""
        check("设置抽屉已打开且含「问题反馈 · 运行日志一键导出」",
              "问题反馈 · 运行日志一键导出" in body)
        check("设置最底部含导出 / 预览两个按钮",
              c.ev("!!document.querySelector('#btnDiagExport') && "
                   "!!document.querySelector('#btnDiagView')"))
        check("设置页暴露新 IP 自动核验与区级补充开关",
              c.ev("!!document.querySelector('[data-k=geo_verify_auto]') && "
                   "!!document.querySelector('[data-k=geo_district_enabled]')"))

        c.ev("document.querySelector('#btnDiagView').click()")
        c.wait(700)
        prev = c.ev("(document.querySelector('#diagPreview')||{}).textContent||''") or ""
        check("点击预览真实拉到脱敏诊断包文本",
              "诊断包" in prev and "已自动脱敏" in prev and
              "生成失败" not in prev,
              "%d 字符" % len(prev))

        # 滚到抽屉底部截图
        c.ev("(function(){var b=document.querySelector('#settingsBody');"
             "b.scrollTop=b.scrollHeight;return b.scrollTop;})()")
        c.wait(250)
        save_png(c, "verify_115_settings.png")

        errs = c.ev("JSON.stringify(window.__errs||[])") or "[]"
        check("全程无未捕获 JS 异常", json.loads(errs) == [], errs[:200])
    finally:
        c.close()

    data = {"version": "1.1.15", "pass": ok, "fail": fail,
            "shots": ["build/verify_115_home.png",
                      "build/verify_115_settings.png"]}
    with io.open(RESULT, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False, indent=2))
    print("\n=== 预览验收：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
    if fail:
        print("失败项：" + ", ".join(fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
