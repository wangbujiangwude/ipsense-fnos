# -*- coding: utf-8 -*-
"""ipsense 1.1.16 离线预览页真实浏览器验收（Chrome CDP）。

与纯源码级 check_116_geometry.mjs 不同，本脚本在真实页面里验证「用户能感知」的部分：
  ① 从首页内联的真实 app.js 源码重建几何函数，确认 SDK 折线 0 个非法经度点；
  ② 用真实鼠标事件点击设置页开关，确认 checkbox 状态翻转（1.1.16 核心反馈）；
  ③ 真实打开 IP 来源画像，确认「目标端口」显示「未记录」而非 5666；
  ④ 确认在线校验入口、区级手工补充接口 UI 与区级字段展示；
  ⑤ 全程无未捕获 JS 异常。

输出 build/verify_116_preview.json 与三张截图。
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
RESULT = os.path.join(OUT, "verify_116_preview.json")
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


def click_at(c, x, y):
    """真实鼠标按下/抬起，而不是 element.click()，用来证明 CSS 没有吃掉点击。"""
    for t in ("mouseMoved", "mousePressed", "mouseReleased"):
        p = {"type": t, "x": x, "y": y, "button": "left", "clickCount": 1}
        if t == "mouseMoved":
            p.pop("button")
            p.pop("clickCount")
        c.cmd("Input.dispatchMouseEvent", p)


# 从页面内联的真实 app.js 源码里按括号配平抽出函数，再在页面上下文中重建。
# 不复制实现、不读本地文件，验证的就是即将装进 FPK 的那份源码。
REBUILD = r"""
(function () {
  var s = '';
  for (var i = 0; i < document.scripts.length; i++) {
    var t = document.scripts[i].textContent || '';
    if (t.indexOf('function worldSegs(') >= 0) { s = t; break; }
  }
  if (!s) return JSON.stringify({err: '内联 app.js 未找到'});
  function grab(name) {
    var i = s.indexOf('function ' + name + '(');
    if (i < 0) return '';
    var j = s.indexOf('{', i), d = 0, k = j;
    for (; k < s.length; k++) {
      if (s[k] === '{') d++;
      else if (s[k] === '}') { d--; if (!d) { k++; break; } }
    }
    return s.slice(i, k);
  }
  var names = ['geoDist', 'arcControl', 'bezierAt', 'wrapSegs',
               'worldSegs', 'arcPaths', 'portLabel'];
  var body = names.map(grab).join('\n');
  if (body.indexOf('function arcPaths(') < 0)
    return JSON.stringify({err: '函数抽取不完整'});
  var F = new Function('var S={arcBend:0.12,cfg:{web_port:5666}};\n' +
                       body + '\nreturn {arcPaths:arcPaths,portLabel:portLabel};')();
  window.__F116 = F;
  window.__src116 = s;
  return JSON.stringify({ok: true, len: s.length});
})()
"""


def main():
    c = CDP(9343, "verify116")
    c.start()
    try:
        c.cmd("Page.addScriptToEvaluateOnNewDocument", {"source": (
            "window.__errs=[];"
            "window.addEventListener('error',function(e){"
            "window.__errs.push(String(e.message||e));});"
            "window.addEventListener('unhandledrejection',function(e){"
            "window.__errs.push('rejection:'+String(e.reason));});")})
        c.load()

        # ---------- A 版本与页面 ----------
        check("预览页完整渲染，指标卡有数据",
              c.ev("(document.querySelector('#mTotal')||{}).textContent.trim().length>0"))
        check("首页页脚标注 1.1.16",
              c.ev("document.querySelector('#footInfo').textContent.indexOf('1.1.16')>=0"))

        # ---------- B ① 弧线 SDK 合法经度窗口 ----------
        rb = json.loads(c.ev(REBUILD) or "{}")
        check("从首页内联源码成功重建真实几何函数", rb.get("ok") is True, str(rb))
        check("源码已无 [-360, 0, 360] 世界副本",
              c.ev("window.__src116.indexOf('[-360, 0, 360]')<0") is True)
        check("SDK 坐标钳制 sdkLat 已接上折线路径",
              c.ev("window.__src116.indexOf('sdkLat(p.lat, p.lng)')>=0") is True)
        check("sdkLat 定义在顶层，SDK 路径不会抛 ReferenceError",
              c.ev("/^  function sdkLat\\(lat, lng\\)/m.test(window.__src116) && !/^    function sdkLat\\(lat, lng\\)/m.test(window.__src116)") is True)
        check("Canvas 本机中心连续窗口仍在",
              c.ev("window.__src116.indexOf('function worldCenteredBounds(')>=0") is True)

        geo = r"""
        (function () {
          var F = window.__F116, home = {lat: 31.8639, lng: 117.2808};
          var cases = [['美国', 39.83, -98.58], ['法国', 46.6, 2.2],
                       ['新加坡', 1.35, 103.82], ['南美', -23.5, -46.6],
                       ['同省', 31.82, 117.229]];
          var out = [];
          cases.forEach(function (c2) {
            var g = F.arcPaths({lat: c2[1], lng: c2[2]}, home, 'overseas');
            var segs = g.sdkSegs || [], pts = 0, bad = 0, lo = 1e9, hi = -1e9;
            segs.forEach(function (s) { s.forEach(function (p) {
              pts++;
              lo = Math.min(lo, p.lng); hi = Math.max(hi, p.lng);
              if (!isFinite(p.lng) || !isFinite(p.lat) ||
                  p.lng < -180 || p.lng > 180 || p.lat < -85 || p.lat > 85) bad++;
            }); });
            out.push({name: c2[0], segs: segs.length, pts: pts, bad: bad,
                      lo: lo, hi: hi});
          });
          return JSON.stringify(out);
        })()
        """
        rows = json.loads(c.ev(geo) or "[]")
        check("5 条真实弧线全部有 SDK 折线点", len(rows) == 5 and
              all(r["pts"] > 0 for r in rows),
              ", ".join("%s:%d点/%d段" % (r["name"], r["pts"], r["segs"])
                        for r in rows))
        check("SDK 折线 0 个非法经纬度点（真机弧线不再整层不渲染）",
              all(r["bad"] == 0 for r in rows),
              ", ".join("%s:%d" % (r["name"], r["bad"]) for r in rows))
        check("所有 SDK 段数 <= 2（不再生成 ±360 世界副本）",
              all(r["segs"] <= 2 for r in rows))
        us = next((r for r in rows if r["name"] == "美国"), {})
        check("美国跨日期变更线长弧切成 2 段", us.get("segs") == 2,
              "段数=%s 经度=[%.1f,%.1f]" % (us.get("segs"), us.get("lo", 0), us.get("hi", 0)))

        # ---------- C ② 设置开关可点击（真实鼠标） ----------
        c.ev("document.querySelector('#btnSettings').click()")
        c.wait(500)
        check("设置抽屉已打开",
              c.ev("!!document.querySelector('#settingsBody')") is True)

        css = r"""
        (function () {
          var inp = document.querySelector('[data-k=map_arc_animate]');
          if (!inp) return JSON.stringify({err: 'missing'});
          var sw = inp.closest('.switch') || inp.parentElement;
          var i = sw.querySelector('i') || sw;
          var a = getComputedStyle(inp), b = getComputedStyle(i);
          var r = inp.getBoundingClientRect();
          return JSON.stringify({w: r.width, h: r.height,
                                 inputPos: a.position, inputOpacity: a.opacity,
                                 sliderPE: b.pointerEvents,
                                 labelFor: !!document.querySelector(
                                   'label[for=' + inp.id + ']')});
        })()
        """
        st = json.loads(c.ev(css) or "{}")
        check("透明 input 已铺满 .switch（不再是 0×0）",
              st.get("w", 0) > 0 and st.get("h", 0) > 0,
              "%.0f×%.0f px" % (st.get("w", 0), st.get("h", 0)))
        check("装饰滑块不吃点击（pointer-events:none）",
              st.get("sliderPE") == "none", st.get("sliderPE"))
        check("label[for] 与 input id 已配对", st.get("labelFor") is True)
        check("「散点模式流动光点」开关存在", st.get("err") is None)

        def real_click_switch(key):
            c.ev("(function(){var e=document.querySelector('[data-k=%s]');"
                 "if(!e)return 0;var s=e.closest('.switch')||e.parentElement;"
                 "(s.querySelector('i')||s).scrollIntoView({block:'center'});"
                 "return 1;})()" % key)
            c.wait(220)
            pos = json.loads(c.ev(
                "(function(){var e=document.querySelector('[data-k=%s]');"
                "if(!e)return '{}';var s=e.closest('.switch')||e.parentElement;"
                "var i=s.querySelector('i')||s;var r=i.getBoundingClientRect();"
                "return JSON.stringify({x:r.left+r.width/2,y:r.top+r.height/2,"
                "w:r.width,h:r.height,checked:e.checked});})()" % key) or "{}")
            if not pos.get("w"):
                return None
            click_at(c, pos["x"], pos["y"])
            c.wait(180)
            after = c.ev("(function(){var e=document.querySelector('[data-k=%s]');"
                         "return e?e.checked:null;})()" % key)
            return pos.get("checked"), after

        r1 = real_click_switch("map_arc_animate")
        check("真实鼠标点「散点模式流动光点」滑块后开关翻转",
              r1 is not None and r1[0] != r1[1],
              "%s -> %s" % (r1[0], r1[1]) if r1 else "未找到")
        r2 = real_click_switch("geo_verify_auto")
        check("真实鼠标点「新 IP 自动核验」开关后翻转",
              r2 is not None and r2[0] != r2[1],
              "%s -> %s" % (r2[0], r2[1]) if r2 else "未找到")
        r3 = real_click_switch("geo_district_api_enabled")
        check("真实鼠标点「启用自定义区级接口」开关后翻转",
              r3 is not None and r3[0] != r3[1],
              "%s -> %s" % (r3[0], r3[1]) if r3 else "未找到")

        body = c.ev("document.querySelector('#settingsBody').innerText") or ""
        check("设置页含「区级归属校验接口（可选）」区块",
              "区级归属校验接口" in body)
        check("设置页提供 {ip} 占位接口 URL 与字段名",
              c.ev("!!document.querySelector('[data-k=geo_district_api]') && "
                   "!!document.querySelector('[data-k=geo_district_field]')") is True)
        c.ev("(function(){var b=document.querySelector('#settingsBody');"
             "b.scrollTop=b.scrollHeight;return b.scrollTop;})()")
        c.wait(250)
        save_png(c, "verify_116_settings.png")

        # ---------- D ③ 端口不再冒充 5666 ----------
        pl = r"""
        (function () {
          var f = window.__F116.portLabel;
          return JSON.stringify([f(0, 'local_web'), f(5666, 'local_web'),
                                 f(22, 'fnos_audit'), f(443, '')]);
        })()
        """
        labels = json.loads(c.ev(pl) or "[]")
        check("portLabel：port=0 显示「未记录」", labels[0:1] == ["未记录"], str(labels))
        check("portLabel：历史 5666 仍兜底显示「未记录」", labels[1:2] == ["未记录"])
        check("portLabel：真实非自身端口原样显示", labels[2:4] == ["22", "443"])

        # 关抽屉再开画像，避免遮罩挡住记录表点击
        c.ev("(function(){var b=document.querySelector("
             "'#settingsDrawer [data-close]');if(b)b.click();"
             "else document.querySelector('#mask').click();return 1;})()")
        c.wait(350)
        c.ev("(function(){var t=document.querySelector('tr[data-ip]');"
             "if(t)t.click();return 1;})()")
        c.wait(700)
        detail = c.ev("(document.querySelector('#detailBody')||{}).innerText||''") or ""
        check("IP 来源画像已真实打开", "目标端口" in detail,
              "%d 字符" % len(detail))
        # 精确按 DOM 取「目标端口」这一行的值：画像里来路 TOP 本来就含
        # http://...:5666/ 这样的历史 URL，全文搜 "5666" 会误判。
        port_cell = c.ev(
            "(function(){var kv=document.querySelectorAll('#detailBody .kv');"
            "for(var i=0;i<kv.length;i++){var b=kv[i].querySelector('b');"
            "if(b&&b.textContent.trim()==='目标端口')"
            "return (kv[i].querySelector('span')||{}).textContent||'';}"
            "return '';})()") or ""
        check("画像「目标端口」单元格精确显示「未记录」",
              port_cell.strip() == "未记录", repr(port_cell))
        check("画像如实说明区级「在线源未返回，可手工补充」",
              "在线源未返回" in detail)
        check("未核验 IP 也渲染区级补全入口（districtBlock(null)）",
              c.ev("window.__src116.indexOf('districtBlock(null)')>=0") is True)
        check("画像提供「在线校验」入口（tool.hiofd.com）",
              c.ev("!!document.querySelector('[data-act=extcheck]')") is True)
        check("画像提供区级输入框与保存按钮",
              c.ev("!!document.querySelector('#districtInput') && "
                   "!!document.querySelector('[data-act=district]')") is True)

        opened = r"""
        (function () {
          window.__opened = [];
          var old = window.open;
          window.open = function (u) { window.__opened.push(String(u)); return {}; };
          try {
            var b = document.querySelector('[data-act=extcheck]');
            if (!b) return JSON.stringify({err: 'no button'});
            b.click();
          } finally { window.open = old; }
          return JSON.stringify(window.__opened);
        })()
        """
        urls = json.loads(c.ev(opened) or "[]")
        check("点「在线校验」真实打开 tool.hiofd.com/ip/ 查询页",
              any("tool.hiofd.com/ip/" in u for u in urls), str(urls))

        # 真实走一遍「手工回填区级 → 后端保存 → 画像重拉 → 归属地出现区县」
        c.ev("(function(){var b=document.querySelector('#districtInput');"
             "if(b)b.value='包河区';return 1;})()")
        c.ev("(function(){var b=document.querySelector('[data-act=district]');"
             "if(b)b.click();return 1;})()")
        c.wait(900)
        detail2 = c.ev("(document.querySelector('#detailBody')||{}).innerText||''") or ""
        check("真实点击「保存区级信息」后归属地出现「包河区」",
              "包河区" in detail2, "%d 字符" % len(detail2))
        check("回填后区级输入框保留新值",
              (c.ev("(document.querySelector('#districtInput')||{}).value||''") or "") == "包河区")
        save_png(c, "verify_116_detail.png")

        # ---------- E 边界与异常 ----------
        check("只观测口径文案未回归",
              "只观测" in (c.ev("document.body.innerText") or ""))
        errs = c.ev("JSON.stringify(window.__errs||[])") or "[]"
        check("全程无未捕获 JS 异常", json.loads(errs) == [], errs[:220])
        save_png(c, "verify_116_home.png")
    finally:
        c.close()

    data = {"version": "1.1.16", "pass": ok, "fail": fail,
            "shots": ["build/verify_116_home.png",
                      "build/verify_116_settings.png",
                      "build/verify_116_detail.png"]}
    with io.open(RESULT, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False, indent=2))
    print("\n=== 1.1.16 预览验收：%d 项通过 / %d 项失败 ===" % (ok, len(fail)))
    if fail:
        print("失败项：" + ", ".join(fail))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
