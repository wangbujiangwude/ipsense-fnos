// 1.1.16 真机弧线回归：直接从真实 app.js 抽取函数执行，不复制实现。
// 核心断言：SDK 折线的每一个点都必须落在合法经纬度窗口内。
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const UI = path.join(ROOT, 'src', 'app', 'ui');
const src = fs.readFileSync(path.join(UI, 'app.js'), 'utf8');
const css = fs.readFileSync(path.join(UI, 'style.css'), 'utf8');

let ok = 0, fail = 0;
function check(name, cond, detail = '') {
  if (cond) { ok++; console.log('  OK   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (detail ? ' | ' + detail : '')); }
}

function grab(name) {
  const i = src.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('missing function ' + name);
  let j = src.indexOf('{', i), d = 0, k = j;
  for (; k < src.length; k++) {
    if (src[k] === '{') d++;
    else if (src[k] === '}') { d--; if (!d) { k++; break; } }
  }
  return src.slice(i, k);
}

const names = ['geoDist', 'arcControl', 'bezierAt', 'wrapSegs', 'worldSegs', 'arcPaths'];
const F = new Function('var S={arcBend:0.12};\n' +
  names.map(grab).join('\n') + '\nreturn {arcPaths,worldSegs,wrapSegs};')();
const home = { lat: 31.8639, lng: 117.2808 };
const cases = [
  ['美国长弧', { lat: 39.83, lng: -98.58 }],
  ['法国长弧', { lat: 46.6, lng: 2.2 }],
  ['新加坡', { lat: 1.35, lng: 103.82 }],
  ['同省短弧', { lat: 31.82, lng: 117.229 }],
  ['南美', { lat: -23.5, lng: -46.6 }],
];

console.log('=== 1. SDK 折线合法经度窗口 ===');
for (const [label, from] of cases) {
  const g = F.arcPaths(from, home, 'overseas');
  const segs = g.sdkSegs || [];
  let pts = 0, illegal = 0, lo = Infinity, hi = -Infinity;
  segs.forEach(seg => seg.forEach(p => {
    pts++;
    lo = Math.min(lo, p.lng); hi = Math.max(hi, p.lng);
    if (!isFinite(p.lng) || !isFinite(p.lat) || p.lng < -180 || p.lng > 180 ||
        p.lat < -85 || p.lat > 85) illegal++;
  }));
  check(label + '：SDK 折线 0 个非法点', illegal === 0,
    '段数=' + segs.length + ' 点数=' + pts + ' 经度=[' + lo.toFixed(1) + ',' + hi.toFixed(1) + '] 越界=' + illegal);
  check(label + '：不再生成 ±360 世界副本（段数 <= 2）', segs.length <= 2,
    '段数=' + segs.length);
  check(label + '：末点落到本机', (() => {
    const last = segs[segs.length - 1] || [];
    const p = last[last.length - 1] || {};
    return Math.abs((p.lat || 0) - home.lat) < 0.01 &&
           Math.abs((p.lng || 0) - home.lng) < 0.01;
  })(), '');
}

console.log('=== 2. 跨日期变更线分段与连续窗口 ===');
const cross = F.arcPaths({ lat: 39.83, lng: -98.58 }, home, 'overseas');
check('美国长弧被切成 2 段（±180 边界）', (cross.sdkSegs || []).length === 2,
  String((cross.sdkSegs || []).length));
check('两段端点贴着 ±180 边界', (() => {
  const a = (cross.sdkSegs || [])[0] || [], b = (cross.sdkSegs || [])[1] || [];
  return a.length > 1 && b.length > 1 &&
         Math.abs(Math.abs((a[a.length - 1] || {}).lng || 0) - 180) < 0.001 &&
         Math.abs(Math.abs((b[0] || {}).lng || 0) - 180) < 0.001;
})(), '');
check('Canvas 本机中心连续窗口仍在源码里',
  /function worldCenteredBounds\(home\)/.test(src) && /c - 180/.test(src));
check('SDK 坐标钳制兜底 sdkLat 已接上 paths',
  /function sdkLat\(lat, lng\)/.test(src) && /sdkLat\(p\.lat, p\.lng\)/.test(src));
check('源码里已无 [-360, 0, 360] 副本数组', !src.includes('[-360, 0, 360]'));
check('sdkLat 定义在 IIFE 顶层（createTMaps 内嵌会抛 ReferenceError）',
  /^  function sdkLat\(lat, lng\)/m.test(src) &&
  !/^    function sdkLat\(lat, lng\)/m.test(src));

console.log('=== 3. 设置开关可点击（DOM + CSS） ===');
const sw = grab('sw');
check('sw() 生成 label[for] 与 input id', /for="/.test(sw) && /var id = 'sw_'/.test(sw));
check('CSS input 铺满整个 .switch',
  /\.switch input\{position:absolute;inset:0;width:100%;height:100%/.test(css));
check('CSS 滑块不吃点击', /\.switch i\{[^}]*pointer-events:none/.test(css));

console.log('\n=== 结果：%d 项通过 / %d 项失败 ===', ok, fail);
process.exit(fail ? 1 : 0);
