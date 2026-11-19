// 1.1.18 地图接缝回归：三世界副本裁剪后，跨 ±180° 长弧的两段必须
// 首尾严格对齐、所有点落在 SDK 合法窗口内，且不写死 ±180 触发回卷。
// 运行：node tools/check_118_geometry.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = fs.readFileSync(path.join(ROOT, 'src/app/ui/app.js'), 'utf8');

let ok = 0, fail = 0;
function chk(name, cond, extra = '') {
  if (cond) { ok++; console.log('  PASS  ' + name + (extra ? '  ' + extra : '')); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  ' + extra : '')); }
}

function grab(name) {
  const i = SRC.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('missing function ' + name);
  let j = SRC.indexOf('{', i), d = 0, k = j;
  for (; k < SRC.length; k++) {
    if (SRC[k] === '{') d++;
    else if (SRC[k] === '}') { d--; if (!d) { k++; break; } }
  }
  return SRC.slice(i, k);
}

const names = ['geoDist', 'arcControl', 'bezierAt', 'wrapSegs',
               'seamPoint', 'clipToWindow', 'worldSegs', 'arcPaths'];
const F = new Function('var S={arcBend:0.12};\nvar SEAM_EPS=0.001;\n' +
  names.map(grab).join('\n') +
  '\nreturn {arcPaths,worldSegs,wrapSegs,clipToWindow,seamPoint};')();

const home = { lat: 31.8639, lng: 117.2808 };
const cases = [
  ['美国（跨太平洋）', { lat: 39.83, lng: -98.58 }, true],
  ['南美（经度差 <180，不跨 seam）', { lat: -23.5, lng: -46.6 }, false],
  ['加拿大（跨太平洋）', { lat: 56.1, lng: -106.3 }, true],
  ['法国（不跨 seam）', { lat: 46.6, lng: 2.2 }, false],
  ['新加坡（不跨 seam）', { lat: 1.35, lng: 103.82 }, false],
  ['同省短弧', { lat: 31.82, lng: 117.229 }, false],
];

console.log('=== 1. SDK 折线：合法窗口 + 段数 ===');
for (const [label, from, cross] of cases) {
  const g = F.arcPaths(from, home, 'overseas');
  const segs = g.sdkSegs || [];
  let pts = 0, illegal = 0, hardEdge = 0, lo = Infinity, hi = -Infinity;
  for (const seg of segs) {
    for (const p of seg) {
      pts++;
      if (!(p.lng >= -180 && p.lng <= 180) || !(p.lat >= -90 && p.lat <= 90)) illegal++;
      if (Math.abs(Math.abs(p.lng) - 180) < 1e-9) hardEdge++;
      lo = Math.min(lo, p.lng); hi = Math.max(hi, p.lng);
    }
  }
  chk(label + '：点数 > 0 且全部合法', pts > 0 && illegal === 0,
      'pts=' + pts + ' illegal=' + illegal);
  chk(label + '：无写死 ±180 端点（避免 SDK 回卷）', hardEdge === 0,
      'hardEdge=' + hardEdge);
  chk(label + '：段数符合是否跨 seam', cross ? segs.length === 2 : segs.length === 1,
      'segs=' + segs.length);
  chk(label + '：每段至少 2 个点', segs.every(s => s.length > 1));
}

console.log('\n=== 2. 接缝两端点严格对齐 ===');
for (const [label, from] of cases.filter(c => c[2])) {
  const g = F.arcPaths(from, home, 'overseas');
  const segs = g.sdkSegs;
  // 找到落在 +180 附近与 -180 附近的两个端点
  const right = [], left = [];
  for (const seg of segs) {
    for (const p of seg) {
      if (p.lng > 179) right.push(p);
      if (p.lng < -179) left.push(p);
    }
  }
  const r = right.reduce((a, b) => b.lng > a.lng ? b : a, right[0] || { lng: -1, lat: 0 });
  const l = left.reduce((a, b) => b.lng < a.lng ? b : a, left[0] || { lng: 1, lat: 0 });
  chk(label + '：接缝处两段端点纬度一致',
      Math.abs(r.lat - l.lat) < 1e-6,
      'right=' + r.lat.toFixed(6) + ' left=' + l.lat.toFixed(6));
  chk(label + '：端点收进 180-ε 内',
      r.lng <= 180 - 0.0009 && l.lng >= -180 + 0.0009,
      'right=' + r.lng + ' left=' + l.lng);
}

console.log('\n=== 3. Canvas 连续窗口未回归 ===');
for (const [label, from] of cases) {
  const g = F.arcPaths(from, home, 'overseas');
  const flat = [];
  for (const seg of g.segs) for (const p of seg) flat.push(p);
  const unwrapped = flat.map(p => {
    let x = p.lng, c = home.lng;
    while (x - c > 180) x -= 360;
    while (x - c < -180) x += 360;
    return x;
  });
  const maxJump = unwrapped.slice(1).reduce(
    (m, x, i) => Math.max(m, Math.abs(x - unwrapped[i])), 0);
  chk(label + '：unwrapTo 后无 >180° 跳变', maxJump < 180,
      'maxJump=' + maxJump.toFixed(3));
}

console.log('\n=== 4. 三世界副本都产出合法几何 ===');
const g = F.arcPaths({ lat: 39.83, lng: -98.58 }, home, 'overseas');
const segs = g.sdkSegs;
chk('跨 seam 长弧生成两个世界副本段', segs.length === 2, 'segs=' + segs.length);
chk('两段分别位于东西两侧',
    segs.some(s => s[0].lng > 0) && segs.some(s => s[0].lng < 0));
chk('主窗口内无孤立单点段', segs.every(s => s.length >= 2));

console.log('\n=== 结果：' + ok + ' 项通过 / ' + fail + ' 项失败 ===');
process.exit(fail ? 1 : 0);
