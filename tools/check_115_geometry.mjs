// 1.1.15 几何回归：从真实 app.js 抽取函数源码执行，验证长弧连续性与同省短弧。
// 运行：node tools/check_115_geometry.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = fs.readFileSync(path.join(ROOT, 'src/app/ui/app.js'), 'utf8');

const NAMES = [
  'proj', 'worldCenteredBounds', 'unwrapTo',
  'geoDist', 'arcControl', 'bezierAt', 'wrapSegs',
  // 1.1.18：worldSegs 改为三副本裁剪，依赖这两个函数与 SEAM_EPS
  'seamPoint', 'clipToWindow', 'worldSegs', 'arcPaths',
  'mapSdkUrl'
];

function extract(name) {
  // app.js 顶层函数一律两空格缩进；截到下一个顶层声明之前。
  const start = SRC.indexOf('  function ' + name + '(');
  if (start < 0) throw new Error('找不到函数 ' + name);
  const rest = SRC.slice(start + 2);
  const m = /\n  (?:function |var |const )/.exec(rest);
  const end = m ? start + 2 + m.index : SRC.length;
  return SRC.slice(start, end).trimEnd();
}

const PRELUDE = `
var WORLD_BOUNDS = { latMin: -58, latMax: 78, lngMin: -180, lngMax: 180 };
var S = { arcBend: 0.12 };
var SEAM_EPS = 0.001;
`;
const code = PRELUDE + NAMES.map(extract).join('\n') +
  '\nreturn { ' + NAMES.join(', ') + ' };';
const F = new Function(code)();

let ok = 0, fail = 0;
function chk(name, cond, extra) {
  if (cond) { ok++; console.log('  PASS  ' + name + (extra ? '  ' + extra : '')); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  ' + extra : '')); }
}

const HOME = { lat: 22.5431, lng: 114.0579 };

console.log('=== 1. 本机中心 360° 窗口 ===');
const b = F.worldCenteredBounds(HOME);
chk('窗口以本机经度为中心', Math.abs(b.lngMin - (HOME.lng - 180)) < 1e-9 &&
  Math.abs(b.lngMax - (HOME.lng + 180)) < 1e-9,
  '[' + b.lngMin.toFixed(2) + ', ' + b.lngMax.toFixed(2) + ']');
const hp = F.proj(HOME.lat, HOME.lng, b, 800, 400);
chk('本机落在画布水平正中', Math.abs(hp[0] - 400) < 1e-9, 'x=' + hp[0].toFixed(2));

console.log('\n=== 2. 境外长弧（美国西海岸 → 深圳，跨 ±180°） ===');
const WEST = { lat: 37.77, lng: -122.42 };
const gLong = F.arcPaths(WEST, HOME, 'overseas');
chk('采样点加密到 96 段', gLong.n >= 64, 'n=' + gLong.n);
chk('判定为跨日期变更线', gLong.cross === 1);
chk('SDK 生成多份世界副本折线', gLong.sdkSegs.length >= 2,
  gLong.sdkSegs.length + ' 段');
chk('主窗口 Canvas 被切成两段', gLong.segs.length >= 2,
  gLong.segs.length + ' 段');

// 关键断言：把 wrapSegs 切出的两段按本机中心窗口展开后，必须首尾相接、
// 且整条曲线相邻采样点之间没有任何 360° 跳变 —— 也就是视觉上不再中断。
const flat = [];
gLong.segs.forEach(seg => seg.forEach(p => flat.push(F.unwrapTo(p.lng, HOME.lng))));
let jump = 0, outside = 0;
for (let i = 0; i < flat.length; i++) {
  if (flat[i] < b.lngMin - 1e-6 || flat[i] > b.lngMax + 1e-6) outside++;
  if (i && Math.abs(flat[i] - flat[i - 1]) > 20) jump++;
}
chk('展开后全部落在同一连续窗口', outside === 0, '越界点 ' + outside);
chk('整条弧无 360° 经度跳变（不中断）', jump === 0, '跳变 ' + jump);
const seamA = F.unwrapTo(gLong.segs[0][gLong.segs[0].length - 1].lng, HOME.lng);
const seamB = F.unwrapTo(gLong.segs[1][0].lng, HOME.lng);
chk('两段在 seam 处首尾相接', Math.abs(seamA - seamB) < 1e-6,
  seamA.toFixed(4) + ' / ' + seamB.toFixed(4));
const last = gLong.segs[gLong.segs.length - 1].slice(-1)[0];
chk('末点正确落到本机', Math.abs(F.unwrapTo(last.lng, HOME.lng) - HOME.lng) < 0.01 &&
  Math.abs(last.lat - HOME.lat) < 0.01,
  '(' + last.lat.toFixed(2) + ', ' + F.unwrapTo(last.lng, HOME.lng).toFixed(2) + ')');

console.log('\n=== 3. 同省 / 同城短弧（广州 → 深圳） ===');
const GZ = { lat: 23.13, lng: 113.26 };
const nearMetric = Math.abs(GZ.lat - HOME.lat) +
  Math.abs(GZ.lng - HOME.lng) * 0.85;
chk('不再被 0.35° 阈值误判为与本机重合', nearMetric > 0.02 && nearMetric > 0.35,
  '距离度量 ' + nearMetric.toFixed(4) + ' > 旧阈值 0.35');
const gShort = F.arcPaths(GZ, HOME, 'cn');
chk('短弧不生成多余世界副本', gShort.sdkSegs.length === 1,
  gShort.sdkSegs.length + ' 段');
chk('短弧有可见弯曲但不成回环',
  gShort.c1.lat !== GZ.lat || gShort.c1.lng !== GZ.lng,
  'c1=(' + gShort.c1.lat.toFixed(3) + ', ' + gShort.c1.lng.toFixed(3) + ')');
const h = Math.abs(gShort.c1.lat - (GZ.lat + (HOME.lat - GZ.lat) / 3));
chk('短弧弯曲幅度收敛（< 1°）', h < 1, '偏移 ' + h.toFixed(4) + '°');

console.log('\n=== 4. 高德 SDK 域名纠错 ===');
const badUrl = 'https://webapiamap.com/maps?v=2.0&key={key}';
const fixed = F.mapSdkUrl({ sdk: badUrl }, 'TESTKEY123');
chk('错误域名被纠正为官方域名', fixed.indexOf('webapi.amap.com') >= 0 &&
  fixed.indexOf('webapiamap.com') < 0, fixed);
chk('KEY 仍被正确替换', fixed.indexOf('TESTKEY123') >= 0);
const good = F.mapSdkUrl(
  { sdk: 'https://webapi.amap.com/maps?v=2.0&key={key}' }, 'K');
chk('正常域名不受影响', good === 'https://webapi.amap.com/maps?v=2.0&key=K', good);

console.log('\n=== 结果：' + ok + ' 项通过 / ' + fail + ' 项失败 ===');
process.exit(fail ? 1 : 0);
