/* IP 动态感知 · 前端（内联注入首页，避免网关对静态资源的票据校验） */
(function () {
  'use strict';

  // ---- 基础工具 ----
  var BASE = location.pathname;
  if (!BASE.endsWith('/')) BASE = BASE.slice(0, BASE.lastIndexOf('/') + 1);
  var TICKET = location.search ? location.search.slice(1) + '&' : '';
  function url(path) {
    var sep = path.indexOf('?') >= 0 ? '&' : '?';
    return BASE + path.replace(/^\//, '') + sep + TICKET + '_=' + Date.now();
  }
  // ---- 1.1.17：前端运行时报错采集 ----
  // 旧版只把底图错误显示在页面上，JS 异常 / SDK 加载失败 / 接口失败一关页面就没了，
  // 用户没法把「软件运行时到底报了什么错」交给别人定位。这里做三件事：
  //   ① 全局捕获 error / unhandledrejection / 资源加载失败 / 接口失败；
  //   ② 内存环形缓冲 + 同因合并，避免轮询失败把日志刷爆；
  //   ③ 批量 POST /api/runtime/errors 落盘，失败静默退避，绝不产生新的异常。
  // 只记录错误本身与环境上下文，不记录请求体、票据、Cookie 或原始事件行。
  var RT = { buf: [], pending: [], timer: null, seen: {}, max: 200,
             blocked: 0, fails: 0, sent: 0, dropped: 0 };
  var RT_HOST = { tencent: 'map.qq.com', amap: 'webapi.amap.com',
                  bmapgl: 'api.map.baidu.com', tianditu: 'api.tianditu.gov.cn' };
  function rtSafeUrl(u) {
    try {
      var s = String(u || ''), i = s.indexOf('?');
      if (i < 0) return s.slice(0, 300);
      // 参数名保留（能看出 URL 带了 key / callback），参数值一律不落盘
      var q = s.slice(i + 1).split('&')
        .map(function (p) { return p.split('=')[0]; })
        .filter(Boolean).join(',');
      return (s.slice(0, i) + (q ? '?<参数名:' + q + '>' : '')).slice(0, 300);
    } catch (e) { return String(u || '').slice(0, 300); }
  }
  function rtCtx() {
    var c = { ver: '', provider: '', mapState: '', mapError: '', pill: '',
              ua: navigator.userAgent, page: location.pathname };
    try {
      c.ver = (S && S.version) || '';
      c.provider = (S && S.mapProvider) || '';
      c.mapState = (S && S.tmapState) || '';
      c.mapError = (S && S.tmapError) || '';
      var pill = document.querySelector('#statusPill span');
      c.pill = pill ? pill.textContent : '';
    } catch (e) {}
    return c;
  }
  function rtDupWindow(kind) { return kind === 'api' ? 60000 : 5000; }
  function rtPush(o) {
    try {
      var now = Date.now();
      o = o || {};
      var e = {
        ts: now / 1000,
        kind: String(o.kind || 'js').slice(0, 40),
        level: String(o.level || 'error').slice(0, 16),
        msg: String(o.msg || '').slice(0, 500),
        src: rtSafeUrl(o.src || ''), url: rtSafeUrl(o.url || ''),
        stack: String(o.stack || '').slice(0, 1500),
        line: Number(o.line) || 0, col: Number(o.col) || 0,
        status: Number(o.status) || 0, dur: Number(o.dur) || 0,
        count: 1, provider: String(o.provider || '').slice(0, 60),
        host: String(o.host || '').slice(0, 120),
        tag: String(o.tag || '').slice(0, 16)
      };
      var k = e.kind + '|' + e.msg.slice(0, 160) + '|' + e.src;
      var prev = RT.seen[k], at = prev ? RT.buf.indexOf(prev.ref) : -1;
      if (prev && now - prev.at < rtDupWindow(e.kind) && at >= 0) {
        prev.ref.count++; prev.at = now; prev.idx = at;
        return;
      }
      if (RT.buf.length >= RT.max) RT.buf.shift();
      RT.buf.push(e);
      RT.seen[k] = { at: now, idx: RT.buf.length - 1, ref: e };
      if (RT.pending.length >= RT.max) RT.dropped++;
      else RT.pending.push(e);
      rtSchedule();
    } catch (err) {}
  }
  function rtSchedule() {
    if (!RT.timer) RT.timer = setTimeout(rtFlush, 800);
  }
  function rtRetry(items) {
    RT.fails++;
    RT.blocked = Date.now() + Math.min(60000, 5000 * RT.fails);
    RT.pending = items.concat(RT.pending).slice(0, RT.max);
    if (!RT.timer) RT.timer = setTimeout(rtFlush, 5000);
  }
  function rtFlush() {
    RT.timer = null;
    if (!RT.pending.length) return;
    if (Date.now() < RT.blocked) {
      if (!RT.timer) RT.timer = setTimeout(rtFlush, 5000);
      return;
    }
    var items = RT.pending.splice(0, 20);   // 单批 <= 20 条，避免请求体过大
    try {
      var p = fetch(url('api/runtime/errors'), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ items: items, ctx: rtCtx() }),
        cache: 'no-store'
      });
      if (p && p.then) {
        p.then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          RT.fails = 0; RT.sent += items.length;
        }, function () { rtRetry(items); });
      }
    } catch (e) { rtRetry(items); }
    if (RT.pending.length && Date.now() >= RT.blocked) rtSchedule();
  }
  // 捕获阶段才能拿到 <script>/<link>/<img> 的加载失败，SDK 挂掉就靠这一条
  window.addEventListener('error', function (e) {
    var t = e.target;
    if (t && t !== window && (t.src || t.href)) {
      rtPush({ kind: 'resource', msg: '资源加载失败：' + rtSafeUrl(t.src || t.href),
               src: t.src || t.href, tag: (t.tagName || '').toLowerCase() });
    } else {
      rtPush({ kind: 'js', msg: e.message || '未捕获异常', src: e.filename || '',
               line: e.lineno || 0, col: e.colno || 0,
               stack: (e.error && e.error.stack) || '' });
    }
  }, true);
  window.addEventListener('unhandledrejection', function (e) {
    var r = e.reason || {};
    rtPush({ kind: 'rejection', msg: String(r.message || r || '未处理的 Promise 拒绝'),
             stack: r.stack || '' });
  });
  window.addEventListener('pagehide', function () { rtFlush(); });
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') rtFlush();
  });

  function api(path, method, body) {
    // 1.1.1：给所有请求加超时兜底。以前一旦后端卡住，抽屉会永远停在
    // 「加载中…」且没有任何错误提示；现在超时/失败都会落到 catch 显示原因。
    var ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timeout = method && method !== 'GET' ? 30000 : 15000;
    var timer = ctl ? setTimeout(function () { ctl.abort(); }, timeout) : null;
    return fetch(url(path), {
      method: method || 'GET',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      cache: 'no-store',
      signal: ctl ? ctl.signal : undefined
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (v) {
      if (timer) clearTimeout(timer);
      return v;
    }, function (e) {
      if (timer) clearTimeout(timer);
      if (e && e.name === 'AbortError') throw new Error('请求超时，请稍后重试');
      throw e;
    });
  }
  // 1.1.7：把单个请求的失败收敛成 {ok:false}，同轮其它接口照常渲染。
  // 旧版 loadLight / loadHeavy 直接 Promise.all，9 个接口里任意一个超时就
  // 整轮结果全丢，还把状态标误打成「连接失败」；现在失败只影响自己那块数据。
  function settle(p, label) {
    return p.then(function (r) { return { ok: true, data: r }; },
                  function (e) {
                    console.warn('api ' + label + ' failed: ' + (e && e.message || e));
                    // 1.1.17：接口失败也要留痕；同一接口 60 秒内只记一条并累计次数
                    rtPush({ kind: 'api', msg: '接口失败 ' + label + '：' +
                             (e && e.message || e), url: label });
                    return { ok: false, err: e, label: label };
                  });
  }
  function badNames(rs, names) {
    var bad = [];
    for (var i = 0; i < rs.length; i++) if (!rs[i].ok) bad.push(names[i]);
    return bad;
  }
  function markLightResult(bad) {
    S.lightBad = bad;
    if (!bad.length) { S.lightFails = 0; S.lastLightOk = Date.now(); }
    else if (bad.length >= 3) S.lightFails++;
    updateLinkPill();
  }
  function markHeavyResult(bad) {
    S.heavyBad = bad;
    if (!bad.length) { S.heavyFails = 0; S.lastHeavyOk = Date.now(); }
    else if (bad.length >= 6) S.heavyFails++;
    updateLinkPill();
  }
  // 1.1.7：状态标统一由这里计算，不受数据指纹短路影响，任何一轮成功都能恢复。
  // 三级语义：全绿「运行中」/ 橙「部分数据异常」/ 红「连接失败」或「归属库异常」。
  function updateLinkPill() {
    var pill = $('statusPill'); if (!pill) return;
    var span = pill.querySelector('span');
    var bad = (S.lightBad || []).concat(S.heavyBad || []);
    var allBad = S.lightFails >= 2 || S.heavyFails >= 2;
    var cls = 'status-pill', txt, tip = '';
    if (allBad) { cls += ' bad'; txt = '连接失败'; tip = '连续两轮接口全部无响应'; }
    else if (bad.length) { cls += ' warn'; txt = '部分数据异常'; tip = '未响应：' + bad.join('、'); }
    else if (S.geoReady === false) { cls += ' bad'; txt = '归属库异常'; tip = 'IP 归属库未就绪'; }
    else txt = '运行中 · ' + countSources(S.sources) + ' 路数据源';
    pill.className = cls;
    span.textContent = txt;
    pill.title = tip || ('最近刷新 ' + new Date(
      Math.max(S.lastLightOk, S.lastHeavyOk) || Date.now()).toLocaleTimeString());
  }
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function num(n) { return (Number(n) || 0).toLocaleString('zh-CN'); }
  function tm(ts) {
    if (!ts) return '—';
    var d = new Date(ts * 1000);
    return ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2) + ' ' +
      ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' +
      ('0' + d.getSeconds()).slice(-2);
  }
  function toast(msg) {
    var t = $('toast'); t.textContent = msg; t.classList.add('on');
    clearTimeout(t._timer); t._timer = setTimeout(function () { t.classList.remove('on'); }, 2600);
  }
  var SRC_NAME = {
    local_auth: '本机 SSH', local_web: '本机 Web', local_kern: '内核日志',
    router_syslog: '路由器 syslog', router_file: '路由器文件', knock: '端口敲门',
    knock_app: '敲门网关',
    fnos_audit: 'fnOS 审计',
    lucky_web: 'Lucky 反代', lucky_sys: 'Lucky 系统'
  };
  var VERDICT_NAME = { normal: '正常访问', scan: '扫描探测', attack: '认证攻击', knock: '端口敲门' };
  var SCOPE_NAME = { cn: '境内', overseas: '境外', private: '内网', lan: '局域网设备', unknown: '未知' };
  var CONF_NAME = { high: '高', medium: '中', low: '低', offline: '离线' };
  // 1.1.0：协议与「判定」是两个独立维度。proto 表达访问通道，verdict 表达行为性质。
  // web = combined 日志不含 scheme 且无可靠推断信号，明确标「未识别」而不是硬猜。
  var PROTO_NAME = {
    https: 'HTTPS', http: 'HTTP', web: 'Web 未识别', ssh: 'SSH',
    tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', unknown: '未识别'
  };
  var SCHEME_CONF = { manual: '设置页手动指定', medium: '同站来路推断',
    port: '已知端口推断', none: '未识别' };
  var PORT_SRC_NAME = {
    log_tail: '目标端口：日志行尾 $server_port（显式记录，最可信）',
    log_field: '目标端口：日志内结构化端口字段',
    request_url: '目标端口：请求行绝对 URL 中写明',
    log_cfg: '目标端口：设置页「Web 日志端口映射」按日志文件指定',
    referer: '目标端口：由同站来路推断（低置信度，可在设置里关闭）',
    '': '未记录：Nginx / Docker combined 日志不含目标端口，可在设置里配置端口映射'
  };
  function portHint(src) { return PORT_SRC_NAME[src || ''] || PORT_SRC_NAME['']; }
  function protoChip(p) {
    var k = String(p || 'unknown');
    if (!PROTO_NAME[k]) k = 'unknown';
    return '<span class="proto-chip ' + k + '">' + esc(PROTO_NAME[k]) + '</span>';
  }

  // ---- 全局状态 ----
  function emptyArcs() {
    return { list: [], merged: 0, skipped: 0, near: 0, nearPts: [], cross: 0 };
  }
  var S = {
    range: '24h', page: 1, size: 50, trendKey: 'all', liveScope: '',
    lastId: 0, hotspots: [], home: { lat: 22.5431, lng: 114.0579, label: '本机' },
    mapConfigured: false, cfg: {}, mapProvider: 'tencent', tmapReady: false, tmapTried: false,
    mapKeysDraft: null, mapCustom: null, selProvider: 'tencent',
    tmapState: 'off', tmapError: '', tmapKey: '',
    world: null, cn: null, anim: 0, live: [],
    // 弧线渲染状态：数据指纹、缓存、统计（避免每次轮询全量重建 GPU 缓冲）
    arcLimit: 16, arcBend: 0.12, arcAnimate: true,
    arcData: { sig: '', world: emptyArcs(), cn: emptyArcs() },
    mapRaf: 0, mapForce: false, geoCache: {}, redraws: 0, lastDrawMs: 0,
    // 圆点交互：TMap geometry id → 聚合点；canvas 每帧的命中点缓存
    markIndex: { world: {}, cn: {} }, hit: { world: [], cn: [] },
    arcDrawn: 0, arcMerged: 0, arcSkipped: 0, arcNear: 0, arcCross: 0, bg: {},
    heavySig: '', lightSig: '', geoVerify: null, mapScroll: true,
    // 1.1.7：逐接口健康状态。bad 记本轮失败的接口名，fails 记「整轮全失败」的
    // 连续次数，只有连续两轮全失败才允许标红「连接失败」，避免一次抖动误报。
    lightBad: [], heavyBad: [], lightFails: 0, heavyFails: 0,
    sources: null, geoReady: true, lastLightOk: 0, lastHeavyOk: 0, heavyBadKey: '',
    // 1.1.2：全球 IP 分布 / Web 访问分析
    // 1.1.2：地域图固定全球，scope=all 一次返回境内 + 境外全部来源
    geoScope: 'all', geoData: null, webData: null,
    // 1.1.21：三图合一后当前显示的地图模式（world / cn / geo）
    mapMode: 'world',
    // 1.1.22：提交单（后端 orders.json）与画像证据快照
    // 1.1.24：独立写标注窗口当前编辑的 IP
    orders: null, currentEvidence: {}, noteIp: '',
    // 1.1.25：提交单四区看板当前 tab 与「已完成」总结展开态
    ordersTab: 'pending', ordersOpen: {},
    // 2.0.0 B2：主界面平级 tab / 布局模式 / 设置卡片内部分组 tab
    mainView: 'overview', layout: 'tabs', settingsTab: 'data',
    geoMap: null, geoMarks: null, geoMarkIndex: {}, geoHits: [],
    // 1.1.3：五卡放大面板状态（来源矩形用于关闭时无缝收回）
    zoomOn: false, zoomDim: '', zoomName: '', zoomFrom: null,
    // 1.1.9：软件汇总日志状态（/api/summary/status 与 /api/config 下发）
    summary: null,
    // 2.0.0 B3：预警通知 state（独立 /api/notify/state，不进主配置）
    notify: null,
    // 2.0.0 B4：地图动效覆盖层（透明 canvas，不刷新底图、不碰数据）
    fx: { on: true, scan: true, revealOn: true, reveal: [], revealAt: 0,
          cursor: 0, loading: true },
    // 2.0.0 返工：默认卫星影像（官方 features:['base'] 不带国界标注），
    // 仅作为有 KEY 路径的视觉选项；无 KEY 降级为纯抽象卫星质感背景。
    mapBase: 'satellite',
    // 2.0.0 返工：设置抽屉「未保存修改」标记（只做视觉提示，不弹阻塞确认）
    settingsDirty: false
  };
  // 细线：频率靠色相（冷→热）而不是粗度区分，避免压盖浅色合规底图上的地名。
  // 1.0.11 起整条弧线统一单色：颜色只表达连接频率，不再沿线做明度渐隐，
  // 境内外两张图共用同一套色阶，方向感交给汇聚端点而非分段拼接。
  var ARC_LEVELS = 5;
  var ARC_TIER_IDS = [1, 2, 3, 4, 5];
  var ARC_TIER = { 1: { w: 2, cw: 1.2, a: 0.50 },
                   2: { w: 2, cw: 1.4, a: 0.62 },
                   3: { w: 2, cw: 1.6, a: 0.74 },
                   4: { w: 3, cw: 1.9, a: 0.87 },
                   5: { w: 3, cw: 2.2, a: 1.0 } };
  // 频率热力色阶：低频冷（青 / 蓝）→ 中频琥珀 → 中高橙 → 高频红。
  // 连线与来源圆点共用这 5 个颜色，图例也直接由此生成。
  var ARC_HEAT = [
    '#5cc3dd',   // 1 低频 · 青
    '#4a9fe0',   // 2 中低 · 蓝
    '#f5b423',   // 3 中频 · 琥珀
    '#f97316',   // 4 中高 · 橙
    '#ef4444'    // 5 高频 · 红
  ];
  var HEAT_NAME = ['低频', '中低', '中频', '中高', '高频'];
  var WORLD_BOUNDS = { latMin: -58, latMax: 78, lngMin: -180, lngMax: 180 };
  var CN_BOUNDS = { latMin: 17, latMax: 55, lngMin: 72, lngMax: 136 };

  // ---- 指标 / 提示条 ----
  function renderStatus(d, sources) {
    $('mTotal').textContent = num(d.total);
    $('mCn').textContent = num(d.cn);
    $('mOs').textContent = num(d.overseas);
    var scan = (d.scan || 0) + (d.attack || 0) + (d.knock || 0);
    $('mScan').textContent = num(scan);
    $('mRate').textContent = '每分钟 ' + num(d.per_minute) + ' 次 · 数据源在线 ' +
      countSources(sources) + ' 路';
    $('mCnSub').textContent = '占比 ' + pct(d.cn, d.total) + '% · 独立 IP ' + num(d.unique_ip) + ' 个';
    $('mOsSub').textContent = '占比 ' + pct(d.overseas, d.total) + '%';
    var inner = (d.private || 0) + (d.lan || 0);
    $('mScanSub').textContent = '正常访问 ' + num(d.normal) + ' 次 · 内网 ' + num(inner) + ' 次' +
      (S.geoVerify && S.geoVerify.enabled
        ? ' · 已核验 ' + num(S.geoVerify.cached) + ' IP' : '');
    // 1.1.7：连接状态不再由这里独占，交给 updateLinkPill 综合所有接口健康度。
    S.sources = sources;
    S.geoReady = !sources || sources.geo_ready !== false;
    updateLinkPill();
    updateBanner();
  }
  function setMapState(state, msg) {
    S.tmapState = state;
    S.tmapError = msg || '';
    // 1.1.17：底图失败是用户最常反馈的问题，把服务商 / 域名 / 原始提示一起落盘。
    // 资源本身的加载失败由全局 capture error 另记一条 resource，两者互补。
    if (state === 'error' && S.tmapError) {
      rtPush({ kind: 'map_sdk', msg: '底图未显示：' + S.tmapError,
               provider: S.mapProvider || '', host: RT_HOST[S.mapProvider] || '',
               src: RT_HOST[S.mapProvider] || '' });
    }
    // 供自动化验收读取，不影响界面
    try {
      document.body.dataset.mapState = state;
      document.body.dataset.mapError = S.tmapError;
      var w = $('worldMap').getBoundingClientRect();
      document.body.dataset.mapSize = Math.round(w.width) + 'x' + Math.round(w.height);
    } catch (e) {}
    updateBanner();
    updateFooterMap();
    if ($('mapDiagBox') && $('settingsDrawer').classList.contains('on')) renderMapDiag();
  }
  function updateBanner() {
    var b = $('complianceBanner'), t = $('bannerText'), a = $('bannerAction');
    if (!b) return;
    var txt, act = '', warn = true;
    if (!mapIsConfigured()) {
      txt = '地图密钥未配置：当前使用「坐标散点示意」（不绘制国界）。到「设置 → 地图服务」选服务商并填 KEY 后可查看合规底图。';
      act = '去设置'; a.setAttribute('data-act', 'settings');
    } else if (S.tmapState === 'ready') {
      warn = false;
      txt = '底图由 ' + mapProviderName() + ' 提供，国界与行政区划以官方底图为准；中国香港 / 中国澳门 / 中国台湾均计入境内。';
      a.setAttribute('data-act', 'none');
    } else if (S.tmapState === 'error') {
      txt = '底图未显示：' + (S.tmapError || '未知原因') + '。已回退为坐标散点示意，数据功能不受影响。';
      act = '重试底图'; a.setAttribute('data-act', 'retry');
    } else if (S.tmapState === 'loading') {
      txt = '正在加载 ' + mapProviderName() + ' 底图…（长时间无响应多为网络或密钥白名单限制）';
      act = '重试底图'; a.setAttribute('data-act', 'retry');
    } else {
      txt = '地图密钥已配置，正在准备底图…';
      act = '重试底图'; a.setAttribute('data-act', 'retry');
    }
    b.className = 'banner' + (warn ? ' warn' : '');
    t.textContent = txt;
    a.textContent = act;
    a.style.display = act ? '' : 'none';
  }
  function pct(a, b) { return b ? Math.round((a / b) * 1000) / 10 : 0; }
  function countSources(s) {
    if (!s || !s.tailers) return 0;
    var n = s.tailers.filter(function (t) { return t.exists && !t.error; }).length;
    if (s.syslog_ok) n++;
    return n;
  }

  // ---- 实时事件 ----
  function renderLive(list) {
    S.live = list || [];
    var box = $('liveList');
    // 1.1.15：监控范围筛选只作用于这块实时列表，不影响记录表与地图。
    // 后端事件流仍全量推送，按 e.scope 在前端过滤，切换范围无需重新请求。
    var rowsData = S.live.filter(function (e) {
      return !S.liveScope || e.scope === S.liveScope;
    });
    var tag = $('liveTag');
    if (tag) tag.textContent = (S.liveScope ? SCOPE_NAME[S.liveScope] + ' · ' : '实时 · ') +
      num(rowsData.length) + ' 条';
    if (!rowsData.length) {
      box.innerHTML = '<div class="empty">' +
        (S.live.length ? '当前监控范围内暂无实时事件' : '暂无实时事件') + '</div>';
      return;
    }
    var rows = rowsData.slice(-30).reverse().map(function (e) {
      var loc = [e.country, e.province, e.city, e.district]
        .filter(function (x) { return x && x !== '0'; }).join(' · ') || '未知归属';
      return '<div class="live-item">' +
        '<span class="badge ' + esc(e.scope) + '">' + esc(SCOPE_NAME[e.scope] || '未知') + '</span>' +
        '<span class="ip">' + esc(e.ip) + '</span>' +
        '<span class="loc">' + esc(loc) + '</span>' +
        protoChip(e.proto) +
        '<span class="badge ' + esc(e.verdict) + '">' + esc(VERDICT_NAME[e.verdict] || '记录') + '</span>' +
        '<span class="act" title="' + esc(e.action) + '">' + esc(e.action) + '</span>' +
        '<span class="tm">' + tm(e.ts) + '</span></div>';
    });
    box.innerHTML = rows.join('');
  }

  // ---- 趋势图 ----
  function renderTrend(data) {
    var pts = (data && data.points) || [];
    $('trendSub').textContent = '时间桶 ' + bucketName(data && data.bucket) + ' · 共 ' + pts.length + ' 个数据点';
    var W = 720, H = 240, pl = 46, pr = 14, pt = 14, pb = 28;
    var iw = W - pl - pr, ih = H - pt - pb;
    var key = S.trendKey;
    var vals = pts.map(function (p) { return p[key] || 0; });
    var max = Math.max.apply(null, vals.concat([1]));
    max = Math.ceil(max / Math.pow(10, Math.max(0, String(Math.floor(max)).length - 2))) * Math.pow(10, Math.max(0, String(Math.floor(max)).length - 2));
    var allVals = pts.map(function (p) { return p.all || 0; });
    var svg = [];
    for (var g = 0; g <= 4; g++) {
      var y = pt + ih * g / 4;
      svg.push('<line class="grid-line" x1="' + pl + '" y1="' + y + '" x2="' + (W - pr) + '" y2="' + y + '"/>');
      svg.push('<text class="axis-text" x="' + (pl - 8) + '" y="' + (y + 3) + '" text-anchor="end">' + num(Math.round(max * (4 - g) / 4)) + '</text>');
    }
    function xy(i, v) {
      var x = pl + (pts.length <= 1 ? iw / 2 : iw * i / (pts.length - 1));
      var y = pt + ih - ih * (v / max);
      return [x, y];
    }
    function pathOf(arr) {
      return arr.map(function (v, i) {
        var p = xy(i, v); return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1);
      }).join(' ');
    }
    var color = { all: '#3b82f6', cn: '#34d399', overseas: '#ff4d6d', scan: '#fbbf24' }[key];
    var d = pathOf(vals);
    svg.push('<path class="chart-area" d="' + d + ' L' + (pl + iw) + ' ' + (pt + ih) + ' L' + pl + ' ' + (pt + ih) + ' Z" fill="' + color + '"/>');
    if (key !== 'all') svg.push('<path class="chart-line" d="' + pathOf(allVals) + '" stroke="#4b6a94" stroke-dasharray="4 4" stroke-width="1.4"/>');
    svg.push('<path class="chart-line" d="' + d + '" stroke="' + color + '"/>');
    for (var k = 0; k < pts.length; k += Math.max(1, Math.ceil(pts.length / 6))) {
      var p = xy(k, vals[k]);
      svg.push('<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="2.4" fill="' + color + '"/>');
    }
    var labels = [0, Math.floor(pts.length / 4), Math.floor(pts.length / 2), Math.floor(pts.length * 3 / 4), pts.length - 1];
    labels.forEach(function (i) {
      if (i < 0 || !pts[i]) return;
      var x = xy(i, vals[i])[0];
      var d2 = new Date(pts[i].t * 1000);
      var lab = data.bucket >= 21600
        ? (d2.getMonth() + 1) + '/' + d2.getDate()
        : ('0' + d2.getHours()).slice(-2) + ':' + ('0' + d2.getMinutes()).slice(-2);
      svg.push('<text class="axis-text" x="' + x + '" y="' + (H - 8) + '" text-anchor="middle">' + lab + '</text>');
    });
    $('trendSvg').innerHTML = svg.join('');
    $('trendSvg')._pts = pts; $('trendSvg')._max = max; $('trendSvg')._key = key;
  }
  function bucketName(b) {
    if (!b) return '—';
    if (b < 3600) return '1 分钟'; if (b < 21600) return '5 分钟';
    if (b < 172800) return '1 小时'; return '6 小时';
  }

  // ---- 排名 ----
  // 1.1.2：图4 双榜界面保留，叠加图3 的「点击条目下钻来源 IP」功能。
  function renderRank(elId, list, cls, scope) {
    var el = $(elId);
    if (!list || !list.length) { el.innerHTML = '<div class="empty">该时间范围内暂无数据</div>'; return; }
    var max = list[0].count || 1;
    var h = ['<div class="rank-head"><span>地区</span><span>访问次数 / 独立 IP</span></div>'];
    list.forEach(function (r, i) {
      h.push('<div class="rank-row ' + cls + '" data-region="' + esc(r.name) +
        '" data-scope="' + (scope || '') + '" title="点击查看该地区来源 IP 明细">' +
        '<span class="idx">' + (i + 1) + '</span>' +
        '<span class="nm" title="' + esc(r.name) + '">' + esc(r.name) + '</span>' +
        '<span class="bar"><i style="width:' + Math.max(3, (r.count / max) * 100).toFixed(1) + '%"></i></span>' +
        '<span class="num">' + num(r.count) + ' <small>/' + num(r.ips) + '</small></span></div>');
    });
    el.innerHTML = h.join('');
  }

  // ---- 1.1.0：协议构成 / 来路 / 受访页 / 入口页 / 终端设备 ----
  function renderMiniList(elId, list, opt) {
    var el = $(elId);
    if (!el) return;
    opt = opt || {};
    if (!list || !list.length) {
      el.innerHTML = '<div class="empty">该时间范围内暂无数据</div>';
      return;
    }
    var max = list[0].count || 1;
    el.innerHTML = list.map(function (r, i) {
      var label = opt.label ? opt.label(r) : r.name;
      var color = opt.color ? opt.color(r, i) : 'var(--blue)';
      return '<div class="mini-row" data-dim="' + esc(opt.dim || '') + '"' +
        ' data-name="' + esc(r.name) + '"' +
        ' title="点击查看「' + esc(r.name) + '」的详细信息与来源 IP">' +
        (opt.chip ? opt.chip(r) : '') +
        '<span class="mn">' + esc(label) + '</span>' +
        '<span class="mb"><i style="width:' + Math.max(4, (r.count / max) * 100).toFixed(1) +
        '%;background:' + color + '"></i></span>' +
        '<span class="mv">' + num(r.count) + '</span></div>';
    }).join('');
  }

  function renderWebCards(ov) {
    if (!ov) return;
    S.webData = ov;
    var p = ov.protocols || [], pv = ov.protocol_verdict || [], s = ov.summary || {};
    // 1.1.3：首屏取 30 条，卡片只显示前 8 条保持紧凑；完整列表留在 S.webData，
    // 放大面板直接复用，不需要再发一次请求（口径与卡片完全一致）。
    renderMiniList('protoList', (p || []).slice(0, 8), {
      dim: 'proto',
      chip: function (r) { return protoChip(r.name); },
      label: function (r) { return PROTO_NAME[r.name] || r.name; },
      color: function (r, i) { return ARC_HEAT[Math.min(4, i % 5)]; }
    });
    var manual = 0, inferred = 0, unknown = 0, abnormal = 0;
    p.forEach(function (r) {
      manual += r.manual || 0;
      inferred += r.inferred || 0;
      if (r.name === 'web' || r.name === 'unknown') unknown += r.count;
    });
    (pv || []).forEach(function (x) {
      if (x.verdict !== 'normal') abnormal += x.count;
    });
    var hint = '共 ' + num(s.requests || 0) + ' 次 Web 请求 · ' +
      num(s.ips || 0) + ' 个来源 IP · ' + num(s.sessions || 0) + ' 个会话。';
    if (inferred) hint += ' <span class="conf">' + num(inferred) + ' 次由同站来路推断 scheme</span>；';
    if (manual) hint += ' <span class="conf">' + num(manual) + ' 次来自设置页手动指定</span>；';
    if (unknown) hint += ' ' + num(unknown) + ' 次标「Web 未识别」：combined 日志不含 scheme，' +
      '可在设置里指定 http / https 或按端口补协议（点卡片放大看完整成因）。';
    if (abnormal) hint += ' 其中 ' + num(abnormal) + ' 次被判为扫描或攻击。';
    $('protoHint').innerHTML = hint;
    renderMiniList('refList', (ov.referrers || []).slice(0, 8), { dim: 'referer' });
    renderMiniList('pageList', (ov.pages || []).slice(0, 8), { dim: 'page' });
    renderMiniList('entryList', (ov.entries || []).slice(0, 8), { dim: 'entry' });
    renderMiniList('deviceList', (ov.devices || []).slice(0, 8), { dim: 'device' });
  }

  // ---- 1.1.3：五卡「无缝放大」+ 条目下钻 --------------------------------
  // 放大不新建列表接口：完整列表直接复用 S.webData（loadHeavy 取 30 条），
  // 条目详情走 /api/web/breakdown。关闭时按来源矩形反向动画收回，视觉上就是卡片缩回去。
  var ZOOM_DIM = {
    proto:   { title: '访问协议构成', tag: '协议', field: 'protocols',
               sub: '按访问协议通道聚合，「Web 未识别」= combined 日志不含 scheme，点条目看成因' },
    referer: { title: '来路', tag: '来源', field: 'referrers',
               sub: '按 referer 归一化：直接输入 / 站内路径 / 外站域名' },
    page:    { title: '受访页', tag: '页面', field: 'pages',
               sub: '按去掉查询串的路径聚合，静态资源已从榜单剔除' },
    entry:   { title: '入口页', tag: '会话', field: 'entries',
               sub: '每个会话（IP + UA + 30 分钟桶）首次访问的页面' },
    device:  { title: '终端设备', tag: 'UA', field: 'devices',
               sub: '按 User-Agent 粗略归一为「浏览器 · 系统」' }
  };
  var ZOOM_TAG_CLS = {
    proto: 'tag-blue', referer: 'tag-green', page: 'tag-blue',
    entry: 'tag-amber', device: 'tag-gray'
  };

  function zoomLabel(dim, name) {
    return dim === 'proto' ? (PROTO_NAME[name] || name) : name;
  }

  function openCardZoom(dim, card, name) {
    var meta = ZOOM_DIM[dim];
    if (!meta || !card) return;
    var from = card.getBoundingClientRect();
    S.zoomFrom = { left: from.left, top: from.top, width: from.width, height: from.height };
    S.zoomDim = dim;
    S.zoomName = name || '';
    S.zoomOn = true;

    $('zoomTitle').textContent = meta.title;
    $('zoomSub').textContent = meta.sub + ' · 点条目查看详细信息与来源 IP';
    $('zoomTag').textContent = meta.tag;
    $('zoomTag').className = 'tag ' + (ZOOM_TAG_CLS[dim] || 'tag-blue');

    var vw = window.innerWidth, vh = window.innerHeight;
    var w = Math.min(1080, vw - 32), h = Math.min(660, vh - 56);
    var left = Math.max(12, (vw - w) / 2), top = Math.max(12, (vh - h) / 2);
    var z = $('cardZoom');
    // 先无动画摆到卡片原位，再过渡到目标尺寸：内容不会被 transform 拉伸变形
    z.className = 'card zoom-card on';
    z.setAttribute('aria-hidden', 'false');   // 1.1.3：视觉打开的同时同步无障碍语义
    z.style.transition = 'none';
    z.style.left = from.left + 'px';
    z.style.top = from.top + 'px';
    z.style.width = from.width + 'px';
    z.style.height = from.height + 'px';
    z.style.opacity = '1';
    void z.offsetWidth;                 // 强制 reflow，让下一帧 transition 生效
    z.style.transition = '';
    z.style.left = left + 'px';
    z.style.top = top + 'px';
    z.style.width = w + 'px';
    z.style.height = h + 'px';
    $('zoomMask').classList.add('on');
    setMapScroll(false);
    setTimeout(function () { if (S.zoomOn) z.classList.add('ready'); }, 150);

    renderZoomList(dim, S.zoomName);
    if (S.zoomName) openZoomItem(dim, S.zoomName);
    else $('zoomDetail').innerHTML =
      '<div class="empty">点击左侧任意条目，查看该条目的详细信息与来源 IP</div>';
  }

  function closeCardZoom(instant, cb) {
    if (!S.zoomOn) { if (cb) cb(); return; }
    var z = $('cardZoom'), f = S.zoomFrom || {};
    S.zoomOn = false;
    $('zoomMask').classList.remove('on');
    z.classList.remove('ready');
    var finish = function () {
      z.className = 'card zoom-card';
      z.setAttribute('aria-hidden', 'true');  // 1.1.3：收回后重新对辅助技术隐藏
      z.style.transition = 'none';
      z.style.opacity = '0';
      if (!drawerOpen()) setMapScroll(true);
      if (cb) cb();
    };
    if (instant) { finish(); return; }
    z.style.transition = '';
    z.style.left = (f.left != null ? f.left : 0) + 'px';
    z.style.top = (f.top != null ? f.top : 0) + 'px';
    z.style.width = (f.width != null ? f.width : 0) + 'px';
    z.style.height = (f.height != null ? f.height : 0) + 'px';
    setTimeout(finish, 310);
  }

  function renderZoomList(dim, activeName) {
    var meta = ZOOM_DIM[dim], list = (S.webData || {})[meta.field] || [];
    $('zoomCount').textContent = list.length + ' 项';
    if (!list.length) {
      $('zoomList').innerHTML = '<div class="empty">该时间范围内暂无数据</div>';
      return;
    }
    var max = list[0].count || 1;
    $('zoomList').innerHTML = list.map(function (r) {
      return '<div class="zoom-row' + (r.name === activeName ? ' on' : '') + '"' +
        ' data-name="' + esc(r.name) + '" title="点击查看详细信息">' +
        (dim === 'proto' ? protoChip(r.name) : '') +
        '<span class="zr-n">' + esc(zoomLabel(dim, r.name)) + '</span>' +
        '<span class="zr-b"><i style="width:' +
          Math.max(4, (r.count / max) * 100).toFixed(1) + '%"></i></span>' +
        '<span class="zr-v">' + num(r.count) + ' <small>/' + num(r.ips) + '</small></span>' +
        '<span class="zr-go">›</span></div>';
    }).join('');
  }

  function openZoomItem(dim, name) {
    S.zoomName = name;
    renderZoomList(dim, name);
    var label = zoomLabel(dim, name);
    $('zoomDetail').innerHTML = '<div class="empty">正在读取「' + esc(label) + '」的详细信息…</div>';
    api('api/web/breakdown?dim=' + dim +
        '&name=' + encodeURIComponent(name) +
        '&rng=' + encodeURIComponent(S.range) + '&limit=50')
      .then(function (r) {
        if (!r.ok) throw new Error(r.msg || '读取失败');
        // 用户可能已切到别的条目或已关闭面板，丢弃过期响应
        if (!S.zoomOn || S.zoomDim !== dim || S.zoomName !== name) return;
        renderZoomDetail(dim, name, r.data || {});
      })
      .catch(function (e) {
        if (S.zoomOn && S.zoomName === name)
          $('zoomDetail').innerHTML = '<div class="empty">' + esc(e.message) + '</div>';
      });
  }

  function renderZoomDetail(dim, name, d) {
    var label = zoomLabel(dim, name);
    var ips = d.ip_list || [], rec = d.recent || [];
    var h = '<div class="zd-head"><h3>' + esc(label) + '</h3>' +
      '<span class="tag tag-blue">' + esc(ZOOM_DIM[dim].tag) + '</span></div>';
    h += '<div class="zoom-stat">' +
      '<div><b>' + num(d.requests || 0) + '</b><span>访问次数</span></div>' +
      '<div><b>' + num(d.ips || 0) + '</b><span>独立 IP</span></div>' +
      '<div><b>' + tm(d.first_ts) + '</b><span>首次</span></div>' +
      '<div><b>' + tm(d.last_ts) + '</b><span>末次</span></div></div>';
    if (d.note) h += '<p class="zoom-hint">' + esc(d.note) + '</p>';
    if (dim === 'proto' && (name === 'web' || name === 'unknown')) {
      h += '<div class="verify-box"><p class="hint" style="margin:0">' +
        '<b>为什么会有「Web 未识别」：</b>Nginx / Docker 的 combined 日志只记录 ' +
        '<code>GET /path HTTP/1.1</code>，不含 scheme（http / https），也没有 ' +
        'X-Forwarded-Proto；只有带「同站内网来路」的请求能从 Referer 读出协议。' +
        '其余请求（直接访问、API 轮询、健康检查、无 Referer、外部来路）没有可信信号，' +
        '按「不伪造」原则统一归入此类，<b>这不是故障</b>。' +
        '想让协议可识别：在设置里把整站协议指定为 http / https，或开启「按已知端口补协议」；' +
        '日志里出现显式 $server_port 时会自动据此判定。' +
        '另外，本明细的「来源 IP」是该 IP 的全部访问记录，不只统计这一协议下的次数。</p></div>';
    }
    h += '<h3 class="zd-h">来源 IP 明细（' + ips.length +
      ' 个 · 点击任意一行查看该 IP 的完整来源画像）</h3>';
    h += ips.length ? '<div class="zoom-ips">' + ips.map(function (x) {
      var loc = [x.country, x.province, x.city, x.district].filter(function (v) {
        return v && v !== '0';
      }).join(' · ') || '—';
      return '<div class="zoom-ip" data-ip="' + esc(x.ip) + '"' +
        ' title="点击查看该 IP 的完整来源画像">' +
        '<span class="ip">' + esc(x.ip) + '</span>' +
        '<span class="zl">' + esc(loc) + '</span>' +
        '<span class="badge ' + esc(x.scope || '') + '">' +
        esc(SCOPE_NAME[x.scope] || '未知') + '</span>' +
        '<span class="zv">' + num(x.n) + ' 次</span>' +
        '<span class="zt">' + tm(x.last_ts) + '</span></div>';
    }).join('') + '</div>' : '<div class="empty">该条目下没有来源 IP</div>';
    h += '<h3 class="zd-h">最近 20 条动作</h3>';
    h += rec.length ? rec.map(function (x) {
      return '<div class="src-line"><span>' + tm(x.ts) + ' · ' +
        protoChip(x.proto) + ' · ' + esc(x.ip) + ' · ' +
        esc(VERDICT_NAME[x.verdict] || x.verdict || '记录') + ' · ' +
        esc(x.path || x.action || '连接') +
        (x.status ? ' <small style="color:var(--dim)">' + esc(x.status) + '</small>' : '') +
        '</span><span>' + portLabel(x.port, x.source) + '</span></div>';
    }).join('') : '<div class="empty">暂无连接记录</div>';
    $('zoomDetail').innerHTML = h;
  }

  // ---- 1.1.21 · 三图合一：右上角的三种地图模式 ----
  // 三张地图的容器、SDK 实例与绘制逻辑全部保留，只是叠在同一块 .map-stage 里。
  // 关键约束：TMap SDK 初始化时容器必须有真实宽高，display:none 会抛异常白屏，
  // 所以非活动层只降透明度 + 关指针事件，绝不隐藏、绝不重建实例。
  var MAP_MODE_LAYERS = { world: 'worldWrap', cn: 'cnWrap', geo: 'geoWrap' };
  function setMapMode(mode, save) {
    if (!MAP_MODE_LAYERS[mode]) mode = 'world';
    S.mapMode = mode;
    var btn = null;
    Array.prototype.forEach.call($('mapModeSeg').querySelectorAll('button[data-mode]'), function (b) {
      var on = b.getAttribute('data-mode') === mode;
      if (on) b.classList.add('on'); else b.classList.remove('on');
      if (on) btn = b;
    });
    if (btn) {
      $('mapModeTitle').textContent = btn.getAttribute('data-title') || '';
      $('mapModeDesc').textContent = btn.getAttribute('data-desc') || '';
      var tag = $('mapModeTag');
      tag.textContent = btn.getAttribute('data-tag') || '';
      tag.className = 'tag ' + (btn.getAttribute('data-tagcls') || 'tag-blue');
      var lg = $('mapModeLegend'), line = $('mapModeLegendLine');
      lg.style.display = mode === 'geo' ? 'none' : '';
      line.className = mode === 'cn' ? 'lg-green' : 'lg-red';
    }
    Object.keys(MAP_MODE_LAYERS).forEach(function (k) {
      var el = $(MAP_MODE_LAYERS[k]);
      if (!el) return;
      if (k === mode) el.classList.add('active'); else el.classList.remove('active');
    });
    // 供自动化验收读取当前模式
    try { document.body.dataset.mapMode = mode; } catch (e) {}
    // 切过去之后补一次重绘 / resize：部分浏览器会暂停透明层的渲染帧
    if (mode === 'geo') {
      try { if (S.geoMap) S.geoMap.resize(); } catch (e) {}
      drawGeo();
    } else {
      try {
        var m = mode === 'cn' ? S.cn : S.world;
        if (S.tmapReady && m && m.resize) m.resize();
      } catch (e) {}
      requestMapDraw(true);
    }
    if (save !== false) writeUiPref({ mapMode: mode });
    // 2.0.0 B4：切视图立即重画 FX，清掉旧层残留的一帧与上一视图的投放点
    try {
      S.fx.reveal = []; S.fx.revealAt = 0; S.fx.cursor = 0;
      Object.keys(FX.IDS).forEach(function (k) {
        var c = fxCanvas(k); if (!c) return;
        try { c.getContext('2d').clearRect(0, 0, c.width, c.height); } catch (e) {}
      });
      drawFx();
    } catch (e) {}
  }
  function bindMapMode() {
    var seg = $('mapModeSeg');
    if (!seg) return;
    // 1.1.5 起不依赖 Element.closest：部分内嵌 WebView 不支持，改用父链遍历
    seg.onclick = function (e) {
      var t = e.target, b = null;
      while (t && t !== seg) {
        if (t.getAttribute && t.getAttribute('data-mode')) { b = t; break; }
        t = t.parentNode;
      }
      if (!b) return;
      setMapMode(b.getAttribute('data-mode'), true);
    };
    setMapMode(S.mapMode, false);
  }

  // ---- 1.1.2：全球 IP 来源分布（固定全球视图） ----
  // 合规：只搬运截图的信息结构（数量色阶、详情下钻），不自绘国界 / 省界轮廓。
  // 有密钥时复用合规底图 + 数量气泡；无密钥时降级为不绘任何边界的
  // canvas 坐标散点。境内 / 全球切换与右侧重复排名已移除，统计与排名合并到下方模块。
  function assignGeoTier(list) {
    if (!list || !list.length) return list;
    var logs = list.map(function (r) {
      return Math.log1p(Math.max(0, Number(r.count) || 0));
    });
    var lo = Math.min.apply(null, logs), hi = Math.max.apply(null, logs), span = hi - lo;
    list.forEach(function (r, i) {
      var v = span > 1e-6 ? (logs[i] - lo) / span : 0.5;
      r.heat = v;
      r.tier = Math.max(1, Math.min(5, 1 + Math.floor(v * 5)));
    });
    return list;
  }

  function renderGeoLegend() {
    var el = $('geoLegend');
    if (!el) return;
    el.innerHTML = '<span class="gl-txt">访问次数</span>' +
      ARC_HEAT.map(function (c) {
        return '<i class="gl-sw" style="background:' + c + '"></i>';
      }).join('') + '<span class="gl-txt">少 → 多</span>';
  }

  function renderGeoDist(data) {
    S.geoData = data || { regions: [] };
    var rs = S.geoData.regions || [];
    assignGeoTier(rs);
    var total = S.geoData.total || 0;
    var ips = rs.reduce(function (a, r) { return a + (r.ips || 0); }, 0);
    // 1.1.2：三个统计卡与双榜合并到地图下方，全页只有这一处排名
    $('rankSum').innerHTML =
      '<div><b>' + num(total) + '</b><span>访问次数</span></div>' +
      '<div><b>' + num(rs.length) + '</b><span>国家 / 地区 · 省份</span></div>' +
      '<div><b>' + num(ips) + '</b><span>独立 IP 合计</span></div>';
    $('geoStat').textContent = rs.length + ' 个国家 / 地区 · 省份 · ' + num(total) +
      ' 次访问 · 点击气泡查看详情';
    $('rankTip').textContent = '统计与地图同为当前时间范围的境内 + 境外全部来源；' +
      '1.1.15 起境内按省细分、境外按国家 / 地区细分，同省访问不再被合并成一个「中国」气泡；' +
      '气泡按内置中心点绘制，只表达数量，不代表行政边界，' +
      '中国香港 / 中国澳门 / 中国台湾均计入中国。点击排名条目或气泡可下钻该地区的来源 IP 明细。';
    renderGeoLegend();
    drawGeo();
  }

  function drawGeo() {
    if (S.tmapReady && S.geoMap && S.geoMarks) drawGeoMarkers();
    else drawGeoCanvas();
  }

  function drawGeoCanvas() {
    var c = $('geoCanvas');
    if (!c) return;
    var dpr = window.devicePixelRatio || 1;
    var w = c.clientWidth || 600, h = c.clientHeight || 340;
    var pw = Math.round(w * dpr), ph = Math.round(h * dpr);
    if (c.width !== pw || c.height !== ph) { c.width = pw; c.height = ph; }
    var ctx = c.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    var b = WORLD_BOUNDS;   // 1.1.2：固定全球视图，不再按境内 / 全球切换
    ctx.clearRect(0, 0, w, h);
    var bg = ctx.createLinearGradient(0, 0, 0, h);
    bg.addColorStop(0, '#0d2440'); bg.addColorStop(1, '#071326');
    ctx.fillStyle = bg; ctx.fillRect(0, 0, w, h);
    // 只画经纬网，不绘制任何国界 / 省界 / 海岸线
    ctx.strokeStyle = 'rgba(80,140,200,.13)'; ctx.lineWidth = 1;
    ctx.setLineDash([3, 5]); ctx.beginPath();
    var step = 30, lng, lat, x, y;
    for (lng = Math.ceil(b.lngMin / step) * step; lng <= b.lngMax; lng += step) {
      x = proj(0, lng, b, w, h)[0]; ctx.moveTo(x, 0); ctx.lineTo(x, h);
    }
    for (lat = Math.ceil(b.latMin / step) * step; lat <= b.latMax; lat += step) {
      y = proj(lat, 0, b, w, h)[1]; ctx.moveTo(0, y); ctx.lineTo(w, y);
    }
    ctx.stroke(); ctx.setLineDash([]);
    ctx.fillStyle = 'rgba(140,170,210,.4)'; ctx.font = '10px sans-serif';
    ctx.fillText('全球 · 国家 / 地区中心点（含中国）', 10, 16);
    var rs = (S.geoData && S.geoData.regions) || [];
    var max = rs.length ? rs[0].count : 1;
    var picks = [], labels = [];
    rs.slice().sort(function (a, b2) { return b2.count - a.count; }).forEach(function (r) {
      if (r.lat == null || r.lng == null) return;
      var p = proj(r.lat, r.lng, b, w, h);
      // 半径收窄 + 大者先画：省份中心点本就集中，过大的气泡会糊成一团
      var rad = 5 + 15 * Math.sqrt(Math.max(0, r.count) / Math.max(1, max));
      var col = ARC_HEAT[r.tier - 1];
      ctx.globalAlpha = .18; ctx.fillStyle = col;
      ctx.beginPath(); ctx.arc(p[0], p[1], rad + 5, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = .6; ctx.fillStyle = col;
      ctx.beginPath(); ctx.arc(p[0], p[1], rad, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = 1; ctx.strokeStyle = col; ctx.lineWidth = 1.4;
      ctx.beginPath(); ctx.arc(p[0], p[1], rad, 0, Math.PI * 2); ctx.stroke();
      // 气泡内直接写次数，即使外部标签被避让掉也读得到数量
      if (rad >= 11) {
        ctx.fillStyle = '#fff'; ctx.font = 'bold 10px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(num(r.count), p[0], p[1] + 3);
        ctx.textAlign = 'left';
      }
      // 标签避让：与已绘制标签矩形相交就跳过，避免「广东省 / 安徽省」叠字
      ctx.font = '10px sans-serif';
      var text = r.name + ' ' + num(r.count);
      var lx = p[0] + rad + 4, ly = p[1] + 3;
      var rect = { x: lx, y: ly - 9, w: ctx.measureText(text).width + 4, h: 12 };
      var clash = labels.some(function (q) {
        return !(rect.x + rect.w < q.x || q.x + q.w < rect.x ||
                 rect.y + rect.h < q.y || q.y + q.h < rect.y);
      });
      if (!clash) {
        labels.push(rect);
        ctx.fillStyle = 'rgba(7,17,34,.74)';
        ctx.fillRect(rect.x - 2, rect.y, rect.w, rect.h);
        ctx.fillStyle = '#e8f0fb';
        ctx.fillText(text, lx, ly);
      }
      picks.push({ x: p[0], y: p[1], r: rad + 4, name: r.name,
                   scope: r.scope || 'all' });
    });
    S.geoHits = picks;
    $('geoNote').textContent = '示意坐标分布 · 不绘制国界与省界，边界以官方地图为准';
  }

  function geoMarkStyles() {
    var out = {};
    ARC_TIER_IDS.forEach(function (t) {
      [0, 1, 2].forEach(function (sz) {
        var s = 18 + sz * 12;
        out['g' + t + '_' + sz] = new SDK.MarkerStyle({
          width: s, height: s, anchor: { x: s / 2, y: s / 2 },
          src: markerIcon(ARC_HEAT[t - 1], s)
        });
      });
    });
    return out;
  }

  function drawGeoMarkers() {
    var rs = (S.geoData && S.geoData.regions) || [];
    var max = rs.length ? rs[0].count : 1;
    var geos = [], idx = {};
    rs.forEach(function (r, i) {
      if (r.lat == null || r.lng == null) return;
      var sz = Math.min(2, Math.floor(3 * Math.sqrt(r.count / Math.max(1, max))));
      var id = 'gr' + i;
      geos.push({ id: id, styleId: 'g' + r.tier + '_' + sz,
                  position: new SDK.LatLng(r.lat, r.lng) });
      idx[id] = r;
    });
    S.geoMarkIndex = idx;
    try { S.geoMarks.setGeometries(geos); }
    catch (e) { console.warn('geo marks', e); }
    $('geoNote').textContent = '底图 © ' + mapProviderName() + ' · 国界与行政区划以官方底图为准 · 气泡仅表示数量';
  }

  // 地域下钻：复用 1.0.7 的「整组 IP 来源画像」抽屉，字段与地图圆点完全一致
  // 1.1.15：省份名短后缀归一（「安徽」≡「安徽省」），保证按省合并后的
  // 气泡下钻不会漏掉库里用短名保存的那些 IP。
  function canonRegion(s) {
    return String(s || '')
      .replace(/(省|市|自治区|特别行政区)$/, '')
      .replace(/(壮族|回族|维吾尔)$/, '');
  }
  function openRegionProfile(name, scope) {
    // 1.1.15：全球分布图境内按省、境外按国家细分，气泡自带 r.scope。
    // 旧逻辑把所有气泡都按 country 匹配，境内省份气泡永远匹配不到热点，
    // 点开就是「没有可展开的 IP」——这正是同省来源看起来不显示的一环。
    var hs = (S.hotspots || []).filter(function (h) {
      if (scope === 'cn') return canonRegion(h.province) === canonRegion(name);
      if (scope === 'overseas') return String(h.country || '') === name;
      return canonRegion(h.province) === canonRegion(name) ||
             String(h.country || '') === name;
    });
    if (!hs.length) {
      toast('该地区在当前热点列表中没有可展开的 IP');
      return;
    }
    var members = hs.map(function (h) {
      return { ip: h.ip, n: h.n, last_ts: h.last_ts, verdict: h.verdict,
               city: h.city || '', district: h.district || '', isp: h.isp || '',
               province: h.province || '', country: h.country || '',
               lat: h.lat, lng: h.lng, scope: scope };
    });
    if (members.length === 1) {
      openDetail(members[0].ip, {
        scope: scope,
        data: { region: name, members: members, n: members[0].n,
                lat: hs[0].lat, lng: hs[0].lng, verdict: hs[0].verdict }
      });
      return;
    }
    var lat = 0, lng = 0, wsum = 0;
    hs.forEach(function (h) { var w = h.n || 1; lat += h.lat * w; lng += h.lng * w; wsum += w; });
    openGroupProfile({
      scope: scope,
      data: { region: name, members: members,
              n: members.reduce(function (a, m) { return a + (m.n || 0); }, 0),
              lat: lat / wsum, lng: lng / wsum, verdict: hs[0].verdict }
    });
  }

  // ---- 记录表 ----
  // 1.1.20：打开一个应用（如 /fnzerror）会在同一秒并发发出一批
  // /fnzerror/api/... 请求，combined 日志逐条落库，于是表格里除路径外所有字段
  // 都相同，被同一 IP 刷屏。这里把「同秒 + 同 IP + 相同来源/归属/范围/协议/
  // 端口/判定/动作」的记录合并为一行，只记录动作，并标注合并条数与一级应用
  // 前缀；路径明细不再逐行铺开，统一到 IP 来源画像「路径明细 · 高频路径」看
  // —— 两处原本都在回答「这个 IP 访问过哪些路径」，功能重复。
  // 注意：只合并当前页可见记录，分页与总条数仍按原始事件数，导出 CSV 也仍是
  // 逐条原始明细，取证用途不受影响。
  function pathRoot(p) {
    var s = String(p || '').split('?')[0];
    var m = /^\/([^/]+)/.exec(s);
    return m ? '/' + m[1] : (s || '—');
  }
  function recGroupKey(r) {
    return [
      Math.floor(Number(r.ts) || 0), r.ip, r.source,
      r.country, r.province, r.city, r.district,
      r.scope, r.proto, r.status, r.port, r.port_src,
      r.verdict, r.action
    ].join('|');
  }
  function mergeRecords(rows) {
    var out = [], idx = {};
    (rows || []).forEach(function (r) {
      var k = recGroupKey(r);
      if (!Object.prototype.hasOwnProperty.call(idx, k)) {
        idx[k] = out.length;
        var g = {}, key;
        for (key in r) {
          if (Object.prototype.hasOwnProperty.call(r, key)) g[key] = r[key];
        }
        g._n = 1; g._paths = {}; g._roots = {};
        if (r.path) { g._paths[r.path] = 1; g._roots[pathRoot(r.path)] = 1; }
        out.push(g);
      } else {
        var cur = out[idx[k]];
        cur._n++;
        if (r.path) { cur._paths[r.path] = 1; cur._roots[pathRoot(r.path)] = 1; }
      }
    });
    out.forEach(function (g) {
      var roots = Object.keys(g._roots);
      g._root = roots.length === 1 ? roots[0] :
        (roots.length ? roots[0] + ' 等' : '—');
      g._pathN = Object.keys(g._paths).length;
    });
    return out;
  }
  function renderRecords(data) {
    var body = $('recBody');
    var groups = [];
    if (!data.rows || !data.rows.length) {
      body.innerHTML = '<tr><td colspan="9" class="empty">没有匹配的记录</td></tr>';
    } else {
      groups = mergeRecords(data.rows);
      body.innerHTML = groups.map(function (r) {
        var loc = [r.country, r.province, r.city, r.district].filter(function (x) { return x && x !== '0'; }).join(' · ') || '—';
        var act = esc(r.action || VERDICT_NAME[r.verdict] || '记录');
        var sub = '<span class="act-sub">' + esc(r._root) + ' · ' +
          (r._n > 1 ? (r._n + ' 个请求已合并（' + r._pathN + ' 条路径）') :
            (r._pathN + ' 条路径')) +
          ' · 点行看路径明细</span>';
        return '<tr data-ip="' + esc(r.ip) + '">' +
          '<td>' + tm(r.ts) + '</td>' +
          '<td>' + esc(SRC_NAME[r.source] || r.source) + '</td>' +
          '<td><span class="ip">' + esc(r.ip) + '</span></td>' +
          '<td>' + esc(loc) + '</td>' +
          '<td><span class="badge ' + esc(r.scope) + '">' + esc(SCOPE_NAME[r.scope] || '未知') + '</span></td>' +
          '<td>' + protoChip(r.proto) + (r.status ? ' <small style="color:var(--dim)">' + r.status + '</small>' : '') + '</td>' +
          '<td title="' + esc(portHint(r.port_src)) + '">' + portLabel(r.port, r.source, r.port_src) + '</td>' +
          '<td><span class="badge ' + esc(r.verdict) + '">' + esc(VERDICT_NAME[r.verdict] || '记录') + '</span></td>' +
          '<td title="点击查看该 IP 的路径明细"><span class="act-main">' + act + '</span>' + sub + '</td></tr>';
      }).join('');
    }
    $('recTotal').textContent = '共 ' + num(data.total) + ' 条' +
      (groups.length ? ' · 本页合并为 ' + groups.length + ' 行' : '');
    var pages = Math.max(1, Math.ceil(data.total / data.size));
    $('recPage').textContent = data.page + ' / ' + pages;
    $('btnPrev').disabled = data.page <= 1;
    $('btnNext').disabled = data.page >= pages;
  }

  // ==================================================================
  // 1.1.8 地图引擎适配层
  // ------------------------------------------------------------------
  // 把四家 SDK 统一包装成「形状与 TMap.* 完全一致」的 SDK 对象，于是
  // drawTMaps / syncGeos / bindMarkerEvents / geoMarkStyles 等整套弧线、
  // 圆点、增量同步与点击事件逻辑零改动即可复用到任意一家底图上。
  // 合规：只内置腾讯 / 高德 / 百度 / 天地图四家，KEY 全部由用户自行申请，
  // 代码里不含任何有效密钥；国界与行政区划一律以官方底图为准。
  // ==================================================================
  var SDK = null;   // 当前引擎的 TMap 兼容对象
  var BUILTIN_PROVIDERS = [
    { id: 'tencent', name: '腾讯地图 GL JS', engine: 'tmap',
      sdk: 'https://map.qq.com/api/gljs?v=1.exp&key={key}',
      apply_url: 'https://lbs.qq.com/dev/console/application/mine',
      apply_text: '腾讯位置服务控制台', coord: 'GCJ-02', key_label: 'key',
      key_placeholder: '请到腾讯位置服务开放平台申请自己的 key 并替换此占位符',
      note: '需勾选「WebGL JavaScript GL」产品，并配置 Referer 白名单。', builtin: true },
    { id: 'amap', name: '高德地图 JS API 2.0', engine: 'amap',
      sdk: 'https://webapi.amap.com/maps?v=2.0&key={key}',
      apply_url: 'https://console.amap.com/dev/key/app',
      apply_text: '高德开放平台控制台', coord: 'GCJ-02', key_label: 'key',
      key_placeholder: '请到高德开放平台申请自己的 key 并替换此占位符',
      note: '需创建「Web端 (JS API)」Key，并配置域名白名单。', builtin: true },
    { id: 'baidu', name: '百度地图 GL v1.0', engine: 'bmapgl',
      sdk: 'https://api.map.baidu.com/api?type=webgl&v=1.0&ak={key}&callback={callback}',
      apply_url: 'https://lbsyun.baidu.com/apiconsole/key',
      apply_text: '百度地图开放平台控制台', coord: 'BD-09（自动转换）', key_label: 'ak',
      key_placeholder: '请到百度地图开放平台申请自己的 ak 并替换此占位符',
      note: '需创建「浏览器端」AK 并配置 Referer 白名单；坐标自动由 GCJ-02 转 BD-09。', builtin: true },
    { id: 'tianditu', name: '天地图 4.0', engine: 'tianditu',
      sdk: 'https://api.tianditu.gov.cn/api?v=4.0&tk={key}',
      apply_url: 'https://console.tianditu.gov.cn/apikey',
      apply_text: '天地图开发平台', coord: 'CGCS2000 / EPSG:4326', key_label: 'tk',
      key_placeholder: '请到天地图开发平台申请自己的 tk 并替换此占位符',
      note: '需申请「浏览器端」key（tk）；底图瓦片由官方服务提供。', builtin: true }
  ];
  var MAP_ENGINE_IDS = { tmap: 1, amap: 1, bmapgl: 1, tianditu: 1 };

  function mapCustomList() { return S.mapCustom || S.cfg.map_custom || []; }
  function mapProviders() { return BUILTIN_PROVIDERS.concat(mapCustomList()); }
  function providerById(pid) {
    var l = mapProviders();
    for (var i = 0; i < l.length; i++) if (l[i].id === pid) return l[i];
    return l[0];
  }
  function providerKey(pid) {
    // 设置界面里未保存的输入优先，避免切换卡片 / 增删接口时丢失
    if (S.mapKeysDraft && Object.prototype.hasOwnProperty.call(S.mapKeysDraft, pid))
      return S.mapKeysDraft[pid];
    var keys = S.cfg.map_keys || {}, k = keys[pid];
    if (!k) {
      var l = mapCustomList();
      for (var i = 0; i < l.length; i++) if (l[i].id === pid) { k = l[i].key; break; }
    }
    if (!k && pid === 'tencent') k = S.cfg.map_key;
    return k || '';
  }
  function keyLooksReal(k) {
    return !!k && String(k).length >= 8 && String(k).indexOf('请') < 0 &&
      String(k).indexOf('替换此占位符') < 0 && String(k).indexOf('填写') !== 0;
  }
  function mapIsConfigured(pid) { return keyLooksReal(providerKey(pid || S.mapProvider)); }
  function mapEngineOf(p) { return MAP_ENGINES[p.engine] || MAP_ENGINES.tmap; }
  function mapProviderName() {
    var p = providerById(S.mapProvider);
    return p.name || '合规底图';
  }
  function updateFooterMap() {
    var el = $('footMap');
    if (el) el.textContent = 'IP 动态感知 · 离线归属库 ip2region · 底图服务：' +
      (mapIsConfigured() ? mapProviderName() : '未配置（坐标散点示意）');
  }
  function mapSdkUrl(p, key, cb) {
    var u = String(p.sdk || '');
    // 1.1.15：旧版本 / 手填配置里可能残留写错点号的高德域名，
    // 报出来就是「请确认能访问 webapiamap.com」这种并不存在的地址。
    // 这里统一纠正为官方域名，诊断里也会标注「已自动纠正旧域名」。
    u = u.replace(/webapiamap\.com/gi, 'webapi.amap.com')
         .replace(/webapi\.amap\.com\.cn/gi, 'webapi.amap.com');
    u = u.replace(/\{key\}/g, encodeURIComponent(key || ''))
         .replace(/\{callback\}/g, cb || '');
    return u.replace(/([?&])callback=&/, '$1').replace(/[?&]callback=$/, '');
  }
  function urlHost(u) {
    var m = /^https?:\/\/([^/:?#]+)/i.exec(u || '');
    return m ? m[1] : '地图服务';
  }

  // ---- 坐标系转换：应用内坐标恒为 GCJ-02，按引擎转换后再交给 SDK ----
  function gcjToBd(lat, lng) {
    var x = lng, y = lat;
    var z = Math.sqrt(x * x + y * y) + 0.00002 * Math.sin(y * Math.PI * 3000.0 / 180.0);
    var th = Math.atan2(y, x) + 0.000003 * Math.cos(x * Math.PI * 3000.0 / 180.0);
    return { lat: z * Math.sin(th) + 0.006, lng: z * Math.cos(th) + 0.0065 };
  }
  function _tLat(x, y) {
    var r = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * Math.sqrt(Math.abs(x));
    r += (20.0 * Math.sin(6.0 * x * Math.PI) + 20.0 * Math.sin(2.0 * x * Math.PI)) * 2.0 / 3.0;
    r += (20.0 * Math.sin(y * Math.PI) + 40.0 * Math.sin(y / 3.0 * Math.PI)) * 2.0 / 3.0;
    r += (160.0 * Math.sin(y / 12.0 * Math.PI) + 320 * Math.sin(y * Math.PI / 30.0)) * 2.0 / 3.0;
    return r;
  }
  function _tLon(x, y) {
    var r = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * Math.sqrt(Math.abs(x));
    r += (20.0 * Math.sin(6.0 * x * Math.PI) + 20.0 * Math.sin(2.0 * x * Math.PI)) * 2.0 / 3.0;
    r += (20.0 * Math.sin(x * Math.PI) + 40.0 * Math.sin(x / 3.0 * Math.PI)) * 2.0 / 3.0;
    r += (150.0 * Math.sin(x / 12.0 * Math.PI) + 300.0 * Math.sin(x / 30.0 * Math.PI)) * 2.0 / 3.0;
    return r;
  }
  function gcjToWgs(lat, lng) {
    var a = 6378245.0, ee = 0.00669342162296594323;
    var dLat = _tLat(lng - 105.0, lat - 35.0), dLon = _tLon(lng - 105.0, lat - 35.0);
    var rad = lat / 180.0 * Math.PI, magic = 1 - ee * Math.sin(rad) * Math.sin(rad);
    var sq = Math.sqrt(magic);
    dLat = (dLat * 180.0) / ((a * (1 - ee)) / (magic * sq) * Math.PI);
    dLon = (dLon * 180.0) / (a / sq * Math.cos(rad) * Math.PI);
    return { lat: lat - dLat, lng: lng - dLon };
  }

  // ---- 通用经纬度对象：getLat/getLng 与 TMap.LatLng 保持同形状 ----
  function LatLngBox(lat, lng) { this.lat = Number(lat) || 0; this.lng = Number(lng) || 0; }
  LatLngBox.prototype.getLat = function () { return this.lat; };
  LatLngBox.prototype.getLng = function () { return this.lng; };
  function laOf(ll) { return typeof ll.getLat === 'function' ? ll.getLat() : ll.lat; }
  function lnOf(ll) { return typeof ll.getLng === 'function' ? ll.getLng() : ll.lng; }
  function nativeOf(v) { return v && v._m ? v._m : v; }

  // ---- MapView：把各引擎原生地图包装出统一 destroy/resize/setScrollable ----
  function MapView(eng, m) { this._eng = eng; this._m = m; }
  MapView.prototype.destroy = function () { try { this._eng.destroyMap(this._m); } catch (e) {} };
  MapView.prototype.resize = function () { try { this._eng.resizeMap(this._m); } catch (e) {} };
  MapView.prototype.setScrollable = function (on) {
    try { this._eng.setScrollable(this._m, !!on); } catch (e) {}
  };

  // ---- GeoLayer：复刻 TMap.MultiPolyline / MultiMarker 的几何接口 ----
  // add / updateGeometries / remove / setGeometries / getGeometries / on
  function GeoLayer(eng, native, kind, styles) {
    this._eng = eng; this._native = native; this._kind = kind;
    this._styles = styles || {}; this._items = {}; this._handlers = {};
  }
  GeoLayer.prototype.on = function (t, fn) {
    (this._handlers[t] = this._handlers[t] || []).push(fn); return this;
  };
  GeoLayer.prototype._emit = function (t, id, geo) {
    var ll = this._kind === 'mark' ? geo.position : (geo.paths && geo.paths[0]);
    var lat = ll ? laOf(ll) : 0, lng = ll ? lnOf(ll) : 0;
    var pos = { lat: lat, lng: lng };
    var evt = {
      geometry: { id: id, properties: geo.properties || { markId: id }, position: pos },
      target: { id: id, position: pos },
      latLng: pos
    };
    var hs = this._handlers[t] || [];
    for (var i = 0; i < hs.length; i++) { try { hs[i](evt); } catch (e) {} }
  };
  GeoLayer.prototype._removeOne = function (id) {
    var it = this._items[id];
    if (!it) return;
    try { this._eng.removeOv(this._native, it.ov); } catch (e) {}
    delete this._items[id];
  };
  GeoLayer.prototype._addOne = function (geo) {
    if (!geo || geo.id == null) return;
    this._removeOne(geo.id);
    var st = this._styles[geo.styleId] || {};
    var ov = this._kind === 'line'
      ? this._eng.makeLine(this._native, geo, st)
      : this._eng.makeMark(this._native, geo, st);
    if (!ov) return;
    try { this._eng.addOv(this._native, ov); } catch (e) { return; }
    var self = this, id = String(geo.id);
    this._eng.onOv(ov, 'click', function () { self._emit('click', id, geo); });
    this._eng.onOv(ov, 'mousemove', function () { self._emit('mousemove', id, geo); });
    this._items[id] = { geo: geo, ov: ov };
  };
  GeoLayer.prototype.setGeometries = function (list) {
    var self = this;
    Object.keys(this._items).forEach(function (id) { self._removeOne(id); });
    (list || []).forEach(function (g) { self._addOne(g); });
  };
  GeoLayer.prototype.add = function (list) {
    var self = this; (list || []).forEach(function (g) { self._addOne(g); });
  };
  GeoLayer.prototype.updateGeometries = function (list) { this.add(list); };
  GeoLayer.prototype.remove = function (ids) {
    var self = this; (ids || []).forEach(function (id) { self._removeOne(String(id)); });
  };
  GeoLayer.prototype.getGeometries = function () {
    var self = this;
    return Object.keys(this._items).map(function (id) { return self._items[id].geo; });
  };
  GeoLayer.prototype.destroy = function () { this.setGeometries([]); };

  // ---- 四家引擎：只声明官方 SDK 的调用形状，不含任何密钥 ----
  function linePoints(eng, geo) {
    return (geo.paths || []).map(function (p) {
      var c = eng.coord(laOf(p), lnOf(p));
      return { lat: c.lat, lng: c.lng };
    });
  }
  function markPoint(eng, geo) {
    var c = eng.coord(laOf(geo.position), lnOf(geo.position));
    return { lat: c.lat, lng: c.lng };
  }
  var MAP_ENGINES = {
    tmap: {
      ns: 'TMap', label: '腾讯地图 GL JS',
      coord: function (lat, lng) { return { lat: lat, lng: lng }; },
      ready: function () { return !!(window.TMap && typeof window.TMap.Map === 'function'); },
      load: function (p, k, done, fail) { loadMapSdk(p, k, done, fail); },
      // 腾讯 SDK 原生就是 TMap.* 形状，直接复用，无需包装
      // 2.0.0 B4：GL JS 官方投影 projectToContainer(LatLng) -> Point
      project: function (m, lat, lng) {
        var p = m.projectToContainer(new window.TMap.LatLng(lat, lng));
        return { x: p.getX ? p.getX() : p.x, y: p.getY ? p.getY() : p.y };
      },
      // 2.0.0 B5：卫星底图（腾讯 GL JS 官方 SDK，合规链路内）
      // 只调用官方 setBaseMap，不拉裸瓦片、不改底图、不自绘边界；
      // 版权 / 审图号由官方底图承载，应用不隐藏、不裁剪。
      setBaseMap: function (m, mode) {
        if (!m || typeof m.setBaseMap !== 'function') return false;
        m.setBaseMap(mode === 'satellite'
          ? { type: 'satellite', features: ['base'] }
          : { type: 'vector' });
        return true;
      },
      build: function () { return window.TMap; }
    },
    amap: {
      ns: 'AMap', label: '高德地图 JS API 2.0',
      coord: function (lat, lng) { return { lat: lat, lng: lng }; },
      ready: function () { return !!(window.AMap && typeof window.AMap.Map === 'function'); },
      load: function (p, k, done, fail) { loadMapSdk(p, k, done, fail); },
      createMap: function (N, el, lat, lng, zoom) {
        return new N.Map(el, { zoom: zoom, center: [lng, lat], viewMode: '2D', resizeEnable: true });
      },
      destroyMap: function (m) { if (m.destroy) m.destroy(); },
      resizeMap: function (m) { if (m.resize) m.resize(); },
      setScrollable: function (m, on) {
        if (m.setStatus) m.setStatus({ zoomEnable: on, scrollWheel: on, doubleClickZoom: on });
      },
      addOv: function (m, ov) { m.add(ov); },
      removeOv: function (m, ov) { m.remove(ov); },
      onOv: function (ov, t, fn) { if (ov.on) ov.on(t, fn); },
      makeLine: function (m, geo, st) {
        var N = window.AMap, path = linePoints(MAP_ENGINES.amap, geo).map(function (c) { return [c.lng, c.lat]; });
        return new N.Polyline({ path: path, strokeColor: st.color || '#5cc3dd',
          strokeWeight: st.width || 2, strokeOpacity: 1, lineCap: 'round', bubble: true });
      },
      makeMark: function (m, geo, st) {
        var N = window.AMap, c = markPoint(MAP_ENGINES.amap, geo);
        var w = st.width || 14, h = st.height || 14;
        return new N.Marker({ position: [c.lng, c.lat], anchor: 'center', cursor: 'pointer',
          icon: new N.Icon({ image: st.src, size: new N.Size(w, h), imageSize: new N.Size(w, h) }) });
      },
      // 2.0.0 B4：lngLatToContainer([lng,lat]) -> Pixel
      project: function (m, lat, lng) {
        var p = m.lngLatToContainer([lng, lat]);
        return { x: p.getX ? p.getX() : p.x, y: p.getY ? p.getY() : p.y };
      },
      build: function () { return buildAdapter(MAP_ENGINES.amap); }
    },
    bmapgl: {
      ns: 'BMapGL', label: '百度地图 GL v1.0',
      coord: function (lat, lng) { return gcjToBd(lat, lng); },
      ready: function () { return !!(window.BMapGL && typeof window.BMapGL.Map === 'function'); },
      load: function (p, k, done, fail) { loadMapSdk(p, k, done, fail); },
      createMap: function (N, el, lat, lng, zoom) {
        var m = new N.Map(el);
        m.centerAndZoom(new N.Point(lng, lat), zoom);
        return m;
      },
      destroyMap: function (m) {
        try { m.clearOverlays(); } catch (e) {}
        try { if (m.destroy) m.destroy(); } catch (e) {}
      },
      resizeMap: function (m) { try { if (m.resize) m.resize(); } catch (e) {} },
      setScrollable: function (m, on) {
        if (on) { if (m.enableScrollWheelZoom) m.enableScrollWheelZoom(); }
        else if (m.disableScrollWheelZoom) m.disableScrollWheelZoom();
      },
      addOv: function (m, ov) { m.addOverlay(ov); },
      removeOv: function (m, ov) { m.removeOverlay(ov); },
      onOv: function (ov, t, fn) { if (ov.addEventListener) ov.addEventListener(t, fn); },
      makeLine: function (m, geo, st) {
        var N = window.BMapGL, e = MAP_ENGINES.bmapgl;
        var pts = linePoints(e, geo).map(function (c) { return new N.Point(c.lng, c.lat); });
        return new N.Polyline(pts, { strokeColor: st.color || '#5cc3dd',
          strokeWeight: st.width || 2, strokeOpacity: 1 });
      },
      makeMark: function (m, geo, st) {
        var N = window.BMapGL, c = markPoint(MAP_ENGINES.bmapgl, geo);
        var w = st.width || 14, h = st.height || 14;
        return new N.Marker(new N.Point(c.lng, c.lat),
          { icon: new N.Icon(st.src, new N.Size(w, h), { anchor: new N.Size(w / 2, h / 2) }) });
      },
      // 2.0.0 B4：GCJ-02 -> BD-09 后 pointToPixel(Point) -> Pixel
      project: function (m, lat, lng) {
        var c = gcjToBd(lat, lng);
        var p = m.pointToPixel(new window.BMapGL.Point(c.lng, c.lat));
        return { x: p.x, y: p.y };
      },
      build: function () { return buildAdapter(MAP_ENGINES.bmapgl); }
    },
    tianditu: {
      ns: 'T', label: '天地图 4.0',
      coord: function (lat, lng) { return gcjToWgs(lat, lng); },
      ready: function () { return !!(window.T && typeof window.T.Map === 'function'); },
      load: function (p, k, done, fail) { loadMapSdk(p, k, done, fail); },
      createMap: function (N, el, lat, lng, zoom) {
        var m = new N.Map(el, { projection: 'EPSG:4326' });
        m.centerAndZoom(new N.LngLat(lng, lat), zoom);
        return m;
      },
      destroyMap: function (m) { try { m.clearOverLays(); } catch (e) {} },
      resizeMap: function (m) { try { if (m.checkResize) m.checkResize(); } catch (e) {} },
      setScrollable: function (m, on) {
        if (on) { if (m.enableScrollWheelZoom) m.enableScrollWheelZoom(); }
        else if (m.disableScrollWheelZoom) m.disableScrollWheelZoom();
      },
      addOv: function (m, ov) { m.addOverLay(ov); },
      removeOv: function (m, ov) { m.removeOverLay(ov); },
      onOv: function (ov, t, fn) { if (ov.addEventListener) ov.addEventListener(t, fn); },
      makeLine: function (m, geo, st) {
        var N = window.T, e = MAP_ENGINES.tianditu;
        var pts = linePoints(e, geo).map(function (c) { return new N.LngLat(c.lng, c.lat); });
        return new N.Polyline(pts, { color: st.color || '#5cc3dd',
          weight: st.width || 2, opacity: 1 });
      },
      makeMark: function (m, geo, st) {
        var N = window.T, c = markPoint(MAP_ENGINES.tianditu, geo);
        var w = st.width || 14, h = st.height || 14;
        return new N.Marker(new N.LngLat(c.lng, c.lat),
          { icon: new N.Icon({ iconUrl: st.src, iconSize: new N.Point(w, h),
            iconAnchor: new N.Point(w / 2, h / 2) }) });
      },
      // 2.0.0 B4：GCJ-02 -> CGCS2000 后 lngLatToContainer(LngLat) -> Point
      project: function (m, lat, lng) {
        var c = gcjToWgs(lat, lng);
        var p = m.lngLatToContainer(new window.T.LngLat(c.lng, c.lat));
        return { x: p.x, y: p.y };
      },
      build: function () { return buildAdapter(MAP_ENGINES.tianditu); }
    }
  };

  // 把非腾讯引擎包装成 TMap 兼容对象（Map / LatLng / MultiPolyline /
  // MultiMarker / PolylineStyle / MarkerStyle 六件套）
  function buildAdapter(eng) {
    var N = window[eng.ns];
    function LatLng(lat, lng) { return new LatLngBox(lat, lng); }
    function Map(el, opts) {
      opts = opts || {};
      var c = eng.coord(laOf(opts.center || new LatLngBox(26, 10)),
                        lnOf(opts.center || new LatLngBox(26, 10)));
      return new MapView(eng, eng.createMap(N, el, c.lat, c.lng, opts.zoom || 2));
    }
    function PolylineStyle(o) {
      this.color = (o && o.color) || '#5cc3dd'; this.width = (o && o.width) || 2;
      this.borderWidth = (o && o.borderWidth) || 0; this.lineCap = (o && o.lineCap) || 'round';
    }
    function MarkerStyle(o) {
      this.width = (o && o.width) || 14; this.height = (o && o.height) || 14;
      this.anchor = (o && o.anchor) || { x: 7, y: 7 }; this.src = (o && o.src) || '';
    }
    function MultiPolyline(o) {
      var g = new GeoLayer(eng, nativeOf(o.map), 'line', o.styles || {});
      if (o.geometries && o.geometries.length) g.setGeometries(o.geometries);
      return g;
    }
    function MultiMarker(o) {
      var g = new GeoLayer(eng, nativeOf(o.map), 'mark', o.styles || {});
      if (o.geometries && o.geometries.length) g.setGeometries(o.geometries);
      return g;
    }
    return { Map: Map, LatLng: LatLng, MultiPolyline: MultiPolyline,
             MultiMarker: MultiMarker, PolylineStyle: PolylineStyle, MarkerStyle: MarkerStyle };
  }

  // 1.1.15：按服务商给出可执行的失败原因。高德 KEY 无效 / 未绑定 Web 端 /
  // 白名单不含本站时，服务端返回的是 text/plain 的 console.log 文本而不是 JS，
  // 浏览器触发 script.onerror 或「AMap 未创建」；旧文案只说「请确认能访问域名」，
  // 用户会误以为是网络问题，反复换 KEY 也定位不到。
  function sdkFailHint(p, kind) {
    var host = urlHost(mapSdkUrl(p, providerKey(p.id), 'x'));
    if (p.engine === 'amap') {
      return kind === 'net'
        ? '高德 SDK 加载失败（' + host + '）：请确认能访问 webapi.amap.com，' +
          '并检查浏览器扩展 / 路由器是否拦截了该域名。'
        : '高德 SDK 未就绪：KEY 无效、未绑定「Web 端 (JS API)」、' +
          '域名白名单不含本站，或未配置安全密钥 jscode，都会让服务端返回纯文本而不创建 AMap。' +
          '请到高德控制台核对以上四项后重试（正确域名为 ' + host + '）。';
    }
    return kind === 'net'
      ? 'SDK 加载失败：请确认能访问 ' + host
      : 'SDK 已下载但未就绪：请检查 KEY 与域名 / Referer 白名单，' +
        '或确认浏览器扩展没有拦截 ' + host;
  }
  function pollMapReady(p, eng, done, fail) {
    var tries = 0;
    (function wait() {
      if (eng.ready()) { done(); return; }
      if (tries++ < 40) { setTimeout(wait, 100); return; }
      fail(sdkFailHint(p, 'ready'));
    })();
  }
  function loadMapScript(url, onload, onerror) {
    var old = document.getElementById('tmapSdk');
    if (old && old.parentNode) old.parentNode.removeChild(old);
    var s = document.createElement('script');
    s.id = 'tmapSdk'; s.src = url; s.onload = onload; s.onerror = onerror;
    document.head.appendChild(s);
  }
  function loadMapSdk(p, key, done, fail) {
    var eng = mapEngineOf(p), cb = '__ipsenseMapReady__';
    var url = mapSdkUrl(p, key, cb), fired = false;
    function once() { if (fired) return; fired = true; pollMapReady(p, eng, done, fail); }
    if (eng.ready()) { done(); return; }
    setMapState('loading');
    if (p.engine === 'bmapgl') window[cb] = once;
    loadMapScript(url, function () {
      if (p.engine === 'bmapgl') setTimeout(once, 60);
      else once();
    }, function () { fail(sdkFailHint(p, 'net')); });
    setTimeout(function () {
      if (!S.tmapReady && S.tmapState === 'loading') {
        fail(sdkFailHint(p, 'ready'));
      }
    }, 12000);
  }

  // ---- 地图：合规底图（四家引擎统一适配，用户自配 key） ----
  function markerIcon(color, size) {
    var s = size || 16, r = s / 2;
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + s + '" height="' + s +
      '" viewBox="0 0 ' + s + ' ' + s + '">' +
      '<circle cx="' + r + '" cy="' + r + '" r="' + (r - 1) + '" fill="' + color + '" fill-opacity="0.16"/>' +
      '<circle cx="' + r + '" cy="' + r + '" r="' + (r * 0.58).toFixed(1) + '" fill="' + color + '" fill-opacity="0.34"/>' +
      '<circle cx="' + r + '" cy="' + r + '" r="' + (r * 0.30).toFixed(1) + '" fill="' + color + '"/>' +
      '<circle cx="' + r + '" cy="' + r + '" r="' + (r * 0.13).toFixed(1) + '" fill="#ffffff"/>' +
      '</svg>';
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
  }
  // ---- 弧线几何 ----
  // 1.0.4 的画法缺陷：弯曲高度设了 1.2° 硬下限，但境内来源是「省中心 + ±0.6° 抖动」，
  // 距本机常只有 0.1~1°，于是每条短线都鼓出比自身还大的回环并互相打结。
  // 1.0.5：弯曲高度严格与距离成比例、无下限、按视图封顶 —— 近距离几乎是直线，
  // 远距离才是优雅长弧；统一取连线左法向，从四周呈放射状汇聚到本机。
  // 按「本图内相对连接频率」分 5 档：对 log1p(n) 做 min/max 归一化。
  // 相对归一保证 1h / 30d 等任意时间范围下颜色都能拉开：最高频必为红、最低频必为青；
  // 全部来源频率相同时统一落中档，避免整张图全红或全青。
  function assignHeat(list) {
    if (!list || !list.length) return list;
    var logs = list.map(function (b) {
      return Math.log1p(Math.max(0, Number(b.n) || 0));
    });
    var lo = Math.min.apply(null, logs), hi = Math.max.apply(null, logs);
    var span = hi - lo;
    list.forEach(function (b, i) {
      var r = span > 1e-6 ? (logs[i] - lo) / span : 0.5;
      b.heat = r;
      // r=1 时 floor(5)=5 会被钳到 5；最低频恒为 1
      b.tier = Math.max(1, Math.min(ARC_LEVELS, 1 + Math.floor(r * ARC_LEVELS)));
    });
    return list;
  }
  function geoDist(a, b) {
    var dLng = b.lng - a.lng;
    if (dLng > 180) dLng -= 360;
    else if (dLng < -180) dLng += 360;
    var dLat = b.lat - a.lat;
    var k = Math.max(0.35, Math.cos((a.lat + b.lat) / 2 * Math.PI / 180));
    var vx = dLng * k;
    return { dLng: dLng, dLat: dLat, k: k, vx: vx, vy: dLat,
             dist: Math.max(0.001, Math.sqrt(vx * vx + dLat * dLat)) };
  }
  function arcControl(from, to, scope) {
    var d = geoDist(from, to);
    var bend = Math.max(0.04, Math.min(0.28, S.arcBend));
    var cap = scope === 'overseas' ? 20 : 3.5;
    var h = Math.min(cap, d.dist * bend * (scope === 'overseas' ? 1.35 : 1));
    // 1.1.15：同省 / 同城短弧给一个很小的可见弧度，让它从底图上读得出来；
    // 但不给超短弧设硬下限（1.0.4 的 1.2° 下限会让短线鼓出比自身还大的回环）。
    if (d.dist > 0.6 && h < 0.12) h = 0.12;
    var nx = -d.vy / d.dist, ny = d.vx / d.dist;
    // 1.0.12：三次贝塞尔。两个控制点沿连线方向分布、再叠加法向偏移，
    // 端点切线贴合 A→B 方向，中段圆润饱满，比单控制点的二次曲线顺滑。
    // 偏移取 2h/3，使 t=0.5 处顶点偏离仍为 0.5h，视觉弯曲幅度不变。
    var off = 2 * h / 3, dLat = to.lat - from.lat, dLng = d.dLng;
    return {
      from: { lat: from.lat, lng: from.lng },
      to: { lat: to.lat, lng: from.lng + dLng },
      c1: { lat: from.lat + dLat / 3 + ny * off,
            lng: from.lng + dLng / 3 + nx * off / d.k },
      c2: { lat: from.lat + dLat * 2 / 3 + ny * off,
            lng: from.lng + dLng * 2 / 3 + nx * off / d.k },
      // 采样点按距离自适应：长弧最多 64 段，折线逼近光滑曲线，消除肉眼可见折角
      // 1.1.15：跨 ±180° 的长弧加密采样（64 → 96），折线更贴曲线，
      // 减少 SDK 上长直线段被误看成「断了一截」的情况。
      n: Math.max(24, Math.min(d.dist > 90 ? 96 : 64,
                               Math.round(d.dist * 1.5) + 24))
    };
  }
  function bezierAt(g, t) {
    var u = 1 - t, a = u * u * u, b = 3 * u * u * t,
        c = 3 * u * t * t, d = t * t * t;
    return { lat: a * g.from.lat + b * g.c1.lat + c * g.c2.lat + d * g.to.lat,
             lng: a * g.from.lng + b * g.c1.lng + c * g.c2.lng + d * g.to.lng };
  }
  function wrapSegs(pts, base) {
    // 经度跨 ±180° 时切成两段，避免拉出一条横穿地图的直线。
    // 1.1.15：新增 base —— 把点归一化到 [base-180, base+180] 这个「世界副本」，
    // 于是同一条曲线可以在 -360 / 0 / +360 三个窗口各生成一份完整折线。
    base = base || 0;
    var segs = [], cur = [], i, p, lng, q, prev, edge;
    for (i = 0; i < pts.length; i++) {
      p = pts[i]; lng = p.lng;
      while (lng - base > 180) lng -= 360;
      while (lng - base < -180) lng += 360;
      q = { lat: p.lat, lng: lng };
      if (cur.length && Math.abs(q.lng - cur[cur.length - 1].lng) > 180) {
        prev = cur[cur.length - 1];
        edge = prev.lng > base ? base + 180 : base - 180;
        cur.push({ lat: (prev.lat + q.lat) / 2, lng: edge });
        segs.push(cur);
        cur = [{ lat: (prev.lat + q.lat) / 2,
                 lng: (edge > base ? base - 180 : base + 180) }, q];
      } else cur.push(q);
    }
    if (cur.length > 1) segs.push(cur);
    return segs;
  }
  // 1.1.18：SDK 合规底图的跨日期变更线处理。
  // 1.1.16 的做法是「逐点取模归一化 + wrapSegs 切断」，真机会暴露两个缺陷：
  //   ① 逐点取模把连续曲线在跨 180° 处折成两段，端点纬度用「前后两点平均」，
  //      而不是曲线在接缝处的真实插值，两段端点对不齐；
  //   ② 端点写死 ±180，部分 SDK 会把 180 归一化为 -180，段尾瞬间回卷到地图
  //      另一端，视觉上就是「拼接处断了一截」，甚至整层折线不渲染。
  // 现在对 -360 / 0 / +360 三个世界副本各裁剪一次到合法窗口，跨边界处按线性
  // 插值补真实交点，端点收进 (180 - ε)：两段首尾严格对齐，且所有点都落在
  // SDK 接受的 [-180,180] 内；SDK 重复世界副本时，接缝两侧自然首尾相接。
  var SEAM_EPS = 0.001;
  function seamPoint(a, b, bound, lo, hi) {
    var d = b.lng - a.lng;
    var f = Math.abs(d) < 1e-9 ? 0 : (bound - a.lng) / d;
    f = Math.max(0, Math.min(1, f));
    return { lat: a.lat + (b.lat - a.lat) * f,
             lng: Math.max(lo + SEAM_EPS, Math.min(hi - SEAM_EPS, bound)) };
  }
  function clipToWindow(pts, lo, hi) {
    var out = [], cur = [], i, a, b, inA, inB, edge, p1, p2;
    function inside(x) { return x >= lo && x <= hi; }
    for (i = 1; i < pts.length; i++) {
      a = pts[i - 1]; b = pts[i];
      inA = inside(a.lng); inB = inside(b.lng);
      if (inA && !cur.length) cur.push({ lat: a.lat, lng: a.lng });
      if (inA && inB) {
        cur.push({ lat: b.lat, lng: b.lng });
      } else if (inA && !inB) {
        edge = b.lng > hi ? hi : lo;
        cur.push(seamPoint(a, b, edge, lo, hi));
        if (cur.length > 1) out.push(cur);
        cur = [];
      } else if (!inA && inB) {
        edge = a.lng < lo ? lo : hi;
        cur = [seamPoint(a, b, edge, lo, hi), { lat: b.lat, lng: b.lng }];
      } else if ((a.lng < lo && b.lng > hi) || (a.lng > hi && b.lng < lo)) {
        p1 = seamPoint(a, b, a.lng < lo ? lo : hi, lo, hi);
        p2 = seamPoint(a, b, a.lng < lo ? hi : lo, lo, hi);
        out.push([p1, p2]);
      }
    }
    if (cur.length > 1) out.push(cur);
    return out;
  }
  function worldSegs(pts) {
    var out = [];
    [-360, 0, 360].forEach(function (off) {
      var shifted = pts.map(function (p) {
        return { lat: p.lat, lng: (Number(p.lng) || 0) + off };
      });
      clipToWindow(shifted, -180, 180).forEach(function (seg) { out.push(seg); });
    });
    if (!out.length) {
      return [pts.map(function (p) {
        var x = ((Number(p.lng) || 0) + 180) % 360;
        if (x < 0) x += 360;
        return { lat: p.lat, lng: x - 180 + SEAM_EPS };
      })];
    }
    return out;
  }
  function arcPaths(from, to, scope) {
    var g = arcControl(from, to, scope), full = [], i;
    for (i = 0; i <= g.n; i++) full.push(bezierAt(g, i / g.n));
    // 1.0.11：整条曲线一次生成、统一单色；跨 180° 由 wrapSegs 统一切断
    g.segs = wrapSegs(full);            // Canvas 主窗口：配合本机中心窗口首尾相接
    g.sdkSegs = worldSegs(full);        // SDK 合规底图：合法经度窗口，跨 seam 分段
    g.cross = g.sdkSegs.length > 1 ? 1 : 0;
    return g;
  }
  // 1.1.16 真机回归二次修复：sdkLat 必须定义在 IIFE 顶层。
  // 初版把它放在 createTMaps() 内部，而 drawTMaps() 是另一个顶层函数，
  // SDK 合规底图路径一执行就抛 ReferenceError: sdkLat is not defined，
  // 整层折线不渲染 —— 离线预览走 Canvas 降级，所以完全没暴露。
  function sdkLat(lat, lng) {
    var a = Math.max(-85, Math.min(85, Number(lat) || 0));
    var o = Math.max(-180, Math.min(180, Number(lng) || 0));
    return new SDK.LatLng(a, o);
  }
  // 按行政区聚合：境内按省、境外按国家。后端 hotspots 已带 province / country，
  // 坐标取组内加权平均，消除离线库按 IP 做的 MD5 抖动假散点。
  // 同省几十个 IP 只画一条，从根上避免本机周围挤满近距离乱线。
  function buildArcs(scope, home) {
    var bins = {}, keys = [], total = 0;
    S.hotspots.forEach(function (h) {
      if (h.scope !== scope || h.lat == null || h.lng == null) return;
      var lat = Number(h.lat), lng = Number(h.lng);
      total += 1;
      var region = String(scope === 'cn' ? (h.province || '') : (h.country || ''))
        .replace(/^\s*(中国|中华人民共和国)\s*/, '').trim();
      if (/^(0|-|未知|unknown|)$/i.test(region)) region = '';
      var key = region ? 'r:' + region
                       : 'g:' + Math.round(lat / 0.7) + ':' + Math.round(lng / 0.7);
      var b = bins[key];
      if (!b) {
        b = bins[key] = { lat: 0, lng: 0, w: 0, n: 0, ips: 0, region: region,
                          verdict: '', ip: '', last_ts: 0, members: [] };
        keys.push(key);
      }
      var wgt = Number(h.n) || 1;
      b.lat += lat * wgt; b.lng += lng * wgt; b.w += wgt;
      b.n += wgt; b.ips += 1;
      // 保留成员明细：点击圆点时无需请求即可先展示 IP 与最近连接时间
      b.members.push({
        ip: String(h.ip || ''), n: wgt, last_ts: Number(h.last_ts) || 0,
        verdict: h.verdict || '', city: h.city || '',
        district: h.district || '', isp: h.isp || '',
        province: h.province || '', country: h.country || '',
        lat: lat, lng: lng, scope: scope
      });
      if (h.verdict === 'attack' || (h.verdict === 'scan' && b.verdict !== 'attack')) b.verdict = h.verdict;
      if ((Number(h.last_ts) || 0) >= b.last_ts) { b.last_ts = Number(h.last_ts) || 0; b.ip = h.ip || ''; }
    });
    keys.sort(function (x, y) { return bins[y].n - bins[x].n; });
    // 1.1.15 修复「同省内 IP 在地图上不显示」：
    // 旧阈值 0.35° 太大，同省不同市（例 广州 113.26 / 深圳 114.06，差 0.8° 内）
    // 会被整组判成「与本机重合」，只留一个 2.6px 小点、不画任何线段。
    // 现在只有坐标真正重合（<0.02°，约 2km）才合并成点，其余一律画弧；
    // 短弧弯曲高度随距离收敛，不会鼓出回环（见 arcControl）。
    var near = 0, nearPts = [], kept = [];
    keys.forEach(function (k) {
      var b = bins[k];
      b.lat = b.lat / b.w; b.lng = b.lng / b.w;   // 加权平均 → 端点稳定不抖动
      if (Math.abs(b.lat - home.lat) + Math.abs(b.lng - home.lng) * 0.85 < 0.02) {
        near += b.ips;                            // 坐标完全重合：只画点，不画弧
        nearPts.push({ lat: b.lat, lng: b.lng, n: b.n, region: b.region,
                       members: b.members, verdict: b.verdict, last_ts: b.last_ts });
        return;
      }
      kept.push(b);
    });
    var limit = Math.max(5, Math.min(60, S.arcLimit));
    var list = kept.slice(0, limit).map(function (b) {
      b.g = arcPaths({ lat: b.lat, lng: b.lng }, home, scope);
      return b;
    });
    // 弧线与「近距只画点」的来源放进同一个池里比频率：本图最高频必为红、最低频必为青。
    // 按省合并后常只剩 1~2 条弧，只对 list 归一会让所有线退化成中档，颜色变化看不出来。
    var nearList = nearPts.slice(0, 12);
    assignHeat(list.concat(nearList));
    var cross = list.reduce(function (a, b) { return a + (b.g.cross || 0); }, 0);
    return { list: list, merged: Math.max(0, total - keys.length),
             skipped: Math.max(0, kept.length - limit), near: near,
             nearPts: nearList, cross: cross };
  }
  function mapSignature(home) {
    return [S.hotspots.length,
      S.hotspots.map(function (h) {
        return [h.ip, h.lat, h.lng, h.n, h.scope, h.verdict, h.province, h.country].join(',');
      }).join(';'),
      home.lat, home.lng, S.arcLimit, S.arcBend, S.tmapReady ? 1 : 0].join('|');
  }
  function refreshArcData(home, force) {
    var sig = mapSignature(home);
    if (!force && sig === S.arcData.sig) return false;
    S.arcData.sig = sig;
    S.arcData.world = buildArcs('overseas', home);
    S.arcData.cn = buildArcs('cn', home);
    S.arcDrawn = S.arcData.world.list.length + S.arcData.cn.list.length;
    S.arcMerged = S.arcData.world.merged + S.arcData.cn.merged;
    S.arcSkipped = S.arcData.world.skipped + S.arcData.cn.skipped;
    S.arcNear = S.arcData.world.near + S.arcData.cn.near;
    S.arcCross = (S.arcData.world.cross || 0) + (S.arcData.cn.cross || 0);
    return true;
  }
  function tileStat() {
    try {
      var _p = providerById(S.mapProvider);
      var _host = urlHost(mapSdkUrl(_p, providerKey(_p.id), 'x')).replace(/\./g, '\\.');
      var _re = new RegExp(_host +
        '|map\\.qq\\.com|gtimg\\.com|maptiles|mapapi\\.qq\\.com' +
        '|amap\\.com|autonavi\\.com|baidu\\.com|tianditu', 'i');
      var rs = (performance.getEntriesByType('resource') || []).filter(function (r) {
        return _re.test(r.name) && r.name.indexOf('/api/gljs') < 0 &&
               r.name.indexOf('/maps?') < 0 && r.name.indexOf('/api?type=webgl') < 0 &&
               r.name.indexOf('/api?v=4.0') < 0;
      });
      var bad = rs.filter(function (r) { return r.responseStatus && r.responseStatus >= 400; });
      return { n: rs.length, bad: bad.length, first: bad.length ? bad[0].name.split('?')[0].slice(-56) : '' };
    } catch (e) { return { n: -1, bad: 0, first: '' }; }
  }
  function mapDiag() {
    var w = $('worldMap').getBoundingClientRect(), c = $('cnMap').getBoundingClientRect();
    var t = tileStat();
    var tileText = t.n < 0 ? '浏览器不支持统计' :
      (t.n + ' 个' + (t.bad ? ' · ' + t.bad + ' 个被拒（白名单/配额）' : ' · 无 4xx'));
    var _pd = providerById(S.mapProvider), _ed = mapEngineOf(_pd);
    return [
      ['当前服务商', _pd.name + ( _pd.builtin ? '' : ' · 自定义')],
      ['引擎 / 坐标系', _ed.label + ' / ' + (_pd.coord || '—')],
      ['SDK 地址', urlHost(mapSdkUrl(_pd, providerKey(_pd.id), '__cb__')) +
        (/webapiamap\.com|webapi\.amap\.com\.cn/i.test(String(_pd.sdk || '')) ?
          ' · 已自动纠正旧域名' : '')],
      ['KEY 已配置', mapIsConfigured(_pd.id) ?
        '是（长度 ' + providerKey(_pd.id).length + '）' : '否'],
      ['SDK 已加载', _ed.ready() ? '是' : '否'],
      ['SDK.Map 可用', (SDK && typeof SDK.Map === 'function') ? '是' : '否'],
      ['底图状态', S.tmapState + (S.tmapError ? ' · ' + S.tmapError : '')],
      ['底图样式', mapBaseLabel() + (S.mapBase === 'satellite' ?
        '（腾讯 GL JS 官方卫星底图 · 边界以官方底图为准）' : '（默认）')],
      ['全球容器尺寸', Math.round(w.width) + ' × ' + Math.round(w.height)],
      ['中国容器尺寸', Math.round(c.width) + ' × ' + Math.round(c.height)],
      ['底图资源请求', tileText],
      ['弧线绘制', S.arcDrawn + ' 条 · 合并 ' + S.arcMerged + ' 个 · 近距 ' +
        S.arcNear + ' 个 · 省略 ' + S.arcSkipped + ' 个'],
      ['跨日期变更线', S.arcCross + ' 条 · 接缝两端按插值对齐，端点收进 ±180° 内不再回卷'],
      ['地图重绘', S.redraws + ' 次 · 最近 ' + S.lastDrawMs.toFixed(1) + ' ms（数据未变时跳过）'],
      ['刷新间隔', '事件 ' + (Number(S.cfg.map_refresh) || 3) + ' s / 地图 ' +
        (Number(S.cfg.map_heavy_refresh) || 12) + ' s'],
      ['当前地址', location.host || location.href.slice(0, 60)]
    ];
  }
  function failMap(msg) {
    // 失败必须回滚到散点示意，否则容器空白
    $('worldWrap').classList.remove('tmap-on');
    $('cnWrap').classList.remove('tmap-on');
    S.tmapReady = false;
    try { if (S.world && S.world.destroy) S.world.destroy(); } catch (e) {}
    try { if (S.cn && S.cn.destroy) S.cn.destroy(); } catch (e) {}
    S.world = S.cn = null;
    destroyGeoMap();
    setMapState('error', msg);
    $('worldNote').textContent = '底图未显示：' + msg;
    $('cnNote').textContent = '底图未显示：' + msg;
    startCanvasAnim();
    requestMapDraw(true);
    drawGeoCanvas();
  }
  function initTMap(key, force) {
    // 1.1.8：按「当前服务商」取它自己的 key 与 SDK 地址，不再写死腾讯。
    var p = providerById(S.mapProvider);
    S.mapProvider = p.id;
    var k = providerKey(p.id);
    if (!mapIsConfigured(p.id)) { startCanvasAnim(); requestMapDraw(true); return; }
    if (S.tmapReady) return;
    if (S.tmapTried && !force) return;
    S.tmapTried = true;
    S.tmapKey = k;
    var eng = mapEngineOf(p);
    loadMapSdk(p, k, function () {
      SDK = eng.build();
      if (!SDK || typeof SDK.Map !== 'function') {
        failMap('地图 SDK 未就绪：' + eng.label); return;
      }
      try { createTMaps(); }
      catch (e) { failMap('底图初始化失败：' + ((e && e.message) || '未知错误')); }
    }, function (msg) { failMap(msg); });
  }

  // ===== 2.0.0 B5 · 卫星底图（合规链路内，纯渲染层） =====
  // 只经腾讯地图 GL JS 官方 setBaseMap API 切换底图样式；不拉裸瓦片、
  // 不篡改底图、不自绘或改绘任何国界 / 海岸线 / 行政区划边界；
  // 边界一律以官方合规底图为准，版权与审图号由官方底图承载并保留。
  // 无 KEY 的 Canvas 降级路径继续只画散点、不绘任何边界，不受影响。
  function mapBaseLabel() { return S.mapBase === 'satellite' ? '卫星影像' : '矢量底图'; }
  function applyMapBase() {
    if (!S.tmapReady) return;
    var eng = mapEngineOf(providerById(S.mapProvider));
    // 当前仅腾讯 GL JS 提供官方卫星底图；其它引擎保持合规矢量底图
    if (typeof eng.setBaseMap !== 'function') return;
    [S.world, S.cn, S.geoMap].forEach(function (m) {
      if (!m) return;
      try { eng.setBaseMap(nativeOf(m), S.mapBase); }
      catch (e) { console.warn('satellite basemap fallback', e); }
    });
  }
  // ===== B5 卫星底图结束 =====

  function rebuildMap() {
    // 1.1.8：彻底销毁旧引擎实例与覆盖层，回退 Canvas，再按当前服务商重建
    [S.world, S.cn].forEach(function (m) {
      if (!m) return;
      try { if (m.layer && m.layer.destroy) m.layer.destroy(); } catch (e) {}
      try { if (m.marks && m.marks.destroy) m.marks.destroy(); } catch (e) {}
      try { if (m.destroy) m.destroy(); } catch (e) {}
    });
    S.tmapReady = false; S.world = S.cn = null; SDK = null;
    destroyGeoMap();
    S.geoCache = {}; S.tmapTried = false;
    $('worldWrap').classList.remove('tmap-on');
    $('cnWrap').classList.remove('tmap-on');
    setMapState('off');
    startCanvasAnim(); requestMapDraw(true); drawGeoCanvas();
    if (mapIsConfigured()) setTimeout(function () { initTMap('', true); }, 80);
  }
  function createTMaps() {
    if (!SDK || typeof SDK.Map !== 'function') {
      throw new Error('SDK 未就绪');
    }
    // 关键：容器必须先有真实尺寸再 new SDK.Map。
    // display:none(0x0) 时初始化会直接抛异常，导致地图静默白屏。
    $('worldWrap').classList.add('tmap-on');
    $('cnWrap').classList.add('tmap-on');
    void $('worldMap').offsetWidth;
    void $('cnMap').offsetWidth;
    var w = $('worldMap').getBoundingClientRect(), c = $('cnMap').getBoundingClientRect();
    if (w.width < 10 || c.width < 10) {
      $('worldWrap').classList.remove('tmap-on');
      $('cnWrap').classList.remove('tmap-on');
      throw new Error('地图容器尺寸为 0（' + Math.round(w.width) + '×' + Math.round(w.height) + '）');
    }
    S.world = new SDK.Map('worldMap', {
      zoom: 2, center: new SDK.LatLng(26, 10), showControl: false
    });
    S.cn = new SDK.Map('cnMap', {
      zoom: 3, center: new SDK.LatLng(35, 104), showControl: false
    });
    // 1.1.0：地域分布图共用同一份合规底图（1.1.8 起随服务商切换）。
    // 只叠加「数量气泡」，不叠加任何自绘边界 / 区划轮廓；创建失败自动回退 canvas。
    try {
      $('geoWrap').classList.add('tmap-on');
      void $('geoMap').offsetWidth;
      var g = $('geoMap').getBoundingClientRect();
      if (g.width >= 10) {
        S.geoMap = new SDK.Map('geoMap', {
          zoom: 2, center: new SDK.LatLng(26, 10), showControl: false
        });
        S.geoMarks = new SDK.MultiMarker({
          map: S.geoMap, styles: geoMarkStyles(), geometries: []
        });
        S.geoMarks.on('click', function (evt) {
          var id = geoId(evt), r = S.geoMarkIndex[id];
          if (r) openRegionProfile(r.name, r.scope || 'all');
        });
        if (S.geoData) drawGeoMarkers();
      } else {
        $('geoWrap').classList.remove('tmap-on');
      }
    } catch (e) {
      $('geoWrap').classList.remove('tmap-on');
      S.geoMap = S.geoMarks = null;
      console.warn('geo tmap fallback', e);
    }
    // 地图可能在抽屉已打开后才异步创建，按当前状态补一次滚轮缩放开关
    setMapScroll(!drawerOpen());
    function arcStyles() {
      // 1.0.11：5 档频率 = 5 个 style，整条弧线一个颜色，仍在同一图层内
      var out = {};
      ARC_TIER_IDS.forEach(function (t) {
        out['t' + t] = new SDK.PolylineStyle({
          color: ARC_HEAT[t - 1], width: ARC_TIER[t].w, borderWidth: 0,
          lineCap: 'round'   // 1.0.12：端点圆头，配合加密采样让折线拐角更顺
        });
      });
      return out;
    }
    // 圆点按频率档上色：src1..5 / near1..5 与连线共用同一色阶
    function markStyles() {
      var out = {
        home: new SDK.MarkerStyle({ width: 26, height: 26, anchor: { x: 13, y: 13 }, src: markerIcon('#2563eb', 26) })
      };
      ARC_TIER_IDS.forEach(function (t) {
        var c = ARC_HEAT[t - 1];
        out['src' + t] = new SDK.MarkerStyle({
          width: 14, height: 14, anchor: { x: 7, y: 7 }, src: markerIcon(c, 14) });
        out['near' + t] = new SDK.MarkerStyle({
          width: 10, height: 10, anchor: { x: 5, y: 5 }, src: markerIcon(c, 10) });
      });
      return out;
    }
    S.geoCache = {};
    S.world.layer = new SDK.MultiPolyline({
      map: S.world, styles: arcStyles(), geometries: []
    });
    S.world.marks = new SDK.MultiMarker({ map: S.world, styles: markStyles(), geometries: [] });
    S.cn.layer = new SDK.MultiPolyline({
      map: S.cn, styles: arcStyles(), geometries: []
    });
    S.cn.marks = new SDK.MultiMarker({ map: S.cn, styles: markStyles(), geometries: [] });
    S.tmapReady = true;
    setMapState('ready');
    $('worldNote').textContent = '底图 © ' + mapProviderName() + ' · ' + mapBaseLabel() +
      ' · 国界与行政区划以官方底图为准';
    $('cnNote').textContent = '底图 © ' + mapProviderName() + ' · ' + mapBaseLabel() +
      ' · 中国香港 / 澳门 / 台湾均属中国境内';
    bindMarkerEvents(S.world, 'world');
    bindMarkerEvents(S.cn, 'cn');
    requestMapDraw(true);
    applyMapBase();
    // 2.0.0 返工：有 KEY 成功路径同样保证 FX 定时器常驻，
    // 不再让「底图加载完成」把逐帧绘制停掉（startCanvasAnim 幂等）。
    startCanvasAnim();
  }
  // 增量同步：只把新增 / 变化 / 删除的 geometry 交给 SDK。
  // SDK 不支持 add/update/remove 时自动回退 setGeometries，功能不受影响。
  function syncGeos(layer, cacheKey, desired) {
    var cache = S.geoCache[cacheKey] || {}, next = {}, add = [], upd = [], del = [];
    desired.forEach(function (d) {
      next[d.id] = d.sig;
      if (!(d.id in cache)) add.push(d.geo);
      else if (cache[d.id] !== d.sig) upd.push(d.geo);
    });
    Object.keys(cache).forEach(function (id) { if (!(id in next)) del.push(id); });
    S.geoCache[cacheKey] = next;
    if (!add.length && !upd.length && !del.length) return false;
    try {
      // 官方 API：add(geometries[]) / updateGeometries(geometries[]) / remove(ids[])
      // 旧版 SDK 可能叫 update，这里做兼容
      var update = layer.updateGeometries || layer.update;
      if (!layer.add || !update || !layer.remove) throw new Error('no incremental api');
      if (del.length) layer.remove(del);
      if (upd.length) update.call(layer, upd);
      if (add.length) layer.add(add);
      // 部分 SDK 版本增量接口行为不同，数量对不上就退回全量，保证不丢线
      if (layer.getGeometries && layer.getGeometries().length !== desired.length) {
        throw new Error('geometry count mismatch');
      }
    } catch (e) {
      layer.setGeometries(desired.map(function (d) { return d.geo; }));
    }
    return true;
  }
  function drawTMaps(home) {
    if (!S.tmapReady) return;
    [['world', 'overseas', S.world], ['cn', 'cn', S.cn]].forEach(function (t) {
      var name = t[0], scope = t[1], m = t[2];
      var data = (scope === 'cn' ? S.arcData.cn : S.arcData.world) || emptyArcs();
      var prefix = scope === 'cn' ? 'c' : 'w';
      var geos = [], marks = [], mi = S.markIndex[name] = {};
      data.list.forEach(function (b) {
        var cid = prefix + '_' + Math.round(b.lat * 1000) + '_' + Math.round(b.lng * 1000);
        // 指纹含坐标与弯曲幅度：几何真变了才提交 GPU 缓冲
        var sig = [b.tier, b.verdict, b.lat, b.lng, home.lat, home.lng, S.arcBend].join('|');
        // 1.1.16：SDK 折线全部落在合法经度窗口；无该字段时回退主窗口
        (b.g.sdkSegs || b.g.segs).forEach(function (seg, j) {
          var id = cid + '_s' + j;
          geos.push({
            id: id, sig: sig,
            geo: { id: id, styleId: 't' + b.tier,
                   properties: { markId: cid + '_m' },
                   paths: seg.map(function (p) { return sdkLat(p.lat, p.lng); }) }
          });
        });
        marks.push({
          id: cid + '_m', sig: sig,
          geo: { id: cid + '_m', styleId: 'src' + b.tier, position: new SDK.LatLng(b.lat, b.lng),
                 properties: { markId: cid + '_m' } }
        });
        mi[cid + '_m'] = { kind: 'src', scope: scope, data: b };
      });
      // 与本机重合的来源：只画按频率着色的小圆点，不画弧，避免本机周围绕出线圈
      (data.nearPts || []).forEach(function (p, i) {
        var nid = prefix + '_n' + i, tier = p.tier || 3;
        marks.push({
          id: nid, sig: [p.lat, p.lng, tier].join('|'),
          geo: { id: nid, styleId: 'near' + tier, position: new SDK.LatLng(p.lat, p.lng),
                 properties: { markId: nid } }
        });
        mi[nid] = { kind: 'near', scope: scope, data: p };
      });
      marks.push({
        id: 'home', sig: [home.lat, home.lng].join('|'),
        geo: { id: 'home', styleId: 'home', position: new SDK.LatLng(home.lat, home.lng),
               properties: { markId: 'home' } }
      });
      mi.home = { kind: 'home', scope: scope, data: null };
      try {
        syncGeos(m.layer, name + 'Line', geos);
        syncGeos(m.marks, name + 'Mark', marks);
      } catch (e) { console.warn('TMap draw ' + name, e); }
      var total = data.list.reduce(function (a, b) { return a + b.n; }, 0);
      var txt = data.list.length + ' 个来源 · ' + num(total) + ' 次访问';
      if (data.merged) txt += ' · 合并 ' + data.merged;
      if (data.near) txt += ' · 近距 ' + data.near;
      if (data.skipped) txt += ' · 省略 ' + data.skipped;
      $(name === 'world' ? 'worldStat' : 'cnStat').textContent = txt;
    });
  }

  // ---- 地图圆点交互：点击复用「IP 来源记录」的 IP 来源画像抽屉（1.0.7） ----
  function geoId(evt) {
    var e = evt || {}, g = e.geometry || e.target || e;
    if (g && g.geometry) g = g.geometry;
    if (!g) return '';
    return String(g.id || (g.properties && (g.properties.markId || g.properties.id)) || '');
  }
  function evtLatLng(evt) {
    var e = evt || {}, g = e.geometry || e.target || {};
    var ll = e.latLng || g.position || g.latLng;
    if (!ll) return null;
    var lat, lng;
    try {
      lat = typeof ll.getLat === 'function' ? ll.getLat() : ll.lat;
      lng = typeof ll.getLng === 'function' ? ll.getLng() : ll.lng;
    } catch (x) { return null; }
    lat = Number(lat); lng = Number(lng);
    return (isFinite(lat) && isFinite(lng)) ? { lat: lat, lng: lng } : null;
  }
  // SDK 事件对象在不同版本里结构不一致：拿不到 id 时用点击经纬度就近命中
  function nearestMark(evt, name) {
    var ll = evtLatLng(evt);
    if (!ll) return null;
    var idx = S.markIndex[name] || {}, best = null, bd = 1.6;
    Object.keys(idx).forEach(function (id) {
      var it = idx[id], d;
      if (!it || !it.data) return;
      d = Math.abs(it.data.lat - ll.lat) + Math.abs(it.data.lng - ll.lng) * 0.85;
      if (d < bd) { bd = d; best = it; }
    });
    return best;
  }
  // 1.0.7：点击统一交给右侧画像抽屉，不再需要浮层定位
  function bindMarkerEvents(m, name) {
    if (!m.marks || typeof m.marks.on !== 'function') return;
    var el = $(name + 'Map');
    function resolve(evt) {
      var id = geoId(evt), idx = S.markIndex[name];
      var hit = idx[id];
      if (!hit) {
        // 弧线 geometry id 形如 c_31123_117281_b0_s0 → 回指同组来源点
        var mm = /^(.+)_b\d+_s\d+$/.exec(id);
        if (mm && idx[mm[1] + '_m']) hit = idx[mm[1] + '_m'];
      }
      if (!hit) hit = nearestMark(evt, name);
      // 本机点常与近距来源点重叠：点击位置更靠近本机时优先显示本机信息
      var ll = evtLatLng(evt), homeHit = idx.home;
      if (hit && hit.kind !== 'home' && ll && homeHit && S.home && hit.data) {
        var hd = Math.abs(ll.lat - Number(S.home.lat)) +
                 Math.abs(ll.lng - Number(S.home.lng)) * 0.85;
        var pd = Math.abs(ll.lat - hit.data.lat) +
                 Math.abs(ll.lng - hit.data.lng) * 0.85;
        if (hd < 0.2 && hd <= pd + 0.06) return homeHit;
      }
      return hit;
    }
    function onClick(evt) {
      var hit = resolve(evt);
      if (hit) openPointInfo(hit);
    }
    m.marks.on('click', onClick);
    m.marks.on('mousemove', function (evt) {
      if (!el) return;
      el.style.cursor = resolve(evt) ? 'pointer' : '';
    });
    // 细弧线本身就不好点中，允许点线弹出同一来源，提升可用性
    if (m.layer && typeof m.layer.on === 'function') {
      m.layer.on('click', onClick);
      m.layer.on('mousemove', function (evt) {
        if (!el) return;
        var id = geoId(evt), idx = S.markIndex[name], on = !!idx[id];
        if (!on) {
          var mm = /^(.+)_b\d+_s\d+$/.exec(id);
          on = !!(mm && idx[mm[1] + '_m']);
        }
        el.style.cursor = on ? 'pointer' : '';
      });
    }
  }
  // 1.0.7：点地图圆点直接复用「IP 来源记录」的「IP 来源画像」抽屉，
  // 不再弹地图内浮层，两种入口的版式与字段完全一致。
  function openPointInfo(hit) {
    if (!hit) return;
    if (hit.kind === 'home') { openHomeProfile(); return; }
    var ms = sourceMembers(hit);
    // 圆点只对应一个 IP 时，与「IP 来源记录」点行完全一致
    if (ms.length === 1) { openDetail(ms[0].ip, hit); return; }
    openGroupProfile(hit);
  }
  function kvRow(k, v) {
    return '<div class="kv"><b>' + esc(k) + '</b><span>' + esc(v) + '</span></div>';
  }
  function profileHead(big, sub, annotateIp) {
    var head = '<p class="detail-ip">' + esc(big) + '</p>' +
      '<p class="hint" style="color:var(--dim);font-size:12px">' + esc(sub) + '</p>';
    if (!annotateIp) return head;
    var cached = findOrder(annotateIp);
    // 1.1.24：输入框回归 1.1.22 的单行紧凑样式，但改成只读触发器 ——
    // 点它弹出独立「写标注」窗口，不再在画像里原地放大成多行 textarea。
    // 1.1.26：画像里只保留输入框 —— 行内「保存并加入提交单」按钮与弹窗
    // 功能重复且已失效，保存统一由写标注窗口完成。
    return '<div class="detail-ip-row"><div class="detail-ip-main">' + head + '</div>' +
      '<div class="note-inline" id="noteBox">' +
        '<div class="note-label">给这个 IP 写标注 · 点击输入框在弹窗里填写，处置完全交给外部 agent</div>' +
        '<div class="note-row">' +
          '<input type="text" id="noteInput" readonly maxlength="500" autocomplete="off" ' +
          'data-act="open-note" placeholder="点击这里写标注…" ' +
          'value="' + esc(cached ? (cached.note || '') : '') + '">' +
        '</div>' +
        '<div class="note-tip">只保存 IP 信息与你的要求，本应用<b>永远不改防火墙设置</b>、不执行任何动作。' +
        (cached ? ' <span class="note-saved">已保存 · <button type="button" class="link" data-act="open-orders">去提交单查看</button></span>' : '') +
        '</div>' +
      '</div></div>';
  }
  // 1.1.20：表格不再逐行铺路径，这里就是查看路径明细的正式入口 ——
  // 完整路径不截断（长路径换行显示）、点击可复制、给出不同路径总数。
  function pathBlock(list, total) {
    var items = list || [];
    if (!items.length) return '<div class="empty">无路径记录</div>';
    var head = total ? '<p class="hint" style="margin:0 0 8px">最近窗口内共 <b>' +
      num(total) + '</b> 条不同路径' +
      (total > items.length ? '，按次数显示前 ' + items.length + ' 条' : '') +
      '；点击任意路径可复制。</p>' : '';
    return head + '<div class="paths-full">' + items.map(function (p) {
      var full = esc(p.path);
      return '<div class="path-row" data-copy="' + full + '" title="' + full + '">' +
        '<span class="path-full">' + full + '</span>' +
        '<span class="path-n">' + num(p.n) + ' 次</span></div>';
    }).join('') + '</div>';
  }
  function bindIpSwitches(root, hit) {
    if (!root) return;
    root.onclick = function (e) {
      var back = e.target.closest('[data-act="back"]');
      if (back && hit) { openGroupProfile(hit); return; }
      var el = e.target.closest('.ip-item[data-ip]');
      if (el) openDetail(el.getAttribute('data-ip'), hit);
    };
  }
  function samePointBlock(hit, curIp) {
    var ms = sourceMembers(hit), d = hit.data || {};
    if (ms.length < 2) return '';
    return '<h3 style="font-size:13px;margin:18px 0 8px">同一圆点的其它 IP（' +
      ms.length + ' 个 · 共 ' + num(d.n || 0) + ' 次访问）</h3>' +
      '<p class="hint" style="color:var(--dim);font-size:11.5px;margin:0 0 8px">' +
      '地图按' + (hit.scope === 'overseas' ? '国家' : '省份') +
      '合并来源，点击任意 IP 切换画像</p>' +
      '<button class="profile-btn" data-act="back">← 返回「' +
      esc(sourceTitle(hit)) + '」整组画像</button>' +
      '<div id="samePointIps">' + ms.map(function (m) {
        return ipItem(m, m.ip === curIp);
      }).join('') + '</div>';
  }
  // 归属核验：展示离线库主裁决、参考源原始判定、裁决结果与置信度（1.0.8 / 1.1.30 改口径）
  // 1.1.16：Nginx combined 日志不记录目标端口。1.1.15 之前把应用自身监听
  // 端口（web_port，默认 5666）填进 port，导致本机 Web 每条都显示 5666 ——
  // 那是软件自己的端口，不是被访问的端口。现在日志没写就显示「未记录」，
  // 历史值由后端升级时一次性订正为 0；这里再兜一层旧值兼容。
  // 1.1.18：后端按证据链补录端口并带 port_src。只有当这条记录没有任何来源
  // 标注（兼容 1.1.15 前漏网的历史脏数据）、且端口恰好等于应用自身监听端口时，
  // 才兜底显示「未记录」；凡有明确来源（log_tail / log_cfg / referer 等）的端口
  // 一律显示，哪怕它数值上正好是 5666 —— 那是证据读出来的，不是硬塞进去的。
  function portLabel(p, src, portSrc) {
    var n = Number(p) || 0;
    if (n <= 0) return '未记录';
    if (!portSrc) {
      var own = Number((S.cfg || {}).web_port || 5666);
      if (src === 'local_web' && n === own) return '未记录';
    }
    return String(n);
  }

  function verifyBlock(ip, v) {
    var h = '<h3 style="font-size:13px;margin:18px 0 8px">归属核验 · 离线主裁决</h3>';
    if (!v) {
      return h + '<div class="verify-box">' +
        '<p class="hint" style="margin:0 0 10px">该 IP 尚未在线核验，当前展示的是随包离线库判定。' +
        '在线核验以离线库为主裁决，`ip.sb` 仅作参考补坐标与空缺字段，不再改动省 / 市归属。</p>' +
        '<button class="profile-btn" data-act="verify">立即在线核验</button></div>' +
        districtBlock(null);
    }
    // 1.1.15：区级信息（省 / 市 / 区县）统一进入裁决结果、每个数据源明细与画像头部
    var loc = [v.country, v.province, v.city, v.district].filter(Boolean).join(' · ');
    var l = v.local || {};
    var lloc = [l.country, l.province, l.city, l.district].filter(Boolean).join(' · ');
    h += '<div class="verify-box">' +
      '<div class="verify-top"><span class="vf-tag ' + (v.disagree ? 'warn' : 'ok') + '">' +
      (v.disagree ? '参考源有分歧' : '主裁决一致') + '</span>' +
      '<span class="vf-conf">置信度 ' + esc(CONF_NAME[v.confidence] || v.confidence || '—') +
      ' · ' + num(v.online_sources || 0) + ' 家参考源</span></div>';
    h += kvRow('裁决结果', loc || '未知') +
      kvRow('区级信息', v.district || '在线源未返回，可手工补充') +
      kvRow('本地离线库', lloc || '—') +
      kvRow('核验时间', tm(v.checked_at)) +
      kvRow('在线坐标', (v.lat != null && v.lat !== '') ? v.lat + ', ' + v.lng : '—');
    if (v.sources && v.sources.length) {
      h += '<div class="verify-src">' + v.sources.map(function (s) {
        return '<div class="vs-row"><b>' + esc(s.source || '') + '</b><span>' +
          esc([s.country, s.province, s.city, s.district].filter(Boolean).join(' · ') || '—') +
          '</span></div>';
      }).join('') + '</div>';
    }
    if (v.disagree) {
      h += '<p class="hint" style="color:var(--amber);margin:10px 0 0">' +
        '参考源与离线库判定不一致，归属仍以离线库为准。出口 IP 的归属不等于设备物理位置。</p>';
    }
    h += '<button class="profile-btn" data-act="verify">重新核验（忽略缓存）</button></div>';
    h += districtBlock(v);
    return h;
  }
  // 1.1.18：区县级归属补全入口。
  // tool.hiofd.com 的查询接口带 k/t/x/r 反爬签名、免签名返回 444，不是公开 API，
  // 因此不内置后台抓取。改为两条可用路径：
  //   ① 「站内查询」直接调用本应用已有的多源在线核验，在画像里展示逐源结果；
  //   ② 「在线校验」自动复制 IP 后打开查询页，人工核对再回填。
  function districtBlock(v) {
    v = v || {};
    return '<div class="verify-box" style="margin-top:10px">' +
      '<p class="hint" style="margin:0 0 8px">区县级归属：免费接口覆盖不全，自动补充通常为空。' +
      '可点「站内查询」直接在软件里用在线源核对，或点「在线校验」自动复制 IP 后到 ' +
      'tool.hiofd.com 查，把结果里的「区」填到下面保存。' +
      '该站接口带反爬签名、不是公开 API，本应用不内置自动抓取；' +
      '也可以在设置里填一个自己的区级接口自动补全。</p>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px">' +
      '<button class="profile-btn" data-act="incheck">站内查询（在线源直接核对）</button>' +
      '<button class="profile-btn" data-act="extcheck">在线校验（打开查询页并复制 IP）</button>' +
      '<button class="profile-btn" data-act="copyip">仅复制 IP</button></div>' +
      '<div id="inlineCheckResult" style="margin-bottom:8px"></div>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">' +
      '<input id="districtInput" type="text" maxlength="40" placeholder="例如：蜀山区" ' +
      'value="' + esc(v.district || '') + '" style="flex:1;min-width:160px;background:var(--panel-2);' +
      'border:1px solid var(--line);border-radius:8px;padding:7px 9px;color:inherit">' +
      '<button class="profile-btn" data-act="district">保存区级信息</button></div></div>';
  }
  // ---- 1.1.18 · 剪贴板可靠复制 ----
  // fnOS 内嵌 WebView / 页面未聚焦时 navigator.clipboard.writeText 会被拒绝，
  // 1.1.16 只能静默吞掉 rejection，用户点了「在线校验」却什么都没复制。
  // 这里补一层 execCommand 降级，并把成功 / 失败都明确 toast 出来。
  function legacyCopy(text) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      try { ta.setSelectionRange(0, String(text).length); } catch (e) {}
      var ok = document.execCommand('copy');
      if (ta.parentNode) ta.parentNode.removeChild(ta);
      return !!ok;
    } catch (e) { return false; }
  }
  function copyTextRobust(text, cb) {
    var text = String(text || '');
    var done = false;
    function finish(ok) {
      if (done) return;
      done = true;
      if (cb) cb(ok);
    }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        var cp = navigator.clipboard.writeText(text);
        if (cp && cp.then) {
          // 1.1.22：部分内嵌 WebView / 无头环境里 clipboard Promise 会长期
          // pending（既不 resolve 也不 reject），补一个 600ms 兜底走旧复制，
          // 避免「复制读取提示词」点了没有任何反馈。finish 保证只回调一次。
          var fallback = setTimeout(function () { finish(legacyCopy(text)); }, 600);
          cp.then(function () {
            clearTimeout(fallback); finish(true);
          }, function () {
            clearTimeout(fallback); finish(legacyCopy(text));
          });
          return;
        }
      }
    } catch (x) {}
    if (cb) cb(legacyCopy(text));
  }

  // 画像抽屉统一事件：IP 切换 / 返回整组 / 在线核验
  function bindDetailEvents(root, ip, groupHit) {
    if (!root) return;
    root.onclick = function (e) {
      // 1.1.24：点只读标注输入框 -> 弹出独立「写标注」窗口（放在 INPUT 拦截之前）
      if (e.target && e.target.id === 'noteInput') { openNoteDialog(ip); return; }
      // 1.1.24：其余表单控件（含写标注窗口里的 textarea）不参与抽屉内点击委托
      if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return;
      // 1.1.26：画像里已无行内「保存并加入提交单」按钮，保存统一由写标注窗口完成。
      var oo = e.target.closest('[data-act="open-orders"]');
      if (oo) { openOrders(); return; }
      var back = e.target.closest('[data-act="back"]');
      if (back && groupHit) { openGroupProfile(groupHit); return; }
      var el = e.target.closest('.ip-item[data-ip]');
      if (el) { openDetail(el.getAttribute('data-ip'), groupHit); return; }
      // 1.1.18：window.open 必须在用户点击的同步调用栈里，否则会被浏览器拦截；
      // 复制走 Promise 降级（clipboard API → execCommand），结果明确反馈。
      var ec = e.target.closest('[data-act="extcheck"]');
      if (ec) {
        var w = window.open('https://tool.hiofd.com/ip/', '_blank', 'noopener');
        copyTextRobust(ip, function (ok) {
          toast(ok
            ? ('已复制 ' + ip + '，粘贴到查询框；查到的「区」填到下面保存')
            : ('复制未成功，请手动复制 IP：' + ip + '；查询页 ' +
               (w ? '已打开' : 'tool.hiofd.com/ip/')));
        });
        return;
      }
      var ci = e.target.closest('[data-act="copyip"]');
      if (ci) {
        copyTextRobust(ip, function (ok) {
          toast(ok ? ('已复制 ' + ip) : ('复制未成功，请手动复制：' + ip));
        });
        return;
      }
      // 1.1.18：站内查询 —— 复用后端已有的多源在线核验，不依赖第三方反爬页面。
      var ic = e.target.closest('[data-act="incheck"]');
      if (ic) {
        var box = root.querySelector('#inlineCheckResult');
        ic.disabled = true;
        if (box) box.innerHTML = '<p class="hint" style="margin:0">正在用在线源核对 ' +
          esc(ip) + '（约 2–8 秒）…</p>';
        api('api/geo/verify?ip=' + encodeURIComponent(ip) + '&force=1').then(function (r) {
          if (!r.ok) throw new Error(r.msg || '查询失败');
          var vf = r.verification || {}, g = r.geo || {};
          var srcs = vf.sources || [];
          var lines = srcs.map(function (s) {
            var loc = [s.country, s.province, s.city, s.district]
              .filter(function (x) { return x && x !== '0'; }).join(' · ') || '—';
            return '<div class="src-line"><span>' + esc(s.source || '在线源') + ' · ' +
              esc(loc) + '</span><span>' + esc(s.isp || '') + '</span></div>';
          }).join('');
          var verdict = [g.country, g.province, g.city, g.district]
            .filter(function (x) { return x && x !== '0'; }).join(' · ') || '—';
          if (box) box.innerHTML = '<div class="about-box">' +
            '<p class="hint" style="margin:0 0 6px"><b>站内查询结果</b> · 裁决：' +
            esc(verdict) + ' · 在线源 ' + num(vf.online_sources || 0) + ' 家 · 置信度 ' +
            esc(CONF_NAME[vf.confidence] || '—') + '</p>' +
            (lines || '<p class="hint" style="margin:0">在线源未返回逐源明细，' +
              '可点「在线校验」到网页人工核对。</p>') +
            '<p class="hint" style="margin:6px 0 0">在线源多数不返回区县；' +
            '把查到的「区」填进下面输入框后点「保存区级信息」即可固化。</p></div>';
          toast('站内查询完成');
          ic.disabled = false;
        }).catch(function (er) {
          if (box) box.innerHTML = '<p class="hint" style="margin:0;color:var(--amber)">' +
            '查询失败：' + esc(er.message) + '。可点「在线校验」到网页人工核对。</p>';
          ic.disabled = false;
        });
        return;
      }
      // 1.1.15：手工补充区级信息，写 geo_cache 并回写历史事件
      var di = e.target.closest('[data-act="district"]');
      if (di) {
        var box = root.querySelector('#districtInput');
        var val = box ? String(box.value || '').trim().slice(0, 40) : '';
        di.disabled = true;
        api('api/geo/district', 'POST', { ip: ip, district: val }).then(function (r) {
          if (!r.ok) throw new Error(r.msg || '保存失败');
          toast(val ? '区级信息已保存：' + val : '已清空区级信息');
          openDetail(ip, groupHit);
        }).catch(function (er) {
          toast('保存失败：' + er.message);
          di.disabled = false;
        });
        return;
      }
      var v = e.target.closest('[data-act="verify"]');
      if (!v) return;
      v.disabled = true; v.textContent = '核验中…（约 2–8 秒）';
      api('api/geo/verify?ip=' + encodeURIComponent(ip) + '&force=1').then(function (r) {
        if (!r.ok) {
          toast(r.msg || '核验失败'); v.disabled = false; v.textContent = '立即在线核验';
          return;
        }
        toast('核验完成：' + (r.geo.province || r.geo.country) +
          ' · ' + num(r.verification.online_sources) + ' 家在线源');
        openDetail(ip, groupHit);
        loadHeavy();
      }).catch(function (er) {
        toast('核验失败：' + er.message);
        v.disabled = false; v.textContent = '重新核验';
      });
    };
  }
  function sourceMembers(hit) {
    var ms = ((hit.data && hit.data.members) || []).slice();
    ms.sort(function (a, b) { return (b.n - a.n) || (b.last_ts - a.last_ts); });
    return ms;
  }
  function sourceTitle(hit) {
    return (hit.data && hit.data.region) ||
      (hit.scope === 'overseas' ? '未知国家 / 地区' : '未知省份');
  }
  function loadGroup(hit) {
    if (hit.detail !== undefined) return Promise.resolve(hit.detail);
    var ips = sourceMembers(hit).map(function (m) { return m.ip; }).filter(function (x) { return x; });
    if (!ips.length) { hit.detail = null; return Promise.resolve(null); }
    return api('api/group', 'POST', { ips: ips, rng: 'all', limit: 60 }).then(function (r) {
      hit.detail = r.data || null;
      return hit.detail;
    });
  }
  function geoText(m) {
    // 1.1.15：整组画像里的每个 IP 也展示到区级，和「IP 来源记录」口径一致
    return [m.country, m.province, m.city, m.district, m.isp]
      .filter(function (x) { return x && x !== '0'; }).join(' · ');
  }
  function ipItem(m, cur) {
    var loc = geoText(m);
    return '<div class="ip-item' + (cur ? ' cur' : '') + '" data-ip="' + esc(m.ip) +
      '" title="' + esc(loc || m.ip) + '">' +
      '<span class="ip">' + esc(m.ip) +
      (loc ? '<small class="ip-loc">' + esc(loc) + '</small>' : '') + '</span>' +
      '<span class="badge ' + esc(m.verdict || 'normal') + '">' +
      esc(VERDICT_NAME[m.verdict] || '记录') + '</span>' +
      '<span class="t">' + num(m.n) + ' 次<br>' + tm(m.last_ts) + '</span></div>';
  }
  // 整组画像：与单 IP 画像共用同一个抽屉和版式，字段换成按省/国家合并后的聚合值
  function openGroupProfile(hit) {
    var title = sourceTitle(hit), d = hit.data || {}, ms = sourceMembers(hit);
    $('detailTitle').textContent = 'IP 来源画像';
    openDrawer('detailDrawer');
    $('detailBody').innerHTML = '<div class="empty">正在读取该来源点的画像…</div>';
    loadGroup(hit).then(function (g) {
      g = g || {};
      var scopeName = hit.scope === 'overseas' ? '境外来源' : '中国境内';
      var rows = [
        ['来源地区', title], ['范围', scopeName],
        ['坐标', Number(d.lat).toFixed(3) + ', ' + Number(d.lng).toFixed(3)],
        ['累计访问', num(g.total || d.n || 0) + ' 次'],
        ['来源 IP', ms.length + ' 个'],
        ['首次 / 末次', tm(g.first_ts) + ' → ' + tm(g.last_ts)],
        ['最近判定', VERDICT_NAME[d.verdict] || d.verdict || '正常访问']
      ];
      var h = profileHead(title, scopeName + ' · 地图按' +
        (hit.scope === 'overseas' ? '国家' : '省份') + '合并的圆点') +
        '<div style="margin:14px 0">' + rows.map(function (x) { return kvRow(x[0], x[1]); }).join('') + '</div>';
      h += '<h3 style="font-size:13px;margin:18px 0 8px">来源 IP 明细（点击查看单 IP 画像）</h3>' +
        '<div id="groupIps">' + (ms.map(function (m) { return ipItem(m); }).join('') ||
          '<div class="empty">无 IP 明细</div>') + '</div>';
      h += '<h3 style="font-size:13px;margin:18px 0 8px">路径明细 · 高频路径</h3>' +
        '<p class="hint" style="margin:0 0 8px">表格已把同秒同 IP 的请求合并，这里查看该来源点的路径明细。</p>' +
        pathBlock(g.top_paths);
      h += '<h3 style="font-size:13px;margin:18px 0 8px">归属核验 · 离线主裁决</h3>' +
        '<div class="verify-box"><p class="hint" style="margin:0">本圆点合并了 ' +
        ms.length + ' 个 IP。点上方任意 IP 可查看该 IP 的归属核验结果：' +
        '离线库主裁决、参考源原始判定与置信度。</p></div>';
      h += '<h3 style="font-size:13px;margin:18px 0 8px">最近 20 条动作（精确到秒）</h3>' +
        ((g.recent || []).slice(0, 20).map(function (x) {
          return '<div class="src-line"><span>' + tm(x.ts) + ' · ' + protoChip(x.proto) +
            ' · ' + esc(x.ip) + ' · ' +
            esc(VERDICT_NAME[x.verdict] || x.verdict || '记录') + ' · ' +
            esc(x.action || x.path || '连接') + '</span><span>' + portLabel(x.port, x.source) + '</span></div>';
        }).join('') || '<div class="empty">暂无连接记录</div>');
      $('detailBody').innerHTML = h;
      var box = $('groupIps');
      if (box) bindIpSwitches(box.parentNode, hit);
    }).catch(function (e) {
      $('detailBody').innerHTML = '<div class="empty">' + esc(e.message) + '</div>';
    });
  }
  // 本机点：同一个「IP 来源画像」抽屉，展示出口 IP 与定位信息
  function openHomeProfile() {
    var c = S.cfg || {}, ip = c.home_ip || '—';
    $('detailTitle').textContent = 'IP 来源画像';
    openDrawer('detailDrawer');
    var rows = [
      ['标签', '本机 · ' + (c.home_label || '本机')],
      ['出口 IP', ip], ['出口归属', c.home_geo || '—'],
      ['坐标', Number(S.home.lat).toFixed(4) + ', ' + Number(S.home.lng).toFixed(4)],
      ['定位方式', c.home_source === 'manual' ? '手动填写' : (c.home_source || '自动定位')],
      ['代理出口', c.proxy_ip || '—'], ['代理归属', c.proxy_geo || '—'],
      ['定位时间', c.home_locate_at ? tm(c.home_locate_at) : '—']
    ];
    $('detailBody').innerHTML = profileHead(ip, '本机出口 · 所有弧线的汇聚中心') +
      '<div style="margin:14px 0">' + rows.map(function (x) { return kvRow(x[0], x[1]); }).join('') + '</div>' +
      '<h3 style="font-size:13px;margin:18px 0 8px">说明</h3>' +
      '<div class="src-line"><span>点击境内 / 境外来源圆点，可查看对应 IP 的完整画像与逐条连接时间</span></div>';
  }

  // ---- 地图：无 key 时的坐标散点示意（不绘制任何国界/海岸线） ----
  function setupCanvas(id) {
    var c = $(id); if (!c) return null;
    var dpr = window.devicePixelRatio || 1;
    var w = c.clientWidth || 600, h = c.clientHeight || 340;
    var pw = Math.round(w * dpr), ph = Math.round(h * dpr);
    // 只有尺寸真的变了才重置画布（重置会清空并触发一次昂贵的全量重绘）
    if (c.width !== pw || c.height !== ph) { c.width = pw; c.height = ph; S.bg = {}; }
    var ctx = c.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { c: c, ctx: ctx, w: w, h: h, dpr: dpr };
  }
  function proj(lat, lng, b, w, h) {
    return [((lng - b.lngMin) / (b.lngMax - b.lngMin)) * w,
            ((b.latMax - lat) / (b.latMax - b.latMin)) * h];
  }
  // 1.1.15 修复「境外全球视图长弧线中断」——等距投影侧：
  // 旧窗口固定 [-180,180]，跨国际日期变更线的长弧被 wrapSegs 切成两半，
  // 分别落在画布最左 / 最右，中间隔着整幅地图，看起来就是线画到一半断了。
  // 改成「以本机经度为中心的 360° 窗口」后，每条弧按最短经度差展开到同一个
  // 连续区间里，被切开的两段在窗口内自然首尾相接，整条弧一笔画完。
  // 本机也正好落在画布中央，与「所有来源汇聚到本机」的放射语义一致。
  function worldCenteredBounds(home) {
    var c = Number(home && home.lng) || 114.06;
    return { latMin: WORLD_BOUNDS.latMin, latMax: WORLD_BOUNDS.latMax,
             lngMin: c - 180, lngMax: c + 180 };
  }
  function unwrapTo(lng, center) {
    var x = Number(lng) || 0, c = Number(center) || 0;
    while (x - c > 180) x -= 360;
    while (x - c < -180) x += 360;
    return x;
  }
  function canvasBg(which, w, h, dpr, b) {
    // 2.0.0 返工：无 KEY 降级底图改成「卫星影像质感」的纯抽象背景。
    // 合规红线：这里只有深色渐变 + 程序化颗粒，绝不自绘陆地 / 海岸线 /
    // 国界 / 省界 / 经纬网，也绝不拉取任何外部影像瓦片或境外影像源。
    // 旧版虚线经纬网看起来像「轮廓图」，用户明确要求去掉，故整段删除。
    var key = w + 'x' + h + '@' + dpr + '#S' + which;
    var cached = S.bg[which];
    if (cached && cached.key === key) return cached.img;
    var off = document.createElement('canvas');
    off.width = Math.round(w * dpr); off.height = Math.round(h * dpr);
    var c = off.getContext('2d');
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    // 深空底：径向冷光 + 纵向渐暗，模拟夜间遥感影像的整体色调
    var bg = c.createRadialGradient(w * 0.52, h * 0.44, 0,
                                   w * 0.52, h * 0.44, Math.max(w, h) * 0.78);
    bg.addColorStop(0, '#123252'); bg.addColorStop(0.55, '#0a1e38');
    bg.addColorStop(1, '#050e1e');
    c.fillStyle = bg; c.fillRect(0, 0, w, h);
    // 两道极淡的斜向光带，制造影像层次感（不含任何地理轮廓）
    var band = c.createLinearGradient(0, 0, w, h);
    band.addColorStop(0, 'rgba(90,160,220,0)');
    band.addColorStop(0.42, 'rgba(90,160,220,.055)');
    band.addColorStop(0.58, 'rgba(60,120,190,.035)');
    band.addColorStop(1, 'rgba(90,160,220,0)');
    c.fillStyle = band; c.fillRect(0, 0, w, h);
    // 程序化细颗粒：固定种子，保证每帧复用同一张离屏图、不闪烁
    var seed = 20200200 + (which === 'cn' ? 7 : 0);
    function rnd() { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; }
    var n = Math.min(1400, Math.round(w * h / 260));
    for (var i = 0; i < n; i++) {
      var x = rnd() * w, y = rnd() * h, r = rnd() * 1.1 + 0.25;
      c.globalAlpha = 0.05 + rnd() * 0.16;
      c.fillStyle = rnd() > 0.22 ? '#9dc6ee' : '#4d86bd';
      c.beginPath(); c.arc(x, y, r, 0, Math.PI * 2); c.fill();
    }
    c.globalAlpha = 1;
    // 说明文字：明确这只是抽象示意背景，不是真实地图影像
    c.fillStyle = 'rgba(150,180,215,.42)'; c.font = '10px sans-serif';
    c.fillText('卫星风格坐标散点示意 · 非地图影像 · 未绘制任何边界', 10, 16);
    S.bg[which] = { key: key, img: off };
    return off;
  }
  function drawCanvas(which) {
    var isWorld = which === 'world';
    var s = setupCanvas(isWorld ? 'worldCanvas' : 'cnCanvas');
    if (!s) return;
    var home = { lat: Number(S.home.lat) || 22.54, lng: Number(S.home.lng) || 114.06 };
    // 1.1.15：全球散点视图以本机经度为中心，长弧不再在 ±180° 处断成两截
    var ctx = s.ctx, w = s.w, h = s.h;
    var b = isWorld ? worldCenteredBounds(home) : CN_BOUNDS;
    var picks = [];
    ctx.clearRect(0, 0, w, h);
    ctx.drawImage(canvasBg(which, w, h, s.dpr, b), 0, 0, w, h);

    var scope = isWorld ? 'overseas' : 'cn';
    var data = (isWorld ? S.arcData.world : S.arcData.cn) || emptyArcs();
    var hp = proj(home.lat, home.lng, b, w, h);
    var t = (S.anim % 100) / 100;

    // 按频率档分组描边：整条弧线统一单色，颜色只表达连接频率
    ARC_TIER_IDS.forEach(function (tier) {
      var group = data.list.filter(function (p) { return p.tier === tier; });
      if (!group.length) return;
      ctx.beginPath();
      group.forEach(function (p) {
        p.g.segs.forEach(function (seg) {
          seg.forEach(function (q, i) {
            var xy = proj(q.lat, unwrapTo(q.lng, home.lng), b, w, h);
            if (i === 0) ctx.moveTo(xy[0], xy[1]); else ctx.lineTo(xy[0], xy[1]);
          });
        });
      });
      ctx.globalAlpha = ARC_TIER[tier].a;
      ctx.strokeStyle = ARC_HEAT[tier - 1]; ctx.lineWidth = ARC_TIER[tier].cw;
      ctx.lineJoin = 'round'; ctx.lineCap = 'round'; ctx.stroke();
    });
    ctx.globalAlpha = 1;

    // 流动光点：所有点合成一个 path，一次 fill
    if (S.arcAnimate && data.list.length) {
      ctx.beginPath();
      data.list.forEach(function (p) {
        var q = bezierAt(p.g, t);
        // 1.1.15：与描边使用同一套「本机中心窗口」展开，光点不会瞬移到画布另一端
        var xy = proj(q.lat, unwrapTo(q.lng, home.lng), b, w, h);
        ctx.moveTo(xy[0] + 1.8, xy[1]);
        ctx.arc(xy[0], xy[1], 1.8, 0, Math.PI * 2);
      });
      ctx.globalAlpha = 0.9; ctx.fillStyle = '#fff'; ctx.fill(); ctx.globalAlpha = 1;
    }

    // 来源点：光晕与实心点各按档批量绘制
    ARC_TIER_IDS.forEach(function (tier) {
      var group = data.list.filter(function (p) { return p.tier === tier; });
      if (!group.length) return;
      function ring(extra, mul, alpha) {
        ctx.beginPath();
        group.forEach(function (p) {
          var sp = proj(p.lat, unwrapTo(p.lng, home.lng), b, w, h);
          var r = Math.min(7, 2.5 + Math.log(1 + p.n) * 1.4) * mul + extra;
          ctx.moveTo(sp[0] + r, sp[1]);
          ctx.arc(sp[0], sp[1], r, 0, Math.PI * 2);
        });
        ctx.globalAlpha = alpha; ctx.fillStyle = ARC_HEAT[tier - 1];
        ctx.fill(); ctx.globalAlpha = 1;
      }
      ring(4, 1, 0.22);
      ring(0, 0.55, 1);
    });
    // 记录命中区域：散点模式没有 SDK 事件，靠坐标命中实现同样的点击交互
    data.list.forEach(function (p) {
      var sp = proj(p.lat, unwrapTo(p.lng, home.lng), b, w, h);
      picks.push({ x: sp[0], y: sp[1], r: Math.min(11, 4 + Math.log(1 + p.n) * 1.4),
                   kind: 'src', scope: scope, data: p });
    });
    (data.nearPts || []).forEach(function (p) {
      var np = proj(p.lat, unwrapTo(p.lng, home.lng), b, w, h);
      ctx.globalAlpha = 0.85; ctx.fillStyle = ARC_HEAT[(p.tier || 3) - 1];
      ctx.beginPath(); ctx.arc(np[0], np[1], 2.6, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = 1;
      picks.push({ x: np[0], y: np[1], r: 8, kind: 'near', scope: scope, data: p });
    });
    // 本机：多层光晕，明确所有弧线的汇聚中心
    ctx.fillStyle = '#3b82f6'; ctx.globalAlpha = .16;
    ctx.beginPath(); ctx.arc(hp[0], hp[1], 15, 0, Math.PI * 2); ctx.fill();
    ctx.globalAlpha = .32;
    ctx.beginPath(); ctx.arc(hp[0], hp[1], 8, 0, Math.PI * 2); ctx.fill();
    ctx.globalAlpha = 1; ctx.fillStyle = '#60a5fa';
    ctx.beginPath(); ctx.arc(hp[0], hp[1], 4, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#fff';
    ctx.beginPath(); ctx.arc(hp[0], hp[1], 1.6, 0, Math.PI * 2); ctx.fill();
    ctx.font = '11px sans-serif'; ctx.fillStyle = '#cfe2ff';
    ctx.fillText(S.home.label || '本机', hp[0] + 9, hp[1] - 7);
    picks.push({ x: hp[0], y: hp[1], r: 14, kind: 'home', scope: scope,
                 data: { lat: home.lat, lng: home.lng } });
    S.hit[isWorld ? 'world' : 'cn'] = picks;
    var total = data.list.reduce(function (a, p2) { return a + p2.n; }, 0);
    var txt = data.list.length + ' 个来源 · ' + num(total) + ' 次访问';
    if (data.merged) txt += ' · 合并 ' + data.merged;
    if (data.near) txt += ' · 近距 ' + data.near;
    if (data.skipped) txt += ' · 省略 ' + data.skipped;
    $(isWorld ? 'worldStat' : 'cnStat').textContent = txt;
    if (!S.tmapReady) {
      $(isWorld ? 'worldNote' : 'cnNote').textContent = S.tmapState === 'error'
        ? '底图未显示：' + S.tmapError
        : '卫星风格坐标散点示意 · 非地图影像（未绘制任何边界）；配置密钥后切换为官方合规卫星底图';
    }
  }
  function canvasHit(which, ev) {
    var c = $(which + 'Canvas'); if (!c) return null;
    var r = c.getBoundingClientRect();
    var x = ev.clientX - r.left, y = ev.clientY - r.top, best = null, bd = 1e9;
    (S.hit[which] || []).forEach(function (p) {
      var d = Math.sqrt((x - p.x) * (x - p.x) + (y - p.y) * (y - p.y));
      if (d <= p.r + 7 && d < bd) { bd = d; best = p; }
    });
    return best;
  }
  function bindCanvasPicks() {
    ['world', 'cn'].forEach(function (name) {
      var c = $(name + 'Canvas'); if (!c) return;
      c.addEventListener('click', function (e) {
        var hit = canvasHit(name, e);
        if (hit) openPointInfo(hit);
      });
      c.addEventListener('mousemove', function (e) {
        c.style.cursor = canvasHit(name, e) ? 'pointer' : '';
      });
    });
  }
  // ================= 2.0.0 B4 · 地图动效覆盖层 =================
  // 背景：无 KEY 的 Canvas 降级路径一直有「沿弧线流动的白色光点」，
  // 但配了 KEY 接了合规底图后，弧线是静态折线图层，光点就消失了。
  // 这里在三个地图容器上各叠一张透明 canvas，统一负责：
  //   ① 有 KEY 路径补回流动光点（两条路径视觉一致）；
  //   ② 以出口 IP / 本机为中心的一波波雷达波纹（伪 3D 神识扫描）；
  //   ③ 每 5 秒渐显一批新坐标点，只在覆盖层绘制、绝不刷新底图几何。
  // 合规：覆盖层只画应用自有数据（IP 散点 / 连线 / 本机装饰环），
  // 不绘制任何国界、海岸线或行政区划边界，边界一律以官方底图为准。
  var FX = {
    IDS: { world: 'worldFx', cn: 'cnFx', geo: 'geoFx' },
    REVEAL_MS: 5000,   // 每 5 秒投放一批新坐标点
    REVEAL_N: 5,       // 每批最多 5 个
    LIFE_MS: 4200,     // 单个点存活时长
    MAX_DOTS: 240,     // 光点数量上限，控制每帧成本
    RINGS: 3           // 同时存在的雷达波纹数
  };
  function fxCanvas(which) { return $(FX.IDS[which]); }
  function fxSetup(which) {
    var c = fxCanvas(which); if (!c) return null;
    var dpr = window.devicePixelRatio || 1;
    var w = c.clientWidth || 600, h = c.clientHeight || 340;
    var pw = Math.round(w * dpr), ph = Math.round(h * dpr);
    // 只有尺寸真的变了才重置画布（重置会清空并触发一次全量重绘）
    if (c.width !== pw || c.height !== ph) { c.width = pw; c.height = ph; }
    var ctx = c.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { c: c, ctx: ctx, w: w, h: h, dpr: dpr };
  }
  // GCJ-02 经纬度 → 当前激活图层的容器像素。
  // 有 KEY 时优先用各引擎原生投影（随 SDK 缩放 / 平移一起移动）；
  // 任一环节不支持或抛错，回退到与 Canvas 降级路径一致的等距投影。
  function fxProject(which, lat, lng, s, home) {
    var b = which === 'cn' ? CN_BOUNDS : worldCenteredBounds(home);
    var fallback = proj(lat, unwrapTo(lng, home.lng), b, s.w, s.h);
    if (!S.tmapReady) return fallback;
    try {
      var m = which === 'geo' ? S.geoMap : (which === 'cn' ? S.cn : S.world);
      var eng = mapEngineOf(providerById(S.mapProvider));
      var p = eng.project ? eng.project(nativeOf(m), lat, lng) : null;
      if (p && isFinite(p.x) && isFinite(p.y)) return [p.x, p.y];
    } catch (e) {}
    return fallback;
  }
  // 2.0.0 返工：每帧清掉非激活图层的 fx canvas 旧帧。
  // 原实现只清当前激活层，切换 mapMode 或底图加载后，其它层的
  // 最后一帧会残留在 z-index 1103 的覆盖层上，视觉上「卡在上方图层」。
  function fxClearInactive(which) {
    Object.keys(FX.IDS).forEach(function (k) {
      if (k === which) return;
      var c = fxCanvas(k); if (!c) return;
      try { c.getContext('2d').clearRect(0, 0, c.width, c.height); } catch (e) {}
    });
  }
  function fxActive() { return MAP_MODE_LAYERS[S.mapMode] ? S.mapMode : 'world'; }
  function fxData(which) {
    if (which === 'geo') return (S.geoData && S.geoData.regions) || [];
    return ((which === 'cn' ? S.arcData.cn : S.arcData.world) || emptyArcs()).list;
  }
  // 每 5 秒从当前视图数据里挑一批「新坐标点」，按年龄渐显 → 停留 → 渐隐。
  function fxPickReveal(which, now) {
    if (!S.fx.revealOn) { S.fx.reveal = []; return; }
    if (now - (S.fx.revealAt || 0) < FX.REVEAL_MS) return;
    S.fx.revealAt = now;
    var list = fxData(which), picks = [];
    for (var i = 0; i < list.length && picks.length < FX.REVEAL_N; i++) {
      var r = list[(S.fx.cursor + i) % list.length];
      if (r && r.lat != null && r.lng != null) picks.push({ lat: r.lat, lng: r.lng, born: now });
    }
    S.fx.cursor = (S.fx.cursor + FX.REVEAL_N) % Math.max(1, list.length);
    S.fx.reveal = (S.fx.reveal || []).filter(function (p) { return now - p.born < FX.LIFE_MS; })
      .concat(picks).slice(-FX.MAX_DOTS);
  }
  // 2.0.0 二次返工：流动光点必须严格落在 SDK 折线上。
  // 旧实现用 bezierAt(g, t) 重新按「本机中心窗口」算经纬度，而 SDK 折线
  // 用的是 worldSegs(full) 归一化到 [-180,180] 的采样点：跨日期变更线的
  // 长弧两者经度窗口差 360°（实测美国西岸→中国 bezierAt 低到 -245.9°，
  // 21 个采样点里 11 个超出合法窗口），再交给 SDK 投影就会甩到线外 ——
  // 用户反馈「光球移动有了，但是位置不对，不在线上」。
  // 这里直接复用 SDK 折线提交给 geometry 的同一批采样点，按 t 线性插值，
  // 经纬度与 SDK 折线顶点完全一致，光点必然落在弧线上。
  function fxArcPoint(g, t) {
    var segs = (g && g.sdkSegs && g.sdkSegs.length) ? g.sdkSegs
             : (g && g.segs && g.segs.length) ? g.segs : null;
    if (!segs) return null;
    var pts = [], i, j, s;
    for (i = 0; i < segs.length; i++) {
      s = segs[i];
      for (j = 0; j < s.length; j++) pts.push(s[j]);
    }
    if (!pts.length) return null;
    if (pts.length === 1) return { lat: pts[0].lat, lng: pts[0].lng };
    var f = Math.max(0, Math.min(1, t)) * (pts.length - 1);
    var lo = Math.floor(f), hi = Math.min(pts.length - 1, lo + 1), u = f - lo;
    // seam 两侧经度差 360° 的相邻点不插值，直接取端点，避免光点横穿整幅地图
    if (Math.abs(pts[hi].lng - pts[lo].lng) > 180) u = 0;
    return { lat: pts[lo].lat + (pts[hi].lat - pts[lo].lat) * u,
             lng: pts[lo].lng + (pts[hi].lng - pts[lo].lng) * u };
  }
  // 2.0.0 二次返工：SDK 路径光点只走引擎原生投影。
  // fxProject() 的等距 fallback 与 SDK 底图的墨卡托投影不是同一坐标系，
  // 一旦原生投影不可用，用它画出来的光点必然错位；此时宁可不画，也不
  // 在地图上线外乱跑。投影来源写到 body dataset，供诊断 / 验收排查。
  function fxSdkPoint(which, lat, lng, s, home) {
    if (!S.tmapReady) return null;
    try {
      var m = which === 'geo' ? S.geoMap : (which === 'cn' ? S.cn : S.world);
      var eng = mapEngineOf(providerById(S.mapProvider));
      var p = eng.project ? eng.project(nativeOf(m), lat, lng) : null;
      if (p && isFinite(p.x) && isFinite(p.y)) {
        if (S.fxProjMode !== 'native') {
          S.fxProjMode = 'native';
          try { document.body.dataset.fxProjMode = 'native'; } catch (e) {}
        }
        return [p.x, p.y];
      }
    } catch (e) {}
    if (S.fxProjMode !== 'off') {
      S.fxProjMode = 'off';
      try { document.body.dataset.fxProjMode = 'off'; } catch (e) {}
    }
    return null;
  }
  function drawFx() {
    if (!S.fx || S.fx.on === false) return;
    var which = fxActive(), s = fxSetup(which);
    if (!s) return;
    var ctx = s.ctx, now = Date.now();
    var home = { lat: Number(S.home.lat) || 22.54, lng: Number(S.home.lng) || 114.06 };
    fxClearInactive(which);
    ctx.clearRect(0, 0, s.w, s.h);
    // ① 雷达波纹：以出口 IP / 本机为中心，一圈圈向外扩散（椭圆压扁做伪 3D）。
    //    2.0.0 二次返工：按用户要求「雷达效果直接去除，回滚到之前的效果」，
    //    整块还原为 B6 之前（GA）的三层椭圆波纹，移除返工时新增的全部
    //    附加装饰（辉光 / 扇形 / 亮弧 / 刻度 / 准星）。仍只画应用自有装饰，
    //    不绘制任何国界、海岸线或行政区划边界，边界一律以官方底图为准。
    if (S.fx.scan !== false) {
      var hp = fxProject(which, home.lat, home.lng, s, home);
      var span = Math.min(s.w, s.h) * 0.55;
      for (var k = 0; k < FX.RINGS; k++) {
        var ph = ((now / 2600) + k / FX.RINGS) % 1;
        var r = 8 + span * ph, a = (1 - ph) * 0.42;
        if (a <= 0.01) continue;
        ctx.globalAlpha = a; ctx.strokeStyle = '#5db8ff'; ctx.lineWidth = 1.4;
        ctx.beginPath(); ctx.ellipse(hp[0], hp[1], r, r * 0.62, 0, 0, Math.PI * 2); ctx.stroke();
        ctx.globalAlpha = a * 0.5;
        ctx.beginPath(); ctx.ellipse(hp[0], hp[1], r * 0.72, r * 0.45, 0, 0, Math.PI * 2); ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }
    // ② 流动光点：只补「有 KEY」的 SDK 路径（无 KEY 时 Canvas 已画，避免双份）。
    //    2.0.0 二次返工：光点取 SDK 折线的同一批采样点（fxArcPoint）并走
    //    引擎原生投影（fxSdkPoint），严格贴合弧线、不会甩到线外。
    //    所有点合成一个 path 一次 fill，不逐点 fill、不重建任何 SDK geometry。
    if (S.arcAnimate && S.tmapReady && which !== 'geo') {
      var data = (which === 'cn' ? S.arcData.cn : S.arcData.world) || emptyArcs();
      var t = (S.anim % 100) / 100, n = 0;
      ctx.beginPath();
      data.list.forEach(function (p) {
        if (n++ >= FX.MAX_DOTS || !p.g) return;
        var q = fxArcPoint(p.g, t);
        if (!q) return;
        var xy = fxSdkPoint(which, q.lat, q.lng, s, home);
        if (!xy) return;
        ctx.moveTo(xy[0] + 2.2, xy[1]);
        ctx.arc(xy[0], xy[1], 2.2, 0, Math.PI * 2);
      });
      ctx.globalAlpha = 0.92; ctx.fillStyle = '#eaf6ff'; ctx.fill(); ctx.globalAlpha = 1;
    }
    // ③ 5 秒新坐标点：只在覆盖层渐显渐隐，不新增 / 不删除任何底图几何
    fxPickReveal(which, now);
    (S.fx.reveal || []).forEach(function (p) {
      var age = (now - p.born) / FX.LIFE_MS;
      if (age < 0 || age > 1) return;
      var alpha = age < 0.18 ? age / 0.18 : (age > 0.72 ? (1 - age) / 0.28 : 1);
      alpha = Math.min(1, alpha);
      var xy = fxProject(which, p.lat, p.lng, s, home);
      var rr = 3 + 7 * (1 - age);
      ctx.globalAlpha = alpha * 0.28; ctx.fillStyle = '#7dd3fc';
      ctx.beginPath(); ctx.arc(xy[0], xy[1], rr + 5, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = alpha; ctx.fillStyle = '#bae6fd';
      ctx.beginPath(); ctx.arc(xy[0], xy[1], 2.4, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = 1;
    });
  }
  function hideMapLoading() {
    var el = $('mapLoading');
    if (el) el.classList.add('off');
    if (S.fx) S.fx.loading = false;
    try { document.body.dataset.mapLoading = 'off'; } catch (e) {}
  }

  var canvasTimer = null;
  function startCanvasAnim() {
    if (canvasTimer) return;
    canvasTimer = setInterval(function () {
      if (document.hidden) return;
      S.anim += 2;
      // 2.0.0 B4：FX 覆盖层两条路径都逐帧更新（有 KEY 时补 SDK 缺失的
      // 流动光点，无 KEY 时叠加雷达波纹与 5 秒新点）；只有无 KEY 路径需要
      // 额外重绘 Canvas 散点，几何已由 drawMaps 缓存，不再重新计算。
      // 60ms 一帧（~16fps）足够表达流动，不给低配设备加负担。
      try { drawFx(); } catch (e) {}
      if (!S.tmapReady) { drawCanvas('world'); drawCanvas('cn'); }
    }, 60);
  }
  function stopCanvasAnim() {
    if (canvasTimer) { clearInterval(canvasTimer); canvasTimer = null; }
  }
  function drawMaps(force) {
    var t0 = (window.performance && performance.now) ? performance.now() : Date.now();
    var home = { lat: Number(S.home.lat) || 22.54, lng: Number(S.home.lng) || 114.06 };
    var changed = refreshArcData(home, force);
    // 数据指纹未变时完全不碰地图：曲线多时反复重建 GPU 缓冲是卡顿主因
    if (!changed && !force) return;
    if (S.tmapReady) {
      // 2.0.0 返工：FX 覆盖层定时器必须常驻。原来这里 stop 掉，
      // 配了 KEY 之后 drawFx() 不再逐帧执行：流动光点消失、
      // 雷达最后一帧残留并浮在底图上层（用户反馈的「卡在上方图层」）。
      drawTMaps(home);
    } else {
      drawCanvas('world'); drawCanvas('cn');
    }
    S.redraws++;
    S.lastDrawMs = ((window.performance && performance.now) ? performance.now() : Date.now()) - t0;
    // 供自动化验收读取：确认弧线确实交给了地图 SDK，而不是只算了没画
    try {
      document.body.dataset.arcDrawn = String(S.arcDrawn);
      document.body.dataset.arcMerged = String(S.arcMerged);
      document.body.dataset.arcSkipped = String(S.arcSkipped);
      document.body.dataset.arcNear = String(S.arcNear);
      document.body.dataset.mapRedraws = String(S.redraws);
      if (S.tmapReady && S.world && S.world.layer && S.world.layer.getGeometries) {
        document.body.dataset.worldLines = String(S.world.layer.getGeometries().length);
        document.body.dataset.cnLines = String(S.cn.layer.getGeometries().length);
      }
    } catch (e) {}
  }
  function requestMapDraw(force) {
    // 用 setTimeout 而非 rAF：rAF 在后台标签页 / headless 下会被节流甚至不触发，
    // 会直接丢掉数据到达后的那次刷新。16 ms 窗口仍可合并同一批重复请求。
    if (S.mapRaf) { if (force) S.mapForce = true; return; }
    S.mapForce = !!force;
    S.mapRaf = setTimeout(function () {
      S.mapRaf = 0;
      drawMaps(S.mapForce);
      S.mapForce = false;
    }, 16);
  }

  // ---- 数据加载 ----
  function loadHeavy() {
    var names = ['趋势', '排名', '记录', '热点', '访问画像', '地域分布'];
    return Promise.all([
      settle(api('api/trend?rng=' + S.range), 'trend'),
      settle(api('api/ranking?rng=' + S.range), 'ranking'),
      settle(api('api/records?page=' + S.page + '&size=' + S.size + '&range=' + S.range +
          '&scope=' + $('fScope').value + '&verdict=' + $('fVerdict').value +
          '&proto=' + $('fProto').value +
          '&source=' + $('fSource').value + '&q=' + encodeURIComponent($('fQuery').value)), 'records'),
      settle(api('api/hotspots?rng=' + S.range), 'hotspots'),
      // 1.1.3：一次取 30 条，卡片显示前 8 条，放大面板复用完整列表，无需二次请求
      settle(api('api/web/overview?rng=' + S.range + '&limit=30'), 'web/overview'),
      settle(api('api/geodist?rng=' + S.range + '&scope=all&limit=40'), 'geodist')
    ]).then(function (r) {
      var bad = badNames(r, names);
      markHeavyResult(bad);
      // 失败集合变化时才提示，避免每 12 秒刷屏
      var key = bad.join('|');
      if (key && key !== S.heavyBadKey) toast('部分数据加载失败：' + bad.join('、'));
      S.heavyBadKey = key;
      // 一轮里六个接口的数据都没变 → 全部跳过重绘；失败项保留上一轮 DOM
      var sig = JSON.stringify(r.map(function (x) { return x.ok ? x.data : null; }));
      if (sig === S.heavySig) return;
      S.heavySig = sig;
      if (r[0].ok) renderTrend(r[0].data.data);
      if (r[1].ok) {
        renderRank('rankCn', r[1].data.data.cn, '', 'cn');
        renderRank('rankOs', r[1].data.data.overseas, 'os', 'overseas');
      }
      if (r[2].ok) renderRecords(r[2].data.data);
      if (r[3].ok) {
        S.hotspots = r[3].data.data || [];
        S.home = r[3].data.home || S.home;
      }
      if (r[4].ok) renderWebCards(r[4].data.data);
      if (r[5].ok) renderGeoDist(r[5].data.data);
      requestMapDraw();
    });
  }
  // 1.1.2：固定全球视图，只重取一份全球地域分布，不刷新整页
  function loadGeoDist() {
    return api('api/geodist?rng=' + S.range + '&scope=all&limit=40')
      .then(function (r) { renderGeoDist(r.data); })
      .catch(function (e) { toast('地域分布加载失败：' + e.message); });
  }
  function loadLight() {
    var names = ['状态', '实时事件', '实时列表'];
    return Promise.all([
      settle(api('api/status?rng=' + S.range), 'status'),
      settle(api('api/events?since=' + S.lastId + '&limit=200'), 'events'),
      settle(api('api/live?limit=60'), 'live')
    ]).then(function (r) {
      var bad = badNames(r, names);
      // 1.1.7：连接状态每轮都重算，不受下面数据指纹短路影响，成功即恢复
      markLightResult(bad);
      // 只看界面真正用到的字段，避免采集计数变化引起无谓 DOM 重绘
      if (r[0].ok) {
        var a = r[0].data;
        var sig = JSON.stringify([a.data, a.sources && a.sources.syslog_ok,
                                  a.sources && a.sources.geo_ready,
                                  a.geo_verify && a.geo_verify.cached,
                                  r[1].ok && r[1].data.data.last_id,
                                  r[2].ok && r[2].data.data]);
        if (sig !== S.lightSig) {
          S.lightSig = sig;
          S.geoVerify = a.geo_verify || null;
          renderStatus(a.data, a.sources);
        }
      }
      // 事件流独立：events 失败时退回 live，不再让整块实时区域跟着停更
      var evs = r[1].ok ? (r[1].data.data.events || []) : [];
      if (r[1].ok) S.lastId = r[1].data.data.last_id || S.lastId;
      if (evs.length) renderLive(evs.slice(-60));
      else if (r[2].ok) renderLive(r[2].data.data);
    });
  }
  function loadAll() { return Promise.all([loadLight(), loadHeavy()]); }

  // ---- 设置抽屉 ----
  // 1.0.12：遮罩挡不住地图 SDK 自己的滚轮手势，必须在 SDK 层关掉滚轮缩放，
  // 否则点开 IP 画像后滚轮仍会缩放底下的地图。
  // 1.1.3：放大面板同样是模态，滚轮拦截与地图缩放要一并覆盖
  function drawerOpen() {
    return $('mask').classList.contains('on') || $('zoomMask').classList.contains('on');
  }
  function setMapScroll(on) {
    S.mapScroll = on;
    [S.world, S.cn, S.geoMap].forEach(function (m) {
      if (!m) return;
      try {
        if (typeof m.setScrollable === 'function') m.setScrollable(on);
      } catch (e) {}
    });
  }
  function destroyGeoMap() {
    try { if (S.geoMap && S.geoMap.destroy) S.geoMap.destroy(); } catch (e) {}
    S.geoMap = S.geoMarks = null;
    $('geoWrap').classList.remove('tmap-on');
  }
  function openDrawer(id) {
    $(id).classList.add('on'); $('mask').classList.add('on');
    setMapScroll(false);
    // 每次打开画像抽屉都清掉上一次绑定的 IP 切换事件，避免与表格行点击串扰
    if (id === 'detailDrawer') $('detailBody').onclick = null;
  }
  function closeDrawers() {
    $('settingsDrawer').classList.remove('on'); $('detailDrawer').classList.remove('on');
    $('mask').classList.remove('on');
    // 1.1.3：放大面板还开着时，不要把地图滚轮放出来
    if (!$('zoomMask').classList.contains('on')) setMapScroll(true);
  }
  function sw(key, label, hint) {
    var c = S.cfg[key] ? 'checked' : '';
    // 1.1.16：原实现里 input 是 0×0 且 opacity:0，可见滑块是不在 label 内的
    // <i>，点它根本不会切换 checkbox —— 真机上所有开关都点不动。现在让
    // label[for] 指向 input，配合 CSS 把 input 铺满整个 .switch 区域。
    var id = 'sw_' + key;
    return '<div class="field"><label for="' + id + '">' + label +
      '<br><span style="color:var(--dim);font-size:11px">' +
      hint + '</span></label><span class="switch"><input id="' + id +
      '" type="checkbox" data-k="' + key + '" ' + c + '><i></i></span></div>';
  }
  function fld(key, label, type, hint, step) {
    return '<div class="field"><label>' + label + '</label><input type="' + (type || 'text') +
      '" data-k="' + key + '" value="' + esc(S.cfg[key]) + '"' +
      (step ? ' step="' + step + '"' : '') + '></div>' +
      (hint ? '<p class="hint" style="margin:-4px 0 10px">' + hint + '</p>' : '');
  }
  function renderMapDiag() {
    var box = $('mapDiagBox'); if (!box) return;
    box.innerHTML = mapDiag().map(function (x) {
      var v = String(x[1]);
      var bad = (x[0].indexOf('尺寸') >= 0 && /^0\s|×\s*0/.test(v)) ||
                (x[0] === 'SDK 已加载' && v === '否') ||
                (x[0] === '底图资源请求' && /被拒/.test(v)) ||
                (x[0] === '底图状态' && /error|超时|失败/.test(v));
      return '<div class="kv"><b>' + esc(x[0]) + '</b><span class="' +
        (bad ? 'diag-bad' : 'diag-ok') + '">' + esc(v) + '</span></div>';
    }).join('');
  }
  function kv(k, v, bad) {
    return '<div class="kv"><b>' + esc(k) + '</b><span class="' +
      (bad ? 'diag-bad' : 'diag-ok') + '">' + esc(String(v == null ? '—' : v)) + '</span></div>';
  }
  function renderGeoSources() {
    var box = $('geoSrcBox');
    if (!box) return;
    box.innerHTML = kv('读取中', '正在查询数据源状态…');
    api('api/geo/sources').then(function (r) {
      var d = r.data || {}, c = r.cache || {};
      var h = kv('校验开关', d.enabled ? '已启用' : '已关闭', !d.enabled) +
        kv('已核验 IP', num(d.cached || 0) + ' 个（缓存 ' + num(c.count || 0) + ' 条）') +
        kv('源间分歧', num(c.disagree || 0) + ' 个') +
        kv('后台队列', num(d.queue || 0) + ' 个待校验') +
        kv('本轮成功 / 失败', num(d.verified || 0) + ' / ' + num(d.failed || 0));
      h += '<div style="margin-top:8px">' + (d.source_names || []).map(function (n) {
        var hits = (d.sources || {})[n] || 0;
        return '<div class="src-line"><span>' + esc(n) + '</span><span>' +
          (n.indexOf('本地') >= 0 ? '基础源 · 始终参与' :
            (hits ? '命中 ' + num(hits) + ' 次' : '尚无成功记录')) + '</span></div>';
      }).join('') + '</div>';
      box.innerHTML = h;
    }).catch(function (e) { box.innerHTML = kv('读取失败', e.message, true); });
  }
  function fmtLocateTime(t) {
    if (!t) return '未定位';
    var d = new Date(Number(t) * 1000);
    return isNaN(d.getTime()) ? '未定位' : d.toLocaleString('zh-CN', { hour12: false });
  }
  function renderLocate() {
    var box = $('locateBox');
    if (!box) return;
    var c = S.cfg || {};
    var src = c.home_source === 'auto' ? '自动定位' :
              (c.home_source === 'manual' ? '手动填写' : '内置默认值（未定位）');
    var rows = [
      ['出口 IP', c.home_ip || '未定位'],
      ['归属', c.home_geo || '—'],
      ['代理出口', c.home_proxy_ip || '无（未发现分流）'],
      ['定位方式', src],
      ['定位时间', fmtLocateTime(c.home_locate_at)],
      ['当前坐标', (c.home_lat || 0) + ', ' + (c.home_lng || 0)]
    ];
    box.innerHTML = rows.map(function (x) {
      return kv(x[0], x[1], x[0] === '出口 IP' && !c.home_ip);
    }).join('');
  }
  function renderLocateResult(r) {
    var onlineTxt = r.geo_text || (r.online
      ? [r.online.country, r.online.region, r.online.city].filter(Boolean).join(' ')
      : '—');
    var rows = [
      ['直连出口 IP', r.ip],
      ['代理出口 IP', r.proxy_ip || '无'],
      ['在线归属', onlineTxt],
      ['坐标来源', r.coord_source],
      ['本地库判定', (r.local && r.local.label) || '—'],
      ['已写入', r.home.label]
    ];
    var warn = r.mismatch
      ? '<p class="hint" style="color:#ffb86b;margin:8px 0 0">离线库与在线结果不一致：' +
        esc((r.local && r.local.label) || '—') + ' ≠ ' + esc(onlineTxt) +
        '。本机已采用在线结果；其它来源 IP 的归属仍以随包离线库为准。</p>'
      : '';
    $('locateResult').style.display = 'block';
    $('locateResult').innerHTML = rows.map(function (x) { return kv(x[0], x[1]); }).join('') + warn;
  }
  // ---- 1.1.11 设置界面：软件汇总日志 + 飞牛原生「应用内模态」文件夹选择器 ----
  // 真机取证（2026-11-14，读 /usr/trim/www/assets/index-BERCugxW.js 桌面壳主包与
  // /var/apps/zerrorfnos/target/ui/assets/index-DrXPtCR3.js 内打包的 @trimjs/web-app）：
  //  ZError 图一那张卡片不是 window.open 弹窗，而是 SDK 在 iframe 内通过 penpal
  //  与桌面父窗口握手后，调用父窗口暴露的 pickUserFile()，由桌面壳在「应用窗口内」
  //  渲染的原生 dialog（title / okText / creatable / sidebarGroup / fullScreen）。
  //  SDK 分流：window.parent !== window && !isStandaloneWeb → I7e() 主通道；
  //            否则 N7e() 降级，才会 window.open(..., 'width=750,height=630')。
  //  1.1.9 用 location.assign 整页跳转；1.1.10 误把 N7e 当主通道 → 新开独立窗口。
  //  桌面壳父窗口侧 connectToChild：收到 {penpal:'syn'} 回
  //  {penpal:'synAck', id, appName, config, methodNames:[...]}；
  //  子窗口回 {penpal:'ack', methodNames:[], config}；之后
  //  {penpal:'call', id, methodName, args} → {penpal:'reply', id, resolution, returnValue}。
  //  父窗口 methods 含 pickFile / pickUserFile / pickSharedFile / openFileManager / …
  //  1.1.11 三层：① penpal 主通道（同 ZError）② 应用内模态卡片 + 同源 iframe 内嵌
  //  飞牛原生 /app-auth 授权页 ③ 手填路径。全程不再 window.open，当前页面不跳走。
  //  1.1.13 真机复取证（index-BERCugxW.js / methods-CKCf4fL2.js / _method_）：
  //  父窗口 B$e 用 t[methodName].apply(t, args) 展开参数，args 必须是数组；
  //  pickUserFile 选中后强制 l8()=addUserAuthorizationPath，失败吞成 {code:1,data:[]}；
  //  W7=e=>({code:0,msg:'',data:e})、K7=(e,t)=>({code:-1/1,msg,data:t})。
  //  故主通道改 pickFile（无授权）+ args 数组化，降级改 /app-auth/pick-file，
  //  并把「空路径 / code=1」从「已取消选择」改为展示真实原因。
  var PICK_STATE_KEY = 'ipsense.pickUserFile.state';
  var PICK_AT_KEY = 'ipsense.pickUserFile.at';
  var PICK_TIMEOUT = 300000;
  var PICK_MSG_TYPE = 'ipsense:fnos-picker';
  var PICK_RESULT_KEY = 'ipsense.fnos.picker.result';
  var PICK_CB_FLAG = 'fnosPickerCallback';
  var PICK_BRIDGE_TIMEOUT = 1500;          // 对齐官方 SDK 的 host bridge 探测超时
  var PICK_CARD_TITLE = '选择汇总日志保存位置';
  var PICK_SIDEBAR = ['myFiles', 'otherShare', 'favorites'];
  var PENPAL = { syn: 'syn', synAck: 'synAck', ack: 'ack', call: 'call',
                 reply: 'reply', fulfilled: 'fulfilled', rejected: 'rejected' };
  var RANGE_LABEL = { '1h': '近 1 小时', '24h': '近 24 小时', '7d': '近 7 天',
                      '30d': '近 30 天', 'all': '全部历史' };
  var bridgePromise = null;                 // 启动时预热，避开父窗口 60s 握手超时
  var pickerWatcher = null;                 // 当前 watchPicker 的收口函数

  function pickStateNew() {
    var rnd = (window.crypto && typeof crypto.randomUUID === 'function')
      ? crypto.randomUUID()
      : Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
    var s = 'ips-' + rnd;
    try {
      sessionStorage.setItem(PICK_STATE_KEY, s);
      sessionStorage.setItem(PICK_AT_KEY, String(Date.now()));
    } catch (e) {}
    return s;
  }
  function pickRead() {
    try {
      var s = sessionStorage.getItem(PICK_STATE_KEY) || '';
      var at = Number(sessionStorage.getItem(PICK_AT_KEY) || 0);
      sessionStorage.removeItem(PICK_STATE_KEY);
      sessionStorage.removeItem(PICK_AT_KEY);
      return { state: s, at: at };
    } catch (e) { return { state: '', at: 0 }; }
  }
  function currentSummaryDir() {
    var el = document.querySelector('[data-k="summary_dir"]');
    return el ? String(el.value || '').trim() : String(S.cfg.summary_dir || '');
  }
  // 复刻 @trimjs/web-app 的 connectToParent（penpal）最小客户端：
  // 只在 iframe 内启用；发 syn → 等 synAck → 回 ack → 生成父窗口方法调用代理。
  // 不引入任何外部 SDK，也不依赖全局 window.TrimApp（真机上并不存在）。
  function fnosBridge() {
    return new Promise(function (resolve, reject) {
      // 离线预览（file://）专用仿真桥：真机 http/https 永远不走这里，
      // 让探针能覆盖「主通道 pickUserFile 调用与参数」这条代码路径。
      if (location.protocol === 'file:' && window.__ipsenseMockBridge) {
        var m = window.__ipsenseMockBridge;
        try { window.__ipsenseBridgeNames = (m.names || []).slice(); } catch (e0) {}
        resolve({
          names: (m.names || []).slice(), config: m.config || {},
          call: function (name, args) {
            try {
              window.__ipsenseBridgeCalls = (window.__ipsenseBridgeCalls || [])
                .concat([{ method: name, args: args }]);
            } catch (e1) {}
            return Promise.resolve(m.result);
          }
        });
        return;
      }
      if (window.parent === window) { reject(new Error('standalone')); return; }
      var settled = false, pending = {}, seq = 0, onMsg = null;
      function cleanup() {
        try { window.removeEventListener('message', onMsg); } catch (e) {}
      }
      function fail(msg) {
        if (settled) return; settled = true; cleanup(); reject(new Error(msg));
      }
      onMsg = function (ev) {
        var d = ev.data;
        if (!d || typeof d !== 'object') return;
        if (d.penpal === PENPAL.synAck) {
          if (ev.source !== window.parent) return;
          var ackOrigin = ev.origin === 'null' ? '*' : ev.origin;
          // 回 ACK：methodNames 为空表示本应用不向父窗口暴露方法
          try {
            window.parent.postMessage({ penpal: PENPAL.ack,
                                        methodNames: [], config: {} }, ackOrigin);
          } catch (e) { fail('ack 发送失败'); return; }
          var names = Array.isArray(d.methodNames) ? d.methodNames : [];
          try { window.__ipsenseBridgeNames = names.slice(); } catch (e2) {}
          var api = {
            names: names.slice(),
            config: d.config || {},
            call: function (name, args) {
              return new Promise(function (res, rej) {
                var id = ++seq;
                pending[id] = { res: res, rej: rej };
                // 1.1.13：飞牛桌面壳父窗口处理 call 用的是
                //   new Promise(e => e(t[methodName].apply(t, args)))
                // args 必须是「参数数组」。1.1.11 / 1.1.12 误传单个对象，
                // .apply 把参数全部丢弃，pickUserFile 收到 {} →
                // directory / sidebarGroup / title 全部失效，选择器退回
                // 默认「选文件」模式，选中文件夹后返回空 data，被误报成取消。
                try {
                  window.parent.postMessage({ penpal: PENPAL.call, id: id,
                                              methodName: name, args: [args || {}] },
                                            ackOrigin);
                } catch (e3) { delete pending[id]; rej(e3); return; }
                setTimeout(function () {
                  if (!pending[id]) return;
                  delete pending[id]; rej(new Error('host call timeout: ' + name));
                }, PICK_TIMEOUT);
              });
            }
          };
          settled = true;
          resolve(api);
          return;
        }
        if (d.penpal === PENPAL.reply) {
          var p = pending[d.id]; if (!p) return;
          delete pending[d.id];
          if (d.resolution === PENPAL.rejected) {
            var v = d.returnValue || {};
            p.rej(new Error(v.message || 'host call rejected'));
          } else { p.res(d.returnValue); }
        }
      };
      try { window.addEventListener('message', onMsg); } catch (e) { fail('监听失败'); return; }
      // 官方 SDK 用 '*' 发 SYN，父窗口按 iframe.contentWindow 校验来源
      try { window.parent.postMessage({ penpal: PENPAL.syn }, '*'); }
      catch (e2) { fail('syn 发送失败'); return; }
      setTimeout(function () { fail('host bridge timeout'); }, PICK_BRIDGE_TIMEOUT);
    });
  }
  function getBridge() {
    if (!bridgePromise) {
      bridgePromise = fnosBridge();
      bridgePromise.catch(function () { bridgePromise = null; });
    }
    return bridgePromise;
  }
  // 1.1.13：飞牛桌面壳的返回形态并不统一 —— pickFile 直接给路径数组，
  // pickUserFile 给 W7/K7 包装 {code, msg, data}（code 0 成功 / -1 取消 / 1 失败）。
  // 统一归一化：拿到路径就是成功；只有明确的取消信号才提示「已取消选择」；
  // 其余一律显示真实 msg，绝不再把空路径 / code=1 兜底成「取消」把错误吞掉。
  function pickPathsFrom(r) {
    var raw = null;
    if (r == null) raw = null;
    else if (Array.isArray(r)) raw = r;
    else if (typeof r === 'string') raw = [r];
    else if (typeof r === 'object') {
      if (Array.isArray(r.data)) raw = r.data;
      else if (Array.isArray(r.paths)) raw = r.paths;
      else if (Array.isArray(r.path)) raw = r.path;
      else if (typeof r.path === 'string') raw = [r.path];
      else if (r.data && typeof r.data === 'object') {
        raw = r.data.paths || r.data.path || r.data.list || null;
      } else if (Array.isArray(r.list)) raw = r.list;
      else if (Array.isArray(r.files)) raw = r.files;
    }
    if (raw == null) return [];
    if (!Array.isArray(raw)) raw = [raw];
    var out = [];
    for (var i = 0; i < raw.length; i++) {
      var v = raw[i], p = '';
      if (typeof v === 'string') p = v;
      else if (v && typeof v === 'object') {
        p = v.path || v.filePath || v.fullPath || v.url || v.name || '';
      }
      if (typeof p === 'string' && p.trim()) out.push(p.trim());
    }
    return out;
  }
  function pickIsCancel(r) {
    if (r && typeof r === 'object') {
      if (Number(r.code) === -1) return true;            // K7 的 Cancelled
      if (/cancel|取消/i.test(String(r.msg || r.error || ''))) return true;
    }
    return false;
  }
  function pickErrMsg(r) {
    return (r && typeof r === 'object')
      ? String(r.msg || r.error || r.message || '').trim() : '';
  }
  function finishBridge(r) {
    var paths = pickPathsFrom(r);
    if (paths.length) { saveSummaryDir(paths[0]); return; }
    if (pickIsCancel(r)) { toast('已取消选择'); return; }
    // 1.1.13：失败时给出真实原因 + 手填路径兜底，不再伪装成「取消」
    toast('选择失败：' + (pickErrMsg(r) || '没有拿到目录路径') +
          '，可手动填写 NAS 绝对路径');
  }
  function fnosPickFolder() {
    // 离线预览探针可强制走「应用内模态卡片」分支，便于截图与 DOM 验收。
    if (location.protocol === 'file:' && window.__ipsenseForcePickerCard) {
      openPickerCard(''); return;
    }
    var opts = {
      directory: true, multiple: false, title: PICK_CARD_TITLE,
      okText: '选择', creatable: true, accept: [],
      sidebarGroup: PICK_SIDEBAR.slice()
    };
    getBridge().then(function (bridge) {
      // 1.1.13：优先 pickFile —— 纯路径选择，不触发 addUserAuthorizationPath。
      // 真机取证：pickUserFile 选中后会强制调 l8() 授权，授权失败直接把结果
      // 吞成 {code:1, data:[]}；本应用只需要一个目录字符串，无需 fnOS 文件授权。
      var names = bridge.names || [];
      var method = names.indexOf('pickFile') >= 0 ? 'pickFile' : 'pickUserFile';
      return bridge.call(method, opts).then(
        function (r) { return r; },
        function (e) {
          // 选择器取消 / 方法级失败：交回 finishBridge 统一判定，不再盲目重弹卡片
          var msg = (e && e.message) || '';
          return { code: /cancel|取消/i.test(msg) ? -1 : 1, msg: msg, data: [] };
        });
    }).then(function (r) {
      finishBridge(r);
    }).catch(function (e) {
      // 仅握手失败 / 独立浏览器：应用内模态卡片，绝不新开窗口
      openPickerCard((e && e.message) || '');
    });
  }
  // 1.1.13 降级通道：应用内模态卡片。外层只画遮罩 + 标题栏 + 关闭按钮，
  // 目录树 / 左侧分组 / 新建文件夹 / 取消 / 选择全部由同源 iframe 内嵌的
  // 飞牛原生 /app-auth/pick-file 页面渲染，不自绘目录树；回跳到 picker-cb.html。
  // 走 pick-file 而非 pick-user-file：后者 onOk 要强制授权，失败只回 error。
  function pickerKeyHandler(e) {
    if (e.key === 'Escape') closePickerCard(true);
  }
  function openPickerCard(reason) {
    closePickerCard(false);
    var state = pickStateNew();
    var back = new URL(location.href);
    back.hash = '';
    var base = location.pathname.replace(/\/+$/, '');
    back.pathname = base + '/picker-cb.html';
    back.searchParams.set(PICK_CB_FLAG, '1');
    var q = new URLSearchParams();
    q.set('appName', 'ipsense');
    q.set('redirectUri', back.toString());
    q.set('redirect_uri', back.toString());   // createAppAuthRequest 两种写法都兼容
    q.set('state', state);
    q.set('directory', 'true');
    q.set('sidebarGroup', PICK_SIDEBAR.join(','));
    q.set('creatable', 'true');
    q.set('title', PICK_CARD_TITLE);
    q.set('okText', '选择');
    // 1.1.13：降级改用 /app-auth/pick-file 路由。真机取证 _method_ 页面：
    // pickUserFile 分支 onOk 会先调 addUserAuthorizationPath，失败只回
    // status=error 且不回传 path；pickFile 分支直接 k('success', paths)，
    // 无授权步骤。本应用只要一个目录字符串，走 pickFile 更稳。
    var src = location.origin + '/app-auth/pick-file?' + q.toString();

    var mask = document.createElement('div');
    mask.className = 'pick-mask'; mask.id = 'pickMask';
    mask.innerHTML =
      '<div class="pick-card" id="pickCard" role="dialog" aria-modal="true">' +
        '<div class="pick-card-head"><b>' + esc(PICK_CARD_TITLE) + '</b>' +
          '<button class="pick-x" type="button" id="pickClose" aria-label="关闭">×</button>' +
        '</div>' +
        '<div class="pick-card-body" id="pickCardBody"></div>' +
        '<div class="pick-card-foot" id="pickCardFoot">' +
          (reason ? '桌面通道不可用（' + esc(reason) + '），已切换为应用内原生授权页' :
                    '飞牛原生目录选择器 · 当前页面不跳走') +
        '</div>' +
      '</div>';
    document.body.appendChild(mask);
    $('pickClose').onclick = function () { closePickerCard(true); };
    mask.onclick = function (e) { if (e.target === mask) closePickerCard(true); };
    document.addEventListener('keydown', pickerKeyHandler);

    var body = $('pickCardBody');
    // 离线预览（file://）专用仿真：真机 http/https 永远不走这里，不构成生产后门。
    if (location.protocol === 'file:' &&
        typeof window.__ipsensePickerCardRender === 'function') {
      try { window.__ipsensePickerCardRender(body, state, src); } catch (e) {}
    } else {
      var fr = document.createElement('iframe');
      fr.id = 'pickFrame'; fr.className = 'pick-frame';
      fr.setAttribute('title', '飞牛原生文件夹选择器');
      fr.src = src;
      body.appendChild(fr);
    }
    try { window.__ipsensePickerOpen = { state: state, src: src, via: 'modal' }; }
    catch (e2) {}
    watchPicker(state);
    toast('已打开文件夹选择卡片，选好后会自动回填');
  }
  function closePickerCard(byUser) {
    var mask = $('pickMask');
    if (mask && mask.parentNode) mask.parentNode.removeChild(mask);
    document.removeEventListener('keydown', pickerKeyHandler);
    var w = pickerWatcher;
    if (w) { pickerWatcher = null; if (byUser) w.finish('cancel'); }
  }
  // 1.1.11 三路收结果：① postMessage（校验 origin + type + state）
  // ② sessionStorage 600ms 轮询（iframe 回跳页写入）③ 300s 超时。
  // 用户关闭卡片 → closePickerCard(true) 直接收口为 cancel。
  // 拿到结果后统一交给 saveSummaryDir() 走后端四层校验。
  function watchPicker(state) {
    var done = false, poll = null, timer = null, onMsg = null;
    function finish(status, paths, err) {
      if (done) return; done = true;
      if (poll) clearInterval(poll);
      if (timer) clearTimeout(timer);
      if (onMsg) { try { window.removeEventListener('message', onMsg); } catch (e) {} }
      try { sessionStorage.removeItem(PICK_RESULT_KEY); } catch (e2) {}
      pickerWatcher = null;
      closePickerCard(false);
      if (status === 'success' || status === 'ok' || status === '1') {
        var list = pickPathsFrom(paths);
        if (!list.length) {
          toast('选择失败：没有拿到目录路径，可手动填写 NAS 绝对路径'); return;
        }
        saveSummaryDir(String(list[0] || ''));
        setTimeout(renderSummaryStatus, 900);
        setTimeout(renderSummaryStatus, 2200);
      } else if (status === 'cancel') {
        toast('已取消选择');
      } else {
        // 1.1.13：error / access_denied 不再显示成「已取消选择」，给出可排查原因
        toast('选择失败' + (err ? '：' + err : '，未拿到目录') +
              '，可手动填写 NAS 绝对路径');
      }
    }
    pickerWatcher = { finish: finish };
    onMsg = function (ev) {
      if (ev.origin !== location.origin) return;
      var d = ev.data;
      if (!d || d.type !== PICK_MSG_TYPE || d.state !== state) return;
      finish(d.status, d.path, d.error);
    };
    try { window.addEventListener('message', onMsg); } catch (e) {}
    poll = setInterval(function () {
      var raw = null;
      try { raw = sessionStorage.getItem(PICK_RESULT_KEY); } catch (e2) {}
      if (!raw) return;
      try {
        var d = JSON.parse(raw);
        if (d && d.state === state) finish(d.status, d.path, d.error);
      } catch (e3) {}
    }, 600);
    timer = setTimeout(function () { finish('error', null, '等待超时（5 分钟）'); },
                       PICK_TIMEOUT);
  }
  function saveSummaryDir(dir) {
    if (!dir) { toast('没有拿到目录，请重新选择'); return; }
    // 路径一律交给后端四层校验，前端不信任选择器回传。
    api('api/summary/validate', 'POST', { path: dir }).then(function (r) {
      if (!r.ok) { toast('目录不可用：' + (r.reason || '未知原因')); return null; }
      return api('api/config', 'POST', { summary_dir: r.path || dir }).then(function (c) {
        if (!c.ok) throw new Error(c.msg || '保存失败');
        S.cfg.summary_dir = r.path || dir;
        var el = document.querySelector('[data-k="summary_dir"]');
        if (el) el.value = r.path || dir;
        renderSummaryStatus();
        toast('保存位置已设置：' + (r.path || dir));
        // 后端保存后会立即后台生成一份，稍后再取一次状态
        setTimeout(renderSummaryStatus, 1600);
        return true;
      });
    }).catch(function (e) { toast('保存位置失败：' + e.message); });
  }
  function consumePickerCallback() {
    var p;
    try { p = new URLSearchParams(location.search); } catch (e) { return false; }
    // 离线预览 / 自动化探针：只在 file:// 下允许注入模拟回调。
    // 真机走 fnOS 网关（http/https），这段永远不会生效，不构成生产后门。
    if (location.protocol === 'file:' && window.__ipsensePickerMock &&
        typeof window.__ipsensePickerMock === 'object') {
      Object.keys(window.__ipsensePickerMock).forEach(function (k) {
        p.set(k, String(window.__ipsensePickerMock[k]));
      });
    }
    if (!p.has('status') || !p.has('state')) return false;
    var method = p.get('method') || '';
    // 1.1.13：降级路由改 /app-auth/pick-file，method 可能是 pickFile / pick-file
    if (method && method !== 'pickUserFile' && method !== 'pick-user-file' &&
        method !== 'pickFile' && method !== 'pick-file') return false;
    var rec = pickRead();
    var gotState = p.get('state'), raw = p.get('path') || '[]';
    var status = p.get('status'), err = p.get('error') || '';
    if (status === 'ok' || status === '1' || status === 'true') status = 'success';
    // 先读完再清理 URL 参数，保留网关票据等原有查询串，避免刷新重复处理。
    try {
      ['status', 'method', 'appName', 'error', 'state', 'path', PICK_CB_FLAG].forEach(function (k) { p.delete(k); });
      var qs = p.toString();
      history.replaceState(null, '', location.pathname + (qs ? '?' + qs : '') + location.hash);
    } catch (e) {}
    if (!rec.state || gotState !== rec.state || (Date.now() - rec.at) > PICK_TIMEOUT) {
      toast('选择结果已过期或校验未通过，请重新选择'); return true;
    }
    var paths;
    try { paths = JSON.parse(raw); } catch (e2) { paths = []; }
    if (!Array.isArray(paths)) paths = [];
    // 1.1.11：兼容 1.1.9/1.1.10 遗留的整页回跳 URL。新路径不再走这里，
    // 由 picker-cb.html 静态回调页直接回传；此处仍把结果交给 opener / parent
    // 与同源 sessionStorage，保证旧链接刷新也能收得到。
    var payload = { type: PICK_MSG_TYPE, state: gotState, status: status,
                    path: paths, error: err };
    try { sessionStorage.setItem(PICK_RESULT_KEY, JSON.stringify(payload)); } catch (e4) {}
    try {
      if (window.opener && window.opener !== window) {
        window.opener.postMessage(payload, location.origin);
      }
      if (window.parent !== window) {
        window.parent.postMessage(payload, location.origin);
      }
    } catch (e5) {}
    if (status !== 'success') {
      // 1.1.13：只有明确 cancel 才提示取消；授权失败 / 空路径给出真实原因
      if (status === 'cancel') { toast('已取消选择'); return true; }
      toast('选择失败' + (err ? '：' + err : '，未拿到目录') +
            '，可手动填写 NAS 绝对路径');
      return true;
    }
    if (!paths.length) { toast('没有拿到目录路径'); return true; }
    saveSummaryDir(String(paths[0] || ''));
    // 没有 opener 且是顶层窗口，说明是整页回跳（旧路径 / 独立浏览器），
    // 恢复设置界面上下文；iframe 内不重复渲染。
    if (!window.opener && window.parent === window) {
      setTimeout(function () {
        api('api/sources').then(function (r) {
          renderSettings(r.data);
          openDrawer('settingsDrawer');
          var box = $('summaryServiceBox');
          if (box) setTimeout(function () {
            try { box.scrollIntoView({ block: 'start', behavior: 'smooth' }); } catch (e3) {}
          }, 120);
        }).catch(function () {});
      }, 220);
    }
    return true;
  }
  function summaryRangeOptions() {
    return [['1h', '近 1 小时'], ['24h', '近 24 小时'], ['7d', '近 7 天'],
            ['30d', '近 30 天'], ['all', '全部历史']].map(function (x) {
      return '<option value="' + x[0] + '"' +
        ((S.cfg.summary_range || '24h') === x[0] ? ' selected' : '') + '>' + x[1] + '</option>';
    }).join('');
  }
  function summaryServiceHtml() {
    var d = String(S.cfg.summary_dir || '');
    return '<div class="form-group" id="summaryServiceBox"><h3>软件汇总日志（1.1.14）</h3>' +
      '<p class="hint">把设备访问态势汇总成一份 Markdown 日志，直接交给 AI 分析并给出防护建议。' +
      '包含态势总览、高频来源 IP、可疑事件明细、地域与 Web 访问画像、频率峰值、数据口径与免责声明。' +
      '应用只观测、不修改防火墙、不封禁 IP，所有处置动作请人工确认。</p>' +
      '<div class="sum-path"><div><b>保存位置</b><span id="sumPathText">' +
      esc(d || '（未设置）') + '</span></div><div style="display:flex;gap:8px;flex-wrap:wrap">' +
      '<button class="btn primary sm" type="button" id="btnPickFolder">选择文件夹（飞牛原生）</button>' +
      '<button class="btn sm" type="button" id="btnSumValidate">校验并保存路径</button></div></div>' +
      '<div class="field"><label>手动填写 NAS 绝对路径（兜底）</label>' +
      '<input type="text" data-k="summary_dir" id="cfgSummaryDir" value="' + esc(d) +
      '" placeholder="/vol1/1000/…"></div>' +
      '<p class="hint">点「选择文件夹」会在 <b>当前应用窗口内</b>弹出飞牛原生文件夹选择卡片' +
      '（我的文件 / 他人共享 / 我的收藏 + 目录树 + 新建文件夹 + 取消 / 选择），' +
      '由飞牛桌面直接渲染，<b>不新开浏览器窗口、当前页面不跳走</b>，选好后自动回填并保存。' +
      '桌面通道不可用时（例如独立浏览器直连）自动切换为应用内嵌的飞牛原生授权页，同样不新开窗口；' +
      '也可手动填写路径。只允许 /vol、/home、/mnt、/media 下的数据目录，' +
      '应用目录与系统目录会被拒绝；目录还要通过真实可写测试。</p>' +
      sw('summary_enabled', '自动生成汇总日志', '按下方间隔在后台刷新，页面不用打开') +
      fld('summary_interval', '生成间隔（分钟，1–1440）', 'number') +
      '<div class="field"><label>统计窗口</label><select data-k="summary_range">' +
      summaryRangeOptions() + '</select></div>' +
      '<div id="sumStatusBox" class="diag-box"></div>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">' +
      '<button class="btn" type="button" id="btnSumGenerate">立即生成</button>' +
      '<button class="btn" type="button" id="btnSumPreview">预览全文</button>' +
      '<button class="btn ghost" type="button" id="btnSumCopy">复制全文</button>' +
      '<button class="btn ghost" type="button" id="btnSumDownload">下载 .md</button></div>' +
      '<div id="sumPreviewBox" class="sum-preview" style="display:none"></div>' +
      '<p class="hint" style="margin:10px 0 0">固定文件名 <code>ipsense-summary-latest.md</code> 每次覆盖，' +
      '便于把同一个文件持续交给 AI；另按天归档 <code>ipsense-summary-YYYYMMDD.md</code>，' +
      '同天覆盖，不自动删除任何历史文件。</p></div>';
  }
  function renderSummaryStatus() {
    var box = $('sumStatusBox'); if (!box) return;
    api('api/summary/status').then(function (r) {
      S.summary = r.data;
      var d = r.data;
      var rows = [
        ['保存位置', d.dir || '（未设置）'],
        ['目录状态', d.dir_ok ? '可写 ✓' : '不可用：' + d.dir_reason],
        ['自动生成', d.enabled ? '开启 · 每 ' + d.interval + ' 分钟' : '关闭'],
        ['统计窗口', RANGE_LABEL[d.range] || d.range],
        ['最新文件', d.latest_name || '—'],
        ['上次生成', d.last_at ? tm(d.last_at) : '尚未生成'],
        ['文件大小', d.last_size ? num(d.last_size) + ' 字节' : '—'],
        ['累计生成', num(d.writes) + ' 次']
      ];
      if (d.last_error) rows.push(['最近错误', d.last_error]);
      box.innerHTML = rows.map(function (x) {
        return kv(x[0], x[1], x[0] === '目录状态' && !d.dir_ok);
      }).join('');
      var pt = $('sumPathText'); if (pt) pt.textContent = d.dir || '（未设置）';
    }).catch(function (e) { box.innerHTML = kv('状态', '读取失败：' + e.message, true); });
  }
  function bindSummary() {
    var box = $('summaryServiceBox'); if (!box) return;
    $('btnPickFolder').onclick = fnosPickFolder;
    $('btnSumValidate').onclick = function () {
      var v = currentSummaryDir();
      if (!v) { toast('请先选择或填写保存位置'); return; }
      saveSummaryDir(v);
    };
    $('btnSumGenerate').onclick = function () {
      var b = this; b.disabled = true; b.textContent = '生成中…';
      api('api/summary/generate', 'POST', { dir: currentSummaryDir() }).then(function (r) {
        b.disabled = false; b.textContent = '立即生成';
        if (!r.ok) throw new Error(r.msg || '生成失败');
        toast('已生成 ' + num(r.data.bytes) + ' 字节 → ' + r.data.latest);
        renderSummaryStatus();
      }).catch(function (e) {
        b.disabled = false; b.textContent = '立即生成';
        toast('生成失败：' + e.message); renderSummaryStatus();
      });
    };
    $('btnSumPreview').onclick = function () {
      api('api/summary/preview').then(function (r) {
        var b = $('sumPreviewBox'); b.style.display = 'block'; b.textContent = r.data.text;
        toast('已载入全文 · ' + num(r.data.bytes) + ' 字节 / ' + num(r.data.lines) + ' 行');
      }).catch(function (e) { toast('预览失败：' + e.message); });
    };
    $('btnSumCopy').onclick = function () {
      api('api/summary/preview').then(function (r) {
        var t = r.data.text;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          return navigator.clipboard.writeText(t).then(function () { toast('全文已复制，可直接粘贴给 AI'); });
        }
        var ta = document.createElement('textarea');
        ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); toast('全文已复制，可直接粘贴给 AI'); }
        catch (e2) { toast('复制失败，请用「预览全文」手动选中'); }
        ta.remove();
      }).catch(function (e) { toast('复制失败：' + e.message); });
    };
    $('btnSumDownload').onclick = function () {
      fetch(url('api/summary/download')).then(function (r) { return r.blob(); }).then(function (b) {
        var a = document.createElement('a'); a.href = URL.createObjectURL(b);
        a.download = 'ipsense-summary-latest.md';
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 3000);
      }).catch(function (e) { toast('下载失败：' + e.message); });
    };
    renderSummaryStatus();
  }

  // ---- 1.1.8 设置界面：四家预设 + 自定义接口 ----
  function captureMapKeys() {
    var d = {};
    Array.prototype.forEach.call(document.querySelectorAll('[data-mk]'), function (el) {
      d[el.getAttribute('data-mk')] = el.value;
    });
    S.mapKeysDraft = d;
  }
  function mapServiceCardsHtml() {
    return mapProviders().map(function (p) {
      return '<button type="button" class="prov-card' +
        (p.id === S.selProvider ? ' on' : '') + '" data-act="pick" data-pid="' + esc(p.id) + '">' +
        '<b>' + esc(p.name) + '</b><span>' + esc(p.coord || '') + ' · ' +
        (mapIsConfigured(p.id) ? '已配置' : '未配置') +
        (p.builtin ? '' : ' · 自定义') + '</span></button>';
    }).join('');
  }
  function mapServiceDetailHtml() {
    return mapProviders().map(function (p) {
      var k = providerKey(p.id);
      var ph = p.key_placeholder || '请填写你自己申请的 API 密钥';
      return '<div class="prov-detail-item" data-detail="' + esc(p.id) + '"' +
        (p.id === S.selProvider ? '' : ' style="display:none"') + '>' +
        '<div class="kv"><b>SDK 地址</b><span>' + esc(p.sdk) + '</span></div>' +
        '<div class="kv"><b>密钥申请</b><span>' + (p.apply_url
          ? '<a href="' + esc(p.apply_url) + '" target="_blank" rel="noopener" style="color:var(--blue-l)">' +
            esc(p.apply_text || '开放平台') + ' ↗</a>'
          : '自定义接口') + '</span></div>' +
        '<div class="kv"><b>坐标系</b><span>' + esc(p.coord || '—') + '</span></div>' +
        '<div class="kv"><b>兼容引擎</b><span>' +
          esc((MAP_ENGINES[p.engine] || MAP_ENGINES.tmap).label) + '</span></div>' +
        '<div class="field"><label>' + esc(p.key_label || 'key') +
          '（仅存本机）</label><input type="text" data-mk="' + esc(p.id) +
          '" value="' + esc(k) + '" placeholder="' + esc(ph) + '"></div>' +
        '<p class="hint" style="margin:-4px 0 6px">' + esc(p.note || '') +
          ' 请为密钥配置 Referer / 域名白名单，不要提交到公开仓库。</p></div>';
    }).join('');
  }
  function mapServiceCustomHtml() {
    var l = mapCustomList();
    if (!l.length) return '<p class="hint" style="margin:6px 0 0">尚未添加自定义接口。可指向四家官方 SDK 地址，或你自建的合规代理。</p>';
    return l.map(function (c) {
      return '<div class="prov-custom-row"><div><b>' + esc(c.name) + '</b><span>' +
        esc((MAP_ENGINES[c.engine] || MAP_ENGINES.tmap).label) + ' · ' +
        esc(urlHost(c.sdk)) + '</span></div><div>' +
        '<button type="button" class="btn sm" data-act="edit" data-cid="' + esc(c.id) + '">编辑</button> ' +
        '<button type="button" class="btn sm ghost" data-act="del" data-cid="' + esc(c.id) + '">删除</button>' +
        '</div></div>';
    }).join('');
  }
  function mapServiceFormHtml(c) {
    c = c || {};
    var opts = Object.keys(MAP_ENGINE_IDS).map(function (k) {
      return '<option value="' + k + '"' + ((c.engine || 'tmap') === k ? ' selected' : '') +
        '>' + esc(MAP_ENGINES[k].label) + '</option>';
    }).join('');
    function f(k, label, ph, type) {
      return '<div class="field"><label>' + label + '</label><input type="' + (type || 'text') +
        '" data-cf="' + k + '" value="' + esc(c[k] || '') + '" placeholder="' + esc(ph || '') + '"></div>';
    }
    return '<div class="prov-form" id="mapCustomForm">' +
      f('name', '接口名称', '例如：自建腾讯地图代理') +
      f('id', '接口 id（小写字母 / 数字）', '例如：myproxy') +
      '<div class="field"><label>兼容引擎</label><select data-cf="engine">' + opts + '</select></div>' +
      f('sdk', 'SDK 地址（含 {key}）', 'https://map.qq.com/api/gljs?v=1.exp&key={key}') +
      f('key', 'API 密钥', '选填，也可保存后在上方填写') +
      f('apply_url', '密钥申请地址（选填）', '') +
      f('note', '备注（选填）', '') +
      '<p class="hint">SDK 地址必须含 {key} 占位符；百度引擎请保留 {callback}。' +
      '仅允许四家合规官方域名或你自建的合规代理，禁止 Google Maps / OpenStreetMap / ' +
      'Mapbox / Leaflet 等未获资质来源。</p>' +
      '<div style="display:flex;gap:8px"><button type="button" class="btn primary sm" data-act="save">保存接口</button>' +
      '<button type="button" class="btn ghost sm" data-act="cancel">取消</button></div></div>';
  }
  function mapServiceHtml() {
    return '<div class="form-group" id="mapServiceBox"><h3>地图服务（1.1.8）</h3>' +
      '<p class="hint">内置腾讯 / 高德 / 百度 / 天地图四家合规底图，点选即切换，各自密钥分开保存、切换不丢。' +
      '应用不内置任何有效密钥，请到对应开放平台自行申请并配置 Referer / 域名白名单。' +
      '禁止接入 Google Maps / Apple Maps / Bing 海外版 / OpenStreetMap / Mapbox 等未获资质来源；' +
      '国界与行政区划一律以官方底图为准。</p>' +
      '<div id="mapProvCards" class="prov-grid">' + mapServiceCardsHtml() + '</div>' +
      '<div id="mapProvDetail" class="prov-detail">' + mapServiceDetailHtml() + '</div>' +
      '<input type="hidden" data-k="map_provider" id="cfgMapProvider" value="' + esc(S.selProvider) + '">' +
      '<div class="prov-custom"><div class="prov-custom-head"><b>自定义接口</b>' +
      '<button type="button" class="btn sm" data-act="add">+ 添加接口</button></div>' +
      '<div id="mapCustomList">' + mapServiceCustomHtml() + '</div>' +
      '<div id="mapCustomFormWrap"></div></div></div>';
  }
  function renderMapServiceParts() {
    captureMapKeys();
    var c = $('mapProvCards'), d = $('mapProvDetail'), l = $('mapCustomList');
    if (c) c.innerHTML = mapServiceCardsHtml();
    if (d) d.innerHTML = mapServiceDetailHtml();
    if (l) l.innerHTML = mapServiceCustomHtml();
    var h = $('cfgMapProvider'); if (h) h.value = S.selProvider;
  }
  function bindMapService() {
    var box = $('mapServiceBox');
    if (!box) return;
    box.onclick = function (e) {
      var t = e.target, btn = null;
      while (t && t !== box && t !== document) {
        if (t.getAttribute && t.getAttribute('data-act')) { btn = t; break; }
        t = t.parentNode;
      }
      if (!btn) return;
      var act = btn.getAttribute('data-act');
      var pid = btn.getAttribute('data-pid'), cid = btn.getAttribute('data-cid');
      if (act === 'pick') {
        S.selProvider = pid; renderMapServiceParts(); return;
      }
      if (act === 'add' || act === 'edit') {
        captureMapKeys();
        var item = null;
        if (act === 'edit') {
          var l = mapCustomList();
          for (var i = 0; i < l.length; i++) if (l[i].id === cid) item = l[i];
        }
        var w = $('mapCustomFormWrap');
        if (w) { w.innerHTML = mapServiceFormHtml(item); w.setAttribute('data-edit', item ? item.id : ''); }
        return;
      }
      if (act === 'cancel') {
        var w2 = $('mapCustomFormWrap'); if (w2) w2.innerHTML = ''; return;
      }
      if (act === 'del') {
        captureMapKeys();
        S.mapCustom = mapCustomList().filter(function (x) { return x.id !== cid; });
        if (S.selProvider === cid) S.selProvider = 'tencent';
        var w3 = $('mapCustomFormWrap'); if (w3) w3.innerHTML = '';
        renderMapServiceParts(); toast('已删除自定义接口（保存后生效）'); return;
      }
      if (act === 'save') {
        var w4 = $('mapCustomFormWrap'); if (!w4) return;
        function g(k) { var el = w4.querySelector('[data-cf="' + k + '"]'); return el ? String(el.value).trim() : ''; }
        var o = { id: g('id').toLowerCase(), name: g('name'), engine: g('engine'),
                  sdk: g('sdk'), key: g('key'), apply_url: g('apply_url'), note: g('note') };
        if (!/^[a-z0-9][a-z0-9_-]{0,23}$/.test(o.id)) { toast('接口 id 非法（小写字母 / 数字，≤24 字）'); return; }
        if (BUILTIN_PROVIDERS.some(function (x) { return x.id === o.id; })) { toast('接口 id 与内置服务商冲突'); return; }
        if (!o.name) { toast('请填写接口名称'); return; }
        if (!/^https?:\/\//i.test(o.sdk)) { toast('SDK 地址必须以 http(s):// 开头'); return; }
        if (o.sdk.indexOf('{key}') < 0) { toast('SDK 地址必须包含 {key} 占位符'); return; }
        if (!MAP_ENGINE_IDS[o.engine]) { toast('请选择兼容引擎'); return; }
        if (/google|gstatic|openstreetmap|mapbox|bing\.com|apple|leaflet|carto/i.test(o.sdk)) {
          toast('合规限制：禁止接入未获资质的地图来源'); return;
        }
        var editId = w4.getAttribute('data-edit') || '';
        var list = mapCustomList().slice();
        var dup = list.some(function (x) { return x.id === o.id && x.id !== editId; });
        if (dup) { toast('接口 id 已存在'); return; }
        if (editId) {
          for (var j = 0; j < list.length; j++) if (list[j].id === editId) { o.id = editId; list[j] = o; break; }
        } else list.push(o);
        S.mapCustom = list;
        S.selProvider = o.id;
        w4.innerHTML = '';
        renderMapServiceParts();
        toast('自定义接口已加入列表（保存后生效）'); return;
      }
    };
  }

  // 2.0.0 B2：设置卡片内部分组 tab。所有 pane 一次性写进 DOM，
  // 绑定逻辑（btnSaveCfg / bindMapService / renderMapDiag 等）不受切换影响。
  function initSettingsTabs() {
    var box = $('settingsTabs'); if (!box) return;
    box.onclick = function (e) {
      var b = e.target, t = null;
      while (b && b !== box) {
        if (b.getAttribute && b.getAttribute('data-pane')) { t = b; break; }
        b = b.parentNode;
      }
      if (!t) return;
      var v = t.getAttribute('data-pane');
      S.settingsTab = v;
      Array.prototype.forEach.call($('settingsBody').querySelectorAll('.settings-pane'), function (p) {
        p.classList.toggle('on', p.getAttribute('data-pane') === v);
      });
      Array.prototype.forEach.call(box.querySelectorAll('.settings-tab'), function (x) {
        x.classList.toggle('on', x === t);
      });
    };
    if (S.settingsTab && S.settingsTab !== 'data') {
      var last = box.querySelector('.settings-tab[data-pane="' + S.settingsTab + '"]');
      if (last) last.click();
    }
  }

  // ---------------- 2.0.0 B3 · 预警通知（严格纯外发） ----------------
  // 配置走独立的 /api/notify/*；输入用 data-ng / data-nr / data-nf，
  // 不带 data-k，避免被 collectConfig() 收进主配置。
  function notifyChMeta(id) {
    var list = (S.notify && S.notify.channels) || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return { id: id, label: id, group: '', fields: [], note: '' };
  }
  function notifyFieldHtml(cid, f, val) {
    var v = (val === undefined || val === null) ? (f.default || '') : val;
    var attr = 'data-nf="' + esc(f.key) + '" data-cid="' + esc(cid) + '"';
    var lab = '<label class="notify-lab">' + esc(f.label) +
      (f.secret ? '<span class="notify-secret">已保存；留着不动即可，填新值覆盖，清空则删除</span>' : '') +
      '</label>';
    var input;
    if (f.type === 'select') {
      input = '<select ' + attr + '>' + (f.options || []).map(function (o) {
        return '<option value="' + esc(o) + '"' +
          (String(v) === String(o) ? ' selected' : '') + '>' + esc(o) + '</option>';
      }).join('') + '</select>';
    } else if (f.type === 'textarea') {
      input = '<textarea ' + attr + ' rows="2">' + esc(String(v)) + '</textarea>';
    } else {
      var t = f.type === 'number' ? 'number' : (f.secret ? 'password' : 'text');
      input = '<input type="' + t + '" ' + attr + ' value="' + esc(String(v)) + '"' +
        (f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : '') + '>';
    }
    return '<div class="notify-f">' + lab + input +
      (f.hint ? '<p class="hint">' + esc(f.hint) + '</p>' : '') + '</div>';
  }
  function notifyChannelHtml(ch) {
    var m = notifyChMeta(ch.channel);
    var cid = esc(ch.id);
    return '<div class="notify-ch" data-cid="' + cid + '">' +
      '<div class="notify-ch-head"><b>' + esc(m.label) + '</b>' +
      '<span class="notify-badge">' + (ch.enabled ? '已启用' : '已停用') + '</span>' +
      '<span style="flex:1"></span>' +
      '<button type="button" class="btn ghost" data-act="test" data-cid="' + cid + '">测试发送</button>' +
      '<button type="button" class="btn ghost" data-act="del" data-cid="' + cid + '">删除</button></div>' +
      '<input type="hidden" data-nf="channel" data-cid="' + cid + '" value="' + esc(ch.channel) + '">' +
      '<div class="notify-f"><label class="notify-lab">启用该渠道</label>' +
      '<label class="notify-sw"><input type="checkbox" data-nf="enabled" data-cid="' + cid + '"' +
      (ch.enabled ? ' checked' : '') + '> 发送时包含此渠道</label></div>' +
      notifyFieldHtml(ch.id, { key: 'title_prefix', label: '标题前缀', type: 'text',
                               default: '[ipsense]' }, ch.title_prefix) +
      (m.fields || []).map(function (f) {
        return notifyFieldHtml(ch.id, f, ch[f.key]);
      }).join('') +
      (m.note ? '<p class="hint" style="margin:8px 0 0">' + esc(m.note) + '</p>' : '') +
      '</div>';
  }
  function notifyRuleHtml(rule, rc) {
    rc = rc || {};
    return '<div class="form-group"><h3>' + esc(rule.label) + '</h3>' +
      '<p class="hint">' + esc(rule.desc) + '</p>' +
      '<label class="notify-sw"><input type="checkbox" data-nr="' + esc(rule.id) + '.enabled"' +
      (rc.enabled ? ' checked' : '') + '> 启用这条规则</label>' +
      '<div class="notify-grid">' + (rule.fields || []).map(function (f) {
        return '<div class="notify-f"><label class="notify-lab">' + esc(f.label) + '</label>' +
          '<input type="number" data-nr="' + esc(rule.id) + '.' + esc(f.key) + '" value="' +
          esc(rc[f.key] == null ? f.min : rc[f.key]) + '" min="' + f.min + '" max="' + f.max + '"></div>';
      }).join('') + '</div></div>';
  }
  function renderNotifyPane() {
    var host = $('notifyPane');
    if (!host || !S.notify) return;
    var r = S.notify, c = r.config || {}, st = r.stats || {};
    var channels = c.channels || [];
    var rulesHtml = (r.rules || []).map(function (rule) {
      return notifyRuleHtml(rule, (c.rules || {})[rule.id]);
    }).join('');
    var chansHtml = channels.map(notifyChannelHtml).join('') ||
      '<p class="hint">还没有配置渠道。从下方选一个渠道添加；不配渠道、不打开总开关，' +
      '就不会有任何外发。</p>';
    var addOpts = (r.channels || []).map(function (m) {
      return '<option value="' + esc(m.id) + '">' + esc(m.label) + ' · ' + esc(m.group) + '</option>';
    }).join('');
    var hist = (r.history || []).slice(0, 8).map(function (x) {
      return '<tr><td>' + esc(tm(x.at)) + '</td><td>' + esc(x.rule) + '</td>' +
        '<td>' + esc(x.ip || '—') + '</td><td>' + esc(x.title || '') + '</td>' +
        '<td class="' + (x.ok ? 'diag-ok' : 'diag-bad') + '">' +
        esc(x.ok) + '/' + esc(x.total) + '</td></tr>';
    }).join('');
    host.innerHTML =
      '<div class="redline-note">纯外发 · 只观测 · 不封禁 · 不改防火墙 · 不自动处置。' +
      '预警只把观测到的异常发到你配置的渠道，不写提交单、不调用处置通道。</div>' +
      '<div class="form-group"><h3>总开关与调度</h3>' +
      '<label class="notify-sw"><input type="checkbox" data-ng="enabled"' +
      (c.enabled ? ' checked' : '') + '> 启用预警通知（默认关闭）</label>' +
      '<div class="notify-grid">' +
      '<div class="notify-f"><label class="notify-lab">检测间隔（秒）</label>' +
      '<input type="number" data-ng="interval" value="' + esc(c.interval || 30) + '" min="10" max="3600"></div>' +
      '<div class="notify-f"><label class="notify-lab">同 IP 冷却（秒）</label>' +
      '<input type="number" data-ng="cooldown" value="' + esc(c.cooldown || 300) + '" min="30" max="86400"></div>' +
      '<div class="notify-f"><label class="notify-lab">全局配额（条/分钟）</label>' +
      '<input type="number" data-ng="global_rate" value="' + esc(c.global_rate || 10) + '" min="1" max="120"></div>' +
      '</div><p class="hint">冷却与全局配额用来避免 IP 抖动时刷屏、触发渠道限流' +
      '（PushPlus 实名 1 分钟 5 次、MeoW 3 秒 1 条最严）。</p></div>' +
      '<h3 style="margin:16px 0 8px">异常规则</h3>' + rulesHtml +
      '<h3 style="margin:16px 0 8px">通知渠道（' + channels.length + '）</h3>' + chansHtml +
      '<div class="form-group" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">' +
      '<select id="notifyAddSel">' + addOpts + '</select>' +
      '<button type="button" class="btn" data-act="add">添加渠道</button></div>' +
      '<div class="notify-save-tip">配置改动与所有分组一样，统一点右上角 ' +
      '<strong>「保存配置」</strong> 生效；「立即检测一次」用的是后端已保存的配置。</div>' +
      '<div style="display:flex;gap:10px;flex-wrap:wrap;margin:12px 0">' +
      '<button type="button" class="btn" data-act="dispatch">立即检测一次</button>' +
      '<button type="button" class="btn ghost" data-act="refresh">刷新状态</button></div>' +
      '<div class="diag-box" style="margin:10px 0">检测 ' + num(st.ticks || 0) +
      ' 轮 · 告警 ' + num(st.alerts || 0) + ' 条 · 成功 ' + num(st.sent || 0) +
      ' · 失败 ' + num(st.failed || 0) + ' · 抑制 ' + num(st.suppressed || 0) +
      ' · 启用渠道 ' + num(st.channels_enabled || 0) +
      (st.last_error ? '<br>上次错误：' + esc(st.last_error) : '') + '</div>' +
      '<h3 style="margin:16px 0 8px">最近预警</h3>' +
      '<table class="notify-hist"><thead><tr><th>时间</th><th>规则</th><th>IP</th>' +
      '<th>标题</th><th>成功/总数</th></tr></thead><tbody>' +
      (hist || '<tr><td colspan="5">暂无预警记录</td></tr>') + '</tbody></table>';
  }
  function collectNotify() {
    var host = $('notifyPane');
    var cfg = { rules: { scan: {}, traffic: {} }, channels: [] };
    Array.prototype.forEach.call(host.querySelectorAll('[data-ng]'), function (el) {
      cfg[el.getAttribute('data-ng')] = el.type === 'checkbox' ? el.checked : Number(el.value);
    });
    Array.prototype.forEach.call(host.querySelectorAll('[data-nr]'), function (el) {
      var p = el.getAttribute('data-nr').split('.');
      cfg.rules[p[0]][p[1]] = el.type === 'checkbox' ? el.checked : Number(el.value);
    });
    var byId = {};
    Array.prototype.forEach.call(host.querySelectorAll('[data-nf]'), function (el) {
      var cid = el.getAttribute('data-cid');
      if (!byId[cid]) byId[cid] = { id: cid };
      byId[cid][el.getAttribute('data-nf')] =
        el.type === 'checkbox' ? el.checked : el.value;
    });
    Object.keys(byId).forEach(function (k) { cfg.channels.push(byId[k]); });
    return cfg;
  }
  function notifyAddChannel() {
    var sel = $('notifyAddSel');
    if (!sel || !S.notify) return;
    var m = notifyChMeta(sel.value);
    var ch = { id: 'ch-' + Date.now().toString(36), channel: sel.value,
               enabled: true, title_prefix: '[ipsense]' };
    (m.fields || []).forEach(function (f) { ch[f.key] = f.default || ''; });
    var box = document.createElement('div');
    box.innerHTML = notifyChannelHtml(ch);
    var host = $('notifyPane');
    host.insertBefore(box.firstChild, sel.parentNode);
  }
  function bindNotify() {
    var host = $('notifyPane');
    if (!host) return;
    host.innerHTML = '<p class="hint">正在读取预警配置…</p>';
    api('api/notify/state').then(function (r) {
      if (!r.ok) throw new Error(r.msg || '读取失败');
      S.notify = r;
      renderNotifyPane();
    }).catch(function (e) {
      host.innerHTML = '<div class="diag-box">读取失败：' + esc(e.message) +
        '。预警通知为可选功能，不影响采集与统计。</div>';
    });
    if (host.__bound) return;
    host.__bound = true;
    host.onclick = function (e) {
      var t = e.target;
      var act = t && t.getAttribute ? t.getAttribute('data-act') : null;
      if (!act) return;
      if (act === 'add') { notifyAddChannel(); return; }
      if (act === 'del') {
        var card = t.closest ? t.closest('.notify-ch') : null;
        if (card && card.parentNode) card.parentNode.removeChild(card);
        return;
      }
      if (act === 'refresh') { bindNotify(); return; }
      // 2.0.0 返工：面板内已不再放独立「保存」按钮（统一走右上角），
      // 保留分支仅用于兼容旧缓存页面残留的按钮，不影响新交互与红线。
      if (act === 'save') {
        api('api/notify/config', 'POST', collectNotify()).then(function (r) {
          if (!r.ok) throw new Error(r.msg || '保存失败');
          toast('预警配置已保存 · ' + (r.changed || []).length + ' 项变更');
          bindNotify();
        }).catch(function (er) { toast('保存失败：' + er.message); });
        return;
      }
      if (act === 'dispatch') {
        api('api/notify/dispatch', 'POST', {}).then(function (r) {
          toast('已触发一次检测：' + ((r.data && r.data.alerts) || 0) + ' 条告警');
          setTimeout(bindNotify, 800);
        }).catch(function (er) { toast('检测失败：' + er.message); });
        return;
      }
      if (act === 'test') {
        var cid = t.getAttribute('data-cid');
        var one = collectNotify().channels.filter(function (x) {
          return x.id === cid;
        })[0];
        if (!one) { toast('找不到该渠道'); return; }
        t.disabled = true; t.textContent = '发送中…';
        api('api/notify/test', 'POST', { channel: one }).then(function (r) {
          t.disabled = false; t.textContent = '测试发送';
          toast(r.ok ? ('测试发送成功：' + (r.msg || '')) :
                       ('测试失败：' + (r.msg || '')));
          setTimeout(bindNotify, 600);
        }).catch(function (er) {
          t.disabled = false; t.textContent = '测试发送';
          toast('测试失败：' + er.message);
        });
      }
    };
  }

  // 2.0.0 返工：设置抽屉「未保存修改」提示。只做视觉标记，
  // 不弹阻塞式 confirm，避免打断低配 WebView 与自动化验收。
  function updateSaveBadge() {
    var badge = $('saveBadge'), btn = $('btnSaveCfg');
    if (badge) badge.hidden = !S.settingsDirty;
    if (btn) btn.classList.toggle('dirty', !!S.settingsDirty);
  }
  // 2.0.0 返工：一次点击统一保存时，顺带收集预警通知的独立配置。
  // 预警输入用 data-ng / data-nr / data-nf，与 collectConfig() 的
  // data-k 完全不重叠，不会串值；面板未加载时返回 null 跳过。
  function collectNotifySafe() {
    var host = $('notifyPane');
    if (!host || !S.notify || !host.querySelector('[data-ng]')) return null;
    try { return collectNotify(); } catch (e) { return null; }
  }
  function renderSettings(sources) {
    S.mapKeysDraft = {};
    S.mapCustom = JSON.parse(JSON.stringify(S.cfg.map_custom || []));
    S.selProvider = S.mapProvider || 'tencent';
    var src = (sources && sources.tailers || []).map(function (t) {
      return '<div class="src-line"><span>' + esc(t.name) + '</span><span>' +
        (t.exists ? (t.error ? '读取异常' : '已读取 ' + num(t.count) + ' 条') : '文件不存在') + '</span></div>';
    }).join('');
    var html = '' +
      '<div class="settings-tabs" id="settingsTabs">' +
      '<button type="button" class="settings-tab on" data-pane="data">数据来源</button>' +
      '<button type="button" class="settings-tab" data-pane="geo">归属核验</button>' +
      '<button type="button" class="settings-tab" data-pane="map">地图与位置</button>' +
      '<button type="button" class="settings-tab" data-pane="collect">采集策略</button>' +
      '<button type="button" class="settings-tab" data-pane="diag">诊断与反馈</button>' +
      '<button type="button" class="settings-tab" data-pane="notify">预警通知</button>' +
      '</div>' +
      '<div class="settings-pane on" data-pane="data">' +
      '<div class="form-group"><h3>数据来源</h3><p class="hint">采集器在点右上角「保存配置」后自动重载，无需重启应用。' +
      '路由器请把 syslog 指向本机 UDP 端口；也可把日志文件放进导入目录。</p>' +
      sw('source_local_auth', '本机日志 · SSH 认证', '/var/log/auth.log，需 root 读取') +
      sw('source_local_web', '本机日志 · Web 访问', 'fnOS nginx access.log') +
      sw('source_router_syslog', '路由器日志 · Syslog 接收', 'UDP 监听，默认 5514') +
      fld('syslog_port', 'Syslog UDP 端口', 'number') +
      fld('inbox_dir', '路由器日志导入目录', 'text', '放入 .log / .txt 文件即自动解析，避免重复导入请换文件名。') +
      sw('source_knock', '端口敲门 · 内核日志', '需先在路由器转发敲门端口并启用内核日志标记') +
      sw('source_knock_app', '敲门网关 · 请求日志', '只读 fn-knock-lite 按天分片的 JSON 日志，默认关闭') +
      fld('knock_app_dir', '敲门网关日志目录', 'text',
          '填敲门网关运行目录下的 logs 目录。日志开关请在敲门应用里开启，本应用不会替你改对方配置。') +
      fld('knock_app_port', '敲门网关入口端口', 'number') +
      '<div class="form-group" style="margin:14px 0 0;padding:12px;border:1px solid var(--line);border-radius:10px">' +
      '<h3 style="margin:0 0 8px">Lucky 日志（解析器框架 · 预留）</h3>' +
      '<p class="hint">真机只读取证确认当前 lucky 无落盘文本日志，本批次只落地解析器框架与两个新来源，' +
      '不接实时 tail、不改 lucky 任何配置。等后台「日志中心」提供原始文本样例后再校准正则并接入。</p>' +
      sw('source_lucky_web', 'Lucky 反代 Web 日志', '预留开关，默认关闭；当前不接 tail') +
      sw('source_lucky_sys', 'Lucky 系统运行日志', '预留开关，默认关闭；当前不接 tail') +
      fld('lucky_web_log', 'Lucky 反代日志路径', 'text', '仅当 lucky 开启日志落盘并填写绝对路径后才有意义，留空不启用。') +
      fld('lucky_sys_log', 'Lucky 系统日志路径', 'text', '同上；应用不会替你创建或修改 lucky 日志文件。') +
      '</div>' +
      sw('source_fnos_audit', 'fnOS 结构化登录审计', '解析 auth.log 里的 TRIMEVENT JSON，可区分登录成功与认证失败') +
      sw('source_auth_rotated', '回填 SSH 轮转日志', '读取 auth.log.1 / .gz 里的历史失败登录，找回被漏采的攻击记录') +
      fld('auth_rotated_max', '轮转日志读取份数', 'number') +
      sw('lan_separate', '内网设备单独归类', '局域网访问不计入公网排名与地图，但仍保留在记录表') +
      fld('auth_log', 'SSH 日志路径') + fld('web_log', 'Web 日志路径') + fld('kern_log', '内核日志路径') +
      fld('web_scheme_override', 'Web 协议覆盖（留空 / http / https）', 'text',
          'Nginx combined 日志的 $request 不含 scheme，这正是「Web 未识别」的成因。' +
          '留空时只信同站来路推断；若整站走 HTTPS 可填 https 手动指定，不会伪造无法确认的协议。') +
      sw('web_scheme_by_port', '按已知端口补协议',
         '目标端口命中 443 / 8443 等标 HTTPS、80 / 5666 等标 HTTP，标低置信度') +
      fld('web_port_map', 'Web 日志端口映射（每行 路径=端口）', 'text',
          'combined 日志不含目标端口。填 /usr/trim/nginx/logs/access.log=5666 即可补录；' +
          'Docker 反代日志把容器日志路径写进同一份映射即可；留空不猜。') +
      sw('web_port_infer_referer', '同站来路推断端口',
         'Referer 明确写有同站端口时低置信度补录，端口列会标注来源') +
      '<p class="hint">端口读取优先级：日志行尾 $server_port → 日志内结构化端口字段 → ' +
      '请求行绝对 URL → 此处端口映射 → 同站来路推断（低置信度）。' +
      '全部读不到才显示「未记录」，绝不把应用自身端口硬塞进去。</p>' +
      '<p class="hint">结构化审计 ' + (sources && sources.fnos_audit ? '已启用' : '已关闭') +
      ' · 轮转日志 ' + (sources && sources.auth_rotated ? '已启用' : '已关闭') +
      ' · 局域网设备 ' + num(sources && sources.lan ? sources.lan.count : 0) + ' 条</p>' +
      '</div>' +
      summaryServiceHtml() +
      '</div>' +
      '<div class="settings-pane" data-pane="geo">' +
      '<div class="form-group"><h3>归属信息源 · 离线主裁决 + 参考源</h3>' +
      '<p class="hint">归属以内置 ip2region 离线库为主裁决，实测比两家在线源更稳；' +
      '`ip.sb` 仅作参考补坐标与空缺字段，不改写国家 / 省 / 市。' +
      '参考源分歧只降级置信度，在线不可用时完全回退离线库，不影响采集。</p>' +
      sw('geo_verify_enabled', '启用在线参考校验', '后台低频查询 ip.sb 补坐标与运营商，归属仍以离线库为准') +
      sw('geo_verify_auto', '新 IP 首次出现即自动核验',
         '1.1.15：新公网 IP 一入库就进后台队列，不用再手动点「批量校验高频 IP」') +
      sw('geo_district_enabled', '补充探测区级信息',
         '用独立源补区县（如蜀山区），不参与归属裁决，避免把国内库偏差带进来') +
      fld('geo_verify_days', '核验结果有效期（天）', 'number') +
      fld('geo_verify_batch', '后台批量校验 IP 数', 'number') +
      '<div id="geoSrcBox" class="diag-box"></div>' +
      '<div style="display:flex;gap:10px;margin-top:10px;flex-wrap:wrap">' +
      '<button class="btn" id="btnGeoRefresh">批量校验高频 IP</button>' +
      '<button class="btn ghost" id="btnGeoNormalize">订正历史归属</button></div>' +
      '<p class="hint" style="margin:8px 0 0">在「IP 来源画像」里点「立即在线核验」可单独复核某个 IP，' +
      '查看每个数据源的原始判定与置信度。「订正历史归属」会清洗旧版本留下的英文国名、IPv6 省份与错位坐标。' +
      '出口 IP 归属不等于设备物理位置。</p>' +
      '</div>' +
      '</div>' +
      '<div class="settings-pane" data-pane="map">' +
      '<div class="form-group"><h3>地图与位置</h3>' +
      '<p class="hint">渲染全球范围需使用合规底图服务。请到 ' +
      '<a href="https://lbs.qq.com/dev/console/application/mine" target="_blank" rel="noopener" style="color:var(--blue-l)">腾讯位置服务控制台</a> ' +
      '创建应用并申请 WebGL JavaScript GL 的 key，填到下方后刷新页面。' +
      '未配置时使用「卫星质感坐标散点示意」（纯抽象背景、不绘制任何边界、不拉取外部影像），数据功能不受影响。' +
      '请为 key 配置 Referer 白名单，不要提交到公开仓库。</p>' +
      mapServiceHtml() +
      '<div class="form-group" style="margin:14px 0 0;padding:12px;border:1px solid var(--line);border-radius:10px">' +
      '<h3 style="margin:0 0 8px">底图样式</h3>' +
      '<div class="field"><label>底图类型</label><select data-k="map_base" id="cfgMapBase">' +
      '<option value="satellite"' + (S.cfg.map_base === 'vector' ? '' : ' selected') + '>卫星影像（默认 · 无国界标注）</option>' +
      '<option value="vector"' + (S.cfg.map_base === 'vector' ? ' selected' : '') + '>矢量底图（含官方行政区划）</option>' +
      '</select></div>' +
      '<p class="compliance-note">卫星影像仅通过腾讯地图 GL JS 官方 SDK 的 ' +
      '<code>setBaseMap</code> 接入，不内置任何有效 KEY、不拉取裸瓦片、不篡改底图、不自绘或改绘国界 / 海岸线 / 行政区划边界；' +
      '边界一律以官方合规底图为准，版权与审图号由官方底图承载并保留，不隐藏、不裁剪。' +
      '请自行申请浏览器端 Key 并配置 Referer / 域名白名单；禁止接入 Google / Bing / Esri / OSM 等境外影像源。' +
      '卫星底图使用官方 features:[\'base\'] 只加载影像主体，不叠加国界 / 省界 / 行政区划标注；' +
      '未配置 KEY 的降级路径改为抽象卫星质感背景，同样不绘制任何边界、不拉取任何外部影像瓦片；' +
      '当前仅腾讯 GL JS 支持卫星底图，其它引擎保持矢量底图。' +
      '公开发布 / 商用前请另行确认商业授权与主管部门要求。</p>' +
      '</div>' +
      '<div class="form-group" style="margin:14px 0 0;padding:12px;border:1px solid var(--line);border-radius:10px">' +
      '<h3 style="margin:0 0 8px">弧线与性能</h3>' +
      '<p class="hint">弧线弯曲幅度与距离成比例，近距离不再鼓出大回环；' +
      '境内按省、境外按国家合并来源，尾迹由浅到深指向本机，细线不遮挡底图地名。</p>' +
      fld('map_arc_limit', '每张地图最多显示弧线（5–60）', 'number') +
      fld('map_arc_bend', '弧线弯曲幅度（0.04–0.28，越大越弯）', 'number', '', '0.01') +
      sw('map_arc_animate', '弧线流动光点', '底图 / 散点两条路径通用；关闭可进一步降低低配设备的 CPU 占用') +
      fld('map_refresh', '实时事件刷新间隔（秒）', 'number') +
      fld('map_heavy_refresh', '地图 / 统计刷新间隔（秒）', 'number') +
      '<p class="hint" style="margin:6px 0 0">2.0.0 起底图 / 散点两条路径都有流动光点；' +
      '动效覆盖层只画应用自有数据（IP 点 / 连线 / 本机装饰环），不绘制任何边界。' +
      '页面切到后台自动暂停刷新，回到前台立即补一次。' +
      '诊断面板可看当前绘制条数、合并 / 省略数量与重绘耗时。</p>' +
      sw('map_fx', '地图动效覆盖层', '总开关：关闭后不再有任何逐帧绘制，低配设备可关') +
      sw('map_fx_scan', '出口 IP 雷达波纹', '以本机 / 出口 IP 为中心一圈圈向外扩散的椭圆波纹') +
      sw('map_fx_reveal', '每 5 秒渐显新坐标点', '只在覆盖层渐显渐隐，不新增 / 不删除底图几何') +
      '</div>' +
      '<div style="margin:14px 0 4px;padding:12px;border:1px solid var(--line);border-radius:10px">' +
      '<h3 style="margin:0 0 8px">本机位置</h3>' +
      '<div id="locateBox" class="diag-box"></div>' +
      '<div id="locateResult" class="diag-box" style="display:none;margin-top:10px"></div>' +
      '<div style="display:flex;gap:10px;margin-top:10px;flex-wrap:wrap">' +
      '<button class="btn" id="btnLocate">自动定位本机</button></div>' +
      '<p class="hint" style="margin:10px 0 0">按宽带出口 IP 定位，会识别 clash 代理的第二个出口；' +
      '定位结果写入配置，升级重装不丢。也可直接在下方手动填写经纬度。</p>' +
      '</div>' +
      fld('home_lat', '本机纬度', 'number') + fld('home_lng', '本机经度', 'number') +
      fld('home_label', '本机标注', 'text') +
      '<p class="hint">本机位置与上方所有分组的配置，统一点右上角「保存配置」生效，无需刷新页面。</p>' +
      '</div>' +
      '<div class="form-group"><h3>底图诊断</h3>' +
      '<p class="hint">填了 key 仍看不到地图时，先看下面的状态，再对照排查项逐条检查。</p>' +
      '<div id="mapDiagBox" class="diag-box"></div>' +
      '<div style="display:flex;gap:10px;margin-top:10px;flex-wrap:wrap">' +
      '<button class="btn" id="btnRetryMap">重试底图</button>' +
      '<button class="btn ghost" id="btnCopyDiag">复制诊断信息</button></div>' +
      '<p class="hint">常见原因：① key 未勾选「WebGL JavaScript GL」产品；② key 的 Referer 白名单未包含本站地址' +
      '（如 ' + esc(location.host || 'http://设备IP:5666') + '）；③ 浏览器或插件拦截了地图服务域名；' +
      '④ 当日调用配额用尽；⑤ 上方「底图资源请求」显示被拒，基本可确定是白名单或配额。' +
      '以上只影响底图，采集与统计功能不受影响。</p>' +
      '</div>' +
      '</div>' +
      '<div class="settings-pane" data-pane="collect">' +
      '<div class="form-group"><h3>采集策略</h3>' +
      fld('keep_days', '记录保留天数', 'number') +
      fld('ignore_ips', '忽略的 IP（逗号分隔）', 'text') +
      sw('filter_self_web', '过滤软件自身访问',
         '1.1.30：丢弃 /app/ipsense/ 页面与 API 轮询，避免污染访问统计') +
      '<p class="hint">当前数据源状态：' +
      (sources && sources.syslog_ok ? 'Syslog 端口 ' + sources.syslog_port + ' 监听中' : 'Syslog 未监听') +
      ' · 端口敲门 ' + (sources && sources.knock_installed ? '已安装' : '未安装（预留）') +
      ' · 敲门网关 ' + (sources && sources.knock_app_enabled ? '已接入' : '未接入') + '</p>' + src +
      '</div>' +
      '<div class="form-group"><h3>区级归属校验接口（可选）</h3>' +
      '<p class="hint">离线库与在线参考源都不返回区县。这里可以填一个自己可用的 ' +
      'JSON 接口，在线核验时自动取「区」写回该 IP 的历史记录。' +
      'tool.hiofd.com 查询页能查到区县，但接口带反爬签名、不是公开 API，' +
      '不内置自动调用；请用画像里的「在线校验」人工核对后回填。</p>' +
      sw('geo_district_api_enabled', '启用自定义区级接口', '默认关闭；仅对境内且区县为空的 IP 请求') +
      fld('geo_district_api', '接口 URL（用 {ip} 占位）', 'text', '例 https://your-api/ip?ip={ip}，仅允许 https') +
      fld('geo_district_field', '区县字段路径', 'text', '例 data.district 或 district，支持点号层级') +
      '</div>' +
      '<div style="display:flex;gap:10px;flex-wrap:wrap">' +
      '<button class="btn" id="btnReload">重载采集器</button>' +
      '<button class="btn ghost" id="btnExport2">导出 CSV</button>' +
      '<button class="btn ghost" id="btnBackfill">回填历史日志</button></div>' +
      '<p class="hint" style="margin:8px 0 0">以上三项为即时操作，不需要保存；' +
      '任何分组里的配置改动，统一点右上角「保存配置」生效。</p>' +
      // 1.1.15：问题反馈出口放在设置最底部，一份文件就能定位「打不开 / 没数据 / 底图异常」
      '</div>' +
      '<div class="settings-pane" data-pane="diag">' +
      '<div class="form-group"><h3>问题反馈 · 运行日志一键导出</h3>' +
      '<p class="hint">把主运行日志、兜底副本、生命周期日志、应用状态与数据源状态合成一份纯文本。' +
      '地图 KEY / 令牌 / 口令会被抹除，来访 IP 只保留前两段（例 220.205.*.*），' +
      '精确坐标与本机位置描述也已剔除；应用中心心跳会折叠，不再淹没故障记录。' +
      '导出后直接贴到 Issue 即可，不必再手动翻服务器。</p>' +
      '<div style="display:flex;gap:10px;margin-top:10px;flex-wrap:wrap">' +
      '<button class="btn" id="btnDiagExport">导出运行日志（已脱敏）</button>' +
      '<button class="btn ghost" id="btnDiagView">先在界面预览</button></div>' +
      // 1.1.17：真正「软件运行时报出来的错」单独一份，含地图 SDK 专项与堆栈
      '<h3 style="margin-top:18px">运行报错一键导出（1.1.17）</h3>' +
      '<p class="hint">页面 JS 异常、地图 SDK 没正常加载、资源加载失败、接口 4xx/5xx 与超时，' +
      '现在会自动记录并脱敏落盘，关掉页面也不会丢。这份文件只收录真正报出来的错，' +
      '含「地图 SDK 专项」与逐条堆栈，最适合交给 AI 定位底图 / 白屏 / 接口问题。</p>' +
      '<div style="display:flex;gap:10px;margin-top:10px;flex-wrap:wrap">' +
      '<button class="btn" id="btnRtExport">导出运行报错（已脱敏）</button>' +
      '<button class="btn ghost" id="btnRtView">查看最近报错</button></div>' +
      '<div id="diagPreview" class="diag-box" style="display:none;margin-top:10px"></div>' +
      '<p class="hint" style="margin:8px 0 0">命令行用户也可以用仓库里的 ' +
      '<code>tools/diag_bundle.sh</code> 收集同样的信息并自动打 tar.gz。</p>' +
      '</div>' +
      '</div>' +
      '<div class="settings-pane" data-pane="notify">' +
      '<div id="notifyPane"></div>' +
      '</div>';
    $('settingsBody').innerHTML = html;
    // 2.0.0 返工：保存按钮移到抽屉右上角后，任何 pane 的改动都打「未保存」标记
    S.settingsDirty = false;
    updateSaveBadge();
    $('settingsBody').oninput = function () { S.settingsDirty = true; updateSaveBadge(); };
    $('settingsBody').onchange = function () { S.settingsDirty = true; updateSaveBadge(); };
    initSettingsTabs();
    bindMapService();
    bindSummary();
    renderMapDiag();
    renderLocate();
    renderGeoSources();
    bindNotify();
    $('btnGeoRefresh').onclick = function () {
      api('api/geo/refresh', 'POST', {}).then(function (r) {
        toast(r.msg || '已加入后台校验队列');
        setTimeout(renderGeoSources, 1500);
      }).catch(function (e) { toast('批量校验失败：' + e.message); });
    };
    $('btnGeoNormalize').onclick = function () {
      var b = this;
      b.disabled = true; b.textContent = '订正中…';
      api('api/geo/normalize', 'POST', {}).then(function (r) {
        b.disabled = false; b.textContent = '订正历史归属';
        var d = r.data || {};
        toast('订正完成：省份 ' + num(d.province_cleared) +
              ' / 国名 ' + num(d.country_fixed) +
              ' / 坐标 ' + num(d.coord_fixed) +
              ' / 缓存 ' + num(d.cache_fixed));
        loadHeavy();
        setTimeout(renderGeoSources, 800);
      }).catch(function (e) {
        b.disabled = false; b.textContent = '订正历史归属';
        toast('订正失败：' + e.message);
      });
    };
    $('btnLocate').onclick = function () {
      var b = this;
      b.disabled = true; b.textContent = '定位中…（约 5–15 秒）';
      $('locateResult').style.display = 'block';
      $('locateResult').innerHTML = kv('状态', '正在探测出口 IP…');
      api('api/locate', 'POST', {}).then(function (r) {
        b.disabled = false; b.textContent = '自动定位本机';
        if (!r.ok) {
          $('locateResult').innerHTML = kv('失败', r.msg || '未知原因', true);
          toast('定位失败：' + (r.msg || '未知原因'));
          return;
        }
        renderLocateResult(r);
        return api('api/config').then(function (c) {
          S.cfg = c.data;
          S.home = { lat: c.data.home_lat, lng: c.data.home_lng, label: c.data.home_label };
          ['home_lat', 'home_lng', 'home_label'].forEach(function (k) {
            var el = document.querySelector('[data-k="' + k + '"]');
            if (el) el.value = c.data[k];
          });
          renderLocate();
          loadAll();
          toast('定位完成：' + r.ip);
        });
      }).catch(function (e) {
        b.disabled = false; b.textContent = '自动定位本机';
        $('locateResult').innerHTML = kv('失败', e.message, true);
        toast('定位失败：' + e.message);
      });
    };
    $('btnRetryMap').onclick = function () {
      rebuildMap();
      toast('正在重试底图…');
      setTimeout(renderMapDiag, 800);
    };
    $('btnCopyDiag').onclick = function () {
      var txt = 'IP 动态感知 · 底图诊断\n' + mapDiag().map(function (x) {
        return x[0] + '：' + x[1];
      }).join('\n');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(function () { toast('诊断信息已复制'); });
      } else { toast(txt.replace(/\n/g, ' | ')); }
    };
    $('btnSaveCfg').onclick = saveConfig;
    $('btnReload').onclick = function () {
      api('api/reload', 'POST', {}).then(function () { toast('采集器已重载'); });
    };
    $('btnExport2').onclick = exportCsv;
    $('btnBackfill').onclick = function () {
      api('api/backfill', 'POST', {}).then(function () {
        toast('历史日志回填已在后台启动，约 10–60 秒后刷新页面');
      }).catch(function (e) { toast('回填失败：' + e.message); });
    };
    $('btnDiagExport').onclick = exportDiag;
    $('btnRtExport').onclick = exportRuntimeErrors;
    $('btnRtView').onclick = function () {
      var box = $('diagPreview');
      box.style.display = 'block';
      box.textContent = '正在读取最近运行时报错…';
      api('api/runtime/errors?limit=100').then(function (r) {
        var rows = (r && r.data) || [];
        if (!rows.length) {
          box.textContent = '当前没有采集到运行时报错。\n' +
            '页面 JS 异常、地图 SDK 加载失败、资源加载失败、接口失败会自动记录；' +
            '若刚升级，请复现一次问题后再查看。';
        } else {
          box.textContent = rows.map(function (e, i) {
            var d = new Date(Number(e.ts || 0) * 1000);
            return (i + 1) + '. [' + d.toLocaleString() + '] ' +
              (e.level || '') + ' · ' + (e.kind || '') +
              (Number(e.count) > 1 ? ' ×' + e.count : '') + '\n   ' +
              (e.msg || '') +
              (e.src ? '\n   来源: ' + e.src : '') +
              (e.stack ? '\n   堆栈: ' + String(e.stack).slice(0, 300) : '');
          }).join('\n');
        }
        box.style.whiteSpace = 'pre-wrap';
        box.style.maxHeight = '320px';
        box.style.overflowY = 'auto';
        box.style.fontFamily = 'ui-monospace,Menlo,Consolas,monospace';
        box.style.fontSize = '11px';
      }).catch(function (e) { box.textContent = '读取失败：' + e.message; });
    };
    $('btnDiagView').onclick = function () {
      var box = $('diagPreview');
      box.style.display = 'block';
      box.textContent = '正在生成脱敏诊断包…';
      fetchDiag().then(function (txt) {
        box.textContent = txt;
        box.style.whiteSpace = 'pre-wrap';
        box.style.maxHeight = '320px';
        box.style.overflowY = 'auto';
        box.style.fontFamily = 'ui-monospace,Menlo,Consolas,monospace';
        box.style.fontSize = '11px';
      }).catch(function (e) { box.textContent = '生成失败：' + e.message; });
    };
  }
  function applyCfg() {
    S.arcLimit = Math.max(5, Math.min(60, Number(S.cfg.map_arc_limit) || 16));
    S.arcBend = Math.max(0.04, Math.min(0.28, Number(S.cfg.map_arc_bend) || 0.12));
    S.arcAnimate = S.cfg.map_arc_animate !== false;
    // 2.0.0 B4：动效覆盖层三个开关（默认全开，关掉即零逐帧绘制）
    S.fx.on = S.cfg.map_fx !== false;
    S.fx.scan = S.cfg.map_fx_scan !== false;
    S.fx.revealOn = S.cfg.map_fx_reveal !== false;
    // 2.0.0 返工：默认卫星影像，仅显式选「矢量底图」才回退；
    // 卫星走官方 features:['base']，不叠加国界 / 省界标注。
    S.mapBase = S.cfg.map_base === 'vector' ? 'vector' : 'satellite';
    // 2.0.0 返工：动效总开关真正启停逐帧定时器；
    // 定时器从启动起常驻，不再被「底图加载完成」停掉。
    if (S.fx.on) startCanvasAnim(); else stopCanvasAnim();
  }
  function collectConfig() {
    var patch = {};
    Array.prototype.forEach.call($('settingsBody').querySelectorAll('[data-k]'), function (el) {
      var k = el.getAttribute('data-k');
      if (el.type === 'checkbox') patch[k] = el.checked;
      else if (el.type === 'number') patch[k] = Number(el.value);
      else if (k === 'ignore_ips') patch[k] = el.value.split(/[,，\s]+/).filter(Boolean);
      else patch[k] = el.value;
    });
    // 1.1.8：每家（含自定义接口）的 KEY 分别收集，服务商选择与自定义列表一并提交
    var mk = {};
    Array.prototype.forEach.call($('settingsBody').querySelectorAll('[data-mk]'), function (el) {
      mk[el.getAttribute('data-mk')] = el.value;
    });
    patch.map_keys = mk;
    patch.map_custom = mapCustomList();
    return patch;
  }
  function saveConfig() {
    // 2.0.0 返工：右上角「保存配置」一次点完，全局配置 + 预警通知一起提交。
    // 两条链路输入域互不重叠（data-k vs data-ng/data-nr/data-nf），
    // 不会出现「改了地图与位置还要切到采集策略去保存」的割裂。
    var notifyPatch = collectNotifySafe();
    api('api/config', 'POST', collectConfig()).then(function (r) {
      if (!r.ok) throw new Error(r.msg || '保存失败');
      var changed = r.changed || [];
      return api('api/config').then(function (c) {
        var next = notifyPatch
          ? api('api/notify/config', 'POST', notifyPatch).then(function (nr) {
              if (!nr.ok) throw new Error('预警配置：' + (nr.msg || '保存失败'));
              return nr;
            })
          : Promise.resolve(null);
        return next.then(function (nr) {
          toast('配置已保存 · ' + changed.length + ' 项变更' +
                (nr ? ' · 预警配置已同步' : ''));
          S.cfg = c.data;
          S.summary = c.data.summary || S.summary;
          S.mapConfigured = !!c.data.map_configured;
          S.mapProvider = c.data.map_provider || 'tencent';
          S.mapKeysDraft = null; S.mapCustom = null;
          S.home = { lat: c.data.home_lat, lng: c.data.home_lng, label: c.data.home_label };
          S.settingsDirty = false; updateSaveBadge();
          applyCfg();
          closeDrawers(); loadAll();
          requestMapDraw(true);
          // 1.1.8：服务商 / KEY / 自定义接口任一变更，都销毁旧引擎后重建
          var mapChanged = ['map_provider', 'map_keys', 'map_custom', 'map_key', 'map_base']
            .some(function (k) { return changed.indexOf(k) >= 0; });
          if (mapChanged || (!mapIsConfigured() && S.tmapReady)) rebuildMap();
          updateBanner();
        });
      });
    }).catch(function (e) { toast('保存失败：' + e.message); });
  }
  function exportCsv() {
    fetch(url('api/export?range=' + S.range)).then(function (r) { return r.blob(); }).then(function (b) {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(b);
      a.download = 'ipsense-' + S.range + '-' + Date.now() + '.csv';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 3000);
    });
  }
  // 1.1.15：运行日志一键导出。后端 /api/diag/export 返回的是 text/plain，
  // 不能走 api() 的 r.json()，这里单独取文本；下载与预览共用同一份内容。
  function fetchDiag() {
    return fetch(url('api/diag/export')).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    });
  }
  function exportDiag() {
    fetchDiag().then(function (txt) {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([txt], { type: 'text/plain;charset=utf-8' }));
      a.download = 'ipsense-diag-' + new Date().toISOString().replace(/[:.]/g, '-') + '.txt';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 3000);
      toast('运行日志已导出（已脱敏）');
    }).catch(function (e) { toast('导出失败：' + e.message); });
  }
  // 1.1.17：运行报错独立导出。后端返回 text/plain，不能走 api() 的 r.json()。
  function fetchRuntimeText() {
    return fetch(url('api/runtime/errors/export')).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    });
  }
  function exportRuntimeErrors() {
    fetchRuntimeText().then(function (txt) {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([txt], { type: 'text/plain;charset=utf-8' }));
      a.download = 'ipsense-runtime-errors-' +
        new Date().toISOString().replace(/[:.]/g, '-') + '.txt';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 3000);
      toast('运行报错已导出（已脱敏）');
    }).catch(function (e) {
      rtPush({ kind: 'api', msg: '导出运行报错失败：' + e.message,
               url: 'api/runtime/errors/export' });
      toast('导出失败：' + e.message);
    });
  }

  // ---- IP 详情：表格行点击与地图圆点点击共用同一套「IP 来源画像」版式 ----
  function openDetail(ip, groupHit) {
    $('detailTitle').textContent = 'IP 来源画像';
    openDrawer('detailDrawer');
    $('detailBody').innerHTML = '<div class="empty">正在读取该 IP 的访问画像…</div>';
    ensureOrders().then(function () {
      return api('api/ip?ip=' + encodeURIComponent(ip));
    }).then(function (r) {
      var g = r.geo || {}, i = r.data.info || {}, a = r.data.agg || {};
      var loc = [g.country, g.province, g.city, g.district, g.isp].filter(function (x) { return x && x !== '0'; }).join(' · ');
      var rows = [
        ['IP 地址', ip], ['归属地', loc || '未知'], ['范围', SCOPE_NAME[g.scope] || '未知'],
        ['坐标', (g.lat != null ? g.lat + ', ' + g.lng : '—')],
        ['累计访问', num(a.n) + ' 次'], ['首次 / 末次', tm(a.first_ts) + ' → ' + tm(a.last_ts)],
        ['目标端口', portLabel(i.port, i.source) +
          '<small style="color:var(--dim);display:block;font-size:11px">' +
          esc(portHint(i.port_src)) + '</small>'],
        ['来源通道', SRC_NAME[i.source] || i.source || '—'],
        ['最近判定', VERDICT_NAME[i.verdict] || i.verdict || '—'],
        ['访问协议', (PROTO_NAME[i.proto] || i.proto || '未识别') +
          (i.scheme_conf ? ' · ' + (SCHEME_CONF[i.scheme_conf] || i.scheme_conf) : '')],
        ['请求方法 / 状态', i.method ? (i.method + ' · ' + (i.status || '—')) : '—'],
        ['入口页会话', num(a.sessions || 0) + ' 个']
      ];
      // 1.1.22：把画像证据做成快照，随标注写入提交单。
      // 只保留展示字段，不携带任何可执行内容；note 由后端统一清洗后放进数据区。
      S.currentEvidence[ip] = {
        geo: loc || '未知', scope: SCOPE_NAME[g.scope] || '未知',
        n: a.n || 0, first: tm(a.first_ts), last: tm(a.last_ts),
        verdict: VERDICT_NAME[i.verdict] || i.verdict || '—',
        proto: PROTO_NAME[i.proto] || i.proto || '未识别',
        port: String(i.port || '—'),
        source: SRC_NAME[i.source] || i.source || '—',
        paths: (r.data.top_paths || []).slice(0, 8).map(function (p) {
          return p.path + ' (' + num(p.n) + ' 次)';
        }),
        recent: (r.data.recent || []).slice(0, 6).map(function (x) {
          return tm(x.ts) + ' ' + (VERDICT_NAME[x.verdict] || x.verdict || '') +
            ' ' + (x.action || x.path || '');
        })
      };
      var h = profileHead(ip, loc, ip) + '<div style="margin:14px 0">' +
        rows.map(function (x) { return kvRow(x[0], x[1]); }).join('') + '</div>';
      // 从地图圆点进入时，追加同组 IP 切换与返回入口
      if (groupHit) h += samePointBlock(groupHit, ip);
      // 1.1.1：热点 IP 明细按最近窗口聚合，口径必须如实标注，避免误读为全历史
      var w = r.data.window || {};
      if (w.truncated) {
        h += '<div class="verify-box"><p class="hint" style="margin:0">' +
          '统计口径：仅「累计访问 / 首次 · 末次」为该 IP 的全历史精确值；' +
          '会话数、端口 / 路径去重数，以及下方协议、来路、路径、设备等明细，' +
          '均基于最近 ' + num(w.rows) + ' 条动作（窗口上限 ' + num(w.limit) +
          ' 条）。超高频 IP 不再做全历史聚合，因此画像可以秒开。</p></div>';
      }
      // 1.1.0：协议与判定拆成两个维度，一眼看出「HTTPS 正常访问」还是「TCP 扫描爆破」
      var protos = r.data.protocols || [];
      h += '<h3 style="font-size:13px;margin:18px 0 8px">访问协议构成 · 协议 × 判定</h3>' +
        (protos.length ? protos.map(function (x) {
          var bad = (r.data.verdicts || []).filter(function (v) {
            return v.k !== 'normal' && v.n > 0;
          }).length;
          return '<div class="src-line"><span>' + protoChip(x.k) +
            (x.manual ? ' <small style="color:var(--amber)">手动指定</small>' : '') +
            '</span><span>' + num(x.n) + ' 次' + (bad ? ' · 含异常判定' : '') + '</span></div>';
        }).join('') : '<div class="empty">无协议记录</div>');
      var refs = r.data.referrers || [];
      h += '<h3 style="font-size:13px;margin:18px 0 8px">来路 TOP</h3>' +
        (refs.length ? refs.map(function (x) {
          var n = x.k === '-' ? '直接输入网址 / 无来路' : x.k;
          return '<div class="src-line"><span style="max-width:300px;overflow:hidden;' +
            'text-overflow:ellipsis;white-space:nowrap">' + esc(n) +
            '</span><span>' + num(x.n) + ' 次</span></div>';
        }).join('') : '<div class="empty">无来路记录</div>');
      var uas = r.data.uas || [];
      h += '<h3 style="font-size:13px;margin:18px 0 8px">终端设备（User-Agent）</h3>' +
        (uas.length ? uas.map(function (x) {
          return '<div class="src-line"><span style="max-width:300px;overflow:hidden;' +
            'text-overflow:ellipsis;white-space:nowrap">' + esc((x.ua || '').slice(0, 90)) +
            '</span><span>' + num(x.n) + ' 次</span></div>';
        }).join('') : '<div class="empty">无 UA 记录</div>');
      h += verifyBlock(ip, r.verification);
      h += '<h3 style="font-size:13px;margin:18px 0 8px">路径明细 · 高频路径</h3>' +
        '<p class="hint" style="margin:0 0 8px">表格已把同秒同 IP 的请求合并，这里查看该 IP 的完整路径。</p>' +
        pathBlock(r.data.top_paths, a.paths);
      h += '<h3 style="font-size:13px;margin:18px 0 8px">最近 20 条动作</h3>' +
        ((r.data.recent || []).slice(0, 20).map(function (x) {
          return '<div class="src-line"><span>' + tm(x.ts) + ' · ' + protoChip(x.proto) + ' · ' +
            esc(VERDICT_NAME[x.verdict] || x.verdict) + ' · ' + esc(x.action || x.path) +
            '</span><span>' + portLabel(x.port, x.source) + '</span></div>';
        }).join('') || '<div class="empty">无记录</div>');
      $('detailBody').innerHTML = h;
      bindDetailEvents($('detailBody'), ip, groupHit);
    }).catch(function (e) { $('detailBody').innerHTML = '<div class="empty">' + esc(e.message) + '</div>'; });
  }

  // ---- 频率色阶图例：与 ARC_HEAT 共用单一数据源，改色阶时无需两处同步 ----
  function renderHeatLegends() {
    var sw = ARC_HEAT.map(function (c, i) {
      return '<i class="hl-sw" style="background:' + c +
             '" title="' + HEAT_NAME[i] + '（本图内相对频率）"></i>';
    }).join('');
    ['worldHeat', 'cnHeat'].forEach(function (id) {
      var el = $(id); if (!el) return;
      el.innerHTML = '<span class="hl-txt">连接频率</span>' +
        '<span class="hl-scale">' + sw + '</span>' +
        '<span class="hl-txt">低 → 高</span>';
    });
  }

  // ---- 事件绑定 ----
  // ---- 1.1.18 · 各功能区筛选设定持久化 ----
  // 用户要求「实时访问事件选境内、IP 来源记录选境外，下次打开保持」。
  // 各功能区用独立字段存同一份 JSON；搜索词 fQuery 不持久化（避免下次
  // 打开还带着上一次的临时搜索条件）。localStorage 不可用时静默降级。
  var UI_PREF_KEY = 'ipsense.ui.filters.v1';
  function readUiPref() {
    try { return JSON.parse(localStorage.getItem(UI_PREF_KEY) || '{}') || {}; }
    catch (e) { return {}; }
  }
  function writeUiPref(patch) {
    try {
      var p = readUiPref();
      Object.keys(patch).forEach(function (k) { p[k] = patch[k]; });
      localStorage.setItem(UI_PREF_KEY, JSON.stringify(p));
    } catch (e) {}
  }
  function applyUiPref() {
    var p = readUiPref();
    ['liveScope', 'fScope', 'fVerdict', 'fProto', 'fSource'].forEach(function (id) {
      var v = p[id === 'liveScope' ? 'live' : id];
      if (!v) return;
      var el = $(id);
      if (!el || !el.options) return;
      var hit = false;
      Array.prototype.forEach.call(el.options, function (o) { if (o.value === v) hit = true; });
      if (hit) el.value = v;
    });
    S.liveScope = $('liveScope').value || '';
    // 1.1.21：地图模式与筛选设定同一份偏好，下次打开保持上次选的那张图
    if (p.mapMode) setMapMode(p.mapMode, false);
    if (p.range) {
      S.range = p.range;
      Array.prototype.forEach.call($('rangeSeg').querySelectorAll('button[data-r]'), function (b) {
        if (b.getAttribute('data-r') === S.range) b.classList.add('on');
        else b.classList.remove('on');
      });
    }
    if (p.trend) {
      S.trendKey = p.trend;
      Array.prototype.forEach.call($('trendLegend').querySelectorAll('button[data-k]'), function (b) {
        if (b.getAttribute('data-k') === S.trendKey) b.classList.add('on');
        else b.classList.remove('on');
      });
    }
  }

  // ---- 1.1.22 · IP 标注 / 提交单 / 读取提示词 ----
  // 主包只把标注与证据写进后端 orders.json，再生成一段提示词交给外部 agent。
  // 这里没有任何执行命令、没有防火墙操作，也永远不会主动连接 agent。
  var ordersPending = null;
  function ensureOrders() {
    if (S.orders) return Promise.resolve(S.orders);
    if (!ordersPending) {
      ordersPending = api('api/orders').then(function (r) {
        S.orders = (r && r.data) || { items: [] };
        updateOrdersBadge(); showOrdersPath();
        return S.orders;
      }).catch(function () {
        S.orders = { items: [] }; ordersPending = null; return S.orders;
      });
    }
    return ordersPending;
  }
  function findOrder(ip) {
    var list = (S.orders && S.orders.items) || [];
    for (var i = 0; i < list.length; i++) if (list[i].ip === ip) return list[i];
    return null;
  }
  // ---- 1.1.25 · 提交单四区看板 -------------------------------------------
  // 规矩/大脑在 skill，mh CLI 是 agent 唯一手眼。这里只把后端 orders.json 的
  // status 状态渲染成四个功能区，不产生任何处置动作、不改防火墙设置。
  var TAB_DEF = {
    pending: {label:'待处理', cmd:'mh read pending', copy:'复制读取提示词',
              empty:'待处理还是空的。<br>在「IP 来源画像」里给 IP 写标注并保存，就会自动放进这里。'},
    done:    {label:'已完成', cmd:'mh read done', copy:'',
              empty:'还没有已完成的条目。<br>把待处理的一句话提示词发给 agent，它通过 mh 提交后会显示在这里。'},
    revert:  {label:'待撤回', cmd:'mh read revert', copy:'复制复原提示词',
              empty:'待撤回是空的。<br>在「已完成」区对某条点「待撤回」，它会出现在这里，再复制复原提示词发给 agent。'},
    all:     {label:'全部', cmd:'mh read all', copy:'',
              empty:'还没有任何操作记录。'}
  };
  var TAB_FILTER = {pending:['pending'], done:['done','restored'],
                    revert:['revert'], all:['pending','done','restored','revert']};
  function ordersTabCounts() {
    var c = {pending:0, done:0, revert:0, all:0};
    var list = (S.orders && S.orders.items) || [];
    for (var i = 0; i < list.length; i++) {
      var x = list[i]; if (x.in_order === false) continue;
      c.all++;
      var st = x.status || 'pending';
      if (st === 'pending') c.pending++;
      else if (st === 'done' || st === 'restored') c.done++;
      else if (st === 'revert') c.revert++;
    }
    return c;
  }
  function statusBadge(x) {
    var st = x.status || 'pending';
    var lb = {pending:'待处理', done:'已完成', revert:'待撤回', restored:'已复原'}[st] || st;
    return '<span class="order-status st-' + st + '">' + esc(lb) + '</span>';
  }
  function historyLine(x) {
    var h = x.history || []; if (!h.length) return '';
    var parts = [];
    for (var i = Math.max(0, h.length - 4); i < h.length; i++) {
      var e = h[i];
      var lb = {pending:'待处理', done:'已完成', revert:'待撤回',
                restored:'已复原', '':'移出'}[e.to] || e.to || '—';
      parts.push('<span class="hist-step">' + (e.by === 'agent' ? 'AI' : '你') +
                 '·' + esc(lb) + '</span>');
    }
    return '<div class="order-hist">' +
           parts.join('<span class="hist-arrow">→</span>') + '</div>';
  }
  function renderLog(log) {
    if (!log || !log.length) return '';
    var rows = log.slice(-30).reverse().map(function (e) {
      var lb = {pending:'待处理', done:'已完成', revert:'待撤回',
                restored:'已复原', '':'移出'}[e.to] || e.to || '—';
      return '<div class="log-row"><span>' + esc(tm(e.at)) + '</span>' +
             '<b>' + esc(e.ip || '—') + '</b>' +
             '<span>' + esc(e.action || '') + ' → ' + esc(lb) + '</span>' +
             '<span class="log-by">' + (e.by === 'agent' ? 'AI' : '你') + '</span></div>';
    }).join('');
    return '<div class="order-log"><div class="order-sum-label">操作流水（全部区域）</div>' +
           rows + '</div>';
  }
  function orderCard(x, tab) {
    var ip = esc(x.ip);
    var note = esc(x.note || '（未填写要求，仅保留观测证据）');
    var ev = esc(evidenceBrief(x.evidence) || '无额外证据');
    var sum = x.summary
      ? '<div class="order-sum"><div class="order-sum-label">AI 处理总结</div>' +
        esc(x.summary) + '</div>' : '';
    var acts = '<button type="button" class="link" data-oact="remove" data-ip="' +
               ip + '">移出</button>';
    if (tab === 'done' && x.status === 'done') {
      acts = '<button type="button" class="link" data-oact="toggle-sum" data-ip="' + ip + '">' +
             (S.ordersOpen[x.ip] ? '收起总结' : '查看 AI 总结') + '</button>' +
             '<button type="button" class="link warn" data-oact="revert" data-ip="' +
             ip + '">待撤回</button>' + acts;
    }
    var openCls = (tab === 'done' && S.ordersOpen[x.ip]) ? ' open' : '';
    var badge = (tab === 'all' || x.status === 'restored') ? statusBadge(x) : '';
    return '<div class="order-item' + openCls + '">' +
      '<div class="order-head"><b>' + ip + '</b>' + badge +
      '<span>' + esc(tm(x.updated)) + '</span>' + acts + '</div>' +
      '<div class="order-note">' + note + '</div>' +
      '<div class="order-ev">' + ev + '</div>' + sum +
      (tab === 'all' ? historyLine(x) : '') + '</div>';
  }
  function renderOrders() {
    var box = $('ordersList'); if (!box) return;
    var tab = S.ordersTab || 'pending', def = TAB_DEF[tab] || TAB_DEF.pending;
    var filter = TAB_FILTER[tab];
    var list = ((S.orders && S.orders.items) || []).filter(function (x) {
      return x.in_order !== false && filter.indexOf(x.status || 'pending') >= 0;
    });
    list.sort(function (a, b) { return (b.updated || 0) - (a.updated || 0); });
    // 四个区的计数角标
    var c = ordersTabCounts();
    var cmap = {pending:'tabCountPending', done:'tabCountDone',
                revert:'tabCountRevert', all:'tabCountAll'};
    for (var k in cmap) { var el = $(cmap[k]); if (el) el.textContent = String(c[k]); }
    Array.prototype.forEach.call(document.querySelectorAll('#ordersTabs .orders-tab'),
      function (b) {
        if (b.getAttribute('data-otab') === tab) b.classList.add('on');
        else b.classList.remove('on');
      });
    // 读取命令 + 复制按钮随 tab 变化；已完成 / 全部是查看区，不显示复制按钮
    var rc = $('ordersReadCmd');
    if (rc) rc.textContent = '读取命令：' + def.cmd + ' · ' +
                             ((S.orders && S.orders.path) || '—');
    var cp = $('btnCopyPrompt');
    if (cp) {
      if (def.copy) { cp.style.display = ''; cp.textContent = def.copy; }
      else cp.style.display = 'none';
    }
    var logHtml = (tab === 'all') ? renderLog((S.orders && S.orders.log) || []) : '';
    if (!list.length) {
      box.innerHTML = '<div class="empty">' + def.empty + '</div>' + logHtml;
      return;
    }
    box.innerHTML = list.map(function (x) { return orderCard(x, tab); }).join('') + logHtml;
  }
  function switchOrdersTab(tab) {
    if (!TAB_DEF[tab]) return;
    S.ordersTab = tab;
    ensureOrders().then(function () { renderOrders(); showOrdersPath(); });
  }
  function requestRevert(ip) {
    api('api/orders', 'POST', { action: 'request-revert', ip: ip }).then(function (r) {
      S.orders = (r && r.data) || S.orders;
      updateOrdersBadge(); renderOrders();
      toast('已移入「待撤回」区，复制复原提示词发给 agent 即可');
    }).catch(function (e) { toast('操作失败：' + e.message); });
  }
  function toggleSummary(ip) { S.ordersOpen[ip] = !S.ordersOpen[ip]; renderOrders(); }
  function updateOrdersBadge() {
    var el = $('ordersBadge'); if (!el) return;
    var n = ordersTabCounts().pending;      // 顶栏角标只提示「待处理」的待办数
    el.textContent = n ? String(n) : '';
    if (n) el.removeAttribute('hidden'); else el.setAttribute('hidden', '');
  }
  function showOrdersPath() {
    var el = $('ordersPath'); if (!el || !S.orders) return;
    el.textContent = '提交单文件：' + (S.orders.path || '—') +
      ' · 四区状态 / 回执 / 流水：GET /api/mh/state · 写入：POST /api/mh/write（mh 唯一接口）';
    var rc = $('ordersReadCmd');
    if (rc) rc.textContent = '读取命令：' +
      (TAB_DEF[S.ordersTab] || TAB_DEF.pending).cmd + ' · ' + (S.orders.path || '—');
  }
  function evidenceBrief(ev) {
    ev = ev || {};
    return [ev.geo, ev.scope, ev.n ? (ev.n + ' 次') : '', ev.verdict, ev.proto,
            ev.port ? ('端口 ' + ev.port) : ''].filter(function (x) { return x; }).join(' · ');
  }
  // ---- 1.1.28：密钥授权（右上角入口 + 点击浮层，用户可知、随时可撤销）------
  // 数据来自 GET /api/keyauth/state；撤销走 POST /api/keyauth/revoke，
  // 只删本应用带标记的那行 authorized_keys 与设备上的密钥副本。
  // 浮层 absolute 定位、不占 .orders-card 的 flex 文档流，
  // 因此 90% / 100% / 125% 缩放下都不会挤压四区列表。
  function loadKeyAuth() {
    api('api/keyauth/state', 'GET').then(function (r) {
      S.keyauth = (r && r.data) || { grants: [] };
      renderKeyAuth();
    }).catch(function (e) {
      var el = $('keyauthList');
      if (el) el.innerHTML = '<div class="empty">读取授权失败：' + esc(e.message) + '</div>';
    });
  }
  function renderKeyAuth() {
    var box = $('keyauthList'), cnt = $('keyauthCount');
    if (!box) return;
    var gs = (S.keyauth && S.keyauth.grants) || [];
    var active = gs.filter(function (g) { return g.status === 'active'; }).length;
    if (cnt) cnt.textContent = String(active);
    if (!gs.length) {
      box.innerHTML = '<div class="empty">还没有授权任何设备。AI 首次通过 SSH 引导授权后，这里会列出指纹 / 公钥 / 时间 / 设备。</div>';
      return;
    }
    box.innerHTML = gs.map(function (g) {
      var revoked = g.status !== 'active';
      var fp = esc((g.fingerprint || '').slice(0, 48));
      var pk = esc((g.pubkey || '').slice(0, 60));
      return '<div class="keyauth-item' + (revoked ? ' is-revoked' : '') + '">' +
        '<div class="keyauth-row"><span class="keyauth-badge' + (revoked ? ' off' : '') + '">' +
        (revoked ? '已撤销' : '生效中') + '</span>' +
        '<span class="keyauth-dev">' + esc(g.device || '未命名设备') + '</span>' +
        '<span class="keyauth-time">' + esc(g.created_at || '') + '</span></div>' +
        '<div class="keyauth-fp">' + fp + '</div>' +
        '<div class="keyauth-pk">' + pk + (g.pubkey && g.pubkey.length > 60 ? '…' : '') + '</div>' +
        (g.key_on_device && !revoked ? '<div class="keyauth-devkey">设备上有私钥副本，撤销会一并删除</div>' : '') +
        (revoked ? '<div class="keyauth-revtime">撤销于 ' + esc(g.revoked_at || '') + '</div>' :
          '<button type="button" class="btn ghost keyauth-revoke" data-grant="' + esc(g.id) + '">撤销授权</button>') +
        '</div>';
    }).join('');
  }
  function keyauthIsOpen() {
    var p = $('keyauthPanel');
    return !!p && !p.hasAttribute('hidden');
  }
  function keyauthOpen() {
    var p = $('keyauthPanel'), tg = $('keyauthToggle');
    if (!p) return;
    p.removeAttribute('hidden');
    if (tg) tg.setAttribute('aria-expanded', 'true');
    loadKeyAuth();
  }
  function keyauthClose() {
    var p = $('keyauthPanel'), tg = $('keyauthToggle');
    if (p) p.setAttribute('hidden', '');
    if (tg) tg.setAttribute('aria-expanded', 'false');
  }
  function bindKeyAuth() {
    var tg = $('keyauthToggle'), panel = $('keyauthPanel'), list = $('keyauthList');
    if (tg && !tg._bound128) {
      tg._bound128 = true;
      tg.onclick = function (e) {
        e.stopPropagation();
        if (keyauthIsOpen()) keyauthClose(); else keyauthOpen();
      };
    }
    if (panel && !panel._bound128) {
      panel._bound128 = true;
      // 浮层内部点击不冒泡到卡片，避免点撤销按钮时浮层被收起
      panel.onclick = function (e) { e.stopPropagation(); };
    }
    if (list && !list._bound128) {
      list._bound128 = true;
      list.onclick = function (e) {
        var b = e.target.closest ? e.target.closest('.keyauth-revoke') : null;
        if (!b) return;
        var id = b.getAttribute('data-grant');
        if (!id) return;
        api('api/keyauth/revoke', 'POST', { grant_id: id }).then(function (r) {
          S.keyauth = (r && r.data) || S.keyauth;
          renderKeyAuth();
          toast('授权已撤销：设备私钥与 authorized_keys 行已删除');
        }).catch(function (err) { toast('撤销失败：' + err.message); });
      };
    }
    // 1.1.28：点浮层外（提交单卡片内任意处）收起浮层
    var card = $('ordersCard');
    if (card && !card._bound128) {
      card._bound128 = true;
      card.addEventListener('click', function (e) {
        if (!keyauthIsOpen()) return;
        // 用 contains 判断触点归属，避免引入 closest 相关子串（历史滚轮断言按子串检查）
        var t = e.target, tg0 = $('keyauthToggle'), p0 = $('keyauthPanel');
        if ((tg0 && (t === tg0 || tg0.contains(t))) ||
            (p0 && (t === p0 || p0.contains(t)))) return;
        keyauthClose();
      });
    }
  }
  function openOrders() {
    closeSponsor();
    bindKeyAuth();
    keyauthClose();          // 1.1.28：每次打开提交单都从「浮层收起」态开始
    loadKeyAuth();           // 角标仍立即刷新（浮层隐藏也能渲染）
    ensureOrders().then(function () { renderOrders(); showOrdersPath(); });
    $('ordersMask').classList.add('on');
    $('ordersCard').setAttribute('aria-hidden', 'false');
    setMapScroll(false);
  }
  function closeOrders() {
    keyauthClose();          // 1.1.28：关弹层时一并收起浮层
    $('ordersMask').classList.remove('on');
    $('ordersCard').setAttribute('aria-hidden', 'true');
    if (!drawerOpen() && !S.zoomOn && !$('aboutMask').classList.contains('on')) setMapScroll(true);
  }
  function saveNote(ip, root, noteOverride, done) {
    // 1.1.26：标注只由写标注窗口保存，走 noteOverride（窗口里多行 textarea 的值）。
    // box 仅用于保存成功后回写只读触发框；画像里不再有行内保存按钮。
    var box = root ? root.querySelector('#noteInput') : null;
    var note = noteOverride !== undefined
      ? String(noteOverride || '').trim().slice(0, 500)
      : (box ? String(box.value || '').trim().slice(0, 500) : '');
    var ev = S.currentEvidence[ip] || { ip: ip };
    api('api/orders', 'POST', {
      action: 'save', ip: ip, note: note, evidence: ev, in_order: true
    }).then(function (r) {
      S.orders = (r && r.data) || S.orders;
      updateOrdersBadge(); showOrdersPath();
      toast(note ? '已保存标注并加入提交单' : '标注已清空，仍保留在提交单');
      if (box) box.value = note;                 // 回写只读触发框，显示最新标注
      if ($('ordersMask').classList.contains('on')) renderOrders();
      if (done) done(true);
    }).catch(function (e) {
      toast('保存失败：' + e.message);
      if (done) done(false);
    });
  }

  // ---- 1.1.24：点击标注输入框弹出的独立「写标注」窗口 -------------------
  // 预设只是「用户可能需要的操作」文字，点一下追加进输入框，仍只是保存为
  // 标注 / 给外部 agent 的要求；应用不执行、不碰防火墙。数据序号与
  // index.html 里 #notePresets 的 data-preset 一一对应。
  var NOTE_PRESETS = [
    '先观察 24 小时，暂不处置，保留观测证据。',
    '若持续异常，请外部 agent 评估后临时封禁 2 小时，务必保留回滚并二次确认。',
    '疑似误报或业务需要，建议加入白名单，不再提示。',
    '记录证据，交给外部 agent 自行判断风险与后续处理。',
    '标记为重点关注，请优先核查该 IP 的登录来源与访问路径。',
    '仅记录观测证据，暂不做任何处置。'
  ];
  function openNoteDialog(ip) {
    S.noteIp = ip;
    var cur = '';
    var inline = $('noteInput');
    if (inline) cur = String(inline.value || '');
    if (!cur) { var o = findOrder(ip); cur = o ? (o.note || '') : ''; }
    var d = $('noteDialogInput'); if (d) d.value = cur;
    var sub = $('noteSub');
    if (sub) sub.textContent = ip + ' · 写下的要求只保存为文字，处置完全交给外部 agent';
    $('noteMask').classList.add('on');
    $('noteCard').setAttribute('aria-hidden', 'false');
    setMapScroll(false);
    setTimeout(function () { if (d) { try { d.focus(); } catch (x) {} } }, 80);
  }
  function closeNoteDialog() {
    $('noteMask').classList.remove('on');
    $('noteCard').setAttribute('aria-hidden', 'true');
    if (!drawerOpen() && !S.zoomOn &&
        !$('ordersMask').classList.contains('on') &&
        !$('aboutMask').classList.contains('on') &&
        !$('sponsorMask').classList.contains('on')) setMapScroll(true);
  }
  function appendPreset(idx) {
    var add = NOTE_PRESETS[idx]; if (!add) return;
    var d = $('noteDialogInput'); if (!d) return;
    var cur = String(d.value || '');
    if (cur.indexOf(add) >= 0) return;                 // 同一条不重复追加
    d.value = ((cur ? cur.replace(/\s+$/, '') + '\n' : '') + add).slice(0, 500);
    try { d.focus(); } catch (x) {}
  }
  function saveNoteFromDialog() {
    var d = $('noteDialogInput');
    var val = d ? d.value : '';
    saveNote(S.noteIp, $('detailBody'), val, function (ok) {
      if (ok) closeNoteDialog();
    });
  }
  function copyOrderPrompt() {
    // 1.1.25：一句话模式 + 单独读取路径；按当前功能区取对应提示词。
    var tab = S.ordersTab || 'pending';
    fetch(url('api/orders/prompt?tab=' + encodeURIComponent(tab))).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    }).then(function (txt) {
      copyTextRobust(txt, function (ok) {
        toast(ok ? '一句话提示词 + 读取路径已复制，发给 agent 即可'
                 : '复制未成功，请重试或到提交单里手动复制');
      });
    }).catch(function (e) { toast('生成提示词失败：' + e.message); });
  }
  function removeFromOrders(ip) {
    api('api/orders', 'POST', { action: 'remove', ip: ip }).then(function (r) {
      S.orders = (r && r.data) || S.orders;
      updateOrdersBadge(); renderOrders(); toast('已移出提交单');
    }).catch(function (e) { toast('操作失败：' + e.message); });
  }
  function clearOrders() {
    api('api/orders', 'POST', { action: 'clear' }).then(function (r) {
      S.orders = (r && r.data) || S.orders;
      updateOrdersBadge(); renderOrders(); toast('提交单已清空（未改动任何防火墙规则）');
    }).catch(function (e) { toast('操作失败：' + e.message); });
  }

  // ---- 1.1.18 · 关于弹窗 ----
  function openAbout() {
    closeSponsor();
    $('aboutMask').classList.add('on');
    $('aboutCard').setAttribute('aria-hidden', 'false');
    setMapScroll(false);
  }
  function closeAbout() {
    closeSponsor();
    $('aboutMask').classList.remove('on');
    $('aboutCard').setAttribute('aria-hidden', 'true');
    if (!drawerOpen() && !S.zoomOn) setMapScroll(true);
  }

  // ---- 1.1.19 · 投喂二维码独立放大弹层 ----
  // 旧版把二维码塞在关于卡片里展开，卡片会撑出滚动条、标题被滚出视野，
  // 图片也只有 210px。现在单独弹一层，放大到约 460px，关于页保持原样。
  function openSponsor() {
    $('sponsorMask').classList.add('on');
    $('sponsorBox').setAttribute('aria-hidden', 'false');
  }
  function closeSponsor() {
    $('sponsorMask').classList.remove('on');
    $('sponsorBox').setAttribute('aria-hidden', 'true');
  }

  // ---- 2.0.0 B2：主界面平级 tab ----
  // 地图 SDK 容器必须始终有真实宽高，所以四个 view 用 CSS grid 叠加，
  // 只切 active 的透明度 / 可见性，绝不用 display:none（1.1.21 白屏坑）。
  // 「单页滚动」把 .views 退回块级流，四个 view 依次铺开，等于旧版布局。
  var VIEW_IDS = ['overview', 'analysis', 'records', 'tools'];
  function lsGet(k, d) {
    try { return localStorage.getItem(k) || d; } catch (e) { return d; }
  }
  function lsSet(k, v) {
    try { localStorage.setItem(k, v); } catch (e) {}
  }
  function applyLayout() {
    var views = $('views'), nav = $('mainTabs');
    if (!views || !nav) return;
    var scroll = S.layout === 'scroll';
    views.classList.toggle('layout-scroll', scroll);
    nav.classList.toggle('scroll', scroll);
    $('btnLayout').textContent = '布局：' + (scroll ? '单页滚动' : 'Tab 分布');
  }
  function switchMainView(v) {
    if (VIEW_IDS.indexOf(v) < 0) return;
    S.mainView = v;
    lsSet('ipsense.mainView', v);
    Array.prototype.forEach.call(document.querySelectorAll('#views .view'), function (el) {
      el.classList.toggle('active', el.getAttribute('data-view') === v);
    });
    Array.prototype.forEach.call(document.querySelectorAll('#mainTabs .main-tab'), function (b) {
      var on = b.getAttribute('data-view') === v;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    // 切回态势总览时容器尺寸没变（grid 叠加），无需重建 SDK；
    // 仍触发一次 resize，兼容 SDK 在隐藏期间暂停了布局计算。
    if (v === 'overview' && S.tmapReady) {
      try { S.world.resize(); S.cn.resize(); if (S.geoMap) S.geoMap.resize(); }
      catch (e) {}
    }
  }
  function initMainTabs() {
    var tabs = $('mainTabs'), views = $('views');
    if (!tabs || !views) return;               // 旧版页面 / 预览降级
    S.mainView = lsGet('ipsense.mainView', 'overview');
    if (VIEW_IDS.indexOf(S.mainView) < 0) S.mainView = 'overview';
    S.layout = lsGet('ipsense.layout', 'tabs') === 'scroll' ? 'scroll' : 'tabs';
    applyLayout();
    switchMainView(S.mainView);
    tabs.onclick = function (e) {
      var b = e.target, t = null, lay = false;
      while (b && b !== tabs) {
        if (b.getAttribute && b.getAttribute('data-view')) { t = b; break; }
        if (b.id === 'btnLayout') lay = true;
        b = b.parentNode;
      }
      if (t) { switchMainView(t.getAttribute('data-view')); return; }
      if (lay) {
        S.layout = S.layout === 'tabs' ? 'scroll' : 'tabs';
        lsSet('ipsense.layout', S.layout);
        applyLayout();
      }
    };
    // 04 工具配置：复用顶栏既有按钮，避免重复绑定两套逻辑
    var tools = $('viewTools');
    if (tools) tools.onclick = function (e) {
      var b = e.target, t = null;
      while (b && b !== tools) {
        if (b.getAttribute && b.getAttribute('data-act')) { t = b; break; }
        b = b.parentNode;
      }
      if (!t) return;
      var map = { settings: 'btnSettings', orders: 'btnOrders', refresh: 'btnRefresh',
                  export: 'btnExport', about: 'btnAbout' };
      var id = map[t.getAttribute('data-act')];
      if (id && $(id)) $(id).click();
    };
  }

  function bind() {
    bindCanvasPicks();
    bindMapMode();
    // 1.0.12：设置 / 画像抽屉与放大面板都是模态，滚轮不能穿透去缩放底下的地图，
    // 所以注册在 window 捕获阶段且早于地图 SDK，配合 passive:false 才能 preventDefault；
    // stopImmediatePropagation 同时挡住 SDK 挂在 window/document 上的滚轮手势。
    // 1.1.5：改用父链遍历，不再依赖 Element.closest —— 部分内嵌 WebView 不支持
    // closest 时会走到 preventDefault，把浮层内部滚轮也一起吞掉（界面无法滑动）。
    // 1.1.6：浮层外部（地图 / 遮罩 / 主内容）的滚轮不再「吞掉就完事」。鼠标停在
    // 左侧地图上滚轮时，设置界面应该照样往下滚；这里把滚轮量重定向到浮层内
    // 可滚动容器，滚轮依然可用，地图与页面仍旧不动。
    function inOverlayScroll(t) {
      while (t && t !== document.body && t !== document.documentElement) {
        if (t.classList && (t.classList.contains('drawer') ||
            t.classList.contains('zoom-card'))) return true;
        t = t.parentNode;
      }
      return false;
    }
    // 选滚动容器：放大面板按鼠标水平位置选左列表 / 右详情，抽屉取当前打开的那一个
    // .drawer-body；选中的容器压根不可滚时才回退到另一个，不做「滚到底连锁」。
    function overlayScrollCandidates(e) {
      if ($('zoomMask').classList.contains('on')) {
        var r = $('cardZoom').getBoundingClientRect();
        var right = e.clientX >= r.left + r.width / 2;
        return right ? [$('zoomDetail'), $('zoomList')]
                     : [$('zoomList'), $('zoomDetail')];
      }
      var d = document.querySelector('.drawer.on .drawer-body');
      return d ? [d] : [];
    }
    function redirectWheel(e) {
      var unit = e.deltaY;
      if (!unit) return;
      var list = overlayScrollCandidates(e);
      for (var i = 0; i < list.length; i++) {
        var el = list[i];
        if (!el || el.scrollHeight - el.clientHeight <= 1) continue;
        var d = e.deltaMode === 1 ? unit * 16 :
                e.deltaMode === 2 ? unit * el.clientHeight : unit;
        el.scrollTop += d;   // 交给浏览器钳制边界，滚动条 / 惯性表现与原生一致
        return;
      }
    }
    window.addEventListener('wheel', function (e) {
      if (!drawerOpen()) return;
      // 浮层内部保留浏览器原生滚动（触控板惯性、滚动条拖动都不受影响）
      if (inOverlayScroll(e.target)) return;
      redirectWheel(e);
      e.preventDefault();
      e.stopImmediatePropagation();
    }, { passive: false, capture: true });
    renderHeatLegends();
    renderGeoLegend();
    // 1.1.3：点卡片头部 / 展开按钮放大；点卡片内任一条目放大并直接下钻到该条目详情
    $('webCards').onclick = function (e) {
      var card = e.target.closest('.mini-card[data-dim]');
      if (!card) return;
      var dim = card.getAttribute('data-dim');
      var row = e.target.closest('.mini-row[data-name]');
      if (row) { openCardZoom(dim, card, row.getAttribute('data-name')); return; }
      if (e.target.closest('.card-head') || e.target.closest('.mini-expand'))
        openCardZoom(dim, card, '');
    };
    $('zoomList').onclick = function (e) {
      var el = e.target.closest('.zoom-row[data-name]');
      if (el && S.zoomDim) openZoomItem(S.zoomDim, el.getAttribute('data-name'));
    };
    // 点来源 IP 收起放大面板后复用已有的「IP 来源画像」抽屉，字段与表格行完全一致
    $('zoomDetail').onclick = function (e) {
      var el = e.target.closest('.zoom-ip[data-ip]');
      if (!el) return;
      var ip = el.getAttribute('data-ip');
      closeCardZoom(false, function () { openDetail(ip); });
    };
    $('zoomClose').onclick = function () { closeCardZoom(false); };
    $('zoomMask').onclick = function () { closeCardZoom(false); };
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      // 1.1.24：写标注窗口在最上层，ESC 先收它，画像抽屉仍留在画面里
      if ($('noteMask').classList.contains('on')) { closeNoteDialog(); return; }
      // 1.1.19：二维码灯箱在最上层，ESC 先收它，关于页仍留在画面里
      if ($('sponsorMask').classList.contains('on')) { closeSponsor(); return; }
      // 1.1.28：密钥授权浮层打开时，ESC 先收浮层，提交单仍留在画面里
      if ($('ordersMask').classList.contains('on') && keyauthIsOpen()) { keyauthClose(); return; }
      if ($('ordersMask').classList.contains('on')) { closeOrders(); return; }
      if ($('aboutMask').classList.contains('on')) { closeAbout(); return; }
      if (S.zoomOn) { closeCardZoom(false); return; }
      if ($('mask').classList.contains('on')) closeDrawers();
    });
    // 1.1.2：排名条目下钻 —— 原地域分布右侧列表的功能，合并到下方双榜上
    ['rankCn', 'rankOs'].forEach(function (id) {
      $(id).onclick = function (e) {
        var el = e.target.closest('.rank-row[data-region]');
        if (el) openRegionProfile(el.getAttribute('data-region'),
                                  el.getAttribute('data-scope'));
      };
    });
    $('geoCanvas').addEventListener('click', function (e) {
      var r = this.getBoundingClientRect();
      var x = e.clientX - r.left, y = e.clientY - r.top, best = null, bd = 1e9;
      (S.geoHits || []).forEach(function (p) {
        var d = Math.sqrt((x - p.x) * (x - p.x) + (y - p.y) * (y - p.y));
        if (d <= p.r + 6 && d < bd) { bd = d; best = p; }
      });
      if (best) openRegionProfile(best.name, best.scope || 'all');
    });
    $('geoCanvas').addEventListener('mousemove', function (e) {
      var r = this.getBoundingClientRect();
      var x = e.clientX - r.left, y = e.clientY - r.top, on = false;
      (S.geoHits || []).forEach(function (p) {
        var d = Math.sqrt((x - p.x) * (x - p.x) + (y - p.y) * (y - p.y));
        if (d <= p.r + 6) on = true;
      });
      this.style.cursor = on ? 'pointer' : '';
    });
    $('rangeSeg').onclick = function (e) {
      var b = e.target.closest('button[data-r]'); if (!b) return;
      S.range = b.getAttribute('data-r'); S.page = 1;
      Array.prototype.forEach.call(this.querySelectorAll('button'), function (x) { x.classList.remove('on'); });
      b.classList.add('on'); writeUiPref({ range: S.range }); loadAll();
    };
    $('trendLegend').onclick = function (e) {
      var b = e.target.closest('button[data-k]'); if (!b) return;
      S.trendKey = b.getAttribute('data-k');
      Array.prototype.forEach.call(this.querySelectorAll('button'), function (x) { x.classList.remove('on'); });
      b.classList.add('on'); writeUiPref({ trend: S.trendKey });
      api('api/trend?rng=' + S.range).then(function (r) { renderTrend(r.data); });
    };
    $('btnRefresh').onclick = function () {
      S.heavySig = ''; S.lightSig = '';
      loadAll(); requestMapDraw(true);
    };
    $('btnSettings').onclick = function () {
      api('api/sources').then(function (r) { renderSettings(r.data); openDrawer('settingsDrawer'); });
    };
    $('btnAbout').onclick = openAbout;
    // 1.1.22：提交单按钮固定在「关于」左侧
    $('btnOrders').onclick = openOrders;
    $('ordersClose').onclick = closeOrders;
    $('ordersMask').onclick = function (e) { if (e.target === $('ordersMask')) closeOrders(); };
    $('btnCopyPrompt').onclick = copyOrderPrompt;
    $('btnOrdersClear').onclick = clearOrders;
    $('ordersList').onclick = function (e) {
      // 1.1.25：父链遍历找任意 data-oact（移出 / 待撤回 / 展开总结），不依赖 closest
      var t = e.target, b = null, box = $('ordersList');
      while (t && t !== box) {
        if (t.getAttribute && t.getAttribute('data-oact')) { b = t; break; }
        t = t.parentNode;
      }
      if (!b) return;
      var act = b.getAttribute('data-oact'), ip = b.getAttribute('data-ip');
      if (act === 'remove') removeFromOrders(ip);
      else if (act === 'revert') requestRevert(ip);
      else if (act === 'toggle-sum') toggleSummary(ip);
    };
    // 1.1.25：四个功能区切换（父链遍历，兼容内嵌 WebView）
    $('ordersTabs').onclick = function (e) {
      var t = e.target, b = null, box = this;
      while (t && t !== box) {
        if (t.getAttribute && t.getAttribute('data-otab') !== null) { b = t; break; }
        t = t.parentNode;
      }
      if (b) switchOrdersTab(b.getAttribute('data-otab'));
    };
    // 1.1.25：给 AI 单独提供的读取路径，一键复制
    $('btnCopyPath').onclick = function () {
      var pth = (S.orders && S.orders.path) || '/vol1/@appdata/ipsense/orders.json';
      var cmd = (TAB_DEF[S.ordersTab] || TAB_DEF.pending).cmd;
      copyTextRobust('读取路径：' + pth + '\n读取命令：' + cmd, function (ok) {
        toast(ok ? '读取路径已复制' : '复制未成功，请手动选取');
      });
    };
    ensureOrders();
    // 1.1.24：独立写标注窗口的事件。预设 chips 用父链遍历找 data-preset，
    // 不依赖 Element.closest，兼容内嵌 WebView。
    $('notePresets').onclick = function (e) {
      var t = e.target, b = null, box = this;
      while (t && t !== box) {
        if (t.getAttribute && t.getAttribute('data-preset') !== null) { b = t; break; }
        t = t.parentNode;
      }
      if (b) appendPreset(Number(b.getAttribute('data-preset')));
    };
    $('noteDialogSave').onclick = saveNoteFromDialog;
    $('noteDialogCancel').onclick = closeNoteDialog;
    $('noteClose').onclick = closeNoteDialog;
    $('noteMask').onclick = function (e) { if (e.target === this) closeNoteDialog(); };
    $('aboutClose').onclick = closeAbout;
    $('aboutMask').onclick = function (e) { if (e.target === this) closeAbout(); };
    $('btnSponsor').onclick = openSponsor;
    $('sponsorClose').onclick = closeSponsor;
    $('sponsorMask').onclick = function (e) {
      // 点遮罩空白处或图片外的舞台区域都收起；点二维码本身不收
      if (e.target === this || e.target.classList.contains('sponsor-stage')) closeSponsor();
    };
    // 1.1.20：改成事件委托，动态插入画像的「路径明细」行也能点击复制；
    // 关于弹窗里的群号 / GitHub 链接复用同一套 [data-copy]。
    document.addEventListener('click', function (e) {
      var el = e.target;
      var b = el && el.closest ? el.closest('[data-copy]') : null;
      if (!b) return;
      copyTextRobust(b.getAttribute('data-copy'), function (ok) {
        toast(ok ? '已复制' : '复制未成功，请手动选取');
      });
    });
    $('bannerAction').onclick = function () {
      if (this.getAttribute('data-act') === 'retry') {
        rebuildMap();
        toast('正在重试底图…');
      } else { $('btnSettings').click(); }
    };
    Array.prototype.forEach.call(document.querySelectorAll('[data-close]'), function (b) {
      b.onclick = closeDrawers;
    });
    $('mask').onclick = closeDrawers;
    ['fScope', 'fVerdict', 'fProto', 'fSource'].forEach(function (id) {
      $(id).onchange = function () {
        S.page = 1;
        writeUiPref({ fScope: $('fScope').value, fVerdict: $('fVerdict').value,
                      fProto: $('fProto').value, fSource: $('fSource').value });
        loadHeavy();
      };
    });
    // 1.1.15：实时访问事件监控范围（全部 / 境内 / 境外 / 内网 / 局域网设备）
    $('liveScope').onchange = function () {
      S.liveScope = this.value;
      writeUiPref({ live: S.liveScope });
      renderLive(S.live);
    };
    var qt = null;
    $('fQuery').oninput = function () {
      clearTimeout(qt); qt = setTimeout(function () { S.page = 1; loadHeavy(); }, 350);
    };
    $('recBody').onclick = function (e) {
      var tr = e.target.closest('tr[data-ip]'); if (tr) openDetail(tr.getAttribute('data-ip'));
    };
    $('btnPrev').onclick = function () { if (S.page > 1) { S.page--; loadHeavy(); } };
    $('btnNext').onclick = function () { S.page++; loadHeavy(); };
    $('btnExport').onclick = exportCsv;
    window.addEventListener('resize', function () {
      if (S.tmapReady) {
        try {
          S.world.resize(); S.cn.resize();
          if (S.geoMap) S.geoMap.resize();
        } catch (e) {}
      } else { S.bg = {}; requestMapDraw(true); }
      if (!S.geoMap) drawGeoCanvas();
    });
    $('trendSvg').addEventListener('mousemove', function (e) {
      var pts = this._pts || [], tip = $('chartTip');
      if (!pts.length) return;
      var rect = this.getBoundingClientRect();
      var rel = (e.clientX - rect.left) / rect.width;
      var i = Math.round(rel * (pts.length - 1));
      i = Math.max(0, Math.min(pts.length - 1, i));
      var p = pts[i];
      tip.style.display = 'block';
      tip.style.left = Math.min(rect.width - 130, e.clientX - rect.left + 10) + 'px';
      tip.style.top = (e.clientY - rect.top - 34) + 'px';
      tip.innerHTML = tm(p.t) + '<br>总量 ' + num(p.all) + ' · 境内 ' + num(p.cn) +
        '<br>境外 ' + num(p.overseas) + ' · 扫描 ' + num(p.scan);
    });
    $('trendSvg').addEventListener('mouseleave', function () { $('chartTip').style.display = 'none'; });
    applyUiPref();   // 1.1.18：恢复上次的筛选设定（必须在 loadAll 之前）
    initMainTabs();  // 2.0.0 B2：平级 tab / 布局切换 / 工具卡入口
  }

  // ---- 启动 ----
  api('api/config').then(function (r) {
    S.cfg = r.data || {};
    S.mapConfigured = !!r.data.map_configured;
    S.mapProvider = r.data.map_provider || 'tencent';
    S.summary = r.data.summary || null;
    S.home = { lat: r.data.home_lat, lng: r.data.home_lng, label: r.data.home_label };
    applyCfg();
  }).catch(function () {}).then(function () {
    // 1.1.17：把版本带进运行时报错上下文，导出时能直接对照发版
    api('api/health').then(function (r) { S.version = r.version || ''; })
      .catch(function () {});
    bind();
    setMapState('off');
    initTMap('');
    // 2.0.0 B4：首帧加载遮罩在首轮数据 / 底图就绪后淡出，6 秒兜底防卡死
    loadAll().then(hideMapLoading).catch(hideMapLoading);
    setTimeout(hideMapLoading, 6000);
    // 1.1.11：尽早与飞牛桌面建立 penpal 桥（父窗口 connectToChild 只有 60s 握手窗口）。
    // 失败不报错，点击「选择文件夹」时会再试一次，仍失败则降级为应用内原生卡片。
    getBridge().catch(function () {});
    // 1.1.9：处理 fnOS 原生文件夹选择器的回跳（必须在 bind 之后，
    // 回调里会重新打开设置抽屉并绑定事件）。
    consumePickerCallback();
    // 单一 1 秒 ticker：间隔从配置实时读取，改设置后无需刷新页面；
    // 后台标签页暂停轮询，避免不可见时仍在重建地图。
    var lastLight = Date.now(), lastHeavy = Date.now();
    setInterval(function () {
      if (document.hidden) return;
      var now = Date.now();
      var li = Math.max(2, Number(S.cfg.map_refresh) || 3) * 1000;
      var hi = Math.max(5, Number(S.cfg.map_heavy_refresh) || 12) * 1000;
      if (now - lastLight >= li) { lastLight = now; loadLight(); }
      if (now - lastHeavy >= hi) { lastHeavy = now; loadHeavy(); }
    }, 1000);
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) { lastLight = lastHeavy = Date.now(); loadAll(); }
    });
  });
})();
