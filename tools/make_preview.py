# -*- coding: utf-8 -*-
"""生成离线预览页：把真实首页 + 模拟数据打包成单文件，供 headless 浏览器截图验收。

预览页不改变应用代码，只是覆盖 window.fetch 返回示例数据，用来检查
JS 运行时错误、DOM 布局、Canvas 地图与 SVG 趋势图是否正常渲染。
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "src", "app", "ui")
OUT = os.path.join(ROOT, "build", "preview-ipsense.html")

MOCK = r"""<script>
/* 1.1.11 离线仿真：只在 file:// 预览页生效。
   主通道：window.__ipsenseMockBridge 模拟飞牛桌面 penpal 桥，验证 pickFile 参数；
   降级：window.__ipsensePickerCardRender 在「应用内模态卡片」里渲染同构目录树。
   真机是 http/https，本段完全不执行，生产仍走飞牛原生选择器 / 桌面桥。*/
(function(){
  if(location.protocol!=='file:') return;
  window.__windowOpenCalls=[];
  window.open=function(u,name,features){
    window.__windowOpenCalls.push({url:String(u),name:String(name||''),
                                  features:String(features||'')});
    return null;   // 1.1.11 生产不该调用；记录后返回 null 便于探针发现回归
  };
  window.__pickerOpen=null; window.__pickerState='';
  window.__ipsenseBridgeCalls=[]; window.__ipsenseBridgeNames=[];
  var CSS=
    '.pk-wrap{height:100%;display:flex;flex-direction:column;background:#fff;color:#222;' +
      'font:13px/1.5 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}' +
    '.pk-title{padding:14px 22px;border-bottom:1px solid #edf0f4;font-size:13px;color:#4a5568}' +
    '.pk-body{display:flex;flex:1;min-height:0}' +
    '.pk-side{width:152px;flex:none;background:#fafbfd;border-right:1px solid #edf0f4;padding:14px 0}' +
    '.pk-side div{padding:10px 22px;cursor:pointer;color:#4a5568}' +
    '.pk-side .pk-side-on{background:#eaf2ff;color:#2f6fed;font-weight:600}' +
    '.pk-list{flex:1;overflow:auto;padding:14px 18px}' +
    '.pk-row{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:7px;' +
      'cursor:pointer;color:#2d3748}' +
    '.pk-row:hover{background:#f4f8ff}' +
    '.pk-row.on{background:#eaf2ff;color:#2f6fed}' +
    '.pk-arrow{color:#aab3c0;font-size:11px;width:12px;flex:none}' +
    '.pk-folder{width:17px;height:13px;background:#3b82f6;border-radius:2px;position:relative;' +
      'flex:none;margin-top:2px}' +
    '.pk-folder:before{content:"";position:absolute;top:-4px;left:0;width:8px;height:4px;' +
      'background:#3b82f6;border-radius:2px 2px 0 0}' +
    '.pk-foot{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;' +
      'border-top:1px solid #edf0f4}' +
    '.pk-foot button{font-family:inherit;font-size:13px;padding:8px 20px;border-radius:7px;' +
      'cursor:pointer;border:1px solid #d8dee8;background:#fff;color:#4a5568}' +
    '.pk-right{display:flex;gap:10px}' +
    '.pk-ok{background:#2f6fed!important;border-color:#2f6fed!important;color:#fff!important}' +
    '.pk-ok:disabled{background:#e6ebf2!important;border-color:#e6ebf2!important;' +
      'color:#aab3c0!important;cursor:not-allowed}';
  var dirs=['_am_backup_20261110','appdata','deploy_tmp','docker','Docker',
            'docker镜像','ipsense-verify-119','media','AIlogs'];
  var listHtml=dirs.map(function(n,i){
    return '<div class="pk-row" data-i="'+i+'"><span class="pk-arrow">▸</span>' +
           '<span class="pk-folder"></span><span>'+n+'</span></div>';
  }).join('');
  function emit(status){
    var payload={type:'ipsense:fnos-picker',state:window.__pickerState||'',
      status:status,path:status==='success'?['/vol1/1000/AIlogs']:[],error:''};
    try{sessionStorage.setItem('ipsense.fnos.picker.result',JSON.stringify(payload));}catch(e){}
    try{window.dispatchEvent(new MessageEvent('message',
      {data:payload,origin:location.origin}));}catch(e2){}
  }
  window.__ipsensePickerCardRender=function(body,state,src){
    window.__pickerState=state;
    window.__pickerOpen={url:String(src),state:state,via:'modal'};
    body.innerHTML='<style>'+CSS+'</style><div class="pk-wrap" id="pkWrap">' +
      '<div class="pk-title">我的文件</div>' +
      '<div class="pk-body"><div class="pk-side">' +
      '<div class="pk-side-on">我的文件</div><div>他人共享</div><div>我的收藏</div></div>' +
      '<div class="pk-list" id="pkList">'+listHtml+'</div></div>' +
      '<div class="pk-foot"><button class="pk-new" type="button">新建文件夹</button>' +
      '<span class="pk-right"><button class="pk-cancel" type="button">取消</button>' +
      '<button class="pk-ok" type="button" disabled>选择</button></span></div></div>';
    var list=document.getElementById('pkList'), ok=body.querySelector('.pk-ok');
    list.addEventListener('click',function(e){
      var row=e.target.closest?e.target.closest('.pk-row'):null;
      if(!row) return;
      Array.prototype.forEach.call(list.querySelectorAll('.pk-row'),function(r){r.className='pk-row';});
      row.className='pk-row on'; ok.disabled=false;
      window.__pickerSelected=row.textContent.trim();
    });
    ok.addEventListener('click',function(){emit('success');});
    body.querySelector('.pk-cancel').addEventListener('click',function(){emit('cancel');});
    body.querySelector('.pk-new').addEventListener('click',function(){
      window.__pickerNewFolder=true;
    });
  };
  window.__ipsenseForcePickerCard=true;   // 默认走降级卡片，便于截图与 DOM 验收
})();
</script>
<script>
window.addEventListener('error',function(e){
  var d=document.createElement('div');
  d.style.cssText='position:fixed;top:0;left:0;right:0;z-index:999;background:#b91c1c;color:#fff;padding:8px 12px;font:12px monospace';
  d.textContent='JS ERROR: '+e.message+' @ '+e.filename+':'+e.lineno;
  document.body.appendChild(d);
});
</script>
<script>
(function(){
  var now = Math.floor(Date.now()/1000);
  // 1.1.9 起：离线验收入口 —— 模拟 fnOS 原生文件夹选择器回跳（兼容旧链接）。
  // 1.1.11：#picker-bridge 走主通道仿真，#picker-modal / #picker-card 走应用内模态卡片。
  (function(){
    var h = location.hash || '';
    if (h.indexOf('#picker-') !== 0) return;
    var kind = h.slice(8).split('?')[0];
    var saved = 'ips-mock-state';
    var at = String(Date.now());
    if (kind === 'expired') at = String(Date.now() - 400000);
    if (kind === 'badstate') saved = 'different-state';
    try {
      sessionStorage.setItem('ipsense.pickUserFile.state', saved);
      sessionStorage.setItem('ipsense.pickUserFile.at', at);
    } catch(e) {}
    var path = JSON.stringify(['/vol1/1000/AIlogs']);
    if (kind === 'badjson') path = '{not-json';
    var isCallback = ['success','cancel','expired','badstate','badjson'].indexOf(kind) >= 0;
    if (isCallback) {
      window.__ipsensePickerMock = {
        status: (kind === 'cancel' ? 'cancel' : 'success'),
        method: 'pickUserFile', appName: 'ipsense',
        state: 'ips-mock-state', path: path,
        error: (kind === 'cancel' ? 'user_cancel' : '')
      };
    }
    // 1.1.13 主通道仿真桥：验证 pickFile 调用参数与多形态返回归一化
    if (kind === 'bridge' || kind === 'bridge-cancel') {
      window.__ipsenseForcePickerCard = false;
      window.__ipsenseMockBridge = {
        names: ['pickFile','pickUserFile','pickSharedFile','authorizeUserFile',
                'openFileManager','setTitle','getPlatformConfig'],
        config: { appName: 'ipsense' },
        result: kind === 'bridge-cancel'
          ? { code: -1, msg: 'Cancelled', data: [] }
          : { code: 0, msg: '', data: ['/vol1/1000/AIlogs'] }
      };
    } else {
      window.__ipsenseForcePickerCard = true;
      window.__ipsenseMockBridge = null;
    }
  })();
  var summaryText = '# IP 动态感知 · 设备访问汇总日志\n\n> 用途：把本文件直接交给 AI。\n\n' +
    '## 0. 生成信息\n\n## 1. 态势总览\n\n## 2. 高频来源 IP\n\n' +
    '## 3. 可疑 / 异常事件明细\n\n## 4. 地域来源分布\n\n' +
    '## 5. Web 访问画像\n\n## 6. 访问频率趋势与峰值\n\n' +
    '## 7. 数据口径与免责声明\n\n## 8. 给 AI 的分析与处置建议提示\n\n只观测，不处置。\n';
  var summaryStatus = {dir:'/vol1/1000/AIlogs',dir_ok:true,dir_reason:'可写',
    real_dir:'/vol1/1000/AIlogs',enabled:true,interval:5,range:'24h',
    latest:'/vol1/1000/AIlogs/ipsense-summary-latest.md',
    latest_name:'ipsense-summary-latest.md',last_at:now-60,
    last_file:'/vol1/1000/AIlogs/ipsense-summary-latest.md',last_size:2841,
    last_error:'',writes:3,next_at:now+240};
  // 1.1.15：运行日志导出走 r.text()，mock Response 补齐 text()
  function R(d){ return {ok:true,status:200,json:function(){return Promise.resolve(d);},
                         text:function(){return Promise.resolve(
                           typeof d==='string'?d:JSON.stringify(d,null,2));},
                         blob:function(){return Promise.resolve(new Blob(['x']));}}; }
  var cfg = {source_local_auth:true,source_local_web:true,source_router_syslog:true,
    source_knock:false,source_knock_app:false,
    knock_app_dir:'/vol1/@appdata/fn-knock-lite/gateway/logs',knock_app_port:8999,
    syslog_port:5514,inbox_dir:'/vol1/@appdata/ipsense/inbox',
    auth_log:'/var/log/auth.log',web_log:'/usr/trim/nginx/logs/access.log',
    kern_log:'/var/log/kern.log',web_port:5666,ssh_port:22,keep_days:30,
    geo_district_api_enabled:false,geo_district_api:'',geo_district_field:'district',
    map_key:'请到腾讯位置服务开放平台申请自己的 key 并替换此占位符',
    home_lat:31.8639,home_lng:117.2808,home_label:'本机 · 中国安徽合肥联通（出口 IP）',
    home_ip:'220.205.86.196',home_geo:'中国 安徽 合肥 联通',home_proxy_ip:'203.10.99.50',
    home_source:'auto',home_locate_at:now-3600,
    chart_range:'24h',map_configured:false,web_scheme_override:'',
    map_provider:'tencent',map_engine:'tmap',map_custom:[],
    map_keys:{tencent:'',amap:'',baidu:'',tianditu:''},
    summary_dir:'/vol1/1000/AIlogs',summary_enabled:true,summary_interval:5,
    summary_range:'24h',summary:summaryStatus,
    geo_verify_enabled:true,geo_verify_days:30,geo_verify_batch:60,
    geo_verify_auto:true,geo_district_enabled:true};
  var trend=[]; for(var i=0;i<24;i++){
    var wave=Math.round(180+90*Math.sin(i/3)+40*Math.cos(i/1.7));
    trend.push({t:now-(24-i)*3600,all:wave+60,cn:Math.round(wave*0.32),
      overseas:Math.round(wave*0.12),private:Math.round(wave*0.56),scan:Math.round(wave*0.09)});
  }
  var cn=[{name:'广东省',count:1280,ips:42},{name:'安徽省',count:964,ips:18},
    {name:'北京市',count:742,ips:31},{name:'江苏省',count:518,ips:22},
    {name:'浙江省',count:386,ips:17},{name:'天津市',count:241,ips:6},
    {name:'四川省',count:180,ips:9},{name:'上海市',count:126,ips:8},
    {name:'中国香港',count:84,ips:4},{name:'山东省',count:62,ips:5}];
  var os=[{name:'美国',count:420,ips:31},{name:'荷兰',count:286,ips:12},
    {name:'德国',count:194,ips:9},{name:'俄罗斯',count:158,ips:11},
    {name:'新加坡',count:96,ips:6},{name:'日本',count:74,ips:5},
    {name:'巴西',count:52,ips:3},{name:'韩国',count:38,ips:2}];
  var spots=[
    {ip:'45.155.205.113',country:'荷兰',province:'South Holland',scope:'overseas',lat:52.1,lng:5.3,n:186,verdict:'scan'},
    {ip:'185.220.101.1',country:'德国',province:'Berlin',scope:'overseas',lat:52.5,lng:13.4,n:142,verdict:'attack'},
    {ip:'8.8.8.8',country:'美国',province:'California',scope:'overseas',lat:37.4,lng:-122.1,n:98,verdict:'normal'},
    {ip:'91.240.118.1',country:'俄罗斯',province:'',scope:'overseas',lat:55.7,lng:37.6,n:77,verdict:'scan'},
    {ip:'1.1.1.1',country:'澳大利亚',province:'Queensland',scope:'overseas',lat:-27.5,lng:153,n:54,verdict:'normal'},
    {ip:'103.28.54.10',country:'新加坡',province:'',scope:'overseas',lat:1.3,lng:103.8,n:41,verdict:'scan'},
    {ip:'200.1.1.1',country:'巴西',province:'',scope:'overseas',lat:-23.5,lng:-46.6,n:28,verdict:'normal'},
    {ip:'220.205.66.123',country:'中国',province:'河北省',scope:'cn',lat:38.0,lng:114.5,n:706,verdict:'scan'},
    {ip:'218.106.90.134',country:'中国',province:'安徽省',scope:'cn',lat:31.8,lng:117.2,n:534,verdict:'normal'},
    {ip:'123.125.71.38',country:'中国',province:'北京市',scope:'cn',lat:39.9,lng:116.4,n:322,verdict:'normal'},
    {ip:'112.28.131.131',country:'中国',province:'广东省',scope:'cn',lat:23.1,lng:113.3,n:288,verdict:'scan'},
    {ip:'116.149.202.147',country:'中国',province:'上海市',scope:'cn',lat:31.2,lng:121.5,n:164,verdict:'normal'},
    {ip:'2408:8244:440::1',country:'中国',province:'中国',scope:'cn',lat:30.6,lng:104.1,n:96,verdict:'normal'}
  ];
  var locs=['美国 / California','荷兰 / South Holland','中国 / 安徽省 / 合肥市',
            '德国 / Berlin','中国 / 广东省 / 深圳市','俄罗斯','中国 / 北京市'];
  var acts=['扫描探测 · GET 404 /.env','正常访问 · GET 200 /','密码认证失败 · 用户 root',
            '扫描探测 · GET 404 /wp-login.php','正常访问 · GET 200 /app/ipsense/'];
  var diagText='IP 动态感知（ipsense）· 运行日志诊断包（离线预览）\n' +
    '生成时间：2026-11-19 00:00:00\n' +
    '说明：本文件已自动脱敏。地图 KEY / 令牌 / 口令已抹除；来访 IP 只保留前两段。\n\n' +
    '1. 环境与应用状态\n  版本：1.1.16 · 运行中 · 数据源 3 路\n\n' +
    '2. 主运行日志（尾部）\n  2026-11-19 00:00:01 INFO collector 已启动\n\n' +
    '3. 数据源状态\n  本机 SSH 已读取 · 本机 Web 已读取 · 路由器 syslog 文件不存在\n';
  var live=[],rows=[];
  for(var j=0;j<24;j++){
    var ip=(j%3===0?'45.155.205.'+(j+10):(j%3===1?'218.106.90.'+(j+100):'192.168.3.'+(j+20)));
    var e={id:1000+j,ts:now-j*7,ip:ip,source:j%5===0?'local_auth':'local_web',
      country:j%3===0?'荷兰':'中国',province:j%3===0?'South Holland':(j%2?'安徽省':'广东省'),
      city:'',district:(j%3===0?'':(j%2===0?'蜀山区':'包河区')),
      scope:j%3===0?'overseas':(j%7===0?'private':'cn'),
      verdict:j%4===0?'scan':(j%9===0?'attack':'normal'),
      action:acts[j%5],path:j%4===0?'/.env':'/app/ipsense/',port:0,
      proto:j%5===0?'ssh':(j%3===0?'https':'web'),scheme_conf:'none',
      method:'GET',status:200,referer:'-',ua:'Mozilla/5.0',sess_id:'s'+j,layer:'web'};
    live.push(e);
    rows.push({id:1000+j,ts:e.ts,source:e.source,ip:ip,country:e.country,
      province:e.province,city:'',district:e.district,
      scope:e.scope,port:e.port,service:'fnOS Web',
      action:e.action,verdict:e.verdict,path:e.path,lat:null,lng:null,isp:'',
      proto:e.proto,scheme_conf:e.scheme_conf,method:e.method,status:e.status,
      referer:e.referer,ua:e.ua,sess_id:e.sess_id,layer:e.layer});
  }
  // 1.1.16：真机区级初始为空（三家在线源 + ip9 都拿不到区县），手工回填后才有值。
  // 预览页用这一份有状态 geo 真实验证「保存区级 → 画像归属地出现区县」。
  var ipGeo={ip:'220.195.201.172',country:'中国',province:'安徽省',city:'合肥',
    district:'',district_source:'',isp:'联通',scope:'cn',lat:31.809806,lng:117.301293,
    confidence:'high',online_sources:3,disagree:1,checked_at:now-3600,
    local:{country:'中国',province:'安徽省',city:'合肥',district:''},
    sources:[{source:'ip-api.com',country:'中国',province:'安徽省',city:'合肥',district:''},
      {source:'ip.sb',country:'中国',province:'安徽',city:'合肥',district:''},
      {source:'ip2region',country:'中国',province:'重庆市',city:'重庆市',district:''}]};
  var sources={started:now-3600,queue:0,syslog_port:5514,syslog_ok:true,syslog_error:'',
    knock_enabled:false,knock_installed:false,geo_ready:true,
    knock_app_enabled:false,knock_app_dir:'/vol1/@appdata/fn-knock-lite/gateway/logs',
    knock_app_files:null,
    tailers:[{name:'本机 · SSH 认证',path:'/var/log/auth.log',exists:true,count:14,error:''},
             {name:'本机 · Web 访问',path:'/usr/trim/nginx/logs/access.log',exists:true,count:92864,error:''}],
    hits:{local_auth:14,local_web:92864}};
  var status={range:'24h',total:12840,unique_ip:187,cn:4231,overseas:928,private:7681,
    unknown:0,normal:11700,scan:1040,attack:100,knock:0,by_source:{local_web:12000},
    per_minute:42,last:{ts:now,ip:'45.155.205.113',scope:'overseas',verdict:'scan'},oldest:now-86400};
  var webOv={
    range:'24h',summary:{requests:12840,ips:187,sessions:963},
    protocols:[{name:'web',count:7420,ips:120,manual:0,inferred:0},
               {name:'http',count:3980,ips:96,manual:0,inferred:3980},
               {name:'ssh',count:1120,ips:41,manual:0,inferred:0},
               {name:'tcp',count:320,ips:18,manual:0,inferred:0}],
    protocol_verdict:[{proto:'web',verdict:'normal',count:6900},{proto:'web',verdict:'scan',count:520},
                      {proto:'http',verdict:'normal',count:3980},{proto:'ssh',verdict:'attack',count:1120},
                      {proto:'tcp',verdict:'scan',count:320}],
    referrers:[{name:'直接输入网址 / 无来路',count:6820,ips:142},
               {name:'站内 · /app/ipsense',count:2410,ips:38},
               {name:'站内首页 · 192.168.3.5:5666',count:1830,ips:26},
               {name:'www.google.com',count:640,ips:9}],
    pages:[{name:'/app/ipsense/',count:4120,ips:88},{name:'/app/ipsense/api/status',count:3260,ips:52},
           {name:'/app/agent2api',count:1840,ips:31},{name:'/',count:980,ips:24}],
    entries:[{name:'/',count:3410,ips:120},{name:'/app/ipsense/',count:2180,ips:88}],
    devices:[{name:'Chrome · Windows',count:7640,ips:96},{name:'Safari · macOS',count:2210,ips:34},
             {name:'curl · 未知系统',count:880,ips:12},{name:'程序客户端 · 未知系统',count:410,ips:8}]
  };
  // 1.1.2：固定全球视图，一份数据同时含境内（归并到「中国」）与境外国家
  // 1.1.15：境内按省细分并带 scope，不再归并成一个「中国」气泡
  var geoAll={range:'24h',scope:'all',total:5159,regions:[
    {name:'安徽省',count:2100,ips:62,lat:31.82,lng:117.23,scope:'cn'},
    {name:'广东省',count:1400,ips:48,lat:23.13,lng:113.26,scope:'cn'},
    {name:'北京市',count:731,ips:24,lat:39.90,lng:116.41,scope:'cn'},
    {name:'美国',count:420,ips:31,lat:39.83,lng:-98.58,scope:'overseas'},
    {name:'荷兰',count:286,ips:12,lat:52.13,lng:5.29,scope:'overseas'},
    {name:'德国',count:194,ips:9,lat:51.17,lng:10.45,scope:'overseas'},
    {name:'俄罗斯',count:158,ips:11,lat:61.52,lng:105.32,scope:'overseas'},
    {name:'新加坡',count:92,ips:6,lat:1.35,lng:103.82,scope:'overseas'}
  ]};
  // 1.1.3：五卡放大面板的条目下钻详情（含来源 IP 明细，点 IP 会打开画像抽屉）
  var breakdown={ok:true,dim:'proto',name:'web',range:'24h',
    requests:7420,ips:3,first_ts:now-86400,last_ts:now,card_count:7420,raw_keys:1,
    note:'协议维度统计全部来源（含 SSH、内核、路由器事件），不限 Web 请求。',
    ip_list:[
      {ip:'192.168.3.38',n:5120,first_ts:now-86400,last_ts:now-120,country:'中国',province:'',city:'',isp:'',scope:'lan',verdict:'normal',proto:'web'},
      {ip:'45.155.205.113',n:1860,first_ts:now-80000,last_ts:now-600,country:'荷兰',province:'South Holland',city:'',isp:'',scope:'overseas',verdict:'scan',proto:'web'},
      {ip:'203.0.113.9',n:440,first_ts:now-70000,last_ts:now-1800,country:'中国',province:'安徽省',city:'合肥市',isp:'联通',scope:'cn',verdict:'normal',proto:'web'}
    ],
    recent:[
      {ts:now-30,ip:'45.155.205.113',proto:'web',verdict:'scan',action:'扫描探测 · GET 404 /.env',path:'/.env',port:0,status:404,method:'GET',referer:'-'},
      {ts:now-95,ip:'192.168.3.38',proto:'web',verdict:'normal',action:'正常访问 · GET 200 /',path:'/app/ipsense/',port:0,status:200,method:'GET',referer:'-'}
    ]};
  window.addEventListener('load',function(){
    setTimeout(function(){
      if(location.hash==='#settings') document.getElementById('btnSettings').click();
      if(location.hash==='#rank-detail'){
        var row=document.querySelector('.rank-row[data-region]'); if(row) row.click();
      }
      if(location.hash==='#geo-detail'){
        var bar=document.querySelector('.rank-row[data-region]'); if(bar) bar.click();
      }
      if(location.hash==='#detail'){ var tr=document.querySelector('tr[data-ip]'); if(tr) tr.click(); }
      // 1.1.3：放大面板 / 条目下钻 / 下钻后点来源 IP 的验收入口
      if(location.hash==='#card-zoom'){
        var head=document.querySelector('.mini-card .card-head'); if(head) head.click();
      }
      if(location.hash==='#card-item'){
        var mini=document.querySelector('.mini-row[data-dim]'); if(mini) mini.click();
      }
      if(location.hash==='#card-ip'){
        var mini2=document.querySelector('.mini-row[data-dim]'); if(mini2) mini2.click();
        setTimeout(function(){ var zip=document.querySelector('.zoom-ip[data-ip]'); if(zip) zip.click(); },900);
      }
      // 1.1.7：连接状态验收入口，注入一次 events 失败后自动恢复
      if(location.hash==='#conn-fail') window.__connFailOnce=true;
      // 1.1.6：浮层外滚轮重定向验收入口，探针会自行往地图区域派发 wheel 事件
      if(location.hash==='#settings-wheel') document.getElementById('btnSettings').click();
      // 1.1.8：地图服务验收入口，#map-custom 额外展开自定义接口表单
      if(location.hash==='#map-provider') document.getElementById('btnSettings').click();
      if(location.hash==='#map-custom'){
        document.getElementById('btnSettings').click();
        setTimeout(function(){ var b=document.querySelector('[data-act="add"]'); if(b) b.click(); },1900);
      }
      // 1.1.9：软件汇总日志验收入口（#picker-* 由启动回调自己处理，不自动开抽屉）
      if(location.hash==='#summary'){
        document.getElementById('btnSettings').click();
        setTimeout(function(){
          var box=document.getElementById('summaryServiceBox');
          if(box && box.scrollIntoView) box.scrollIntoView({block:'start'});
        },1900);
      }
      // 1.1.11：点「选择文件夹」→ 应用内模态卡片（#picker-card 兼容旧入口）
      if(location.hash==='#picker-modal' || location.hash==='#picker-card'){
        document.getElementById('btnSettings').click();
        setTimeout(function(){
          var b=document.getElementById('btnPickFolder'); if(b) b.click();
        },1900);
      }
      // 1.1.13：点「选择文件夹」→ 主通道仿真（桌面桥 pickFile，不弹卡片）
      if(location.hash==='#picker-bridge' || location.hash==='#picker-bridge-cancel'){
        document.getElementById('btnSettings').click();
        setTimeout(function(){
          var b=document.getElementById('btnPickFolder'); if(b) b.click();
        },1900);
      }
      if(location.hash==='#card-wheel'){
        var mw=document.querySelector('.mini-row[data-dim]'); if(mw) mw.click();
      }
    },1600);
  });
  window.fetch=function(u,opt){
    u=String(u);
    // 1.1.7：#conn-fail 下只让 events 失败一次，用于观察琥珀态与自动恢复
    if(window.__connFailOnce && u.indexOf('api/events')>=0 && !window.__connFailDone){
      window.__connFailDone=true;
      return Promise.reject(new Error('模拟瞬时网络中断'));
    }
    var d={ok:true};
    // 1.1.9：软件汇总日志接口
    if(u.indexOf('api/summary/status')>=0) d={ok:true,data:summaryStatus};
    else if(u.indexOf('api/summary/preview')>=0) d={ok:true,data:{text:summaryText,
      range:'24h',bytes:summaryText.length,lines:summaryText.split('\n').length}};
    else if(u.indexOf('api/summary/validate')>=0) d={ok:true,reason:'可写',
      path:'/vol1/1000/AIlogs',allowed:true};
    else if(u.indexOf('api/summary/generate')>=0) d={ok:true,data:{
      dir:'/vol1/1000/AIlogs',latest:'/vol1/1000/AIlogs/ipsense-summary-latest.md',
      archive:'/vol1/1000/AIlogs/ipsense-summary-20261114.md',
      bytes:2841,at:now,name:'ipsense-summary-latest.md'},msg:'汇总日志已生成'};
    else if(u.indexOf('api/summary/download')>=0)
      return Promise.resolve({ok:true,status:200,blob:function(){
        return Promise.resolve(new Blob([summaryText],{type:'text/markdown'}));}});
    else if(u.indexOf('api/config')>=0) d={ok:true,data:cfg};
    else if(u.indexOf('api/health')>=0) d={ok:true,version:'1.1.16'};
    // 1.1.15：脱敏诊断包与区级手工补充
    else if(u.indexOf('api/diag/export')>=0) d=diagText;
    else if(u.indexOf('api/geo/district')>=0){
      var nd='';
      try{ nd=String((JSON.parse((opt&&opt.body)||'{}').district)||'').trim().slice(0,40); }
      catch(eD){}
      ipGeo.district=nd; ipGeo.district_source=nd?'manual':'';
      d={ok:true,ip:ipGeo.ip,district:nd,events_updated:3};
    }
    else if(u.indexOf('api/locate')>=0) d={ok:true,ip:'220.205.86.196',proxy_ip:'203.10.99.50',
      has_proxy:true,geo_text:'中国 安徽 合肥 联通',
      online:{country:'中国',region:'Anhui Sheng',city:'Hefei',lat:31.8639,lng:117.2808,source:'ipwho.is'},
      local:{label:'中国·甘肃省·兰州市'},mismatch:true,coord_source:'ipwho.is',
      home:{lat:31.8639,lng:117.2808,label:'本机 · 中国安徽合肥联通（出口 IP）'},changed:['home_lat']};
    else if(u.indexOf('api/status')>=0) d={ok:true,data:status,sources:sources,sources_stat:{local_web:{count:12000}}};
    else if(u.indexOf('api/trend')>=0) d={ok:true,data:{bucket:3600,start:now-86400,end:now,points:trend}};
    else if(u.indexOf('api/ranking')>=0) d={ok:true,data:{cn:cn,overseas:os}};
    else if(u.indexOf('api/records')>=0) d={ok:true,data:{total:12840,page:1,size:20,rows:rows}};
    else if(u.indexOf('api/events')>=0) d={ok:true,data:{last_id:1024,events:live}};
    else if(u.indexOf('api/live')>=0) d={ok:true,data:live};
    else if(u.indexOf('api/hotspots')>=0) d={ok:true,data:spots,home:{lat:31.8639,lng:117.2808,label:'本机 · 中国安徽合肥联通（出口 IP）'},map_configured:false};
    else if(u.indexOf('api/sources')>=0) d={ok:true,data:sources,stat:{}};
    else if(u.indexOf('api/mapkey')>=0) d={ok:true,configured:false,key:''};
    else if(u.indexOf('api/web/overview')>=0) d={ok:true,data:webOv};
    else if(u.indexOf('api/web/breakdown')>=0) d={ok:true,data:breakdown};
    else if(u.indexOf('api/geodist')>=0) d={ok:true,data:geoAll};
    else if(u.indexOf('api/geo')>=0) d={ok:true,data:spots[0]};
    else if(u.indexOf('api/ip')>=0) d={ok:true,data:{info:rows[0],
      agg:{n:186,first_ts:now-86400,last_ts:now,sessions:12,ports:2,paths:5},
      recent:rows.slice(0,10),top_paths:[{path:'/.env',n:86}],
      protocols:[{k:'web',n:120,manual:0},{k:'ssh',n:66,manual:0}],
      verdicts:[{k:'normal',n:150},{k:'attack',n:36}],
      referrers:[{k:'-',n:98},{k:'http://192.168.3.5:5666/',n:22}],
      uas:[{ua:'Mozilla/5.0 (Windows NT 10.0) Chrome/138.0',n:186}],
      window:{rows:3000,limit:3000,truncated:true}},geo:ipGeo,verification:ipGeo};
    return Promise.resolve(R(d));
  };
})();
</script>
"""


def main():
    def rd(name):
        with open(os.path.join(UI, name), "r", encoding="utf-8") as f:
            return f.read()
    html = rd("index.html")
    html = html.replace("/*__CSS__*/", rd("style.css"))
    html = html.replace("<script>/*__JS__*/</script>", MOCK + "<script>" + rd("app.js") + "</script>")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    print("预览页:", OUT, len(html), "字节")


if __name__ == "__main__":
    main()
