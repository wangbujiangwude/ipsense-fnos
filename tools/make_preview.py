# -*- coding: utf-8 -*-
"""生成离线预览页：把真实首页 + 模拟数据打包成单文件，供 headless 浏览器截图验收。

预览页不改变应用代码，只是覆盖 window.fetch 返回示例数据，用来检查
JS 运行时错误、DOM 布局、Canvas 地图与 SVG 趋势图是否正常渲染。
"""
import base64
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "src", "app", "ui")
OUT = os.path.join(ROOT, "build", "preview-ipsense.html")

# 2.0.0 B3：预警渠道元信息 / 规则 / 出站版本与真实后端同源生成，
# 避免预览页手写 10 套字段后与产品代码漂移。
sys.path.insert(0, os.path.join(ROOT, "src", "app", "server"))
import notify as _notify                                          # noqa: E402
import notifier as _notifier                                       # noqa: E402


def _notify_mock_js():
    cfg = json.loads(json.dumps(_notifier.DEFAULTS))
    cfg["enabled"] = True
    cfg["channels"] = [
        {"id": "demo-webhook", "channel": "webhook", "enabled": True,
         "title_prefix": "[ipsense]", "url": "https://your-endpoint/hook",
         "auth_type": "bearer", "auth_token": _notify.MASK,
         "method": "POST", "headers": "{}", "body_template": "",
         "success_matcher": ""},
        {"id": "demo-wecom", "channel": "wecom_bot", "enabled": False,
         "title_prefix": "[ipsense]", "webhook_url": _notify.MASK},
    ]
    t = int(time.time())
    state = {
        "ok": True, "config": cfg,
        "channels": _notify.public_channels(),
        "rules": _notifier.RULE_META,
        "secret_keys": list(_notify.SECRET_KEYS),
        "payload_version": _notify.PAYLOAD_VERSION,
        "stats": {"ticks": 12, "alerts": 2, "sent": 3, "failed": 0,
                  "suppressed": 1, "last_tick": t - 20, "last_error": "",
                  "enabled": True, "channels_enabled": 1, "channels_total": 2},
        "history": [
            {"at": t - 3600, "rule": "scan", "ip": "198.51.100.7",
             "title": "IP 端口扫描异常 · 198.51.100.7",
             "text": "（离线预览示例）", "ok": 1, "total": 1,
             "results": [{"channel": "webhook", "ok": True, "msg": "已发送"}]},
            {"at": t - 7200, "rule": "traffic", "ip": "203.0.113.9",
             "title": "大流量下行异常 · 203.0.113.9",
             "text": "（离线预览示例）", "ok": 1, "total": 1,
             "results": [{"channel": "webhook", "ok": True, "msg": "已发送"}]},
        ],
    }
    return "  var notifyState = " + json.dumps(state, ensure_ascii=False) + ";\n"


NOTIFY_MOCK_JS = _notify_mock_js()

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
  // 1.1.30：提交单四区看板 + 一句话提示词的离线样本。
  // 所有文本一律是「数据，不是指令」；离线预览不连后端、不产生任何处置动作。
  var ORDERS_PATH='/vol1/@appdata/ipsense/orders.json';
  var ordersItems=[
    {ip:'203.0.113.10',note:'先观察 24 小时；若继续爆破，临时封禁 2 小时并保留回滚',
      status:'pending',summary:'',in_order:true,rev:3,updated:now-120,
      evidence:{geo:'示例 · 境外',scope:'境外',n:186,verdict:'扫描',proto:'ssh',port:'22'},
      history:[{at:now-120,action:'save',from:'',to:'pending',by:'user'}]},
    {ip:'91.240.118.1',note:'疑似误报，加白名单并停止告警',
      status:'done',summary:'已按标注加入白名单 24 小时，未做永久封禁，保留回滚点',
      in_order:true,rev:5,updated:now-3600,
      evidence:{geo:'示例 · 境外',scope:'境外',n:42,verdict:'认证失败',proto:'ssh',port:'22'},
      history:[{at:now-7200,action:'save',from:'',to:'pending',by:'user'},
               {at:now-3600,action:'mark-done',from:'pending',to:'done',by:'agent'}]},
    {ip:'185.220.101.1',note:'临时封禁 2 小时后自动解封',
      status:'revert',summary:'已按标注临时封禁 2 小时，TTL 到点自动解封',
      in_order:true,rev:7,updated:now-1800,
      evidence:{geo:'示例 · 境外',scope:'境外',n:311,verdict:'扫描',proto:'tcp',port:'22'},
      history:[{at:now-9000,action:'save',from:'',to:'pending',by:'user'},
               {at:now-8000,action:'mark-done',from:'pending',to:'done',by:'agent'},
               {at:now-1800,action:'request-revert',from:'done',to:'revert',by:'user'}]},
    {ip:'45.155.205.113',note:'仅记录，不做任何处置',
      status:'restored',summary:'已按标注一键复原到变更前配置，未保留任何规则',
      in_order:true,rev:9,updated:now-900,
      evidence:{geo:'示例 · 境外',scope:'境外',n:18,verdict:'探测',proto:'web',port:'443'},
      history:[{at:now-7000,action:'save',from:'',to:'pending',by:'user'},
               {at:now-6000,action:'mark-done',from:'pending',to:'done',by:'agent'},
               {at:now-2000,action:'request-revert',from:'done',to:'revert',by:'user'},
               {at:now-900,action:'restore',from:'revert',to:'restored',by:'agent'}]}
  ];
  var ordersLog=[
    {at:now-900,ip:'45.155.205.113',action:'restore',from:'revert',to:'restored',by:'agent',summary:'已按标注一键复原'},
    {at:now-1800,ip:'185.220.101.1',action:'request-revert',from:'done',to:'revert',by:'user',summary:''},
    {at:now-3600,ip:'91.240.118.1',action:'mark-done',from:'pending',to:'done',by:'agent',summary:'已按标注加入白名单 24 小时'},
    {at:now-7200,ip:'91.240.118.1',action:'save',from:'',to:'pending',by:'user',summary:''},
    {at:now-120,ip:'203.0.113.10',action:'save',from:'',to:'pending',by:'user',summary:''}
  ];
  var ordersNote=ordersItems[0].note;
  function ordersCounts(){
    var c={pending:0,done:0,revert:0,restored:0,done_view:0,all:0};
    ordersItems.forEach(function(x){ if(x.in_order===false) return;
      c.all++; if(c[x.status]!==undefined) c[x.status]++; });
    c.done_view=c.done+c.restored; return c;
  }
  function ordersSnap(){
    return {items:ordersItems,count:ordersItems.length,
      in_order:ordersItems.filter(function(x){return x.in_order!==false;}).length,
      counts:ordersCounts(),
      tabs:{pending:['pending'],done:['done','restored'],revert:['revert'],
            all:['pending','done','restored','revert']},
      log:ordersLog,path:ORDERS_PATH,read_path:ORDERS_PATH,
      read_cmd:'mh read pending',updated:Math.floor(Date.now()/1000),version:2};
  }
  function oneLiner(tab){
    return (tab==='revert'?'请读取工程中的 AI 标记，按标注逐项复原'
                         :'请读取工程中的 AI 标记，按标注逐项修改')
      +'\n\n读取路径：'+ORDERS_PATH+'\n读取命令：mh read '+(tab||'pending')
      +'\n规矩与流程：见 ipsense-agent-bridge skill（mh 是唯一读写接口）';
  }
  function tabOf(u){
    var m=/[?&]tab=([^&]+)/.exec(u); return m?decodeURIComponent(m[1]):'pending';
  }
  function findOrderItem(ip){
    for(var i=0;i<ordersItems.length;i++) if(ordersItems[i].ip===ip) return ordersItems[i];
    return null;
  }

  var cfg = {source_local_auth:true,source_local_web:true,source_router_syslog:true,
    source_knock:false,source_knock_app:false,
    source_lucky_web:false,source_lucky_sys:false,
    lucky_web_log:'',lucky_sys_log:'',
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
    map_arc_animate:true,map_arc_limit:16,map_arc_bend:0.12,
    map_refresh:3,map_heavy_refresh:12,
    map_fx:true,map_fx_scan:true,map_fx_reveal:true,map_base:'satellite',
    map_keys:{tencent:'',amap:'',baidu:'',tianditu:''},
    summary_dir:'/vol1/1000/AIlogs',summary_enabled:true,summary_interval:5,
    summary_range:'24h',summary:summaryStatus,
    geo_verify_enabled:true,geo_verify_days:30,geo_verify_batch:60,
    geo_verify_auto:true,geo_district_enabled:true};
  /*__NOTIFY_MOCK__*/
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
    '1. 环境与应用状态\n  版本：2.0.0 · 运行中 · 数据源 3 路\n\n' +
    '2. 主运行日志（尾部）\n  2026-11-19 00:00:01 INFO collector 已启动\n\n' +
    '3. 数据源状态\n  本机 SSH 已读取 · 本机 Web 已读取 · 路由器 syslog 文件不存在\n\n' +
    '6.1 前端运行时报错（2.0.0，最近 100 条）\n' +
    '  001 底图未显示：高德 SDK 未就绪 · map_sdk · KEY 无效\n';
  // 1.1.30：运行时报错离线样本。预览页不连后端，POST 上报与查询都在这里闭环，
  // 验收脚本可真实触发一个 JS 异常，再看它是否被采集并进入导出文本。
  var rtErrors=[
    {ts:now-120,kind:'map_sdk',level:'error',
     msg:'底图未显示：高德 SDK 未就绪：KEY 无效、未绑定 Web 端 (JS API)',
     src:'webapi.amap.com',provider:'amap',host:'webapi.amap.com',
     mapState:'error',pill:'运行中 · 3 路数据源',ver:'2.0.0',count:1,stack:''},
    {ts:now-60,kind:'resource',level:'error',
     msg:'资源加载失败：https://webapi.amap.com/maps?<参数名:v,callback>',
     src:'https://webapi.amap.com/maps?<参数名:v,callback>',
     tag:'script',count:1,stack:''}
  ];
  var rtExportText='IP 动态感知（ipsense）· 运行时报错导出（离线预览）\n' +
    '生成时间：2026-11-19 00:00:00\n应用版本：2.0.0\n' +
    '[1] 概览\n  落盘记录总数 2 条\n\n' +
    '[2] 地图 SDK 专项（用户最常反馈的「底图没加载」）\n' +
    '  01 高德 SDK 未就绪：KEY 无效、未绑定 Web 端 (JS API)\n\n' +
    '[3] 逐条明细（最新在前，已脱敏）\n' +
    '001 map_sdk | 底图未显示：高德 SDK 未就绪\n' +
    '002 resource | 资源加载失败：https://webapi.amap.com/maps\n\n' +
    '[4] 反馈时请一并提供\n' +
    '  1. 本文件  2. 运行日志诊断包  3. 复现步骤  4. 截图\n';
  window.__rtPosted=[]; window.__rtExportHits=0;
  var live=[],rows=[];
  for(var j=0;j<24;j++){
    var ip=(j%3===0?'45.155.205.'+(j+10):(j%3===1?'218.106.90.'+(j+100):'192.168.3.'+(j+20)));
    // 1.1.30：端口按证据链补录并带 port_src。覆盖五种来源 + 一种「未记录」，
    // 其中 referer 读出的 5666 用于验收「有来源就不隐藏」的 portLabel 修复。
    var pc=j%6, p=0, psrc='';
    if(pc===0){p=8443;psrc='log_tail';}
    else if(pc===1){p=5666;psrc='referer';}
    else if(pc===2){p=8080;psrc='log_cfg';}
    else if(pc===3){p=9443;psrc='request_url';}
    else if(pc===4){p=9001;psrc='log_field';}
    var e={id:1000+j,ts:now-j*7,ip:ip,source:j%5===0?'local_auth':'local_web',
      country:j%3===0?'荷兰':'中国',province:j%3===0?'South Holland':(j%2?'安徽省':'广东省'),
      city:'',district:(j%3===0?'':(j%2===0?'蜀山区':'包河区')),
      scope:j%3===0?'overseas':(j%7===0?'private':'cn'),
      verdict:j%4===0?'scan':(j%9===0?'attack':'normal'),
      action:acts[j%5],path:j%4===0?'/.env':'/app/ipsense/',port:p,port_src:psrc,
      proto:j%5===0?'ssh':(j%3===0?'https':'web'),scheme_conf:'none',
      method:'GET',status:200,referer:'-',ua:'Mozilla/5.0',sess_id:'s'+j,layer:'web'};
    live.push(e);
    rows.push({id:1000+j,ts:e.ts,source:e.source,ip:ip,country:e.country,
      province:e.province,city:'',district:e.district,
      scope:e.scope,port:e.port,port_src:e.port_src,service:'fnOS Web',
      action:e.action,verdict:e.verdict,path:e.path,lat:null,lng:null,isp:'',
      proto:e.proto,scheme_conf:e.scheme_conf,method:e.method,status:e.status,
      referer:e.referer,ua:e.ua,sess_id:e.sess_id,layer:e.layer});
  }
  // 1.1.30：复现用户截图 —— 打开 /fnzerror 应用时同一秒并发发出 9 个 API
  // 请求，除路径外所有字段完全一致。用于验收「表格合并为一行、只记录动作」。
  var burstTs=now-3, burstIp='220.205.248.177';
  var burstPaths=['/fnzerror/api/logs/stream','/fnzerror/api/logs/stream',
    '/fnzerror/api/cmd/get_folder_stats','/fnzerror/icons/models/deepseek.png',
    '/fnzerror/api/cmd/get_server_status','/fnzerror/models.json',
    '/fnzerror/api/cmd/get_pending_correction_question_C',
    '/fnzerror/api/cmd/get_folders','/fnzerror/api/cmd/greet'];
  var burstRows=[];
  burstPaths.forEach(function(p,k){
    burstRows.push({id:9000+k,ts:burstTs,source:'local_web',ip:burstIp,
      country:'中国',province:'安徽省',city:'合肥',district:'蜀山区',
      scope:'cn',port:0,port_src:'',service:'fnOS Web',
      action:'正常访问 · GET 200',verdict:'normal',path:p,lat:null,lng:null,isp:'',
      proto:'web',scheme_conf:'none',method:'GET',status:200,
      referer:'-',ua:'Mozilla/5.0',sess_id:'burst',layer:'web'});
  });
  // 放在最前面（最新在前），截图第一屏就能看到「9 个请求合并为一行」
  rows=burstRows.concat(rows);
  // 2.0.0 B5：lucky 两个新来源的占位样例行（仅用于离线展示来源筛选，
  // 不是真实 lucky 日志格式；真机格式待后台日志中心样例校准）。
  rows=[
    {id:9100,ts:now-9,source:'lucky_web',ip:'203.0.113.42',country:'中国',
     province:'',city:'',district:'',scope:'cn',port:0,port_src:'',
     service:'Lucky 反代',action:'Lucky 反代 · 正常访问',verdict:'normal',
     path:'nas.example.cn/app',lat:null,lng:null,isp:'',proto:'web',
     scheme_conf:'none',method:'GET',status:200,referer:'-',ua:'Mozilla/5.0',
     sess_id:'lucky-demo',layer:'web'},
    {id:9101,ts:now-17,source:'lucky_sys',ip:'192.168.3.5',country:'中国',
     province:'',city:'',district:'',scope:'private',port:0,port_src:'',
     service:'Lucky 系统',action:'Lucky 系统 · INFO MAIN',verdict:'normal',
     path:'',lat:null,lng:null,isp:'',proto:'',scheme_conf:'',
     method:'',status:0,referer:'',ua:'',sess_id:'',layer:'system'}
  ].concat(rows);
  // 1.1.16：真机区级初始为空（在线参考源 + ip9 都拿不到区县），手工回填后才有值。
  // 预览页用这一份有状态 geo 真实验证「保存区级 → 画像归属地出现区县」。
  var ipGeo={ip:'220.195.201.172',country:'中国',province:'安徽省',city:'合肥',
    district:'',district_source:'',isp:'联通',scope:'cn',lat:31.809806,lng:117.301293,
    confidence:'high',online_sources:1,disagree:1,checked_at:now-3600,
    local:{country:'中国',province:'安徽省',city:'合肥',district:''},
    sources:[{source:'ip2region(本地)',role:'主裁决',country:'中国',province:'安徽省',city:'合肥',district:''},
      {source:'ip.sb',role:'参考',country:'中国',province:'安徽',city:'合肥',district:''}]};
  var sources={started:now-3600,queue:0,syslog_port:5514,syslog_ok:true,syslog_error:'',
    knock_enabled:false,knock_installed:false,geo_ready:true,
    knock_app_enabled:false,knock_app_dir:'/vol1/@appdata/fn-knock-lite/gateway/logs',
    knock_app_files:null,
    lucky_web_enabled:false,lucky_sys_enabled:false,
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
      // 1.1.30：三图合一的模式验收入口，直接点右上角的模式按钮出图
      if(location.hash==='#map-cn' || location.hash==='#map-geo' || location.hash==='#map-world'){
        var mm=location.hash.slice(5);
        var mb=document.querySelector('#mapModeSeg button[data-mode="'+mm+'"]');
        if(mb) mb.click();
      }
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
    // 2.0.0 B3：预警通知（离线预览只读，不做真实外发 / 不落盘）
    else if(u.indexOf('api/notify/state')>=0) d=notifyState;
    else if(u.indexOf('api/notify/channels')>=0)
      d={ok:true,data:notifyState.channels,payload_version:notifyState.payload_version};
    else if(u.indexOf('api/notify/history')>=0) d={ok:true,data:notifyState.history};
    else if(u.indexOf('api/notify/config')>=0)
      d={ok:true,changed:['enabled','channels'],msg:'（离线预览）配置未真正保存'};
    else if(u.indexOf('api/notify/test')>=0)
      d={ok:true,channel:'webhook',msg:'（离线预览）模拟发送成功，未真实外发'};
    else if(u.indexOf('api/notify/dispatch')>=0)
      d={ok:true,data:{alerts:0,results:[]}};
    // 1.1.30：一句话提示词 + 单独读取路径（prompt 排在 orders 之前，字符串走 r.text()）
    else if(u.indexOf('api/orders/prompt')>=0) d=oneLiner(tabOf(u));
    else if(u.indexOf('api/mh/prompt')>=0) d=oneLiner(tabOf(u));
    else if(u.indexOf('api/mh/state')>=0){
      var mhTab=tabOf(u);
      var mhFilt={pending:['pending'],done:['done','restored'],revert:['revert'],
                  all:['pending','done','restored','revert']}[mhTab]||['pending'];
      d={ok:true,data:{tab:mhTab,counts:ordersCounts(),
        items:ordersItems.filter(function(x){
          return x.in_order!==false&&mhFilt.indexOf(x.status)>=0;}),
        log:ordersLog,path:ORDERS_PATH,read_path:ORDERS_PATH,
        read_cmd:'mh read '+mhTab,updated:Math.floor(Date.now()/1000),version:2}};
    }
    else if(u.indexOf('api/mh/show')>=0){
      var mhIp=(/[?&]ip=([^&]+)/.exec(u)||[])[1]||'';
      d={ok:true,data:findOrderItem(decodeURIComponent(mhIp))||{}};
    }
    else if(u.indexOf('api/mh/path')>=0) d={ok:true,data:{file:ORDERS_PATH,
      socket:'/vol1/@appcenter/ipsense/app.sock',skill:'ipsense-agent-bridge skill',
      read_cmds:['mh read pending','mh read done','mh read revert','mh read all'],
      api:{state:'GET /api/mh/state?tab=<tab>',show:'GET /api/mh/show?ip=<IP>',
           prompt:'GET /api/mh/prompt?tab=<tab>',path:'GET /api/mh/path',
           write:'POST /api/mh/write（action=prepare / commit / discard）'}}};
    // 1.1.30：密钥授权浮层离线样本（纯 API 数据，不依赖 DOM 位置）（只给指纹 / 公钥 / 时间 / 设备，不给私钥）
    else if(u.indexOf('api/keyauth/state')>=0){
      if(!window.__ka) window.__ka=[{id:'mh1-preview0001',
        fingerprint:'SHA256:PREVIEW000000000000000000000000000000000',
        pubkey:'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPREVIEW ipsense-agent-bridge:mh1-preview0001',
        device:'预览演示设备',created_at:'2026-11-21T23:30:00+08:00',status:'active',
        revoked_at:'',authorized_keys:'/home/user/.ssh/authorized_keys',key_on_device:true}];
      d={ok:true,data:{version:1,grants:window.__ka,
        note:'撤销只删除本应用带 ipsense-agent-bridge 标记的授权行与密钥副本，不动其它密钥'}};
    }
    else if(u.indexOf('api/keyauth/revoke')>=0){
      var kr={}; try{ kr=JSON.parse((opt&&opt.body)||'{}'); }catch(eK){}
      if(!window.__ka) window.__ka=[];
      window.__ka=window.__ka.map(function(g){
        if(g.id===kr.grant_id){ g.status='revoked'; g.key_on_device=false;
          g.revoked_at='2026-11-21T23:40:00+08:00'; }
        return g;});
      d={ok:true,data:{version:1,grants:window.__ka,
        note:'撤销只删除本应用带 ipsense-agent-bridge 标记的授权行与密钥副本，不动其它密钥'}};
    }
    else if(u.indexOf('api/mh/write')>=0){
      var w={}; try{ w=JSON.parse((opt&&opt.body)||'{}'); }catch(eW){}
      if(w.action==='prepare'){
        var it0=ordersItems.filter(function(x){
          return x.status==='pending'||x.status==='revert';})[0];
        d=it0?{ok:true,data:{plan:{token:'tk-preview',ip:it0.ip,rev:it0.rev,
          action:it0.status==='pending'?'mark-done':'restore',
          from:it0.status,to:it0.status==='pending'?'done':'restored'},
          confirm:'离线预览：确认请 mh commit --token tk-preview'}}
          :{ok:false,msg:'旧回执被拒：找不到匹配的当前条目，请重新 mh read'};
      } else if(w.action==='commit'){
        var it1=ordersItems.filter(function(x){
          return x.status==='pending'||x.status==='revert';})[0];
        if(it1){
          var from1=it1.status; it1.status=from1==='pending'?'done':'restored';
          it1.summary=String(w.summary||''); it1.rev++;
          it1.updated=Math.floor(Date.now()/1000);
          it1.history.push({at:it1.updated,action:'commit',from:from1,
            to:it1.status,by:'agent'});
          ordersLog.unshift({at:it1.updated,ip:it1.ip,action:'commit',
            from:from1,to:it1.status,by:'agent',summary:it1.summary});
          d={ok:true,data:{ok:true,item:it1,
            confirm:'离线预览：已确认 '+it1.ip+' → '+it1.status}};
        } else d={ok:false,msg:'预备不存在或已过期，请重新 mh prepare'};
      } else d={ok:true,data:{ok:true,discarded:true}};
    }
    else if(u.indexOf('api/orders')>=0){
      if(opt && String(opt.method||'').toUpperCase()==='POST'){
        var op={}; try{ op=JSON.parse((opt&&opt.body)||'{}'); }catch(eO){}
        if(op.action==='clear'){ ordersItems=[]; ordersLog=[]; }
        else if(op.action==='remove'){
          ordersItems=ordersItems.filter(function(x){return x.ip!==op.ip;});
        }
        else if(op.action==='toggle'){
          var itT=findOrderItem(op.ip); if(itT) itT.in_order=op.in_order!==false;
        }
        else if(op.action==='request-revert'){
          var itR=findOrderItem(op.ip);
          if(itR && (itR.status==='done'||itR.status==='restored')){
            itR.status='revert'; itR.rev++; itR.updated=Math.floor(Date.now()/1000);
            itR.history.push({at:itR.updated,action:'request-revert',
              from:'done',to:'revert',by:'user'});
            ordersLog.unshift({at:itR.updated,ip:itR.ip,action:'request-revert',
              from:'done',to:'revert',by:'user',summary:''});
          }
        }
        else if(op.action==='save'){
          var itS=findOrderItem(op.ip);
          if(!itS){ itS={ip:op.ip||'—',history:[],rev:0}; ordersItems.unshift(itS); }
          itS.note=String(op.note||''); itS.status='pending'; itS.summary='';
          itS.in_order=true; itS.evidence=op.evidence||{};
          itS.updated=Math.floor(Date.now()/1000); itS.rev++;
          itS.history.push({at:itS.updated,action:'save',from:'',
            to:'pending',by:'user'});
          ordersLog.unshift({at:itS.updated,ip:itS.ip,action:'save',from:'',
            to:'pending',by:'user',summary:''});
          ordersNote=itS.note;
        }
      }
      d={ok:true,data:ordersSnap()};
    }
    else if(u.indexOf('api/health')>=0) d={ok:true,version:'2.0.0'};
    // 1.1.15：脱敏诊断包与区级手工补充
    else if(u.indexOf('api/diag/export')>=0) d=diagText;
    // 1.1.30：运行时报错上报 / 查询 / 导出（export 必须排在 errors 之前）
    else if(u.indexOf('api/runtime/errors/export')>=0){
      window.__rtExportHits++;
      d=rtExportText;
    }
    else if(u.indexOf('api/runtime/errors')>=0){
      if(opt && String(opt.method||'').toUpperCase()==='POST'){
        var posted=[];
        try{ posted=JSON.parse((opt&&opt.body)||'{}').items||[]; }catch(eRt){}
        window.__rtPosted=window.__rtPosted.concat(posted);
        rtErrors=posted.concat(rtErrors).slice(0,200);
        d={ok:true,saved:posted.length,total:rtErrors.length};
      } else d={ok:true,data:rtErrors,total:rtErrors.length};
    }
    // 1.1.30：站内查询（复用离线主裁决核验），不依赖第三方反爬页面
    else if(u.indexOf('api/geo/verify')>=0) d={ok:true,cached:false,ip:'220.205.86.196',
      geo:{country:'中国',province:'安徽省',city:'合肥市',district:'蜀山区'},
      verification:{confidence:'high',online_sources:1,
        sources:[{source:'ip2region(本地)',role:'主裁决',country:'中国',province:'安徽省',city:'合肥市',district:''},
                 {source:'ip.sb',role:'参考',country:'中国',province:'安徽省',city:'合肥',district:''}]}};
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
    else if(u.indexOf('api/records')>=0) d={ok:true,data:{total:12840,page:1,size:50,rows:rows}};
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
      agg:{n:186,first_ts:now-86400,last_ts:now,sessions:12,ports:2,paths:9},
      recent:rows.slice(0,10),top_paths:[
        {path:'/fnzerror/api/logs/stream',n:2},
        {path:'/fnzerror/api/cmd/get_folder_stats',n:2},
        {path:'/fnzerror/api/auth/status',n:2},
        {path:'/fnzerror/icons/models/deepseek.png',n:1},
        {path:'/fnzerror/api/cmd/get_server_status',n:1},
        {path:'/fnzerror/models.json',n:1},
        {path:'/fnzerror/api/cmd/get_pending_correction_question_C',n:1},
        {path:'/fnzerror/api/cmd/get_folders',n:1}],
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
    # 1.1.30：单文件预览页把投喂二维码内联成 data URI，否则 file:// 下
    # images/sponsor.png 相对路径失效，关于弹窗截图会显示破图占位。
    sponsor = os.path.join(UI, "images", "sponsor.png")
    if os.path.isfile(sponsor):
        with open(sponsor, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        html = html.replace("images/sponsor.png", "data:image/png;base64," + b64)
    html = html.replace("/*__CSS__*/", rd("style.css"))
    mock = MOCK.replace("/*__NOTIFY_MOCK__*/", NOTIFY_MOCK_JS)
    html = html.replace("<script>/*__JS__*/</script>", mock + "<script>" + rd("app.js") + "</script>")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    print("预览页:", OUT, len(html), "字节")


if __name__ == "__main__":
    main()
