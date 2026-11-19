# IP 动态感知（ipsense）

飞牛 fnOS 原生应用（FPK），实时呈现「谁在扫描我的设备」。

## 1. 能力对照

| # | 需求 | 实现 |
|---|---|---|
| 1 | 地图上实时看见访问来源 | `1.1.8` 起可在设置里切换腾讯 / 高德 / 百度 / 天地图四家合规底图，或配置自定义接口； 世界地图 + 中国地图双视图，三次贝塞尔圆滑弧线整条单色汇聚到本机；连线按连接频率做 5 档热力着色（低频青蓝 → 高频红）并附图例；点击圆点直接打开「IP 来源画像」，画像打开期间自动关闭地图滚轮缩放；事件 3 s / 地图 12 s 轮询，间隔可配置 |
| 2 | IP 来源记录、攻击来自哪里 | 记录表 + 点击展开 IP 画像（归属、首末次、端口、高频路径、最近 20 条动作）；地图圆点复用同一套画像，并展示多源归属核验结果；`1.1.0` 起画像补充访问协议、请求方法 / 状态、入口页会话、协议构成、来路 TOP 与终端设备 |
| 3 | 数据来源：本机日志 / 路由器日志 / 端口敲门 / 敲门网关 | `auth.log`、`access.log` 增量跟踪；fnOS `TRIMEVENT` 结构化登录审计 + `auth.log.1` / `.gz` 轮转回填；路由器 UDP syslog + 日志文件导入；端口敲门（nft `IPSENSE-KNOCK`）为预留数据源；`1.1.14` 起可只读接入 `fn-knock-lite` 按天分片的结构化 JSON 请求日志（默认关闭） |
| 4 | 国内 / 国外 IP 分开显示 | 两张地图分色（境外红、境内青绿）+ 两套排名 + 四个指标卡 + 表格筛选 |
| 5 | 实时访问频率与趋势图 | 每分钟速率、按时间桶聚合的双线趋势（总量 / 境内 / 境外 / 扫描可切换） |
| 6 | 境内和境外访问排名 | `1.1.2` 起与三个统计卡合并为「访问统计与排名」，放在全球地图正下方；境内按省级行政区、境外按国家或地区，双榜并排，全页只保留这一处排名，条目可点击下钻 |
| 7 | 区分访问协议与行为性质 | `proto` 表示通道（`https` / `http` / `web` / `ssh` / `tcp` / `udp` / `icmp`），`verdict` 表示行为性质（正常 / 扫描 / 攻击 / 敲门）；记录表新增协议列与按协议筛选，导出 CSV 同步补充 |
| 8 | 来路 / 受访页 / 入口页 / 终端设备 | 由 fnOS Nginx combined 日志一次派生五张分析卡；入口页按 `ip + UA + 30 分钟桶` 会话取首条请求，静态资源在榜单剔除但总量口径不变；`1.1.3` 起五张卡与每条记录均可点击放大下钻，查看来源 IP 明细并继续打开完整画像；`1.1.4` 起卡片内不再出现滚动条；`1.1.5` 起设置抽屉滚动稳定、文字不再抖动；`1.1.6` 起浮层外的滚轮也能滚动设置内容 |
| 9 | 全球 IP 来源分布 | `1.1.2` 起固定一张全宽世界地图，境内归并到「中国」、境外按国家 / 地区落点；去掉境内 / 全球切换与右侧重复排名，数量色阶与点击下钻保留；后端 `scope=all` 一次返回境内 + 境外全部来源，只给聚合数字与内置中心点坐标，不产出边界 / 区划轮廓 |

| 10 | 把访问态势交给 AI 做防护分析 | `1.1.9` 起设置界面新增「软件汇总日志」，用飞牛原生文件夹选择器指定保存位置，定时生成一份 Markdown 汇总（态势总览 / 高频来源 IP / 可疑事件 / 地域与 Web 画像 / 频率峰值 / 数据口径 / 免责声明 / 给 AI 的处置建议提示）；支持手填路径兜底、按天归档、立即生成与全文预览复制；目录经四层校验，应用仍只观测、不封禁、不自动处置 |

| 11 | 点开保存位置弹出应用内卡片 | `1.1.11` 起「选择文件夹」在**当前应用窗口内**弹出飞牛原生卡片，不新开浏览器窗口、不整页跳走；主通道复刻 penpal 握手调用桌面桥 `pickUserFile()`（与 ZError 题库一致），握手失败降级为应用内模态卡片 + 同源 iframe 内嵌 `/app-auth` 原生授权页；`picker-cb.html` 回传后自动回填。`1.1.10` 的 `window.open` 独立窗口做法已废弃 |

| 12 | 按钮不再被地图层吃掉 | `1.1.12` 起地图容器加 `isolation:isolate` 创建层叠上下文，锁死地图 SDK 注入的 `z-index:1000` 交互层；顶栏 / 遮罩 / 抽屉 / 放大面板 / 提示条 / 卡片遮罩统一抬到 1000 以上，页面滚动后地图与 sticky 顶栏或右侧抽屉重叠时按钮仍可点击 |

| 13 | 选择文件夹能真正回填路径 | `1.1.13` 起 penpal `args` 数组化、主通道走 `pickFile` 避开应用授权、返回结构统一归一化；选中文件夹点「选择」不再误报「已取消选择」，失败显示真实原因并可手填路径兜底 |
| 14 | 接入外部敲门网关日志 | `1.1.14` 起目录级增量扫描 `fn-knock-lite` 按天落盘的结构化 JSON，按白名单提取 `client_ip` / 认证状态 / WAF 动作 / Host / 路径；区分认证通过、认证被拒与 WAF 拦截，进地图、排名、记录表与汇总日志；只观测，不改对方配置与防火墙 |

## 2. 架构

```
FPK
├── manifest / ICON.PNG / cmd / config / wizard / LICENSE / app.tgz
└── app.tgz
    ├── server/
    │   ├── gateway.py    AF_UNIX + 剥 /app/ipsense 前缀 + HTTP/1.1 + 进程管理
    │   ├── collector.py  三路采集、日志解析、批量写入
    │   ├── store.py      SQLite 事件库与全部聚合查询
    │   ├── geoip.py      ip2region xdb 纯标准库读取 + 境内/境外判定 + 坐标
    │   ├── geosource.py  3 家在线权威源 + 本地库多源投票、缓存与回写
    │   ├── settings.py   配置读写（TRIM_PKGVAR/config.json）
    │   └── data/ip2region_v4.xdb   IPv4 离线归属库（11.1 MB，基础源）
    ├── ui/
    │   ├── index.html / style.css / app.js   （服务端内联成单页下发）
    │   └── config / images/icon_{64,256}.png
    └── scripts/enable_knock.sh   端口敲门只读诊断
```

运行期数据：`/vol1/@appdata/ipsense/`（`events.db`、`config.json`、`inbox/`、`ipsense.pid`）。
应用日志：`/var/log/apps/ipsense.log`。Socket：`/vol1/@appcenter/ipsense/app.sock`。

`1.1.0` 起 `events` 表在原字段基础上追加 8 列：`layer`、`proto`、`scheme_conf`、`method`、`status`、`referer`、`ua`、`sess_id`。升级走 `PRAGMA table_info` + `ALTER TABLE ADD COLUMN` 幂等补列，不重建表；已入库的历史 Web 行由 `upgrade_web_events()` 读 `raw` 重新解析后按 `dedup` 精确 `UPDATE`，不会重复 INSERT、不丢任何一条记录。

### 关键工程决策

- **不监听 TCP 端口**：HTTP 走 Unix Socket，由飞牛 nginx 转发；只有路由器 syslog 采集器监听 UDP 5514（可配置）。
- **前端内联**：iframe 的票据只存在于页面 URL 查询串里，独立静态资源请求不带票据会被网关判 `invalid token`，因此首页由后端把 CSS/JS 内联后一次性下发；所有 `fetch` 都显式拼接 `location.search`，且不使用 `Authorization` 头。
- **零第三方运行时依赖**：Python 3 标准库 + sqlite3；xdb 读取器自研（索引段每条 14 字节，二分查找 553,970 条）。
- **root 运行**：`auth.log` 是 `root:adm 640`，普通应用用户读不到。应用只读日志、写自己的数据库、监听高位 UDP，**不修改任何防火墙规则**。
- **合规地图**：全球底图必须走合规服务。应用不内置任何有效地图密钥，默认降级为「坐标散点示意」（只画经纬网、点与弧线，不绘制国界/海岸线）。配置用户自己的腾讯地图 key 后才加载腾讯地图 GL JS 合规底图。中国香港、中国澳门、中国台湾统一计入境内，不作为国家或境外地区展示。
- **全球 IP 分布只传数字**：`/api/geodist` 默认 `scope=all`，一次返回境内 + 境外按国家 / 地区聚合的 `count`、`ips` 与内置中心点 `lat` / `lng`（境内统一归并到「中国」），**不返回任何 GeoJSON、边界或区划轮廓**。前端只在腾讯地图合规底图上叠加数量气泡；无 key 时降级为只画经纬网的 canvas 散点。国界与行政区划一律以官方合规底图为准。旧的 `scope=cn` / `scope=overseas` 仍保留，供省份级下钻等用途。
- **协议不硬猜**：Nginx combined 的 `$request` 只含 `HTTP/1.1`、不含 scheme，也拿不到可信的 `X-Forwarded-Proto`。因此只信「设置页手动覆盖」与「同站来路推断」两类信号并标注 `scheme_conf`（`manual` / `medium` / `none`）；没有可靠信号就显示「Web 未识别」，绝不伪造 `https` / `http`。延续 `1.0.8` 多源校验「标置信度、不伪造」与 `1.0.3` 「不硬编码本机位置」的同一原则。
- **改动系统配置不可持续**：fnOS 的 `access.log` 本来就是 combined 格式，无需改 nginx `log_format`；改了也会在系统升级时被覆盖。因此解析只在应用侧做。

## 3. 数据源与判定规则

| 来源 | 通道 | 判定 |
|---|---|---|
| 本机 SSH | `/var/log/auth.log` | `Failed password` / `Invalid user` → 认证攻击；`Accepted` → 正常；认证前断开 → 扫描；过滤本地 sudo 与会话噪声 |
| 本机 Web | `/usr/trim/nginx/logs/access.log` | 路径命中 `.env`、`wp-login`、`phpMyAdmin`、`../`、`/actuator` 等探测特征，或非静态资源返回 4xx → 扫描；其余为正常访问。`1.1.0` 起按 combined 格式额外取 `method` / `status` / `referer` / `ua`，并派生协议、来路、受访页、入口页与终端设备 |
| fnOS 结构化审计 | `auth.log` 内 `TRIMEVENT` JSON | `SshdLoginAuthFail` → 认证攻击；`SshdLoginSucc` → 正常；`SshdLogonout` 不入库；JSON 字段直接取 IP 与用户名 |
| SSH 轮转日志 | `auth.log.1`、`auth.log.*.gz` | 首次或手动全量回填时读取尾部，找回此前漏采的历史失败登录 |
| 路由器 syslog | UDP 5514 | 解析 `SRC=` / `DPT=`，敏感端口或 DROP/REJECT 关键字 → 扫描 |
| 路由器文件 | `inbox/*.log`、`*.txt` | 逐行解析，换文件名可重新导入 |
| 端口敲门 | `/var/log/kern.log`（`IPSENSE-KNOCK`） | 预留，默认未安装；`scripts/enable_knock.sh` 只做只读诊断 |
| 敲门网关（1.1.14） | `fn-knock-lite/gateway/logs/*.json*` | 按天分片目录增量扫描；白名单取 `client_ip` 优先，动作分认证通过 / 认证被拒 / WAF 拦截 / 网关请求；`source=knock_app`、`verdict=knock`；默认关闭 |

事件唯一键 `dedup = md5(ts|source|ip|raw)[:20]`，重复导入不会产生重复记录。默认保留 30 天，每小时清理一次。

归属判定以内置 `ip2region` 离线库为基础；设置里开启「在线多源校验」后，`ip-api.com` / `ip.sb` / `ipinfo.io` 与本地库共 4 票，按国家、省份、城市多数派裁决，结果写入 `geo_cache`（默认 30 天有效）并回写 `events` 表，地图、排名与记录立即使用更准的归属。三家源并行查询，单源失败或全部不可用时自动回退离线库并标注置信度。城市名在投票前统一归一为中文，裁决后的坐标与最终省份保持一致（同省票坐标优先，否则取省级中心点）。内网地址单独归类为 `lan`，保留在记录表但不参与公网地图、热点与排名。

## 4. 更新日志（详版）

### 功能演进

**1.1.16（当前版本）**

- 🐛 **真机弧线全部不显示**：1.1.15 为跨日期变更线长弧生成 `-360 / 0 / +360` 三份世界副本折线，真机腾讯地图 GL 的 `MultiPolyline` 只接受 `[-180,180]` 经度，实测美国方向产出 `-540°~+540°`、297 个点里 196 个越界，整层折线被拒绝渲染，两张地图一条线都没有。离线预览走 Canvas 降级、上一轮真机验收又主动屏蔽了外网底图 SDK，因此没覆盖这条路径。修复为 SDK 侧统一归一化到合法窗口并在 `±180` 边界分段（`wrapSegs`），Canvas 侧继续用本机中心连续窗口让两段首尾相接；`sdkLat()` 再做坐标钳制兜底。`tools/check_116_geometry.mjs` 实测 4 组方向全部 0 越界。
- 🐛 **设置开关点不动**：`sw()` 生成的 checkbox 是 `0×0` 且 `opacity:0`，可见滑块是 label 外的 `<i>`，点击不会触发 checkbox。修复为 `label[for]` + input 绝对定位铺满 `.switch`，`<i>` 设 `pointer-events:none`。
- 🐛 **目标端口恒为 5666**：Nginx combined 日志不含目标端口，旧实现把应用自身监听端口 `web_port` 填进 `port`。新增 `web_log_port()` 只认日志行尾的 `$server_port`，Referer 是上一个页面的 URL、不参与推断（真机同站来源带 `:5666` 会让每条又变成 5666）；升级时 `normalize_web_ports()` 幂等订正历史记录，前端显示「未记录」。
- 🐛 **离线库把 `39.144.239.169` 判成重庆市**：该 IP 离线库返回重庆，三家在线源多数派为安徽 / 合肥。旧逻辑每次 `force` 核验都用 `lookup_uncached()` 把重庆重新带进本地票，`geo_cache.local_*` 也一直残留，地域分布缓存因此留下一个「重庆市 165」的假气泡。新增 `geo_local_fix` 表固化在线裁决，`verify()` 优先取订正值；`apply_geo()` 回写后 `clear_cache()`，升级时 `normalize_local_geo()` 幂等同步历史缓存。
- 🆕 **区级归属的现实口径**：实测 `ip-api.com` / `ip.sb` / `ipinfo.io` 免费版都不返回 `district`，`ip9.com.cn` 的 `area` 对 5 个国内 IP 全为空 —— 1.1.15 的自动区级补充实际拿不到数据。用户提到的 `tool.hiofd.com/ip/` 能返回「包河 / 龙川路」，但它的 `/router/rest?method=IpQuery` 带 DES 签名反爬，免签名直连一律 `HTTP 444`，不是公开 API，因此不内置自动调用。改为画像里提供「在线校验」一键打开查询页并复制 IP，查到的区县回填 `/api/geo/district`；设置里另开放自定义 JSON 区级接口（`{ip}` 占位 + 字段路径），默认关闭，强制 https 且禁止内网 / 元数据地址。区级补全入口对**所有** IP 可见，不再只在已在线核验的 IP 上出现 —— 新 IP 恰恰最需要补区县。

**真机回归二次修复（本版额外修掉的 3 个缺陷）**

本版坚持在真机上走**未屏蔽外网的腾讯地图合规底图 SDK 路径**，因此抓出 3 个离线预览与静态自检都覆盖不到的问题：

- `sdkLat()` 初版定义在 `createTMaps()` 内部，而调用它的 `drawTMaps()` 是另一个顶层函数；SDK 底图一执行折线绘制就抛 `Uncaught ReferenceError: sdkLat is not defined`，整层弧线不渲染。离线预览走 Canvas 坐标散点降级，永远执行不到这行。已提升为 IIFE 顶层函数，并在几何检查 / 全量自检 / 包校验 / 预览验收四处加静态作用域断言；修复后真机 hook 捕获到提交给 SDK 的 `LatLng` 从 6 个增至 **205 个**，全程 0 未捕获异常。
- `web_log_port()` 初版允许从 `Referer` 取端口。真机 `access.log` 的 Referer 是 `http://<host>:5666/app/ipsense/`，那是用户浏览器访问 fnOS 桌面时「上一个页面」的端口，不是当前请求的目标端口，于是 `/api/live` 又全变成 5666。已彻底不再解析 Referer，只认自定义 `log_format` 行尾的 `$server_port`；二次部署后实时端口从 `[5666×6]` 变为 `[0×6]`。
- 「在线校验」里的 `navigator.clipboard.writeText()` 在内嵌 WebView / 页面未聚焦时返回被拒绝的 Promise，`try/catch` 抓不到异步拒绝，会污染成 `unhandledrejection`。已显式 `.catch()` 吞掉，功能不变（仍可手动复制并打开查询页）。

上述三项都在 `fn-OESP` 上复现 → 修复 → 重新打包 → 重新卸载重装 → 复验闭环，详见 `build/ipsense-1.1.16-OESP真机回归验收报告.html`（本地报告，不随 FPK 分发）。

**1.1.15**

- 🐛 **境外全球视图长弧线中断**：根因有两层。等距投影侧旧窗口固定 `[-180,180]`，跨国际日期变更线的长弧被 `wrapSegs()` 切成两半分别落在画布最左 / 最右，中间隔着整幅地图；SDK 侧 `MultiPolyline` 只渲染一个 360° 窗口，切两半后通常只有一半落在视野内。修复为「以本机经度为中心的 360° 连续窗口」（`worldCenteredBounds()` / `unwrapTo()`），被切开的两段在窗口内自然首尾相接；SDK 侧另由 `worldSegs()` 生成 `-360 / 0 / +360` 三份世界副本折线，任意视野里都有一条完整弧。跨 seam 长弧采样从 64 段加密到 96 段。数值回归（`tools/check_115_geometry.mjs`）实测展开后 0 个 360° 跳变、两段在 180° 处经度差 0、末点正确落到本机。
- 🐛 **同省内 IP 不显示**：两个独立缺陷叠加。前端 `buildArcs()` 近距阈值 `0.35°` 把同省不同市（广州 113.26 / 深圳 114.06，距离度量 1.2651）整组判成「与本机重合」，只留 2.6px 小点不画弧；后端 `_geo_distribution_uncached(scope="all")` 把所有境内归并成一个「中国」气泡。修复为阈值降到 `0.02°`（约 2km）、后端境内按省细分并返回 `r.scope`、前端气泡下钻按 `r.scope` 选匹配字段。另查出省份名不统一（离线库「安徽省」/ 在线源「安徽」）会拆成两个气泡，新增按 `GeoResolver._province_key()` 归一合并；坐标查找也补了短名宽松匹配，避免 `lat/lng=None` 导致气泡根本不画。
- 🆕 **实时事件监控范围筛选**：记录表已有 `fScope`，实时事件卡片新增 `liveScope` 下拉（全部范围 / 境内 / 境外 / 内网 / 局域网设备）。前端按 `e.scope` 过滤，后端事件流仍全量推送，切换无需重新请求；标签同步显示当前范围与条数。
- 🐛 **新 IP 首次归属判定错误**：实测 `220.205.91.142` 离线库返回「中国|广东省|广州市|联通|CN」，而 `ip-api.com` / `ip.sb` / `ipinfo.io` 三家均为安徽 / 合肥。旧逻辑只在启动后 `queue_top()` 高频 IP，新 IP 不立即核验，必须手动点「批量校验高频 IP」才恢复。修复为 `Collector.set_verifier()` 注入校验器，入库成功后对 `scope` 为 `cn` / `overseas` 的新 IP 调 `verifier.enqueue()`；队列改为有界 `queue.Queue(maxsize=512)` 并用 `_pending` 集合去重，避免日志洪峰打爆后台线程。设置页新增「新 IP 首次出现即自动核验」开关。
- 🆕 **区级信息**：`events` / `geo_cache` 幂等新增 `district` / `district_source` 列；离线库第 6 段可选区县、`ip-api.com` 的 `district` 字段、独立源 `ip9.com.cn` 补区县（明确**不参与**省 / 市 4 票裁决，避免把国内库省级偏差带进多数派）。CSV 导出、10 段汇总日志、记录表、实时事件、单 IP 画像、整组画像、五卡下钻 IP 明细统一带区级。免费源覆盖不稳定时，画像里可手工填写并回写历史事件（`/api/geo/district`）。
- 🐛 **高德 KEY 报错指向不存在的域名**：全仓确认正确域名是 `webapi.amap.com`，用户看到的 `webapiamap.com` 不在当前源码里。实测无效 KEY 时高德返回 `Content-Type: text/plain` 的 `console.log("<AMap JSAPI> Error key!")`，浏览器触发 `script.onerror` 或「AMap 未创建」。修复为 `mapSdkUrl()` 自动纠正历史错误域名、`sdkFailHint()` 按引擎区分「KEY 无效 / 未绑定 Web 端 / 域名白名单 / 未配 jscode / 网络拦截」并给出正确域名，底图诊断标注「已自动纠正旧域名」。
- 🆕 **运行日志一键导出**：新增 `src/app/server/diag.py` 与 `/api/diag/export`，合并主运行日志、兜底副本、生命周期日志、应用状态、数据源状态、配置白名单脱敏版与数据库聚合计数，输出可直接贴 Issue 的纯文本。配置先按键名剔除 `map_key` / `map_keys` / `map_custom` / 出口 IP，文本再整体过 `scrub()`：令牌 / 口令 / Bearer / 私钥 / 邮箱抹除，IPv4 只保留前两段，IPv6 整体替换；**不读取 `events.db` 原始事件行**。设置界面最底部提供导出与预览两个按钮。
- 🆕 **仓库排障三件套**：`tools/diag_bundle.sh`（只读收集 + 自动脱敏 + 自动打 tar.gz，优先复用 `diag.scrub()`，旧版本回退内嵌同规则实现）、`.github/ISSUE_TEMPLATE/bug_report.yml`（结构化表单，把「诊断 6 件套」设为必填）、`docs/排障指南.md`（日志位置、命令清单、按症状排查、隐私边界 SOP）。根 README / 详版 README / 使用说明均加入口链接。
- 🧩 本地验证：新增 `tools/check_115_geometry.mjs`（真实前端函数抽取 + 17 项几何断言）与 `tools/smoke_115_store.py`（临时 SQLite 真实建表 + 19 项后端断言），覆盖省份归一合并、区级字段透传与脱敏不泄漏。

**1.1.14**

- 🆕 新增「敲门网关请求日志」数据源，面向飞牛应用中心的第三方 `fn-knock-lite`（敲门 knock Lite）。该应用本质是反向代理 + 身份认证 + WAF + 内网穿透，公网请求先到它的网关，未通过认证的请求根本进不了 fnOS 的 `auth.log` / `nginx access.log`，是此前 `ipsense` 最大的感知盲区。
- 🆕 接入依据是真机取证而非猜：官方文档「请求分析」说明网关**按天把结构化 JSON 写到运行目录 `logs/`**，字段取自 Go 网关二进制的 `json` tag（`client_ip` / `remote_ip` / `logged_time` / `auth_decision` / `waf_action` / `status_code` / `host` / `path` / `scheme` 等）。因此新增 `KnockDirTailer` 做**目录级增量扫描**（inode + offset、最多 12 个分片、首次只回补尾部 64KB），而不是复用单文件 `LogTailer`。
- 🆕 `parse_knock_app()` 按白名单取字段：优先 `client_ip`，其次 `remote_ip` / `ip`；时间兼容 ISO8601、epoch 秒 / 毫秒与常见文本；协议只在日志明确给出 `http` / `https` 时采用，否则标 `web`（未识别），不硬猜。动作分为「认证通过 / 认证被拒 / WAF 或策略拦截 / 网关请求」四类，统一 `source=knock_app`、`verdict=knock`，可直接用记录表「来源」筛选并与第 2、3 节的同一 IP 时间线对照。
- 🆕 汇总日志新增 `3.1 敲门网关与授信时间线`：按动作分组统计 + 逐条明细，明确写出「认证被拒 / WAF 拦截不等于攻击定性」。未启用该通道时如实写明「未接入」，不填任何推测值。
- 🧩 设置页新增「敲门网关 · 请求日志」开关、「敲门网关日志目录」「敲门网关入口端口」两个输入；默认关闭、默认目录 `/vol1/@appdata/fn-knock-lite/gateway/logs`（真机实证存在），入口端口默认 `8999`（Lite 版 `service_port`）。
- 🧩 合规边界不变：**只读对方落盘日志**，不替用户打开对方日志开关、不修改对方配置、不修改防火墙、不封禁 IP、不自动处置；字段缺失留空、不补齐。与 1.0.0 起预留的 `IPSENSE-KNOCK` 内核日志通道互不干扰，可同时关闭 / 分别开启。
- 🧩 1.1.13 文件夹选择、1.1.12 地图层级、1.1.9 汇总日志、1.1.8 四家地图切换、1.1.7 状态标、1.1.6 滚轮重定向全部无回归。

**1.1.13**

- 🐛 修复「选中文件夹点『选择』却提示『已取消选择』」。真机复取证飞牛桌面壳 `index-BERCugxW.js` / `methods-CKCf4fL2.js` / `_method_-BdHd5sAY.js`：父窗口 penpal 消息处理 `B$e` 用 `t[methodName].apply(t, args)` 展开参数，**`args` 必须是数组**；1.1.11 / 1.1.12 误传单个对象，`.apply` 把参数全部丢弃，`pickUserFile` 收到 `{}`，`directory:true` / `sidebarGroup` / `title` 全部失效，选择器退回默认「选文件」模式（用户截图标题正是「选择文件」、左侧为默认四分组），选中文件夹点「选择」返回空 `data:[]`，`finishBridge` 又把空路径一律兜底成「已取消选择」。
- 🐛 取证到的返回包装：`W7=e=>({code:0,msg:'',data:e})`（成功）、`K7=(e,t)=>({code:-1/1,msg,data:t})`（`-1` 取消 / `1` 失败）；`pickUserFile` 选中后还会强制 `l8()` = `addUserAuthorizationPath()`，授权失败直接把整包结果吞成 `{code:1,data:[]}`。
- 🆕 主通道改为 `pickFile`（纯路径选择、不触发应用文件授权），`pickUserFile` 仅作父窗口未暴露 `pickFile` 时的回退；penpal `call` 的 `args` 包成 `[opts]`，`directory:true` 与 `sidebarGroup` 正常生效，选择器进入「选择文件夹」模式。
- 🆕 新增 `pickPathsFrom()` / `pickIsCancel()` / `pickErrMsg()` 统一归一化返回：兼容裸数组、`{code,msg,data}`、`{paths}`、`{path}`、字符串与 `{path,name}` 对象数组；拿到路径即成功，只有明确取消信号（`code:-1` / `Cancelled`）才提示「已取消选择」，其余显示真实 `msg` 并给出「可手动填写 NAS 绝对路径」兜底。
- 🧩 降级通道 `/app-auth/pick-user-file` 改为 `/app-auth/pick-file`（`_method_` 页 `pickFile` 分支 `onOk` 直接 `k('success', paths)`，无授权步骤），`redirectUri` 同时给 `redirect_uri` 兜底；`picker-cb.html` 兼容单值 / 字符串 / 对象数组与 `ok` / `1` 状态，`consumePickerCallback` 方法白名单补 `pickFile` / `pick-file`。
- 🧩 调用级 reject（用户取消、方法失败）不再盲目重弹卡片，统一交回 `finishBridge` 判定；仅握手失败才降级到应用内模态卡片。
- 🧩 口径不变：1.1.12 地图层级修复、1.1.11 应用内卡片、1.1.9 汇总日志与只观测、1.1.8 四家地图切换、1.1.7 状态标、1.1.6 滚轮重定向均无回归；仍不新开窗口、不改防火墙、不封禁 IP。

**1.1.12**

- 🐛 修复「设置按钮 / 设置界面里的按钮点不动」：腾讯地图 GL（高德 / 百度 / 天地图同理）会往地图容器注入一个 `position:absolute; z-index:1000` 的交互层，而 `.map-wrap` / `.geo-map-wrap` 原先只有 `position:relative`、**不创建层叠上下文**，这个 `z=1000` 子层便跑到根层叠上下文，压过顶栏(20)、遮罩(40)、抽屉(50)、放大面板(45) 与提示条(80)。页面滚动后地图与 sticky 顶栏重叠、或右侧抽屉与全宽地图重叠时，`elementFromPoint` 命中的都是地图那个 DIV，按钮收不到 click。
- 🐛 取证方式：把真机 `https://map.qq.com/api/gljs` 的 SDK 拉到本地，Chrome headless 注入并真实 `new TMap.Map()` 初始化 3 个容器，再用 `document.elementFromPoint()` 打印命中链。修复前 `btnPickFolder` 命中 `DIV z=1000 → #cnMap.tmap → #cnWrap.map-wrap`；修复后命中 `BUTTON#btnPickFolder`。另加「滚动到地图与顶栏重叠」场景验证 `btnSettings` 同样恢复。
- 🆕 给两个地图容器加 `isolation:isolate` 创建层叠上下文，把 SDK 的高层级**锁死在容器内部**；容器整体以 `z-index:auto` 参与根层叠，SDK 内部任何层级都越不过 UI 浮层。
- 🧩 双保险：顶栏 `1100` / 遮罩 `1200` / 放大遮罩 `1300` / 放大面板 `1350` / 抽屉 `1400` / 提示条 `1500` / 卡片遮罩 `20000`，全部抬到 1000 以上，防 SDK 往 body 挂浮层或后续换引擎。
- 🧩 容器内自绘蒙版抬到 `1100`、图注与图例抬到 `1101` / `1102`（并给图注补 `pointer-events:none`），地图水印、频率色阶与地域图例保持可见且不吃地图点击。
- 🧩 口径不变：1.1.11 应用内卡片 / penpal 主通道、1.1.10 小卡片、1.1.9 汇总日志与只观测、1.1.8 四家地图切换、1.1.7 状态标、1.1.6 滚轮重定向均无回归；地图拖动 / 缩放 / 点圆点看 IP 画像不受影响。

**1.1.11**

- 🆕 修复「点开保存位置是单独开一个窗口」：1.1.10 误把 `@trimjs/web-app` SDK 的 standalone 降级函数 `N7e()` 当成主通道，用 `window.open(url, '_blank', 'width=750,height=630')` 新开了一个带地址栏 / 标签栏 / 书签栏的独立 Chrome 窗口。真机第二轮取证（`/usr/trim/www/assets/index-BERCugxW.js` 桌面壳主包 + zerrorfnos 打包 SDK）确认 ZError 的图一卡片走的是 `Ioe()` 分流里的 `I7e()` 主通道：`window.parent !== window && !isStandaloneWeb` 时用 penpal 与桌面父窗口握手，调用父窗口暴露的 `pickUserFile()`，由桌面壳在应用窗口内渲染原生 dialog（`title` / `okText` / `creatable` / `sidebarGroup` / `fullScreen`）。
- 🆕 新增 `fnosBridge()`：复刻官方 `connectToParent` 的最小客户端，`{penpal:'syn'}` → 等 `{penpal:'synAck', methodNames:[...]}` → 回 `{penpal:'ack', methodNames:[], config}` → 用 `{penpal:'call', id, methodName, args}` 调父窗口方法、按 `id` 收 `{penpal:'reply', resolution, returnValue}`；1.5 s 握手超时（对齐 SDK），启动时预热以避开父窗口 60 s 的 `connectToChild` 窗口。不引入外部 SDK，也不再依赖真机上不存在的全局 `window.TrimApp`。
- 🆕 `fnosPickFolder()` 主通道调 `pickUserFile({directory:true, multiple:false, title, okText:'选择', creatable:true, accept:[], sidebarGroup:[...]})`，返回 `{code:0, data:[path]}` 直接 `saveSummaryDir()`；`code===1` / 空数组视为取消，不再误弹降级卡片。
- 🆕 降级通道 `openPickerCard()`：握手失败 / 独立浏览器直连时，在应用内画 750×630 浅色模态卡片（遮罩 + 标题栏 + 关闭 + ESC），内部用**同源 iframe** 内嵌飞牛原生 `/app-auth/pick-user-file` 授权页，目录树与「新建文件夹 / 取消 / 选择」全部由原生页渲染，应用不自绘目录树；`redirectUri` 指向同源静态回调页。
- 🆕 新增静态回调页 `src/app/ui/picker-cb.html`（后端零改动，`static_file()` 直接服务）：读回跳 URL 的 `status` / `state` / `path`（JSON 数组）/ `error`，写 `sessionStorage` 并 `parent.postMessage()` 回主页面；卡片收到后自动关闭并回填。
- 🆕 `watchPicker(state)` 改为三路收结果（`message` 校验 `origin` + `type` + `state`、`sessionStorage` 600 ms 轮询、300 s 超时），用户关闭卡片直接收口为取消；移除 `win.closed` 子窗口判定与 `PICK_WIN_FEATURES`。
- 🆕 离线预览页改为双仿真：`__ipsenseMockBridge` 模拟主通道 `pickUserFile` 调用与参数，`__ipsensePickerCardRender` 在应用内卡片里渲染同构目录树；`window.open` 改为只记录调用，探针可断言它从未被使用。真机 http/https 下两类仿真都不加载。
- 🧩 口径不变：手填路径兜底、目录四层校验、`state` 校验、汇总日志只观测 / 不封禁 / 不自动处置、不产出自绘边界与国界；1.1.10 小卡片、1.1.9 汇总日志、1.1.8 地图切换、1.1.7 状态标与 1.1.6 滚轮重定向均无回归。

**1.1.10**

- 🆕 修复「点开保存位置不是小卡片」：1.1.9 用 `location.assign()` 整页跳到 `/app-auth/pick-user-file`，且父窗口收不到回传。真机取证（读取 `/var/apps/zerrorfnos/target/ui/assets/index-*.js` 里打包的 `@trimjs/web-app` SDK）确认官方 standalone 降级通道是 `window.open(url, '_blank', 'width=750,height=630')`，飞牛桌面壳把它渲染成居中卡片，内容就是「我的文件 / 他人共享 / 我的收藏 + 目录树 + 新建文件夹 + 取消 / 选择」。
- 🆕 `fnosPickFolder()` 通道 B 改为小卡片窗口：URL 补 `creatable=true`（新建文件夹）、`okText=选择`、`fnosPickerCallback=1` 回跳标记；`redirectUri` 用 `new URL(location.href)` 保留原有查询串（网关票据）只清 hash，不再手工拼 `origin + pathname + search`。
- 🆕 SDK 的 `class Eoe` 是模块内单例，真机上并没有全局 `window.TrimApp`，所以通道 A 只作兼容保留（宿主注入时仍优先用桌面父窗口的模态卡片，并补 `creatable: true`）；真正生效的是通道 B。
- 🆕 新增 `watchPicker(win, state)`，照官方 N7e 四路收结果：`message` 事件校验 `origin` + `type=ipsense:fnos-picker` + `state`；`sessionStorage['ipsense.fnos.picker.result']` 600 ms 轮询；`win.closed` 延迟 1.2 s 确认后视为取消（避免抢在结果回传前误报）；300 s 超时。
- 🆕 `consumePickerCallback()` 在回跳页把结果同时写 `sessionStorage` 并 `window.opener.postMessage()`，让父窗口也能收口；本页仍保留兜底保存。URL 清理时一并删掉 `fnosPickerCallback`，有 `opener` 时不再重复渲染设置抽屉。
- 🆕 设置界面说明改为「以 750×630 小卡片弹出」，明确当前页面不跳走、被浏览器拦截时允许弹出或手填。
- 🆕 预览页新增 `file://` 专用离线仿真卡片（拦截 `window.open`，同构渲染我的文件 / 他人共享 / 我的收藏 + 目录树 + 新建文件夹 + 取消 / 选择），点「选择」通过 `MessageEvent` 与 `sessionStorage` 回传，供探针与截图验收；真机 http/https 下不加载，生产仍走飞牛原生选择器。
- 🧩 口径不变：手填路径兜底、目录四层校验、汇总日志只观测 / 不封禁 / 不自动处置、不产出自绘边界与国界；1.1.9 汇总日志、1.1.8 地图切换与自定义接口、1.1.7 三级状态标与 SWR 缓存、1.1.6 浮层外滚轮重定向均无回归。

**1.1.9**

- 🆕 设置界面新增「软件汇总日志」区块：用飞牛原生文件夹选择器指定保存目录。清单加 `micro_app = true` 且 `disable_authorization_path = false`，弹窗由 fnOS 桌面 / `/app-auth` 授权页渲染，应用不自绘目录树；`pickUserFile` 顺带完成用户目录授权，后端才有权限落盘。
- 🆕 通道 A：宿主注入 `window.TrimApp` / `window.trimjs.TrimApp` 时直接 `pickUserFile({directory:true, ...})`，不跳页；通道 C：零依赖拼 `/app-auth/pick-user-file?appName=&redirectUri=&state=&directory=true&sidebarGroup=...`，`redirectUri` 保留 `location.search` 以免回跳丢网关票据。回传 `path` 是 JSON 数组字符串，`state` 必须校验并做 300 s 超时兜底，`status=success|cancel|error` 分别处理。
- 🆕 目录落盘前走四层校验：`path_allowed()` 绝对路径 + 归一化防穿越 + 白名单（`/vol\d*`、`/home`、`/mnt`、`/media`，拒绝 `/vol\d*/@...` 应用数据区与系统目录）→ `os.path.realpath()` 后再次校验防软链越界 → `os.path.isdir()` → `os.access(W_OK|X_OK)` 与实际写探针；前端不信任选择器回传，一律交给 `/api/summary/validate`。
- 🆕 `summary.py` 生成 9 段 Markdown：生成信息 / 态势总览 / 高频来源 IP / 可疑异常事件明细 / 地域来源分布 / Web 访问画像 / 访问频率趋势与峰值 / 数据口径与免责声明 / 给 AI 的分析与处置建议提示。数据全部来自现有 `store.py` 聚合接口，不伪造、不上传。
- 🆕 `write_summary()` 原子写 `ipsense-summary-latest.md`（固定覆盖，便于把同一个文件持续交给 AI）并按天归档 `ipsense-summary-YYYYMMDD.md`（同天覆盖，不自动删除任何历史文件）。
- 🆕 `SummaryWriter` 后台线程 30 秒检查一次，按配置的 `summary_interval` 分钟生成；改设置无需重启，保存配置后若汇总相关项变化会立即后台生成一份。
- 🆕 新增 5 个接口：`/api/summary/status` / `preview` / `validate` / `generate` / `download`；`/api/config` 下发 `summary` 状态块。配置新增 `summary_dir` / `summary_enabled` / `summary_interval` / `summary_range`，其中路径与窗口在 `settings.py` 里做白名单与枚举校验。
- 🆕 设置界面支持「选择文件夹（飞牛原生）」「校验并保存路径」手填兜底、「立即生成」「预览全文」「复制全文」「下载 `.md`」，并显示保存位置、目录状态、自动生成、统计窗口、最新文件、上次生成、文件大小与累计生成次数。
- 🧩 口径不变：汇总日志只汇总既有事实，应用只观测、不修改防火墙、不封禁 IP、不自动处置，所有防护动作都写在「给 AI 的分析与处置建议提示」里请人工确认；不产出自绘边界 / 国界 / 行政区划轮廓。
- 🧩 1.1.8 地图服务切换与自定义接口、1.1.7 三级状态标与 SWR 缓存、1.1.6 浮层外滚轮重定向均无回归。

**1.1.8**

- 🆕 设置界面新增「地图服务」区块：预置腾讯地图 GL JS / 高德 JS API 2.0 / 百度地图 GL v1.0 / 天地图 4.0 四家合规接口，点选卡片即切换底图引擎。
- 🆕 四家 SDK 地址、密钥申请入口、坐标系与产品说明随预设写入设置页；各家 `key` / `ak` / `tk` 分别保存，切换服务商不会丢另一家的密钥。
- 🆕 支持自定义接口：填名称、接口 id、兼容引擎、SDK 地址（含 `{key}` 占位）、API 密钥、申请地址与备注，可增删改，最多 8 个。
- 🆕 切换后 `rebuildMap()` 彻底销毁旧引擎实例与覆盖层，回退 Canvas 散点，再按新服务商重新加载 SDK；失败自动回落散点模式，数据功能不受影响。
- 🆕 底图诊断新增「当前服务商 / 引擎 · 坐标系 / SDK 地址 / KEY 已配置」，`tileStat()` 瓦片统计覆盖四家域名；页脚与合规横幅随当前服务商动态显示。
- 🧩 核心做法是把 `TMap.*` 抽象成统一的 SDK 兼容层（对外暴露 `SDK` 六件套：`Map` / `LatLng` / `MultiPolyline` / `MultiMarker` / `PolylineStyle` / `MarkerStyle`），四家各实现一套适配器，`drawTMaps` / `syncGeos` / `bindMarkerEvents` / `geoMarkStyles` 整套弧线、圆点、增量同步与点击下钻零改动复用。这套 SDK 兼容层是 1.1.8 多引擎切换的地基。
- 🧩 非腾讯引擎用 `GeoLayer` 复刻 `add` / `updateGeometries` / `remove` / `setGeometries` / `getGeometries` / `on` 接口，`MapView` 统一 `destroy` / `resize` / `setScrollable`；事件对象包装成 `geometry.id` + `latLng`，画像抽屉复用不受影响。
- 🧩 坐标系统一按 GCJ-02 输入：腾讯 / 高德直通，百度转 BD-09，天地图近似转 CGCS2000 / EPSG:4326；百度 SDK 用 `callback` 异步加载，天地图用官方 `T.Map` 默认底图。
- 🧩 后端 `map_providers.py` 设合规白名单，明确拦截 Google Maps / Apple Maps / Bing 海外版 / OpenStreetMap / Mapbox / Leaflet 等未获资质来源；自定义域名允许保存但标注需自行确保数据源合规，应用仍不内置任何有效密钥。
- 🧩 1.1.7 三级状态标与 SWR 缓存、1.1.6 浮层外滚轮重定向、1.1.5 滚动稳定性、1.1.3 放大下钻均无回归；合规红线与端口敲门 L0 只观测口径不变。

**1.1.7**

- 🐛 修复顶部状态标偶发误报「连接失败」：旧版轻量与重数据轮询都用 `Promise.all`，9 个接口里任意一个超时就整轮丢弃并直接标红；红标只能靠 `renderStatus` 覆盖，数据恰好静止时会一直挂着不恢复。
- 🐛 真机实测 26 万行下 `/api/status` 冷聚合 4～8 秒，4 秒缓存 TTL 与 3 秒轮询叠加，9 个接口并发最慢排队到 7.75 秒，逼近前端 15 秒超时线。
- 🆕 `store.cached()` 改 stale-while-revalidate：缓存过期先返回旧值，后台单线程重算，每 key 同时只允许一个刷新线程。
- 🆕 `loadLight()` / `loadHeavy()` 逐接口独立容错，失败接口只影响自己那块数据；`events` 失败时实时列表自动退回 `live`。
- 🆕 状态标三级：绿「运行中 · N 路数据源」/ 琥珀「部分数据异常」（悬停看具体接口）/ 红「连接失败」（连续两轮全失败才触发）。
- 🧩 `updateLinkPill()` 每轮重算，不受数据指纹短路影响，任一接口恢复成功立即回到绿标。
- 🧩 重数据失败集合变化时才提示，避免每 12 秒刷屏；1.1.6 滚轮重定向、1.1.5 滚动稳定性与五卡放大下钻均无回归。

**1.1.6**


- 🐛 修复设置界面打开后鼠标停在左侧地图上滚轮完全没反应：`1.0.12` 起浮层外的滚轮事件被 `preventDefault()` 直接吞掉，既不缩放地图也不滚任何内容，看起来像滚轮坏掉
- 🆕 浮层外的滚轮改为**重定向**：把滚轮量交给当前浮层内可滚动容器，鼠标停在地图、遮罩或主内容区上，设置 / 画像 / 放大面板内容照样上下滑动
- 🆕 放大面板按鼠标相对面板中线的左右位置，决定滚左侧条目列表还是右侧详情区；选中的容器不可滚时才回退到另一侧，不做「滚到底连锁」
- 🧩 按行 / 按页滚动做 `deltaMode` 换算（`DOM_DELTA_LINE × 16`、`DOM_DELTA_PAGE × clientHeight`），`scrollTop` 交给浏览器钳制边界，滚动条与惯性表现与原生一致
- 🧩 浮层内部滚轮仍走浏览器原生路径（`inOverlayScroll` 直接 return），触控板惯性、拖动滚动条、键盘翻页全部不受影响
- 🧩 浮层外滚轮依旧 `preventDefault()` + `stopImmediatePropagation()`，地图 SDK 的滚轮缩放手势与页面滚动都收不到事件，关闭浮层后自动恢复
- 🧩 1.1.5 滚动条槽宽恒定、1.1.4 五卡零滚动条、1.1.3 放大下钻、1.1.2 全球地图与排名合并均无回归
- 🧩 合规红线与端口敲门 L0 只观测口径不变

**1.1.5**

- 🐛 修复设置抽屉「时不时文字抖动」：`scrollbar-width` 在 `:hover` 时从 `none` 切到 `thin`，实测内容区 `clientWidth 459 → 449`（-10px），抽屉内 label / input / 说明文字随鼠标进出反复重排
- 🐛 修复设置界面「无法滑动」：`.drawer-body` 作为 flex 子项默认 `min-height:auto` 不肯收缩，`overflow-y:auto` 失效；`.zoom-list` / `.zoom-detail` 同样补齐 `min-height:0`
- 🐛 滚轮拦截改用父链遍历，不再依赖 `Element.closest`；部分内嵌 WebView 不支持时会走到 `preventDefault`，把抽屉内部滚轮一起吞掉
- 🧩 `scrollbar-gutter:stable` 恒定预留槽位，内容增减 / 滚动条显隐都不改变内容区宽度，复验 hover 与 20 组→1 组跳变均为 `+0px`
- 🧩 滚动条改为恒定 6px 淡色细条，thumb 常显极淡色，hover 只加深颜色（纯绘制不重排）；不再出现白底带箭头的原生粗条
- 🧩 遮罩去掉 `backdrop-filter:blur(4px)`，改用不透明度更高的纯半透明；遮罩下是每 2~3 秒刷新的地图，软件合成下全屏高斯模糊会让抽屉文字反复重绘发虚
- 🧩 `.drawer` 加 `backface-visibility:hidden` 稳定合成层文字抗锯齿
- 🧩 页面主滚动条隐藏视觉的规则保持不变（恒定、不抖动），滚轮 / 触摸 / 键盘滚动能力全部保留
- 🧩 1.1.4 五卡零滚动条、1.1.3 放大下钻、1.1.2 全球地图与排名合并均无回归
- 🧩 合规红线与端口敲门 L0 只观测口径不变

**1.1.4**

- 🐛 五张分析卡不再出现垂直与水平两条原生滚动条
- 🐛 根因是 `.mini-list` 的 `overflow-y:auto` 把 `overflow-x:visible` 强制算成 `auto`
- 🐛 该 `auto` 与 `.mini-row` 的 `margin:0 -5px` 叠加，实测横向溢出 5px
- 🐛 横条再吃掉容器高度，连锁触发竖条，1600px 视口下五卡全部中招
- 🧩 去掉 `.mini-list` 的 `max-height` 与 `overflow-y:auto`，8 条自然展开
- 🧩 `.mini-row` 改用内边距做 hover 留白，横向溢出归零
- 🧩 `.mini-card` 改 flex 列、说明文字贴底，五卡实测等高 383px
- 🧩 页面主滚动条隐藏视觉，滚轮、触摸与键盘滚动不受影响
- 🧩 放大面板 / 画像抽屉 / 实时列表 / 记录表默认不显示滚动条
- 🧩 鼠标移入滚动区才淡显 5px 半透明细条，不留白底箭头轨道
- 🧩 8 条压力测试复验：`overflow-x/y=visible`、`scrollW=clientW`、零溢出
- 🧩 合规红线与端口敲门 L0 只观测口径不变

**1.1.3**

- 🆕 五张分析卡改为可交互，点卡片头部或 ⤢ 按钮无缝放大
- 🆕 点卡片内任一条目直接放大并下钻，省掉「先展开再选」两步
- 🆕 放大面板左侧完整列表，右侧四格统计与来源 IP 明细
- 🆕 详情含访问次数、独立 IP、首末次与最近 20 条动作
- 🆕 新增 `Store.web_breakdown()` 与 `/api/web/breakdown` 下钻接口
- 🆕 按展示名反查原始键集合，卡片数字与明细口径完全一致
- 🆕 `entry` 维度下钻走会话首条 JOIN，不把后续请求算进
- 🆕 哨兵值 `-` / `unknown` 还原成空串条件，避免漏记录
- 🆕 来源 IP 点击复用 `openDetail()`，与记录表画像完全一致
- 🧩 放大用位置尺寸过渡而非缩放，文字不拉伸、关闭无缝收回
- 🧩 overview 由 8 条提到 30 条，放大面板复用同一份数据
- 🧩 滚轮拦截与地图缩放同步覆盖放大面板，面板内仍可滚动

**1.1.2**

- 🆕 真机截图体检：地域分布右侧统计 / 排名与下方境内 / 境外双榜是同一份数据的三次渲染，信息重复且割裂
- 🆕 地域数量分布改为固定「全球 IP 来源分布」，全宽世界地图去掉「中国境内 / 全球」切换
- 🆕 `geo_distribution()` 新增 `scope=all`：境内统一归到「中国」、境外按 `country` 聚合，一份数据含境内外全部来源
- 🆕 `CASE WHEN scope='cn' THEN '中国'` 兜底境内 `country` 为空的历史行，避免落进「未知」
- 🆕 `/api/geodist` 默认口径改为 `all`，非法 scope 回退 `all`；`cn` / `overseas` 两档保留兼容
- 🆕 新增「访问统计与排名」模块放在地图正下方：三个统计卡 + 境内 / 境外双榜 + 点击下钻
- 🆕 `renderRank()` 增 `scope` 参数与 `data-region` / `data-scope`，双榜条目复用 `openRegionProfile()` 下钻
- 🆕 删除地域分布右侧 `geoSum` / `geoBars` 与下方独立双榜，全页 `rankCn` / `rankOs` 各只出现一次
- 🆕 `drawGeoCanvas()` 固定 `WORLD_BOUNDS` 与 30° 经纬网，腾讯底图初始 zoom 2 / 中心 (26,10)
- 🧩 `App.warmup()` 去掉 `cn` / `overseas` 两份预热，只预热 `scope=all` 一份，启动少算一次全表聚合
- 🧩 `rank-cols` 双栏在 1180px 以下降为单栏，420px 全宽地图在 640px 以下降为 300px
- 🧩 合规红线不变：接口仍只出聚合数字与中心点，不自绘国界 / 省界，不内置任何地图 key

**1.1.1**

- 🆕 真机体检定位：24.4 万行事件里单个内网 IP 占 19.7 万行，旧画像 8 条全历史聚合合计约 3.5 s
- 🆕 `ip_detail()` 改为一次 `ORDER BY id DESC LIMIT 3000` + Python 内存计数，真机热点 IP 由 3.76 s 降到 0.35 s
- 🆕 累计访问次数、首次 / 末次时间仍用全历史 `COUNT/MIN/MAX`，明细 TOP 榜窗口化并回传 `window` 字段
- 🆕 `group_detail()` 同样窗口化，地图圆点整组画像不再重复全表 `GROUP BY`
- 🆕 `Store.cached()` 给 `status` / `trend` / `ranking` / `hotspots` / `web_overview` / `geo_distribution` / `sources_stat` / `lan_stat` 加 4 s TTL 缓存
- 🆕 `App.warmup()` 启动后台预计算首屏九组聚合，预热项有效期 60 s，页面首次请求直接命中
- 🆕 `serve()` 先 bind / listen 再 `boot_async()`，健康检查与首页不再被回填和队列阻塞
- 🆕 在线校验队列移到预热之后排队，`top_public_ips()` 限定近 7 天，避免启动瞬间抢锁抢网
- 🆕 前端 `api()` 用 `AbortController` 加超时（GET 15 s / 其它 30 s），超时与失败统一落到 catch
- 🆕 抽屉加载态改为明确文案，热点 IP 画像追加「统计口径」提示块
- 🐛 修复超高频 IP 点开画像长时间停在「加载中…」且无错误提示的问题
- 🧩 `sources_safe()` 保证采集器尚未启动时 `/api/status` 与 `/api/sources` 返回同形状数据，不返回 500
- 🧩 `/api/ip` 可选 `window` 参数，便于验收不同窗口下的口径
- 🧩 缓存支持 `clear_cache()` 与自定义 `_ttl`，数据最多滞后数秒，不影响实时采集

**1.1.0**

- 🆕 新增「访问协议」维度：`proto` 表示通道（`https` / `http` / `web` / `ssh` / `tcp` / `udp` / `icmp`），`verdict` 仍表示行为性质，两个维度互不混淆
- 🆕 `collector.py` 用 `NGINX_COMBINED` 一次性拆开 combined 行的 `$request` / `$status` / `$http_referer` / `$http_user_agent`，末两段设为可选组
- 🆕 实测 `/usr/trim/nginx/logs/access.log` 为 65 MB / 257,250 行 combined 格式，**不需要改动 fnOS 系统 nginx 配置**（改了也会被系统升级覆盖）
- 🆕 `infer_scheme()` 延续「标置信度、不伪造」：设置页手动覆盖标 `manual`，同站来路推断标 `medium`，外站来路与无来路一律返回空 + `none`，前端显示「Web 未识别」
- 🆕 `web_scheme_override` 配置项允许手动指定 `https` / `http`，留空时不硬猜；与此前「不硬编码深圳」「归属标置信度」同一原则
- 🆕 SSH / 内核 / 路由器事件由 `_tag()` 补 `layer` 与 `proto`（`ssh` / `tcp` / `udp` / `icmp`），Web 事件标 `layer='web'`
- 🆕 新增 `session_id(ip, ua, ts)` = `md5(ip|ua|int(ts)//1800)[:16]`，纯本地计算，30 分钟桶切分会话
- 🆕 `web_overview()` 一份 combined 日志派生 `summary` / `protocols` / `protocol_verdict` / `referrers` / `pages` / `entries` / `devices` 七组视图
- 🆕 「入口页」= 每个会话第一条请求，SQL 用 `JOIN (SELECT sess_id, MIN(id) mid ...)` 精确定位，不靠时间戳近似
- 🆕 「来路」归一：无 referer → 「直接输入网址 / 无来路」；同站 → 站内路径；外站 → 域名，不外带完整 URL
- 🆕 「受访页 / 入口页」按去掉查询串的 path 聚合，避免 `?_=时间戳` 刷满榜单；静态资源在榜单剔除但**总量口径仍保留入库**
- 🆕 「终端设备」由 UA 粗略归一为「浏览器 · 系统」，不做指纹、不回传任何隐私标识
- 🆕 `geo_distribution()` 只返回聚合数字与 `PROVINCE_COORDS` / `COUNTRY_COORDS` 内置中心点坐标，**不产出任何边界 / 区划轮廓数据**
- 🆕 地域数量分布支持「中国境内 / 全球」切换、数量色阶、右侧排名条与点击下钻到地域画像
- 🆕 前端有 key 时在腾讯地图 GL 合规底图上用 `MultiMarker` 数量气泡表达；无 key 时降级为只画经纬网、不绘国界的 canvas 散点
- 🆕 记录表由 8 列扩为 9 列（新增「协议」列），新增 `fProto` 按协议筛选，导出 CSV 表头补充协议 / 判定 / 状态码 / 来路
- 🆕 「IP 来源画像」新增访问协议、请求方法 / 状态、入口页会话数、协议构成、来路 TOP、终端设备，最近动作带协议 chip
- 🆕 新增 `/api/web/overview`、`/api/protocols`、`/api/referrers`、`/api/pages`、`/api/devices`、`/api/geodist` 六个接口
- 🆕 五个细粒度接口与总览共用同一次聚合，前端默认只请求 `/api/web/overview`，避免高频轮询重复扫表
- 🧩 `events` 表以 `EXTRA_COLUMNS` + `PRAGMA table_info` + `ALTER TABLE ADD COLUMN` 做幂等升级，不重建表、不丢历史事件
- 🧩 `upgrade_web_events()` 用已入库行的 `raw` 重新解析补字段，按 `dedup` 精确 `UPDATE`，结果写入 `meta.web_fields_v110` 防重复扫描
- 🧩 新增 `idx_events_proto(proto, ts)` 与 `idx_events_sess(sess_id, id)` 两个索引，覆盖协议筛选与入口页会话定位
- 🧩 地域气泡半径改为 `5 + 15 * sqrt(count/max)`，大者先画、气泡内写次数，外部标签加矩形碰撞检测避让
- 🧩 `setMapScroll()` 的地图数组扩到 `[S.world, S.cn, S.geoMap]`，地域分布图同样受抽屉滚轮拦截保护
- 🧩 端口敲门保持 L0「只观测、默认不改防火墙」；L1 序列还原 / L2 授信时间线 / L3 显式开启动态白名单列入后续路线图

**1.0.12**

- 🆕 `arcControl()` 由二次贝塞尔改为三次贝塞尔：`c1` / `c2` 沿连线方向分布再叠加法向偏移，端点切线贴合 A→B、中段圆润饱满
- 🆕 控制点偏移取 `2h/3`，使 `t=0.5` 处顶点偏离仍为 `0.5h`，弯曲幅度与旧版一致、只改顺滑度
- 🆕 `bezierAt()` 改用三次公式；采样点 `n` 从 `Math.max(8, Math.min(20, ...))` 提升到 `Math.max(24, Math.min(64, Math.round(dist*1.5)+24))`，按距离自适应
- 🆕 `PolylineStyle` 增加 `lineCap: 'round'`，端点圆头配合加密采样消除折线棱角；散点模式本就用 `lineJoin/lineCap: round`，同步受益
- 🆕 新增 `setMapScroll(on)`，通过 `TMap.Map#setScrollable` 动态开关地图滚轮缩放，方法不存在时静默跳过
- 🆕 `openDrawer()` / `closeDrawers()` 在开合时切换开关；`createTMaps()` 末尾按当前抽屉状态补一次，覆盖「抽屉先开、地图后异步创建」
- 🐛 修复点开「IP 来源画像」后滚轮仍缩放底图：遮罩层挡不住地图 SDK 自身的滚轮手势，必须在 SDK 层关闭
- 🧩 `window` 捕获阶段注册 `wheel` 拦截（`passive:false` + `stopImmediatePropagation`），抽屉外滚轮一律吞掉、抽屉内保留正常滚动
- 🧩 该监听在 `bind()` 中注册，早于异步创建的地图 SDK，可覆盖 SDK 挂在 `window` / `document` / 容器三类位置的滚轮监听
- 🧩 `.drawer-body` 增加 `overscroll-behavior:contain`，阻断滚动链向页面 / 地图传递
- 🧩 自检新增第 13 节，含 Node 实测曲线端点、采样数、顶点偏离与最大折角

**1.0.11**

- 🆕 移除 `ARC_BANDS` 三段渐隐，`arcPaths()` 整条曲线一次生成
- 🆕 `ARC_HEAT` 由 5×3 明度矩阵改为 5 个标准色，连线整条单色
- 🆕 `arcStyles()` 由 15 个 `PolylineStyle` 减到 5 个，`styleId` 去掉段号
- 🆕 `drawCanvas()` 同步按档单色描边，移除单段时的除零表达式
- 🧩 色相只表达连接频率，方向感改由汇聚端点体现
- 🧩 频率图例与 `markStyles()` 圆点仍共用 `ARC_HEAT` 单一数据源
- 🧩 跨 180° 经线由 `wrapSegs()` 统一切断，段间不再有接缝
- 🧩 自检新增第 12 节，断言无 `ARC_BANDS` / `g.bands` / `tXbY` 残留

**1.0.10**

- 🆕 新增 `ARC_HEAT` 五档热力色阶：青 → 蓝 → 琥珀 → 橙 → 红，境内 / 境外两张图共用，线色只表达连接频率
- 🆕 新增 `assignHeat()`：对 `log1p(n)` 做本图内 min/max 归一化，把聚合访问次数映射到 1–5 档
- 🆕 相对归一替代原 `tierOf(n)` 固定阈值，避免 30 天范围全挤进最高档、1 小时范围全落在最低档
- 🆕 两张地图右下角新增「连接频率 低 → 高」色阶图例，色块由 `ARC_HEAT` 直接生成
- 🆕 来源圆点（含近距点）改用同一色阶着色，`markStyles()` 生成 `src1..5` / `near1..5` 共 10 个 `MarkerStyle`
- 🧩 `buildArcs()` 把 `kept` 与 `nearPts` 合并进 `assignHeat(list.concat(nearList))`：真机按省合并后境内常只剩 1 条弧线，高频安徽省组又因与本机重合只画点，只对弧线归一会让所有线退化成档 3
- 🧩 `arcStyles()` 由 3 档 × 3 段 = 9 个 `PolylineStyle` 扩到 15 个，仍在同一 `MultiPolyline` 图层内
- 🧩 `drawCanvas()` 连线与来源点分组改用 `ARC_TIER_IDS`，散点模式与腾讯地图 GL 颜色完全一致
- 🧩 保留三段渐隐尾迹：每段按所属档取色，「由远及深汇聚本机」的方向感不变
- 🧩 频率档写进 `syncGeos()` 指纹，访问次数变化会触发对应几何的增量更新

**1.0.9**

- 🆕 新增 `CITY_CN` 城市名映射，`Hefei` / `Guangzhou` / `Singapore` 等英文名归一为中文，投票前合并同城异名票
- 🆕 新增 `POST /api/geo/normalize`，可随时手动重跑历史脏值订正
- 🆕 `vote()` 坐标改为与最终裁决省份一致：优先取同省票坐标，否则用 `PROVINCE_COORDS` 省级中心点并按 IP 散列
- 🐛 修复 `112.28.131.131` 被裁决为安徽省、坐标却沿用本地库广东省中心点 `23.1317,113.266` 画到广州
- 🐛 修复三家在线源均未返回坐标时回退本地库坐标，导致省份与点位脱钩
- 🐛 新增 `Store.normalize_events()` 一次性清洗：清空历史 `province=中国`、把 `Mauritius` 等英文国名归一、重算与省份偏离超过 3° 的坐标
- 🐛 历史 IPv6 事件此前统一打在北京金融街 `39.9236,116.36`，订正后落到中国中心点 `35.86,104.20`
- 🧩 应用启动时自动执行一次订正，结果写入 `meta` 键 `geo_normalized`，避免每次启动重复扫描
- 🧩 `geo_cache` 同步归一城市名、坐标与 `label`，防止 `GeoResolver.lookup()` 继续吐旧值
- 🧩 省份排名把空省份归入「未细分」，不再用 `COALESCE(NULLIF(province,''),'中国')` 兜底成国家名
- 🧩 复核订正体检结论：`auth.log.1` 的 10113 条 `Failed password` 中 10108 条来自 `127.0.0.1`，属本机回环噪声，`ignore_ips` 过滤正确

**1.0.8**

- 🆕 新增 `geosource.py`：`ip-api.com` / `ip.sb` / `ipinfo.io` 三家在线权威源 + 本地 `ip2region` 共 4 票，按国家 / 省份 / 城市多数派裁决
- 🆕 「IP 来源画像」新增「归属核验 · 多源交叉」区块，逐个列出每个数据源的原始判定、裁决结果、置信度与核验时间
- 🆕 画像内提供「立即在线核验 / 重新核验」，设置页提供「批量校验高频 IP」，后台按 1.5 秒节流执行
- 🆕 接入 fnOS 自带 `TRIMEVENT` 结构化登录审计，`SshdLoginSucc` 判正常、`SshdLoginAuthFail` 判攻击、登出不入库
- 🆕 回填 `auth.log.1` 及 `.gz` 轮转日志，找回此前只读当前日志尾部而漏采的历史失败登录
- 🆕 内网地址单独归类为 `lan`，保留在记录表但不进入公网地图、热点与排名
- 🆕 记录表新增「局域网设备」「fnOS 审计」筛选项，指标卡显示已核验 IP 数
- 🐛 修复 `backfill()` 直接调 `_flush()` 绕过 `emit()` 的忽略 IP 过滤，本机地址被写入记录
- 🐛 修复 IPv6 归属把 `province` 写成「中国」，导致省份排名出现大量伪记录
- 🐛 修复境外国家名残留英文（如 `Mauritius`）与港澳台中文名不一致
- 🧩 裁决结果落 `geo_cache` 表（默认 30 天）并回写 `events`，地图 / 排名 / 记录立即生效
- 🧩 三家在线源并行查询，单源失败或全部不可用时自动回退本地离线库并标记置信度
- 🧩 新增 `/api/geo/verify`、`/api/geo/detail`、`/api/geo/sources`、`/api/geo/refresh` 四个接口

**1.0.7**

- 🆕 地图圆点点击不再弹地图内浮层，改为直接打开右侧「IP 来源画像」抽屉
- 🆕 与「IP 来源记录」行点击共用 `openDetail()`，字段、高频路径与最近动作完全一致
- 🆕 圆点只含一个 IP 时直接展示该 IP 画像；含多个 IP 时先展示按省/国家合并的整组画像
- 🆕 整组画像列出来源 IP 明细，点击任一 IP 切到单 IP 画像，并提供「← 返回整组画像」
- 🆕 从地图进入单 IP 画像时追加「同一圆点的其它 IP」切换条，当前 IP 高亮显示
- 🆕 本机圆点改用同款抽屉，展示出口 IP、归属、代理出口、定位方式与定位时间
- 🧩 抽出 `profileHead()` / `kvRow()` / `pathBlock()` / `bindIpSwitches()` 公共渲染函数
- 🧩 删除 `.map-pop` 浮层容器、亮色卡片样式与 `positionPop()` 定位逻辑
- 🧩 `openDrawer()` 打开画像抽屉时清空 `detailBody.onclick`，防止两种入口事件串扰
- 🧩 首页两张地图副标题改为「点击圆点打开 IP 来源画像」

**1.0.6**

- 🆕 地图来源圆点从纯展示改为可点击：`MultiMarker` 绑定 `click`，点击直接弹出该来源组的信息浮层
- 🆕 浮层展示区域名、坐标、累计访问次数、IP 数，以及每个 IP 的访问次数、最近连接时刻与判定
- 🆕 新增「查看完整画像」入口，抽屉按 `ts` 逐条列出精确到秒的连接时间、IP、动作、端口与高频路径
- 🆕 本机圆点可点击，展示出口 IP、归属、代理出口、定位方式与定位时间
- 🆕 未配置地图 key 的散点模式同样支持点击：缓存每帧命中区域，按坐标就近命中
- 🆕 细弧线同样绑定 `click`，点到线也能弹出对应来源组的信息卡
- 🧩 命中解析兼容不同 SDK 版本的 `geometry.id` / `properties.markId`，拿不到时用 `evt.latLng` 就近兜底
- 🧩 新增 `POST /api/group` 与 `Store.group_detail(ips, rng, limit)`，按 IP 组参数化查询聚合与逐条明细
- 🧩 聚合点保留 `members` 明细，点击先本地渲染再异步补齐连接记录，避免空白等待
- 🧩 圆点悬停时鼠标变为手型；浮层内 IP 可继续点开单 IP 画像，遮罩关闭时一并收起浮层
- 🧩 本机点常与近距来源点重叠，点击位置更靠近本机时优先弹出本机定位信息
- 🧩 信息卡改为亮色实心背景、四行 kv 压缩成一行摘要，去掉 `backdrop-filter`，矮卡片下 IP 列表无需滚动即可见

**1.0.5**

- 🐛 修复近距离来源弧线鼓出大回环、互相打结：1.0.4 的 `arcControl()` 给弯曲高度设了 1.2° 下限，但境内来源是「省中心 + ±0.6° 抖动」，距本机常仅 0.1~1°，每条短线都鼓出比自身更大的回环；叠加 5 px 荧光粗线压在浅色合规底图上，成了一团乱麻
- 🆕 弯曲高度改为与距离严格成比例 `h = dist * bend`，取消下限，境内封顶 3.5° / 境外 20°；近距几乎为直线，远距才是优雅长弧
- 🆕 聚合逻辑由 0.4° 坐标网格改为按行政区：境内按 `province`、境外按 `country`，坐标取组内按访问量的加权平均，消除离线库按 IP 抖动产生的假散点
- 🆕 与本机距离小于 0.35° 的来源只画小灰点、不画弧，避免本机周围绕出线圈，放大到市级仍能看到本机周边来源
- 🆕 每条弧拆成 3 段渐隐尾迹（来源端 → 本机端），浅色底图上由浅到深，不依赖逐帧动画即有方向感
- 🆕 热度改由颜色深浅表达，线宽收敛到 2 / 2 / 3 px；本机点改为 26 px 多层光晕，来源点缩到 14 px
- 🆕 新增 `map_arc_bend`（默认 0.12，范围 0.04–0.28）设置项，保存后立即生效
- 🧩 `map_arc_limit` 默认由 24 调整为 16；数据指纹加入行政区与弯曲幅度，几何变化才提交 GPU 缓冲
- 🧩 底图诊断与地图统计新增「近距」计数，便于确认哪些来源被有意省略

**1.0.4**

- 🐛 修复曲线多时地图卡顿：原实现每轮对 45 条弧线各生成 19 个 `TMap.LatLng` 并全量 `setGeometries()`，数据没变也重建 WebGL 缓冲
- 🆕 弧线改为沿连线法向的二次贝塞尔，控制点按距离自适应，采样点 10–24 个，任意方位都自然弯曲
- 🆕 同一 0.4° 坐标网格内多个来源合并为一条，访问次数累加，重叠线条明显减少
- 🆕 线宽与透明度按访问次数分三档，一个 `MultiPolyline` 内用三个 `styleId` 完成，不增加图层
- 🆕 加入数据指纹：来源未变化时不重绘；变化时只 `add` / `update` / `remove` 差异条目
- 🆕 增量接口不可用时自动回退 `setGeometries()`，并校验 `getGeometries()` 数量，保证不丢线
- 🆕 新增 `map_arc_limit`（默认 24，范围 5–60）与 `map_arc_animate` 两个设置项
- 🆕 `map_refresh` / `map_heavy_refresh` 改为实时生效，后台标签页暂停轮询，回前台立即补一次
- 🧩 散点模式静态背景改为离屏缓存，曲线、光点、来源点按档批量描边与填充
- 🧩 一轮轮询四个接口数据全未变时，跳过趋势图、排名、记录表与地图的全部 DOM 重绘
- 🧩 刷新合并改用 `setTimeout` 而非 `requestAnimationFrame`，避免后台标签页 rAF 被节流导致地图不刷新
- 🧩 底图诊断新增绘制条数、合并 / 省略数量、重绘次数与最近重绘耗时
- 🧩 跨 ±180° 经线的弧线拆成两段，避免拉出横穿地图的直线

**1.0.3**

- 🐛 修复本机位置固定写死为深圳：`settings.py` 的 `DEFAULTS` 预设 `home_lat=22.5431` / `home_lng=114.0579`，从未按出口 IP 判定，与宽带实际归属不符
- 🆕 新增 `/api/locate` 定位接口与设置页「自动定位本机」按钮，点击才联网，不常驻对外请求
- 🆕 定位用 `myip.ipip.net` 取直连出口、`ifconfig.me` / `ipify` 识别 clash 代理的第二个出口，归属由 `ipwho.is` / `ip.sb` 交叉
- 🆕 定位结果与随包 `ip2region_v4.xdb` 对照，不一致时明确提示本机采用在线结果、其它来源 IP 仍用离线库
- 🆕 定位写入 `home_ip` / `home_geo` / `home_proxy_ip` / `home_source` / `home_locate_at`，升级重装不丢
- 🧩 未定位时改用中国中心坐标 `35.86, 104.20`，`home_label` 为「本机 · 未定位」，不再预设任何城市
- 🧩 手动修改经纬度后 `home_source` 自动标记为 `manual`，与自动定位区分

**1.0.2**

- 🐛 修复配置地图 key 后底图不显示：原实现先 `new TMap.Map()` 再给容器加 `tmap-on`，而 `.tmap` 默认 `display:none`，GL 在 `0×0` 容器里构造直接抛异常，被 `catch` 后静默降级为散点图
- 🐛 无 key 启动时 `tmapTried` 即被置 `true`，导致保存 key 后不刷新页面永远不会重试加载 SDK
- 🆕 保存 key 后立即重建底图，无需手动刷新；key 变更时销毁旧实例再重建
- 🆕 新增「底图诊断」面板（SDK / 构造函数 / 容器尺寸 / 状态 / 当前地址）、「复制诊断信息」与「重试底图」按钮
- 🆕 加载失败时 banner 与地图角标显示具体原因，自动回滚到坐标散点示意，不留白屏
- 🆕 诊断面板统计腾讯地图资源请求，`responseStatus >= 400` 时判定白名单或配额被拒
- 🧩 `createTMaps()` 改为先加 `tmap-on`、强制 reflow、校验尺寸再初始化；`resize` 时对 GL 实例调用 `resize()`
- 🧩 暗色蒙版由 `.28/.42` 下调到 `.10/.20`，并提升角标 `z-index`，合规底图细节更清晰

**1.0.1**

- 🆕 新增手动「回填历史日志」入口，设置页可一键补录公网来源
- 🆕 开机自愈探测 `hastart` 检测到进程已死时自动拉起网关
- 🧩 首次回填由尾部 6000 行扩到 24MB / 12 万行，覆盖真实公网访问分布
- 🧩 回填状态写入 `meta` 表，后续启动只读尾部 1500 行，避免反复扫 22MB 日志

**1.0.0**

- 首个版本：完成双地图实时弧线、IP 来源记录与画像、境内境外分色、访问频率趋势、境内省份与境外国家排名六项能力。

### 实测记录（2026-11-09，OESP / fnOS 1.2.x，S922X）

- 安装后 `appcenter-cli install-fpk` 返回 `Installation complete`，socket `srw-rw-rw-` 正常出现，服务以 `run-as: root` 运行。
- 直连与带前缀两种健康检查均返回 `{"ok":true,"version":"1.0.1","geo_ready":true}`；首页内联下发 55,379 字节。
- 归属库 553,970 条索引，`8.8.8.8 → 美国 / California`、`114.114.114.114 → 中国 / 江苏省`、`1.1.1.1 → 澳大利亚`、`192.168.3.38 → 内网地址`，局域网地址不参与地图投影。
- 本地离线自检 39 项全通过（解析、聚合、13 个 API、首页内联），前端 `node --check` 通过。
- 首次安装时回填只读到 6000 行内网调试请求导致 `unique_ip=1`、地图无点，根因是回填窗口太窄，已在 1.0.1 修正。
- `appcenter-cli start ipsense` 在安装钩子已启动服务的情况下返回 `code 10500`，属于状态机与已运行进程冲突，不影响 socket 与页面；应用列表短暂显示 `starting`，稍后自动变为 `running`（`appcenter-cli status ipsense` 已确认）。
- 经 nginx 网关无票据请求 `/app/ipsense/` 返回 `200 / 13 字节 invalid token`，证明应用路由已注册且票据校验生效；iframe 带票据即可正常访问，这也印证了前端必须把 `location.search` 拼进每次 `fetch`。
- 全量回填实跑：解析 92,864 行 Web 日志 + 14 行 SSH 日志，耗时约 22 秒；近 7 天窗口 31,979 条、33 个独立 IP、境内 1,985 次、境外 7 次、扫描 292 次，境内排名出现安徽 / 天津 / 广东等真实省份。
- 1.0.3 本机定位实测：宽带直连出口 `220.205.86.196`，`myip.ipip.net` / `ip.sb` / `ipwho.is` 三源一致为中国安徽合肥联通（ASN 140726 安徽联通省网）；设备 clash TUN（`Meta` 198.18.0.1）分流产生第二出口 `203.10.99.50`（日本东京）。随包离线库把直连出口登记为 `中国|甘肃省|兰州市|联通|CN`、把代理出口登记为 `United States|California|US`，属社区库历史数据精度问题；境内 / 境外判定仍正确，省份与国家字段会偏差。本机位置已采用在线结果，来源 IP 归属仍以离线库为准。
- 1.0.2 地图白屏定位：本机与 OESP 分别请求 `gljs?v=1.exp&key=<用户 key>` 均返回 `200 / 2.23MB`，bootstrap 回显 key 与审图号 `GS(2026)1190号`，排除 key 无效与网络问题。headless Chrome 探测显示 `onload` 时 `TMap.Map` 已是 `function`（排除 SDK 引导时机），但 `display:none` 容器 `new TMap.Map()` 抛异常、可见容器正常 → 根因是容器尺寸为 0。修复后 `worldMap` 尺寸应为非 0、`mapState=ready`。

## 5. 打包与验证

```bash
PY=<python3>
$PY tools/make_icon.py                 # 生成图标
$PY tools/selftest.py                  # 离线自检
node --check src/app/ui/app.js         # 前端语法
PY=$PY bash tools/build_fpk.sh         # 打包（LF / 可执行位 / py_compile / checksum）
$PY tools/deploy.py --fpk build/ipsense_1.1.16_all.fpk
```

`build_fpk.sh` 用 `tarfile` 显式写权限位（`cmd/*` = 0755），避免从 Windows 打包时丢可执行位；
每次先删旧 `app.tgz`、清 `__pycache__`，并把 `app.tgz` 的 md5 写回 `manifest`。

### 多架构包（1.1.14）

fnOS FPK 清单的 `platform` 是**单值**，合法取值只有 `x86` / `arm` / `all`（`V1.1.8+`）；`arch` 字段已废弃，不要再用，也不支持多值。原生二进制应用要覆盖双架构时，必须按 `_{platform}.fpk` 后缀分别出包。

ipsense 是纯 Python 标准库 + JS/CSS + `ip2region` 数据文件，没有任何架构相关原生二进制，所以三个包共用**完全相同的 `app.tgz`**（MD5 `45c4e1335ebb7a8c8515c16f5337d65c`），只改 `manifest` 的一行 `platform`。

| 安装包 | `platform` | 适用 |
|---|---|---|
| `ipsense_1.1.16_all.fpk` | `all` | 通用，x86 与 ARM 都能装，**推荐** |
| `ipsense_1.1.16_x86.fpk` | `x86` | x86_64 设备，或按架构分发的应用源 |
| `ipsense_1.1.16_arm.fpk` | `arm` | aarch64 设备，或按架构分发的应用源 |

`build_fpk.sh` 打完通用包后会自动调用 `tools/build_multiarch.py` 派生另两个包（`SKIP_MULTIARCH=1` 可跳过）。派生脚本不修改 `src/manifest`、不改动 `all` 包，且逐成员校验「除 `platform` 行外字节与权限完全一致」。

架构兼容性验证用同一份源码在两种 CPU 上跑同一支只读冒烟脚本，业务结果逐项对比：

```bash
$PY tools/smoke_arch.py src/app/server > build/smoke_x86_amd64.json   # x86_64 机器上执行
$PY build/run_smoke_arm.py                                            # 上传同一份源码到 ARM 真机执行
$PY build/check_114_multiarch.py                                       # 包结构 + 静态审计 + 双架构对比
```

`1.1.14` 实测：`AMD64 / Python 3.13.12 / SQLite 3.50.4` 与 `aarch64 / Python 3.11.2 / SQLite 3.40.1` 两组环境下，模块导入、xdb 归属查询、显式小端 `struct`、`inet_pton`、敲门日志解析、SQLite 聚合、配置常量共 7 组结果完全一致。**当前只有 ARM 真机，x86 包未做真机安装验收**，详见多架构交付报告。

## 6. 已知边界

- IPv6 只按常见前缀做国家级粗判（`2408/2409/240a/240e` 归中国并标注运营商），未随包分发 37MB 的 IPv6 xdb；IPv6 记录不会细分到省市。
- 端口敲门未安装：需要在路由器转发敲门端口，并自行添加只记录日志的 nft 规则；应用不会替你改防火墙。`1.1.0` 仍保持 L0「只观测、默认不改防火墙」，动态白名单属于后续显式开启的 L3。
- 地图 key 需用户自行申请；未配置时是坐标散点示意，不是合规底图。「全球 IP 来源分布」同样只在合规底图上叠加数量气泡，应用不产出边界 / 区划轮廓。
- `proto=web` 表示 combined 日志无可靠 scheme 信号下的「Web 未识别」，不是「不是 HTTPS」；需要精确协议时在设置页填 `web_scheme_override`，或修改前置反代并自行提供可信的 `X-Forwarded-Proto`（当前版本不读取该头）。
- 入口页按 `ip + UA + 30 分钟桶` 划分会话，是粗略会话而非登录态会话；同一 IP 换 UA 或跨 30 分钟会被算作新会话。
- 应用以 root 运行，请勿把 `/vol1/@appdata/ipsense/config.json` 里的地图 key 提交到公开仓库。

## 7. 排障与问题反馈

`1.1.15` 起仓库补齐了三件套：

| 文件 | 作用 |
|---|---|
| `tools/diag_bundle.sh` | 只读收集三层日志、健康状态、配置脱敏版与数据库聚合计数，自动打 `tar.gz` |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | 结构化 Issue 表单，把「诊断 6 件套」设为必填 |
| `docs/排障指南.md` | 日志位置、命令清单、按症状排查、隐私边界的完整 SOP |

应用内也有等价入口：「设置 → 最底部 → 运行日志一键导出」，返回一份已脱敏的 `.txt`（后端 `/api/diag/export`）。两条通道共用同一套脱敏规则，且都**不读取 `events.db` 原始事件行**。

详细流程与诊断 6 件套见 [排障指南](排障指南.md)。
