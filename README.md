# IP 动态感知（ipsense）

飞牛 fnOS 原生应用（FPK），把散落的访问与扫描日志收成一张能点的地图。

> **只观测、不封禁、不改防火墙、不自动处置。**
> 它只读取、汇总、展示「谁在访问我的设备」，不做实时防护、不改规则，也不会自动处置任何来源。
> **软件永远不改防火墙设置**：需要封禁时由外部 agent 自行判断与执行，本应用不持有任何处置权限；IP 标注、提交单与提示词导出只输出结构化证据，不执行任何处置。

## 它能做什么

- 汇总 6 类日志：本机 SSH / Web、内核、路由器 syslog、端口敲门、fnOS 审计、敲门网关
- 境外 / 境内双地图与全球 IP 来源分布，弧线按连接频率做 5 档单色热力
- 点地图圆点或记录表任意一行，打开完整的「IP 来源画像」
- 离线归属库配合多源交叉核验，标出置信度，不猜值
- 访问频率趋势、境内 / 境外排名、五张访问分析卡，均可点击下钻
- 腾讯 / 高德 / 百度 / 天地图四家合规底图可切换，也支持自定义接口
- 定时生成一份 AI 可读的 Markdown 汇总日志，方便交给 AI 分析态势

内网地址单独归类，不会混进公网地图里冒充「境外来源」。

## 安装

在飞牛 fnOS 应用中心选择「手动安装」，导入 `release/` 下对应架构的 `.fpk`：

| 文件 | 适用 |
|---|---|
| `ipsense_1.1.29_all.fpk` | 通用包，x86 / ARM64 均可 |
| `ipsense_1.1.29_x86.fpk` | x86_64 设备 |
| `ipsense_1.1.29_arm.fpk` | ARM64 设备 |

三个包内容一致，选与设备架构对应的即可。装完打开就能看：默认开启本机日志、路由器日志与 fnOS 审计三路，其余数据源在设置里按需开启。地图密钥需自行申请，未配置时前端只画坐标散点示意。

## 让 agent 接管处置（可选，与 FPK 独立）

应用本身**只观测、不封禁、不改防火墙**；提交单里的标注由外部 agent 通过 SSH 在 NAS 上执行。
**应用（FPK）与 skill 是两个独立产物，都要装，缺一不可。**

### 0. 快速上手（3 分钟，照着做一遍就会）

> 只想尽快用起来？**看这一节就够**。下面 1～4 是排障与高级配置用的完整说明，赶时间可以跳过。

**① 装 skill —— 把压缩包丢给 AI，只说一句话**

下载 [`ipsense-agent-bridge.zip`](https://github.com/wangbujiangwude/ipsense-fnos/releases/latest/download/ipsense-agent-bridge.zip)
（也可在 [Releases 页](https://github.com/wangbujiangwude/ipsense-fnos/releases) 的 Assets 里找到），
把它拖进 AI 对话，只说：

> 帮我装上它

AI 会自己放好文件、装好依赖、一步步问你 NAS 地址与账号、自动生成密钥对、
配好可撤销的 SSH 授权并验证连通。**你不用读文档、不用敲命令**，只回答它问的几个问题。

**② 装完能做什么**

| 你想做的事 | 在软件里点一下 | 发给 AI |
|---|---|---|
| 封禁某个 IP | 画像里写标注 `直接封禁` | 提交单里复制的读取提示词 |
| 只封一会儿 | 标注写 `临时封禁 2 小时` | 同上 |
| 先看看 / 放行 | 标注写 `先观察` / `加白名单` | 同上 |
| 反悔了 | 提交单点「待撤回」→ 复制复原提示词 | 复原提示词 |
| 收回 AI 的钥匙 | 提交单右上角「密钥授权」→ 撤销 | 不用说话 |

**③ 一遍演示**（示例数据，已去掉真实地址、账号与密钥）

```text
软件里：打开 203.0.113.42 的画像 → 标注写「直接封禁」→ 保存并加入提交单
          ↓
提交单：待处理 → 点「复制读取提示词」
          ↓
发给 AI：请读取工程中的 AI 标记，按标注逐项修改
          ↓
AI 回话：已在飞牛原生防火墙添加拒绝规则，提交单已标记「已完成」
          ↓
看结果：① 提交单「已完成」多了一条，点「查看 AI 总结」看它做了什么
        ② 飞牛「设置 → 防火墙 → 入站规则」多了一条 203.0.113.42 的拒绝规则 ✅
           （在防火墙里点「添加 IP」查这个地址，能看到规则就是成功）
```

想**临时封禁**，把标注写成 `临时封禁 2 小时` 即可，AI 会带 `--ttl 7200`，到点自动解封；
不写时长就是永久封禁，重启 NAS 也保持。两种都由飞牛原生防火墙执行，不经 iptables。

### 1. 装 skill 包

把 `skills/ipsense-agent-bridge/` 整个目录放进 agent 的 skills 目录
（WorkBuddy 是 `~/.workbuddy/skills/ipsense-agent-bridge/`）。最小必需 4 个文件：
`SKILL.md`、`scripts/mh.py`、`scripts/fw.py`，加两个可选 shim `scripts/mh` / `scripts/fw`。
完整安装说明内置在该包的 `SKILL.md`「0.5 安装与首次配置」，无需依赖本仓库其它文档。

前置：Python 3.8+、`curl`、`ssh`；**`fw` 与 `mh setup` 的 SSH 引导都必需
`paramiko`**（`pip install paramiko`），即便 `auth=key` 也一样（`mode=local` 除外）。

> 以下命令均在 skill 目录下执行；从别处调用请把 `scripts/` 换成
> `<skill>/scripts/`。Windows 下直接用 `python <skill>/scripts/mh.py ...`，
> **不要裸敲 `mh`**——无扩展名 shim 不可直接执行，且 PATH 里可能已有同名程序
> （实测 `MotionHarness.exe`）。文档里的 `mh read pending` 是逻辑命令，参数照搬即可。

### 2. 配置方法：新用户跑 `mh setup`（一步步引导）

`mh setup` 自动生成 ed25519 公钥私钥、配好 SSH、建立可撤销授权、写好
`~/.ipsense/bridge.json` 并跑完验证，8 步、每步打印 `[n/8]`。
**私钥只进内存与本机文件，绝不打印、不进 UI / 报告 / 日志。**

```bash
# 先演练：不连 NAS、不改任何文件、不生成密钥
python scripts/mh.py setup --dry-run --host <NAS地址> --user <SSH用户>

# A. 新用户最常见：只有 SSH 账号密码
python scripts/mh.py setup --host 192.168.1.10 --user root --bootstrap password

# B. 已有可用私钥，想补一份本应用专用授权
python scripts/mh.py setup --host 192.168.1.10 --user root \
  --bootstrap key --key ~/.ssh/id_ed25519

# C. agent 就装在这台 NAS 上（无需 SSH）
python scripts/mh.py setup --bootstrap local

# D. 交互模式：一步步问 host / user / port / 密码
python scripts/mh.py setup
```

参数：`--port 22`、`--device <设备名>`、`--force`（已有 active 授权也重建）、
`--yes`（强制非交互）、`--dry-run`。
密码只从环境变量 `IPSENSE_SSH_PASSWORD` / `OESP_PASS` 或
`~/.workbuddy/secrets/oesp_cred.txt` 读，**绝不写进配置、日志或聊天**。
非交互缺 `--host` 只打印示例退出，不会卡在 `input()`；已有 active 授权默认跳过，
避免重复授权。fnOS 实测 `$HOME` 目录名可不同于 SSH 用户名，setup 会动态读 `$HOME`。

> 高级 / 手动：只需写连接配置、不建密钥授权时用
> `python scripts/mh.py init --mode ssh --auth key --host ... --key ...`
> （或 `--auth password`），详见 `SKILL.md` 的 D 节。

### 3. 使用方法

```bash
# 装完四项验证（setup 第 8 步会自动跑）
python scripts/mh.py check           # 已连通 · ipsense <版本>
python scripts/mh.py read pending    # 四区状态（可能为空）
python scripts/fw.py status          # channel=native、后端三绿
python scripts/mh.py key status      # 授权列表（指纹 / 公钥 / 时间 / 设备 / 状态）

# agent 读标注 → 按标注直接执行（无需二次确认）→ 回写总结
python scripts/mh.py read pending
python scripts/mh.py show 39.144.159.100
python scripts/fw.py ban 39.144.159.100            # 不带 --ttl = 永久封禁、重启保持
python scripts/mh.py mark-done --receipt <R> --summary "已按标注永久封禁，回滚：fw unban 39.144.159.100"

# 用户点「待撤回」后复原
python scripts/mh.py read revert
python scripts/fw.py unban 39.144.159.100
python scripts/mh.py restore --receipt <R> --summary "已复原"

# 随时收回给 agent 的 SSH 授权（也可在提交单「密钥授权区」点撤销）
python scripts/mh.py key revoke --grant-id mh1-xxxxxxxxxxxx
```

`fw` 只写飞牛原生防火墙 `/usr/trim/etc/fw.conf` 的入站拒绝规则（`memo:ips:<ip>`），
由 `security_service` 加载进 eBPF，重启 NAS 后依旧保持，不再下发 iptables 规则。
常用命令全表见 `SKILL.md` 第 5 节与 [agent 接入说明](docs/agent-bridge.md)。

### 4. 排障

| 现象 | 处理 |
|---|---|
| `mh setup` / `fw status` 报「需要 paramiko」 | `pip install paramiko` |
| `mh setup` 报「取 $HOME 失败」/「写 authorized_keys 失败」 | 确认 bootstrap 能登录、sudo 密码可用；先跑 `--dry-run` 看计划 |
| `mh check` 报「连接超时」 | 核对 `~/.ipsense/bridge.json` 的 `host / user / key` 与 `app.sock` |
| `mh check` 报「Permission denied」 | 查 `mh key status` 是否已被撤销；重新跑 `mh setup --force` |
| 想重建 / 换设备授权 | `mh setup --force`，旧授权在「密钥授权区」撤销 |

> 红线不变：**主包只观测、不封禁、不改防火墙、不自动处置**。`mh` 只读写提交单，
> `fw` 是 agent 在应用之外的处置通道，`mh setup` 只建 SSH 授权，三者都不在主包内执行。

## 文档

- [README（详版功能与技术说明）](docs/README.md)
- [使用说明](docs/使用说明.md)
- [更新日志](docs/CHANGELOG.md)
- [排障指南：日志位置、诊断 6 件套、运行日志 / 运行报错一键导出](docs/排障指南.md)
- [让 agent 连上 ipsense：标注、提交单、skill CLI 与 SSH 配置](docs/agent-bridge.md)

## 故障速查表

按「你看到的现象」直接找对应处理办法；每条都写明原因，避免反复试错。
仍定位不了时，导出运行报错 / 运行日志诊断包再提 Issue（见下一节）。

| 现象 | 原因 | 解决办法 |
|---|---|---|
| 地图空白，只有彩色散点 | 未配置地图 KEY，或 KEY 无效 / 白名单不含本站 | 「设置 → 地图服务」填对应服务商 KEY；高德还需核对「Web 端 (JS API)」与安全密钥 `jscode` |
| 顶部提示「SDK 加载失败」 | 地图域名被浏览器扩展 / 路由器拦截，或 KEY 域名白名单不符 | 看提示里的具体失败原因；在设置最底部「导出运行报错」交 AI 定位 |
| 弧线在地图左右接缝处断开 | 跨国际日期变更线的长弧在世界两端各画一段，旧版端点用平均值、且写死 ±180 被 SDK 回卷 | 升级 `1.1.18`：接缝处按线性插值补真实交点，端点收进 `180 - ε`，两段首尾严格对齐 |
| 端口显示「未记录」 | Nginx / Docker 的 `combined` 日志只记 `GET /path HTTP/1.1`，**不含目标端口** | 设置里填「Web 日志端口映射」`日志路径=端口`；或让日志带 `$server_port`；端口列悬停可看来源 |
| 端口以前全是 `5666` | `1.1.15` 及更早把应用自身监听端口当成了目标端口 | 升级到 `1.1.16+`；`1.1.18` 起按日志证据多级补录并标注来源，不再硬塞 |
| Docker / 反代访问没有端口 | 容器日志与 fnOS 反代日志同样是 `combined`，没有端口字段 | 在「Web 日志端口映射」里把容器日志路径和对外端口写进去；日志含 `"port":` 等字段时自动识别 |
| 「Web 未识别」占比很高 | `combined` 日志不含 `scheme`（http / https），也没有 `X-Forwarded-Proto`；无 Referer 的请求没有可信信号 | 点协议卡片放大看完整成因；设置里指定 `http` / `https`，或开启「按已知端口补协议」 |
| 归属显示「重庆市」/ 省份不对 | 离线库对运营商网段重分配更新滞后 | 画像点「重新核验（忽略缓存）」，四票多数派裁决；`1.1.16` 起订正结果会固化 |
| 区级（区县）一直是空的 | 免费在线源普遍不返回 `district`，`tool.hiofd.com` 接口带反爬签名、不是公开 API | 画像点「站内查询」直接看多源结果，或「在线校验」自动复制 IP 后人工回填「保存区级信息」；也可在设置里填自定义区级接口 |
| 筛选范围每次打开都重置 | `1.1.17` 及更早不记忆界面设定 | 升级 `1.1.18`：实时访问事件、IP 来源记录、时间范围、趋势图例各自写入本地，下次打开保持 |
| 投喂二维码太小、点开后关于页要滚动 | `1.1.18` 把二维码内联展开在关于卡片底部，撑出滚动条且只有 `210px` | 升级 `1.1.19`：二维码独立放大弹层弹出，约 `460px`，关于页不再滚动 |
| IP 来源记录被同一个 IP 刷屏 | `1.1.19` 及更早逐行显示完整路径，同秒并发请求除路径外全一样 | 升级 `1.1.20`：同秒同 IP 合并为一行只记录动作，路径明细点开画像查看 |
| 找不到境内 / 全球分布地图 | `1.1.20` 及更早三张地图分三块卡片，容易以为少了一张 | 升级 `1.1.21`：合并为一张卡片，右上角切「境外连线 / 境内连线 / 全球分布」 |
| 想把某个 IP 交给 agent 处理 | `1.1.21` 及更早只能自己看日志，没有把证据交出去的入口 | 升级 `1.1.22`：画像里写标注 → 提交单 →「复制读取提示词」发给 agent |
| 想更舒服地写标注 / 弹层开关更柔和 | `1.1.23` 及更早标注框在画像里原地放大、弹层用回弹动画 | 升级 `1.1.24`：标注框回归单行，点它弹出独立写标注窗口（带常用要求预设），四个弹层改为淡入淡出 |
| 标注行有个点了没反应的「保存并加入提交单」按钮 | `1.1.25` 及更早留着与写标注窗口重复的行内按钮，1.1.24 改成只读触发器后已失效 | 升级 `1.1.26`：画像里只留输入框，保存统一在弹窗里完成 |
| AI 复制提示词后连不上 NAS / 提示 Permission denied | `mh` 旧版只认密钥，账号密码环境跑不通 | 升级 `1.1.27`：`mh` 支持 `auth: password`，或用「密钥授权区」查看/撤销授权 |
| 想收回给 AI 的 SSH 授权、删掉设备上的私钥 | 授权散落在 `authorized_keys` 里不好找 | 升级 `1.1.27`：提交单 →「密钥授权区」→ 撤销授权，只删本应用那行与密钥副本 |
| 不同缩放下「提交单」里密钥授权挤住列表、内容显示不全 | `1.1.27` 把密钥授权做成 Tab 下方的内嵌区块，展开后抢占弹层高度 | 升级 `1.1.28`：入口移到右上角，点开才显示浮层，不占文档流 |
| 新用户装完 skill 不知怎么配 SSH / 生成密钥 | 旧版只有手工 6 步引导，没有对应 CLI 命令 | 升级 `1.1.29`：`mh setup` 一步步引导，自动生成密钥对、建可撤销授权、写好配置并验证 |
| 提交单只有一长串列表、读取提示词太长 | `1.1.24` 及更早是单列表，提示词含边界 / 白名单 / TTL 等大段重复内容 | 升级 `1.1.25`：四区看板 + 一句话提示词 + 单独读取路径，规矩整合进 skill，AI 通过 `mh` 读写 |
| 设置 / 文件夹选择器点不动 | 地图 SDK 注入的 `z=1000` 交互层越过了容器层叠上下文（`1.1.12` 已修） | 升级到 `1.1.12+`；容器已加 `isolation:isolate` 锁死 SDK 层级 |
| 数据不更新 / 状态标「部分数据异常」 | 单个接口抖动、日志路径不存在、权限不足 | 设置在「数据源」核对路径与开关，点「刷新」；连续两轮全失败才标红，避免一次抖动误报 |
| 敲门网关 / 路由器日志没数据 | 数据源默认关闭，或 syslog 未指向本机 UDP `5514` | 设置里开启数据源并在对端配置；本应用只读，**不改对端配置 / 防火墙** |
| 汇总日志不生成 | 保存目录未选或不可写 | 用飞牛原生文件夹选择器选目录，四层校验通过后会立即生成一份 |
| `fnOS 1.1.31` 安装 ARM 包失败 | 部分 ARM64 应用要求 `fnOS 2.0.0+` | 升级 fnOS，或改用 `all` 通用包 |
| 应用打不开，想反馈 BUG | 需要已脱敏的诊断证据 | 能打开：设置最底部「运行日志一键导出」；打不开：`sh tools/diag_bundle.sh`；**勿直接贴 `config.json` / `events.db`** |

> 合规红线不变：**只观测、不封禁、不改防火墙、不自动处置**。表里所有操作都只在应用内读日志、改展示配置。

## 出问题了怎么反馈

先在应用里点「设置 → 最底部 → 运行日志一键导出」，得到一份已脱敏的 `.txt`；应用打不开时改用
`sh tools/diag_bundle.sh`，会生成 `ipsense-diag-*.tar.gz`。两者都自动抹除地图 KEY、令牌、口令与完整来访 IP，
**请不要直接把 `config.json` 或 `events.db` 贴到 Issue 里**。

完整流程与「诊断 6 件套」见 [排障指南](docs/排障指南.md)，提交时选仓库的「问题反馈（BUG）」模板逐项填完。

## 构建与自检

`tools/build_fpk.sh` 从 `src/` 打包 FPK，`tools/build_multiarch.py` 派生 x86 / arm 分架构包。`tools/selftest.py` 是离线全量自检（覆盖归属库、日志解析、聚合、API、打包与文档一致性），另有四个专项工具：`tools/check_115_geometry.mjs` 校验地图弧线几何、`tools/smoke_115_store.py` 校验后端聚合与区级字段、`tools/verify_115_preview.py` 在真实 Chrome 里点验离线预览页、`tools/verify_115_fpk.py` 解包核对三个 FPK 的版本 / 校验和 / 内容一致性。

## 许可

见 [LICENSE](LICENSE)。原创代码以 MIT 发布；随包分发的 `ip2region_v4.xdb` 遵循 ip2region 原项目许可。应用不内置任何地图服务密钥。
