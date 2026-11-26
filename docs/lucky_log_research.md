# B5 前置调研 · lucky 日志格式查证与 collector.py 接入建议（ipsense 2.0.0）

> 本文为**只读前置调研**产物，不修改任何产品代码，不落地任何实现。
> 调研日期：2026-11-26。对象：NAS 常用反向代理 / 端口转发工具 **lucky（Go 编写）** 的「日志中心」输出，以及 `src/app/server/collector.py` 后续接入的建议方案。
> 关联文件：`docs/satellite_compliance_research.md`（同批次 B5 的卫星底图合规调研）。

---

## 0. 结论速览

- **对象已确认**：用户指的是 Go 编写的「**Lucky（大吉）**」`github.com/gdy666/lucky`，官网 `https://lucky666.cn/`，后台 `:16601`，前端 Vue3。**不是** Crystal 语言的 `luckyframework.org`，也**不是** `helloh2o/lucky` 游戏网络框架（同名干扰，已排除，见第 1 节）。
- **官方明确「没有文档」**：多个官方 README 镜像自述「没有文档，后台各处的提示信息已经足够多」，并写明「Web 后台支持查看最新 100 条日志」。
- **关键缺口（按用户要求明确写出）**：日志中心的**精确日志行格式**（时间戳格式、级别前缀、字段顺序 / 分隔符）、**MAIN / INFO 级别日志样例**、**是否有可供 tail 的落盘日志文件及其路径**、**是否支持 JSON / 自定义格式** —— **未找到官方公开文档，需用户提供本机日志文件样例**。
- **访问日志很可能默认在内存中**（Web 后台查看最新 N 条，`AccessLogMaxNum` 限内存条数），**大概率不存在可直接 `tail` 的标准日志文件**；`LogOutputToConsole` 若开启会输出到终端，属 stdout 采集而非文件 tail。是否可 tail **取决于本机部署方式，必须由用户确认**。
- **已给出 collector.py 接入建议**（新 source 类型 / 解析正则 / 字段映射 / 不影响现有 7 类解析），见第 5 节；**在拿到用户真实日志样例前，正则只做占位骨架，绝不把臆测格式硬编码进产品**。
- 有一篇 CSDN「Lucky 访问日志导出 CSV/JSON」文出现 `/api/logs`、`/var/log/lucky/*.log`、"系统日志 → 导出数据" 菜单，高度疑似 AI 批量生成的**虚构内容**，**不予采信、不得据此设计解析或 API 调用**（见 3.2）。

---

## 1. 对象辨识（避免同名混淆）

| 名称 | 语言 / 定位 | 是否本次对象 |
| --- | --- | --- |
| **Lucky（大吉）** `github.com/gdy666/lucky`，官网 `lucky666.cn`，pkg.go.dev 版本 v1.10.8 | **Golang** 后端 + Vue3 前端；端口转发、反向代理、DDNS、WOL、STUN 内网穿透、ACME 证书、计划任务、网络存储 | ✅ **是**（用户描述「Go 编写、NAS 反代 / 端口转发、日志中心」完全吻合） |
| Lucky Framework `luckyframework.org` | **Crystal** 语言的 Web 框架，日志用 Dexter、`config/log.cr`、production 用 json formatter | ❌ 否。搜索「lucky logging」极易命中，其 `LogHandler` / `json formatter` / 严重级别**不适用于本项目**，本报告不引用其任何结论 |
| `helloh2o/lucky` | Go 游戏 / 应用网络框架（protobuf / TCP / KCP / QUIC） | ❌ 否 |
| 各类 fork / 镜像（wgjas2、xiejindou、kkkcccfff、gitcode `luc/lucky` 等） | 同一 Go 版 Lucky 的 README / 源码副本 | ⚠️ 仅用于交叉核对 README 与 `main.go`，不作"官方文档" |

---

## 2. 已查证到的可靠信息

| 项目 | 内容 | 来源 / 可信度 |
| --- | --- | --- |
| 语言与仓库 | 核心程序完全 Golang；`github.com/gdy666/lucky`；pkg.go.dev 收录 `v1.10.8` | pkg.go.dev、allinone 文档 / 高 |
| 后台 | 默认 `http://<设备IP>:16601`，默认账号 `666` / 密码 `666`；`-p` 可改端口；Vue3.2 前后端分离；提供 **OpenToken** 供第三方调用功能接口 | 官方 README 镜像 / 高 |
| 启动与配置 | `-c <配置文件>` / `-cd <配置文件夹>`（早期用 `-c`，新版用 `-cd`）；Docker 镜像 `gdy666/lucky`，**容器内配置目录 `/goodluck`**，配置文件 `lucky.conf`；持久化用 `-v <宿主目录>:/goodluck` | 官方 README 镜像、allinone 文档 / 高 |
| 源码日志实现 | `main.go` 使用 Go **标准库 `log`**（`log.Printf("...")`），`init()` 里 `time.Local = time.FixedZone("CST", 8*3600)`（**东八区**）；模块含 `config/`、`module/portforward/`、`module/reverseproxy/`、`module/safe/`、`module/sslcertficate/`、`module/wol/`、`web/` | 官方源码 `main.go` 副本 / 高 |
| 官方对文档与日志的自述 | 「**没有文档，后台各处的提示信息已经足够多**」；「**Web 后台支持查看最新 100 条日志**」；「规则日志清晰易懂，便于追踪异常」 | 官方 README 镜像 / 高 |
| 反向代理日志相关配置（第三方深度笔记，非官方） | 子规则 / 默认规则字段：`EnableAccessLog`（是否开启访问日志）、`LogLevel`（日志级别，排障 debug / 平时 info；示例中出现数值 `3`）、`AccessLogMaxNum`（**每条子规则在内存里最多存多少条访问日志，范围 0–102400，0 = 不存**）、`LogOutputToConsole`（是否同时打到终端，生产建议关） | 第三方使用笔记 `hqwc.cn` / **中**（非官方，需用户本机核对） |
| 访问日志字段（同上） | `ClientIP`（Lucky 认定的客户端 IP，开透传时为解析出的真实 IP）、`RemoteIP`（直接与 Lucky 建连的地址，前置代理时两者不同）；配合 `ForwardedByClientIP` + `TrustedCIDRsStrList` + `RemoteIPHeaders` 使用 | 第三方使用笔记 / 中 |
| 日志中的中文提示样例（同上） | 「禁止访问」（名单 / UA 过滤拦截）、「可用证书列表为空」（TLS 降级明文时的提示） | 第三方使用笔记 / 中 |
| 真实 IP 透传 | 子规则 `ForwardedByClientIP: true`、`TrustedCIDRsStrList`（如 `10.0.0.0/8`）、`RemoteIPHeaders`（如 `X-Forwarded-For`）、`AddRemoteIPToHeader` / `X-Real-IP` | 第三方使用笔记 / 中 |

> 小结：能确定的只有「**是什么工具、怎么跑、日志走 Go 标准 log / 东八区、后台看内存里的最新 N 条、访问日志有 ClientIP / RemoteIP 两个关键字段**」。**行长什么样、落不落盘、能不能 JSON，官方没有说。**

---

## 3. 未查到 / 存疑项（关键）

> ### **未找到官方公开文档，需用户提供本机日志文件样例。**
> 具体缺口如下，逐项如实列出，不做推测性填充：

| # | 待确认项 | 状态 |
| --- | --- | --- |
| 3.1 | **日志中心精确日志行格式**：时间戳格式（`2006-01-02 15:04:05`？ISO8601？Go log 默认 `2009/01/23 01:23:23`？）、级别前缀、字段顺序与分隔符 | **未找到官方定义** |
| 3.2 | **「MAIN / INFO」级别日志样例**：用户截图显示日志中心有 MAIN / INFO 标注，但公开资料**未找到对应格式定义**。以下仅为**待核实的推测，不是事实**：日志中心可能按「模块 = MAIN（主程序）/ 级别 = INFO」两列展示，或行内以 `[MAIN][INFO]` / `MAIN INFO` 形式打前缀。**必须以用户提供的截图原文或导出样例为准。** | **未找到，需用户补充** |
| 3.3 | **日志文件路径 / 是否落盘**：官方只说"后台查看最新 100 条日志"、第三方笔记说 `AccessLogMaxNum` 是**内存**条数、`LogOutputToConsole` 控制是否打到终端 → **现有证据指向"内存查看 + 可选 stdout"，未找到任何官方落盘文件路径说明** | **未找到，需用户确认** |
| 3.4 | **是否支持 JSON 格式 / 自定义格式**：官方无说明；源码用标准 `log.Printf`（文本），未见可配置的 formatter 证据 | **未找到，需用户确认** |
| 3.5 | **Web 访问日志是否可被 tail 采集**：见第 4 节分析 | **取决于本机部署，需用户确认** |

### ⚠️ 不予采信的来源（防编造）
- CSDN《Lucky 访问日志导出：CSV/JSON 格式，第三方分析工具对接》（`blog.csdn.net/gitblog_00760/article/details/152472583`）出现 `/var/log/lucky/*.log`、`http://localhost:16601/api/logs`、`jq '.logs'`、`config/config.go` 日志缓冲区、"登录管理界面 → 系统日志 → 导出数据" 菜单，并给出 Filebeat / Elasticsearch 配置。这些**路径、API、菜单均无官方或源码佐证**，文风与 `gitblog_xxx` 类账号特征符合 **AI 批量生成的虚构教程**。
- **处置**：标注为「疑似虚构，需用户提供本机验证」，**不写入字段映射、不写入正则、不写入 API 调用方案**。若用户本机确能复现其中接口，再以用户提供的真实返回样例为准。

---

## 4. Web 访问日志能否被 `tail` 采集（分析）

`collector.py` 现有的两种采集器 `LogTailer`（`collector.py:306`，inode + offset 增量读**单个文件**）与 `KnockDirTailer`（`:362`，按目录分片扫描）**都要求存在落盘文件**。而 lucky 侧的证据是：

- 官方：后台「查看最新 100 条日志」；
- 第三方笔记：`AccessLogMaxNum` 明确是「**在内存里**最多存多少条访问日志」，0 表示不存。

**推断（需用户证实）**：lucky 的 Web 访问日志**默认很可能不落盘成可被 `tail -f` 的标准日志文件**，因此不能直接套用现有 `LogTailer`。可选的采集路径：

| 路径 | 做法 | 前提 / 风险 |
| --- | --- | --- |
| **A. stdout 重定向** | 开启 `LogOutputToConsole`，由 systemd（`StandardOutput=append:` / journald）、`docker logs`、`nohup > file` 把控制台输出重定向成文件，再用 `LogTailer` tail | 输出到的是**运行日志 / 控制台日志**，是否包含结构化访问日志、`EnableAccessLog` 是否同时生效，需用户确认 |
| **B. 后台 API 拉取** | 借 lucky 的 OpenToken 拉取日志（README 仅说 OpenToken 可调"功能接口"） | **未找到日志 API 的官方文档**；路径、字段、鉴权、分页全部需用户提供；**不采信** CSDN 的 `/api/logs` |
| **C. 确有落盘文件** | 某些安装方式 / 插件可能把日志写到 `<配置目录>/logs/` 等位置，直接把该绝对路径填进新 `LogTailer` | 需用户提供 `ls` 结果与 `tail -n 20 <路径>` 真实样例 |
| **D. 暂不接实时 tail** | 先只落地解析器 + 单测样例，等确认落盘方式后再接 `_build_tailers()` | 最稳妥，符合"格式未定不硬编码"原则 |

> **结论：是否可 tail 取决于本机部署与是否落盘，必须由用户提供本机日志文件样例 / 路径确认后，才能定最终采集方案。** 在此之前，解析器可以先写好并用占位样例自测，但不要写死臆测格式。

---

## 5. `collector.py` 接入 lucky 日志的建议方案（仅建议，本次不改代码）

### 5.1 现状核对（只读）
- **现有 7 个解析器**：`parse_auth`(`:496`)、`parse_trimevent`(`:523`)、`parse_auth_any`(`:561`)、`parse_web`(`:569`)、`parse_kern`(`:615`)、`parse_router`(`:635`)、`parse_knock_app`(`:658`)。
- **现有 `source` 枚举**（由各 `_base()` 调用传入）：`local_auth`、`fnos_audit`、`local_web`、`knock`、`local_kern`、`router_syslog`、`router_file`、`knock_app`（共 8 个，≥ 用户所说"6+ 类"）。
- **可复用的既有设施**：`_base()`(`:478`)、`_tag()`(`:488`)、`emit()`(`:735`)、`writer_loop()` / `_flush()`(`:744` / `:761`)、`LogTailer`、`KnockDirTailer`、`tail_lines()`(`:291`)、`backfill()`(`:930`)、`status()`(`:993`)、`web_log_port()`(`:65`)、`infer_scheme()`(`:264`)、`knock_ip()`(`:203`)、`knock_to_ts()`(`:218`)、`to_ts()`(`:243`)、`IP_ANY`(`:132`)、`SCAN_PATH`(`:134`)、`is_self_web()`(`:150`)、`session_id()`(`:258`)、`KNOCK_*_KEYS` / `knock_pick()`(`:176` / `:192`)。

### 5.2 新增 `source` 类型（建议）
建议新增**两个**独立 source，而不是复用现有 `local_web`：

| 新 source | 承载内容 | `layer` | `service` | 说明 |
| --- | --- | --- | --- | --- |
| `lucky_web` | lucky 反向代理 **Web 访问日志**（`ClientIP` / `RemoteIP` / Host / Path / Status / Method…） | `web` | `Lucky 反代` | 与 `local_web`（fnOS nginx）分开，便于区分"经 lucky 进来的访问"与"fnOS 自身 Web" |
| `lucky_sys` | lucky **系统运行日志**（MAIN / INFO 级：启动、规则增删、证书、告警、拦截…） | 建议 `system`（与前端图例约定） | `Lucky 系统` | MAIN/INFO 样例未定，先留框架 |

理由：两类日志格式与字段完全不同、统计口径不同、排障用途不同；分开后 `source_hits`(`:468`) 自动按新 source 计数，`_flush()`(`:761`) 无需改动；与现有 8 个 source 不冲突。

### 5.3 新增解析正则（**占位骨架，待用户样例校准**）

> 原则（沿用现有代码 `web_log_port` / `infer_scheme` 注释里「**有证据才填、标来源、不伪造**」的口径）：**宽松、可配置、字段缺失一律留空，绝不猜值**。以下只是示意，不是可直接合入的产品正则。

建议在 `collector.py:113–140` 正则区并列追加：

- `LUCKY_TS`：兼容三类时间戳文本 —— `YYYY-MM-DD HH:MM:SS`（东八区 CST）、ISO8601（可带 `+08:00` / `Z`）、Go `log` 默认 `YYYY/MM/DD HH:MM:SS`；**统一交给现有 `knock_to_ts()`(`:218`) 转换**（已支持 ISO8601 / epoch 秒 / 毫秒 / 常见文本），不另写一套时间解析。
- `LUCKY_LEVEL`：`(?i)\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b`。
- `LUCKY_MODULE`：`(?i)\b(MAIN|...)\b` —— `MAIN` 来自用户截图，其余模块名待样例补全。
- `LUCKY_ACCESS`：从任意行按「键 = 值 / `"键":"值"`」提取 `ClientIP`、`RemoteIP`、`Host`、`Path` / `RequestURI`、`Status` / `StatusCode`、`Method`、`UserAgent`、`Referer`（字段白名单可参照 `KNOCK_*_KEYS`(`:176`) 的写法做成常量元组，便于按样例增补）。
- **IP 必须过 `knock_ip()`(`:203`) 的 `inet_pton` 严格校验**：现有代码 `:204` 注释已警示「`IP_ANY` 的 IPv6 分支会把 `11:20:31` 这类时间戳误判成地址」——lucky 日志时间戳密集，极易踩此坑，**不要**直接用 `IP_ANY.findall()` 当最终 IP。
- **在拿到用户真实样例前**：只落地「正则常量 + `parse_lucky_web` / `parse_lucky_sys` 空实现 + 待补的单测样例」，**不把任何臆测格式写死进产品**。

### 5.4 字段映射（lucky → `_base()` 事件）

| lucky 字段 | 事件字段 | 映射规则 |
| --- | --- | --- |
| `ClientIP` | `ip` | 首选；缺失时回退 `RemoteIP`；仍缺才用 `IP_ANY` 兜底并**过 `knock_ip()` 严格校验**；都取不到则丢弃该行（沿用 `parse_knock_app` 的"无 IP 不入库"） |
| 时间戳 | `ts` | `knock_to_ts()`；注意 **CST 东八区**，核对落库无 8 小时偏移；不可用时 `time.time()` 并标注低置信（沿用现有降级） |
| `Host` + 请求路径 | `path` | 域名 + 路径拼接，复用 `parse_knock_app`(`:705`) 的 `target` 拼法；`action` 写「Lucky 反代 · …」 |
| `Status` / `StatusCode` | `status` | `int`，非数字置 `0`（参照 `:723`） |
| `Method` | `method` | `[:16]` |
| `UserAgent` / `Referer` | `ua` / `referer` | `[:300]`，缺失留空（`_base` 已给默认值） |
| 「禁止访问」/ 4xx / `SCAN_PATH`(`:134`) 命中 | `verdict` / `action` | `scan` + 「Lucky 拦截 · …」；否则 `normal` |
| — | `proto` | 无证据标 `web`，`scheme_conf="none"`，**不硬猜 http/https**（沿用 `infer_scheme`(`:264`) 原则） |
| — | `port` / `port_src` | 默认 `0` / `""`；仅当日志显式带端口字段时走 `web_log_port()` 的 `log_field` 分支（`:90`） |
| — | `source` | `lucky_web` / `lucky_sys` |
| — | `sess_id` | `lucky_web` 可复用 `session_id(ip, ua, ts)`(`:258`)；`lucky_sys` 留空 |
| — | `raw` | `line[:600]`（`_base` 已截断） |
| 含 `/app/ipsense` 的路径 / 来路 | 丢弃 | 复用 `is_self_web()`(`:150`) 过滤软件自身访问，避免污染统计（与 `parse_web`(`:590`) 一致） |
| `layer` / `proto` | — | 用 `_tag()`(`:488`) 补齐 |

### 5.5 「不影响现有 6+ 类解析」的落地方式（增量原则）

**只做追加，不改存量**：
- ✅ 追加：新正则常量（与 `NGINX_COMBINED` 等并列）、`parse_lucky_web()` / `parse_lucky_sys()` 两个新方法、两个新 `source` 常量、`_build_tailers()`(`:802`) 末尾追加 `LogTailer`、`status()`(`:993`) 追加开关字段、前端来源图例追加 `lucky_web` / `lucky_sys` 标签。
- ❌ 不改动：`_base()` / `_tag()` 签名、现有 7 个 `parse_*` 的**任何一行**、队列 / 写线程 / `store.insert_batch` 去重、`web_log_port()` / `infer_scheme()` 既有逻辑、`compliance_of` 等合规判定。

**新配置项**（仿 `source_local_web` / `web_log`，默认全关，避免影响现有部署）：
`source_lucky_web`、`lucky_web_log`（文件路径，默认空 = 不启用）、`source_lucky_sys`、`lucky_sys_log`、（可选）`lucky_console_log`。

**两个易漏点（提示，非本次改动）**：
1. `backfill()`(`:930`) 只回填 `t.name.startswith("本机")` 的 tailer → 新 tailer 要么命名以「本机 ·」开头以复用历史回填，要么在 `backfill()` 中显式追加，否则全量回填会漏。
2. 若确认日志「按目录 / 按天分片」：直接复用 `KnockDirTailer`(`:362`，`EXTS` 已含 `.json` / `.jsonl` / `.log` / `.txt`)，与 fn-knock-lite 同款增量扫描。

**若确认"无落盘文件"**：暂不接 `LogTailer`，先按第 4 节 A / B / D 走；解析器与字段映射仍可先写好并备占位单测，等用户样例到齐再校准正则。

### 5.6 拿到样例后的验证清单
- [ ] 用用户提供的真实日志行跑 `parse_lucky_web` / `parse_lucky_sys`，逐字段核对 `ts` / `ip` / `path` / `status` / `verdict`。
- [ ] 确认 CST 东八区时间戳落库**无 8 小时偏移**。
- [ ] 确认时间戳**未被 `IP_ANY` 误判成 IP**（走 `knock_ip()`）。
- [ ] 回归现有 7 类解析与 8 个 source 计数不变，`/app/ipsense` 自身访问仍被过滤。
- [ ] 确认 `MAIN / INFO` 级别与模块的真实格式，补全 `LUCKY_MODULE` / `LUCKY_LEVEL` 白名单。
- [ ] 与第 4 节选定的采集路径（A/B/C）联调 `LogTailer` / `KnockDirTailer`。

---

## 6. 必须让用户补充的信息（缺这些无法定稿解析方案）

1. **「日志中心」截图里 MAIN / INFO 那一行的原始文本样例** —— 最好 5–10 行、覆盖不同级别（INFO / WARN / ERROR）与不同模块，或后台导出的日志文件；这是定 `LUCKY_TS` / `LUCKY_LEVEL` / `LUCKY_MODULE` 的唯一依据。
2. **本机 lucky 部署方式**：Docker（`gdy666/lucky`？是否 `-v` 挂载、宿主路径）、二进制 `-cd`、Windows 服务、还是 OpenWrt ipk；以及配置目录 / `lucky.conf` 的实际绝对路径。
3. **日志相关开关的实际值**：`EnableAccessLog`、`LogOutputToConsole`、`LogLevel`、`AccessLogMaxNum` 是否开启、值多少。
4. **本机是否存在落盘日志文件及其绝对路径**（例如 `<配置目录>/logs/` 下），若有请附 `tail -n 20 <路径>` 的真实输出；若无也请明确告知。
5. **期望采集哪一类**：「系统运行日志（MAIN / INFO）」还是「反向代理 Web 访问日志（ClientIP / RemoteIP）」，或两者都要 —— 两者格式不同，对应 `lucky_sys` / `lucky_web` 两套解析。
6. **是否用过 OpenToken 或后台「日志」相关接口**；若有请提供接口返回样例（路径 / 字段 / 鉴权 / 分页），以便评估第 4 节 B 方案。
7. 是否计划把采集结果用于**公网展示**（涉及个人信息保护：他人 IP / 位置数据应仅本机私有存储，见卫星报告的合规红线）。

> 在 1 / 4 / 5 到位前，建议按第 5.5 节 D 路径「**先写解析器框架 + 占位单测，不接实时 tail、不写死格式**」推进，避免把疑似虚构教程里的格式固化进产品。

---

## 7. 参考来源（含可信度与不予采信标注）

| # | 来源 | 类型 / 可信度 | 用途 |
| --- | --- | --- | --- |
| 1 | `https://pkg.go.dev/github.com/gdy666/lucky` （v1.10.8，README 指向 `https://lucky666.cn/`） | 官方包索引 / 高 | 对象辨识、Go 语言、官网 |
| 2 | 官方 README 镜像（github.com/xiejindou/lucky、kkkcccfff/lucky、gist firefox417 等） | 官方 README 副本 / 高 | 「没有文档」「Web 后台支持查看最新 100 条日志」、`:16601`、`666/666`、`-c` / `-cd`、Docker `/goodluck` / `lucky.conf`、OpenToken、Vue3 |
| 3 | 官方源码 `main.go` 副本（guthub wgjas2、atomgit `luc/lucky`、gist zhanjuns） | 官方源码副本 / 高 | Go 标准 `log.Printf`、CST 东八区、模块结构 |
| 4 | `https://allinone.quickso.cn/docs/applications/docker-applications/Lucky/` | 第三方整理文档 / 中高 | 「核心程序完全采用 Golang」「前端 Vue3.2」「OpenToken」、`-v ...:/goodluck` |
| 5 | `http://www.hqwc.cn/a/1919727.html`《Lucky 反向代理实战指南》、`https://www.hqwc.cn/a/1917986.html`《Lucky 使用笔记》 | **第三方个人学习笔记 / 中（非官方）** | `EnableAccessLog` / `LogLevel` / `AccessLogMaxNum`（内存 0–102400）/ `LogOutputToConsole`、`ClientIP` / `RemoteIP`、透传字段、中文提示样例 —— **均需用户本机核对** |
| 6 | `https://luckyframework.org/guides/getting-started/logging` | **同名干扰，已排除** | Crystal 框架 Dexter / `config/log.cr` / json formatter，**不适用于本项目** |
| 7 | CSDN《Lucky 访问日志导出：CSV/JSON…》 `https://blog.csdn.net/gitblog_00760/article/details/152472583` | **疑似 AI 虚构 / 不予采信** | `/api/logs`、`/var/log/lucky/*.log`、"系统日志 → 导出数据"、`jq '.logs'` 无官方 / 源码佐证，**不得据此设计解析或 API 调用** |

> 本报告所有「未找到」项均按用户要求如实标注，未编造任何日志行样例、文件路径或接口返回。本文不含任何可直接使用的 API KEY 或产品代码改动。
