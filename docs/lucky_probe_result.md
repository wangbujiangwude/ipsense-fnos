# B5 真机取证 · lucky 日志落盘情况（2026-11-26）

> 本文是 `docs/lucky_log_research.md` 的**真机只读取证补充**，不改任何产品代码、
> 不改设备任何配置、不打包、不部署。两轮只读命令与原始输出在
> `build/probe_lucky_logs.py` / `build/probe_lucky_logs2.py` 和
> `build/probe_lucky_logs.json` / `build/probe_lucky_logs2.json`。

## 0. 结论（给 B5-3 定方案）

**走调研报告第 5.5 节 D 路径：解析器框架 + 占位单测，不接实时 tail、不写死日志格式。**
理由：真机上找不到任何可直接 tail 的 lucky 文本日志（系统运行日志是空文件、
反代访问日志在内存、配置文件是二进制）。

## 1. 部署方式（已确认）

| 项 | 真机实测 |
| --- | --- |
| 形态 | fnOS 原生应用（**非 Docker**） |
| 版本 | `appcenter-cli list` → `Lucky 3.8.2 running` |
| 进程 | `/vol1/@appcenter/Lucky/bin/arm64/lucky -cd /vol1/@appdata/Lucky/data` |
| 配置目录 | `/vol1/@appdata/Lucky/data`（`-cd` 参数） |
| 后台端口 | 16601（进程在跑；本次未调用后台任何接口） |

## 2. 三类日志的取证结果

| 类别 | 路径 | 实测 | 能否 tail |
| --- | --- | --- | --- |
| 系统运行日志（MAIN / INFO） | `/var/log/apps/Lucky.log` | **0 字节空文件**（`Nov 25 23:46`） | ❌ 无内容 |
| 反代 Web 访问日志 | 全盘 `find` | **未发现任何落盘文件**（`any_access_log` 空） | ❌ |
| 配置 / 状态文件 | `lucky_*.lkcf` | `LKCF` 魔数 + 二进制，`grep` 读不出 `EnableAccessLog` 等开关 | ❌ 文本不可读 |
| LevelDB WAL | `porttrapdb/000001.log`、`lucky_docker_operations/000001.log` | 二进制数据库日志，非文本访问日志 | ❌ 不作为日志源 |

> **更正（重要）**：第一轮 `probe_lucky_logs.py` 的候选筛选过宽，把
> `class-schedule` / `astrbot` / `trim.hermes` / `fnosupgrade` 等**其它应用**的 `.log`
> 也算成「样例」，因此第一轮 JSON 里「找到落盘日志样例」是**误判，已废弃**。
> 第二轮 `probe_lucky_logs2.py` 针对 lucky 精确路径复核，**结论以本表为准**。
> 第一轮控制台开头出现的 `[YYYY-MM-DD HH:MM:SS] main action=status` 来自其它应用日志，
> **不是 lucky 的 MAIN 日志**，不得据此编写解析正则。

## 3. 与调研报告第 6 节「必须让用户补充」的对照

| # | 调研时的缺口 | 本次真机取证后 |
| --- | --- | --- |
| 1 | MAIN / INFO 行格式样例 | 仍缺（stdout 未落盘）；需用户在后台「日志中心」复制原始行或导出 |
| 2 | 部署方式 / 配置目录 | ✅ 已确认（fnOS 原生、`/vol1/@appdata/Lucky/data`） |
| 3 | `EnableAccessLog` 等开关值 | 仍缺（`.lkcf` 二进制，不可文本读取） |
| 4 | 是否有落盘日志文件 | ✅ 已确认：**没有** |
| 5 | 采集哪一类 | 待用户定；`lucky_sys` / `lucky_web` 两套框架都先留 |
| 6 | OpenToken / 日志接口返回样例 | 未调用（调研明确不采信虚构的 `/api/logs`） |
| 7 | 是否公网展示 | 未涉及；批量点位仍只本机私有存储 |

## 4. B5-3 落地边界（据此确定）

- ✅ 追加：`LUCKY_*` 占位正则常量、`parse_lucky_web()` / `parse_lucky_sys()` 框架、
  两个新 `source`、默认全关的配置项、前端来源图例、**基于占位样例的单测**。
- ❌ 不做：`_build_tailers()` 接实时 tail、后台 API 拉取、把 `.lkcf` 当文本解析、
  把其它应用日志当 lucky 样例、把任何臆测格式写死进产品。
- 待用户补：后台日志中心的原始文本行（5–10 行，覆盖不同级别 / 模块），
  拿到后按调研第 5.6 节清单校准 `LUCKY_TS` / `LUCKY_LEVEL` / `LUCKY_MODULE`。

## 5. 合规与边界

只读命令（`id` / `ps` / `appcenter-cli list` / `find` / `ls` / `wc` / `tail` / `grep` / `head`），
未部署、未打包、未写设备文件、未改防火墙、未上传 GitHub。
主包红线「只观测 · 不封禁 · 不改防火墙 · 不自动处置」不动。
