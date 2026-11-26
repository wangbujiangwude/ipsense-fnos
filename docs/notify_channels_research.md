# ipsense 2.0.0 「预警通知 10 渠道全接」接口适配调研

> **性质**：只读前置调研（read-only research）。本次仅新增本文件，**未修改任何产品代码**。
> **调研日期**：2026-11-26
> **信息来源**：各渠道官方网站 / 官方开发者文档 / 官方 GitHub 仓库（WebSearch + WebFetch 抓取原文）。
> **目标**：为 2.0.0 的统一通知适配层提供准确的接口适配依据，而非实现代码。

---

## 0. 置信度口径与结论速览

| 置信度 | 含义 |
| --- | --- |
| **高** | 官方文档 / 官方 GitHub 仓库 / 官方开发者中心明确确认了 URL、鉴权、body 与限制 |
| **中** | 接口格式已确认，但**服务地址需用户确认**或稳定性需实测（自托管、个人服务、社区资料） |
| **低** | 未找到官方公开文档，需用户补充服务地址 |

**本次结果：10 个渠道全部找到了可核验的官方或权威资料，没有出现「完全查不到、需要凭空编造」的渠道。**
但其中有 **1 个渠道（魔法推送）没有统一的官方对外服务地址**（自托管项目，文档里的 base URL 是占位符 `https://your-domain.com/api`），必须请用户确认其实际部署地址；另有 **2 个渠道（Bark / MeoW）为个人或公共免费服务，无企业 SLA，建议实测直连性**。

> 关于用户特别点名的三个「国内第三方推送服务」的核实结论：
> - **PushPlus**：官网 `www.pushplus.plus`，有完整官方 API 文档、官方 Python SDK、明确的额度页 → **高置信，域名与接口真实**。
> - **MeoW**：官网/文档 `www.chuckfang.com/MeoW/api_doc.html`，API 根地址 `https://api.chuckfang.com/`（页面内嵌 OpenAPI 3.1）→ **高置信，域名与接口真实**；但属个人开发者运营的鸿蒙（HarmonyOS）推送服务。
> - **魔法推送**：即飞牛生态的 **MagicPush**（GitHub `magiccode1412/magicpush`，MIT 开源，**自托管**多渠道推送管理平台）→ 接口格式有官方 GitHub 文档，但**没有统一官方 SaaS 地址**，文档 base URL 为占位符，示例地址 `magicpush..heiyu.space` 为脱敏占位 → **中置信，需用户确认服务地址**。

---

## 1. 总览表

| # | 渠道 | 官方接口 / API 根地址 | 鉴权 | 方法 / body | 官方 Python SDK | 免费额度 / 频率限制 | 大陆直连 | 置信度 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 企业微信群机器人（消息推送） | `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=KEY` | Webhook URL 中的 `key`（URL 即凭证） | POST / JSON | 无（直接 HTTP） | 每机器人 **20 条/分钟**；text ≤ 2KB、markdown ≤ 4KB | 是（腾讯） | **高** |
| 2 | 钉钉群机器人 | `https://oapi.dingtalk.com/robot/send?access_token=XXX` | `access_token`（webhook 内）+ 可选 **加签** / 关键词 / IP 白名单 | POST / JSON | 无（群机器人 webhook 直接 HTTP） | 每机器人 **20 条/分钟**，超限限流 10 分钟 | 是（阿里） | **高** |
| 3 | 飞书自定义机器人 | `https://open.feishu.cn/open-apis/bot/v2/hook/XXXX` | Webhook 尾段即凭证 + 可选 **签名校验** / 关键词 / IP 白名单 | POST / JSON | 平台级 `lark-oapi`，webhook 仍直接 HTTP | 单租户单机器人 **100 次/分钟、5 次/秒**；body ≤ 20KB | 是（字节） | **高** |
| 4 | Bark | 公共服务 `https://api.day.app`；自建任意 base | `device_key`（路径或 body）；自建可加 Basic Auth | GET 路径 或 POST `/push` JSON | 无（官方仅给 `requests` 示例） | 官方公共服务免费、无广告、承诺运营至 2031-07；未公开明确限流 | 通常可直连（依赖 Apple APNs，**建议实测/自建**） | **高**（文档）/ 中（直连） |
| 5 | PushPlus（推送加） | `https://www.pushplus.plus/send` | `token`（body 或 query） | GET / POST，POST 为 JSON | **有**：`perk-pushplus-sdk`（`perk_pushplus`） | 未实名 **0 次（错误码 905）**；实名 200 次/天、1 分钟 5 次、相同内容 1 小时 3 条；会员 2000 次/天 | 是（苏州破壳网络） | **高** |
| 6 | 魔法推送（MagicPush） | **自托管**：文档 base 为占位符 `https://your-domain.com/api`，推送 `POST /api/push` | 推送 Token：URL 路径 `/api/push/{token}` 或 `Authorization: Bearer {token}`；管理接口用 JWT | GET / POST，POST 为 JSON | 无（REST） | MIT 开源免费；三层限流额度由部署者后台动态配置，无统一默认值 | 取决于用户部署位置（多为 NAS 内网/自有域名） | **中**（接口格式高 / 服务地址需确认） |
| 7 | SMTP 邮件 | 用户自己的 `smtp://host:port`（无统一 URL） | 账号 + 密码 / **授权码**（`login()`）；部分支持 OAuth2 | SMTP 协议（非 HTTP），`smtplib` 发送 | **有**：Python 标准库 `smtplib` + `email` | 由服务商决定（QQ/163/Gmail 各有日发上限） | 视服务商（国内邮箱可直连，Gmail 不可） | **高**（协议标准） |
| 8 | 企业微信应用（企业号应用消息） | 取 token `GET https://qyapi.weixin.qq.com/cgi-bin/gettoken`；发送 `POST https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=XXX` | `corpid` + `corpsecret` → `access_token`（7200s，需缓存）；body 带 `agentid` | POST / JSON | 无官方（社区有 `wechatpy`） | 每应用 ≤ **账号上限数 × 200 人次/天**；建议避开整点/半点 | 是（腾讯） | **高** |
| 9 | 通用 Webhook（自定义 POST） | 无官方地址，由用户填写目标 URL | 自定义（无 / Bearer / Basic / HMAC / query token 等） | 自定义（建议 POST / JSON） | 用 `requests`（非渠道官方） | 取决于目标服务 | 取决于目标 URL | **高**（自定义协议） |
| 10 | MeoW | `https://api.chuckfang.com/`（也支持 `http://`） | **无 token/key**：用**用户昵称**作路径参数当接收识别码 | GET 路径 / POST（JSON、form、text/plain、multipart） | 无（官方明确「无需 SDK」）；有官方 `meow-push-skill`（TypeScript CLI，非 Python） | 非会员 **3 秒 1 条、15 条/分、60 条/时、1000 条/天**；超限业务码 429 | 是（国内个人开发者域名，无企业 SLA） | **高**（文档）/ 中（稳定性） |

> **重要区分**：#1 企业微信「群机器人 / 消息推送」与 #8 企业微信「应用消息」是两套完全不同的接口、凭证体系与限流模型，不可混用，见 §2.1 与 §2.8。
> **重要区分**：#2 钉钉「加签」与 #3 飞书「签名校验」名称相近但**算法细节不同**（时间戳单位、HMAC 的 key/消息、签名放 query 还是 body、是否 urlEncode），见 §2.11 对照表。

---

## 2. 逐渠道小节

### 2.1 企业微信群机器人（群机器人 Webhook / 现「消息推送」） — 置信度：高

**官方文档**：<https://developer.work.weixin.qq.com/document/path/91770>（消息推送配置说明）、<https://open.work.weixin.qq.com/help2/pc/14931>（如何设置消息推送）。注：v4.1.41 起「群机器人」更名为「消息推送」。

1. **官方接口 URL**：`https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=693a91f6-7xxx-4bc4-97a0-0ec2sifa5aaa`（`key` 由创建者在群「消息推送」详情页获取）。
2. **鉴权方式**：无独立 token，**Webhook 完整 URL 中的 `key` 即是凭证**。官方明确警告须保密，不要提交到 GitHub/博客。
3. **HTTP 方法与 body**：`POST`，`Content-Type: application/json`，**JSON body**。文本示例：`{"msgtype":"text","text":{"content":"hello world"}}`；另支持 `markdown` / `markdown_v2` / `image` / `news` / `file` / `voice` / `template_card`。content 必须 UTF-8。
4. **最小可运行示例**：
   ```bash
   curl 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY' \
     -H 'Content-Type: application/json' \
     -d '{"msgtype":"text","text":{"content":"ipsense 告警：IP 已变更"}}'
   ```
5. **官方 Python SDK**：无。直接用 `requests.post(webhook_url, json=payload)`。
6. **免费额度 / 频率限制**：免费；每个机器人 **每分钟最多 20 条**。文本 ≤ 2KB、Markdown ≤ 4KB（不支持表格）；文件 5B~20MB（先上传 media 再发，素材 3 天有效）。群开启「全员禁言」时会返回成功但消息不显示。
7. **中国大陆可直连**：是（腾讯 `qyapi.weixin.qq.com`）。

**适配备注**：`config` 只需存 `webhook_url`（含 key）。成功判定 `errcode == 0`。仅内部群可用（外部群无入口）。

---

### 2.2 钉钉群机器人 — 置信度：高

**官方文档**：<https://open.dingtalk.com/document/orgapp/custom-robots-send-group-messages>（发送群消息）、<https://open.dingtalk.com/document/orgapp/customize-robot-security-settings>（安全设置/加签）。

1. **官方接口 URL**：`https://oapi.dingtalk.com/robot/send?access_token=XXXXXX`；开启加签后追加 `&timestamp=XXX&sign=XXX`。
2. **鉴权方式**：`access_token` 是 webhook 地址自带的凭证（**注意：这是机器人 webhook token，不是 OAuth access_token**）。安全设置为三选一/可叠加：
   - 自定义关键词（最多 10 个，消息须含至少 1 个）；
   - **加签**（`SEC` 开头的 secret）；
   - IP 地址（段）白名单。
3. **HTTP 方法与 body**：`POST`，`Content-Type: application/json`，**JSON body**。`{"msgtype":"text","text":{"content":"告警内容"},"at":{"isAtAll":false}}`。
4. **最小可运行示例（含加签）**：
   ```python
   import time, hmac, hashlib, base64, urllib.parse, requests

   ACCESS_TOKEN = "YOUR_ACCESS_TOKEN"
   SECRET = "SECxxxxxxxx"          # 未开启加签则留空，删掉 timestamp/sign

   def sign(secret):
       ts = str(round(time.time() * 1000))            # 毫秒
       s = "{}\n{}".format(ts, secret)
       h = hmac.new(secret.encode(), s.encode(), digestmod=hashlib.sha256).digest()
       return ts, urllib.parse.quote_plus(base64.b64encode(h))

   params = {"access_token": ACCESS_TOKEN}
   if SECRET:
       params["timestamp"], params["sign"] = sign(SECRET)

   r = requests.post("https://oapi.dingtalk.com/robot/send",
                     params=params,
                     json={"msgtype": "text",
                           "text": {"content": "ipsense 告警：IP 已变更"}},
                     timeout=10)
   print(r.json())   # {"errcode":0,"errmsg":"ok"}
   ```
   **加签算法**：`string_to_sign = timestamp + "\n" + secret` → 以 **secret 为 HMAC key**、**string_to_sign 为消息**做 `HmacSHA256` → `Base64` → `urlEncode(quote_plus)` → 拼到 **URL query**；`timestamp` 单位**毫秒**，与请求时间误差 ≤ 1 小时。
5. **官方 Python SDK**：无专门针对自定义机器人 webhook 的官方 SDK。平台级 SDK（`dingtalk-sdk` / `alibaba-dingtalk-service-sdk`）服务的是企业内部应用 OpenAPI，不适用于本 webhook，直接 HTTP 即可。
6. **免费额度 / 频率限制**：免费；每个机器人 **每分钟最多 20 条**，超限**限流 10 分钟**。官方建议监控告警类消息整合为 markdown 摘要发送。
7. **中国大陆可直连**：是（阿里 `oapi.dingtalk.com`）。

**适配备注**：若用户选了「关键词」安全设置，标题/正文必须包含关键词，否则消息被静默丢弃——**适配层需在配置里记录关键词并在 text 中拼接**。

---

### 2.3 飞书自定义机器人 — 置信度：高

**官方文档**：<https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot>（自定义机器人使用指南）、<https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN>（快速调用）。

1. **官方接口 URL**：`https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxxxxxxxxxxx`（尾段由机器人在群里生成）。
2. **鉴权方式**：Webhook 尾段即凭证（官方要求保密）。安全设置三选一/可叠加：自定义关键词（≤10）、IP 白名单（≤10 段）、**签名校验**。
3. **HTTP 方法与 body**：`POST`，`Content-Type: application/json`，**JSON body**。`{"msg_type":"text","content":{"text":"request example"}}`；也支持富文本 `post`、卡片 `interactive`、群名片等。**开启签名校验时，`timestamp` 与 `sign` 放在 JSON body 顶层**：
   ```json
   {"timestamp":"1599360473","sign":"xxxxxxxx","msg_type":"text","content":{"text":"request example"}}
   ```
4. **最小可运行示例（含签名校验）**：
   ```python
   import time, hmac, hashlib, base64, requests

   WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/YOUR_HOOK_ID"
   SECRET = "YOUR_SECRET"        # 未开启签名校验则留空

   def gen_sign(secret, ts):
       s = "{}\n{}".format(ts, secret)
       # 注意：飞书以 (timestamp+"\n"+secret) 作为 HMAC key，对【空字符串】签名
       h = hmac.new(s.encode("utf-8"), b"", digestmod=hashlib.sha256).digest()
       return base64.b64encode(h).decode("utf-8")

   body = {"msg_type": "text", "content": {"text": "ipsense 告警：IP 已变更"}}
   if SECRET:
       ts = str(int(time.time()))                    # 秒
       body["timestamp"], body["sign"] = ts, gen_sign(SECRET, ts)

   r = requests.post(WEBHOOK, json=body, timeout=10)
   print(r.json())   # {"code":0,"msg":"success","data":{}}
   ```
   **签名算法**：`string_to_sign = timestamp + "\n" + secret` → 以 **string_to_sign 作为 HMAC key**、**对空字节串 `b""`** 做 `HmacSHA256` → `Base64`（**不做 urlEncode**）→ 放入 **JSON body**；`timestamp` 单位**秒**，距当前不超过 3600 秒。
5. **官方 Python SDK**：平台级有 `lark-oapi`（`pip install lark-oapi`，官方 oapi-sdk-python），用于开放平台应用 API；**自定义机器人 webhook 无专门 SDK**，官方示例即 `requests.post(WEBHOOK_URL, json=params)`。
6. **免费额度 / 频率限制**：免费；单租户单机器人 **100 次/分钟、5 次/秒**；请求体 ≤ 20KB。官方建议避开 10:00、17:30 等整点/半点，否则可能触发 `11232` 限流。
7. **中国大陆可直连**：是（字节 `open.feishu.cn`）。

**适配备注**：自定义机器人**只能在当前群聊使用**，不能添加到其他群；无数据访问权限。关键词校验只对 `text`/`title` 生效（不校验 `href`）。

---

### 2.4 Bark — 置信度：高（官方文档）；直连性：中（建议实测/自建）

**官方资料**：官网 <https://bark.day.app/>、iOS App <https://github.com/Finb/Bark>、服务端 <https://github.com/Finb/bark-server>、API V2 规范 <https://github.com/Finb/bark-server/blob/master/docs/API_V2.md>。

1. **官方接口 URL**：公共服务器 `https://api.day.app`。
   - V1（GET 路径式）：`https://api.day.app/:key/:title/:body` 或 `https://api.day.app/:key/:body`；
   - V2（推荐，REST）：`POST https://api.day.app/push`（自建同样为 `/push`）。
   - 可自建：Docker `finab/bark-server` / `ghcr.io/finb/bark-server`，默认端口 8080，此时 base 由用户自定。
2. **鉴权方式**：`device_key`（V1 在 URL 路径；V2 在 JSON body 的 `device_key` 字段，批量用 `device_keys` 数组）。**无 token**；自建服务可启用 Basic Auth（用户名/密码）。`ciphertext` 参数可加密正文。
3. **HTTP 方法与 body**：`POST`，`Content-Type: application/json; charset=utf-8`，**JSON body**。必填 `body`、`device_key`；可选 `title`、`subtitle`、`level`（`critical`/`active`/`timeSensitive`/`passive`）、`volume`、`badge`、`call`、`autoCopy`、`copy`、`sound`、`icon`、`group`、`ciphertext`、`isArchive`、`ttl`、`url`、`action`。也支持 GET 路径式与 query 参数。
4. **最小可运行示例**：
   ```bash
   curl -X POST "https://api.day.app/push" \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d '{"device_key":"YOUR_DEVICE_KEY","title":"ipsense 告警","body":"IP 已变更","group":"ipsense","sound":"minuet","url":"https://nas.local"}'
   ```
5. **官方 Python SDK**：**无**。官方 `API_V2.md` 里的 Python 示例就是 `pip install requests` + `requests.post(..., data=json.dumps({...}))`。
6. **免费额度 / 频率限制**：官方公共服务**免费、无广告、无收费功能**，官网称 2018-07 上线、至少运营至 **2031-07**；官方未公开明确 QPS/次数限制。自建无平台限流（由部署者控制）。长度限制由 APNs 决定。
7. **中国大陆可直连**：`api.day.app` 通常可直连，但服务最终依赖 **Apple APNs**，且为作者个人维护的公共服务、无 SLA；**建议实测，敏感场景优先自建 + `ciphertext` 加密**（自建部署在 NAS 内网可完全自主可控）。

**适配备注**：`config` 需含 `base_url`（默认 `https://api.day.app`）、`device_key`、可选 `basic_user`/`basic_pass`。这是 10 个渠道中**唯一以 iOS/APNs 为终点**的渠道。

---

### 2.5 PushPlus（推送加） — 置信度：高

**官方资料**：官网 <https://www.pushplus.plus>、文档中心 <https://www.pushplus.plus/doc/>、在线 API <https://api.pushplus.plus/>、消息接口 <https://www.pushplus.plus/doc/guide/api.html>、限制 <https://www.pushplus.plus/doc/help/limit.html>、SDK <https://www.pushplus.plus/doc/guide/sdk.html>。运营主体：苏州破壳网络科技有限公司（2019 年上线）。

1. **官方接口 URL**：`https://www.pushplus.plus/send`（GET / POST / PUT / DELETE 均支持，官方推荐 POST JSON）。
2. **鉴权方式**：`token`（用户令牌 / 消息令牌）。POST 时放在 **JSON body**，GET 时放在 **query**；亦支持 `https://www.pushplus.plus/send/{token}?content=XXX` 路径式。**2024-08 起未实名认证用户无法调用发送接口**（返回 `905`）。
3. **HTTP 方法与 body**：`POST`，`Content-Type: application/json`（官方强调必须设置，否则服务端无法识别 body 中的 JSON），**JSON body**：
   ```json
   {"token":"xxx","title":"标题","content":"消息内容","topic":"code","template":"html"}
   ```
   `content` 必填、`title` 可选；`template`：`html`(默认)/`txt`/`markdown`/`json`；`channel`：`wechat`(默认)/`webhook`/`cp`/`mail`/`clawbot`/`app`/`qq`/`sms`/`voice`；另有 `to`、`topic`、`callbackUrl`、`timestamp`、`option`、`pre`、`pushId`。
4. **最小可运行示例**：
   ```bash
   curl -X POST 'https://www.pushplus.plus/send' \
     -H 'Content-Type: application/json' \
     -d '{"token":"YOUR_TOKEN","title":"ipsense 告警","content":"IP 已变更","template":"markdown"}'
   ```
   返回 `{"code":200,"msg":"请求成功","data":"075074e3...流水号"}`。
5. **官方 Python SDK**：**有**。`pip install perk-pushplus-sdk`（PyPI: `perk-pushplus-sdk`），包名 `perk_pushplus`：
   ```python
   from perk_pushplus import PushPlusClient, SendRequest, Template, Channel
   client = PushPlusClient.builder().token("YOUR_TOKEN").build()
   short_code = client.send_simple("ipsense 告警", "IP 已变更")
   ```
   官方另提供 Java / Node.js / Go SDK，以及 MCP Server 与 Skill。
6. **免费额度 / 频率限制**（限制页更新时间 2026/9/14，按渠道计）：
   - 未实名：**所有渠道 0 次**（错误码 `905`）；必须先完成实名认证。
   - 实名用户：微信渠道 **200 次/天**；企业微信应用 / webhook / 插件 / ClawBot 渠道 **1000 次/天**；邮件 / App / 新消息ClawBot / QQ **200 次/天**。
   - 会员：微信 **2000 次/天**，企业微信应用/webhook **10000 次/天**。
   - 请求频率：实名 **1 分钟 5 次**；相同内容 **1 小时 3 条**；会员 10 秒 5 次。
   - 长度：标题 100 字、内容 2 万字（会员 200 字 / 10 万字）。
   - 超过 200 次当日不再推送；超过 2000 次限制微信推送 7 天。返回码 `900` 表示当日已无法推送，`905` 表示未实名。
7. **中国大陆可直连**：是（国内域名 `www.pushplus.plus`）。

**适配备注（重要）**：接口是**异步**的，`code=200` 仅代表「收到请求」，不代表送达；需用 `data` 流水号查询或配置 `callbackUrl` 回调确认。适配层若把 `code=200` 当作送达成功，会误判。另外注意 `channel=webhook` 额度（1000 次/天）远高于默认 `wechat`（200 次/天），告警场景可按需选择。

---

### 2.6 魔法推送（MagicPush） — 置信度：中（接口格式高 / 服务地址需用户确认）

**核实结论**：用户所称「魔法推送」即飞牛 fnOS 生态流出的 **MagicPush / 魔法推送**，是一个 **MIT 开源、自托管**的「多渠道推送服务管理平台」（把 20+ 渠道统一成一个 REST API）。
**官方资料**：GitHub 项目 <https://github.com/magiccode1412/magicpush>、官方 API 文档 <https://github.com/magiccode1412/magicpush/blob/main/apps/website/guide/dev/api-reference.md>、文档站 <https://magicpush.160621.xyz/>、镜像 `docker.cnb.cool/magiccode1412/magicpush:latest` / `magiccode1412/magicpush:latest`、懒猫微服应用页 <https://lazycat.cloud/appstore/detail/cloud.lazycat.app.magicpush>。

> ⚠️ **未找到统一官方公开 SaaS 服务地址，需用户确认服务地址。**
> 官方 API 文档明写「生产环境：`https://your-domain.com/api`」——这是**占位符**；社区帖与懒猫应用页里的示例 `https://magicpush..heiyu.space/...` 为脱敏/占位（注意域名中出现两个点），**不可作为真实接口使用**。本项目设计为每人自行 Docker 部署，官方明确「不再提供 Demo 预览站」。因此适配层必须把 base URL 作为用户可填配置项，不能硬编码。

1. **官方接口 URL**：`<用户自托管 base>/api`，推送端点 `POST /api/push`（或 `GET/POST /api/push/{token}`）。文档占位：生产 `https://your-domain.com/api`、开发 `http://localhost:3000/api`。容器常见映射 `5001:3000`。
2. **鉴权方式**：推送 Token —— 两种等价方式：
   - **URL Token**：路径参数 `/api/push/{token}`；
   - **Bearer Token**：请求头 `Authorization: Bearer {token}` 打到 `/api/push`（官方称「最安全」）。
   Token 在 Web 管理界面「接口管理 → 创建接口」生成，可 `POST /api/endpoints/:id/regenerate-token` 重置。管理类接口另用 JWT 双令牌（accessToken 15 分钟 / refreshToken 7 天）。
3. **HTTP 方法与 body**：`GET /api/push/{token}?title=&content=&type=text`（query）或 `POST`，`Content-Type: application/json`，**JSON body**：
   ```json
   {"title":"标题","content":"内容","type":"markdown","url":"https://..."}
   ```
   字段：`content` 必填；`title` 可选；`type` = `text`(默认) / `markdown` / `html`；`url` 可选（部分渠道支持）。
4. **最小可运行示例**：
   ```bash
   curl -X POST "https://YOUR-MAGICPUSH-HOST/api/push" \
     -H "Authorization: Bearer YOUR_PUSH_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"title":"ipsense 告警","content":"IP 已变更","type":"markdown"}'
   ```
   推送响应（**注意与「统一响应格式」不同**）：
   ```json
   {"success":true,"total":3,"successCount":2,"failedCount":1,
    "results":[{"success":true,"channelId":1,"channelType":"telegram","logId":101},
               {"success":false,"channelId":3,"channelType":"feishu","error":"Webhook 超时"}]}
   ```
5. **官方 Python SDK**：无（纯 REST，用 `requests`）。
6. **免费额度 / 频率限制**：MIT 开源免费，自托管无平台费用。限流由部署者在后台「安全设置」动态配置、默认开启，共三层：Nginx 层 IP 频率+并发、Express 全局按 IP 每分钟总请求数、接口级（登录/注册/推送/入站）独立限流；推送接口按 **来源 IP + Token 双重限流**。文档给出的唯一确定数字是 `GET /api/health` 独立限流 **30 req/min**，其余额度无统一默认值。
7. **中国大陆可直连**：取决于用户部署位置（多为 NAS 内网 / 自有域名 / 懒猫微服），通常可直连；**无官方公网 SaaS**。

**适配备注（重要洞察）**：MagicPush 本身已内置 20+ 渠道，**恰好覆盖了本清单里的企业微信机器人、企业微信应用、钉钉、飞书、PushPlus、Bark、MeoW、Webhook、SMTP 邮件**（其渠道列表原文含 `Bark、Meow、PushMe、ntfy、PushDeer、iGot`）。因此：
- 若用户已部署 MagicPush，ipsense 其实只需实现 **#9 通用 Webhook** 一个 adapter 指向 `/api/push`，由 MagicPush 负责二次分发，可避免重复适配；
- 但需评估这带来的单点依赖与额外一跳延迟，且「10 渠道全接」的产品目标若要求各渠道独立可配，则仍应保留独立 adapter。

---

### 2.7 SMTP 邮件 — 置信度：高（协议标准 + 官方标准库文档）

**官方资料**：Python 官方 <https://docs.python.org/3/library/smtplib.html>、`email` 包文档；协议 RFC 5321（SMTP）/ RFC 4954（AUTH）/ RFC 3207（STARTTLS）。

1. **官方接口 URL**：**无统一 URL**——SMTP 是邮件协议，端点为用户自己的 `smtp://host:port`。常见：QQ 邮箱 `smtp.qq.com`、163 `smtp.163.com`、Gmail `smtp.gmail.com`；端口 **25**（`SMTP.default_port`，明文/中继）、**465**（`SMTP_SSL.default_port`，隐式 SSL）、**587**（提交 + STARTTLS，需按服务商确认）。
2. **鉴权方式**：`SMTP.login(user, password)`，内置 `CRAM-MD5` / `PLAIN` / `LOGIN`。国内邮箱通常用**授权码/应用专用密码**而非登录密码；部分服务商支持 OAuth2。
3. **HTTP 方法与 body**：**非 HTTP**。用 `smtplib` 建立连接 → 可选 `starttls()` → `login()` → 用 `email.message.EmailMessage` 构造 `From`/`To`/`Subject`/正文 → `send_message()`。
4. **最小可运行示例**（465 隐式 SSL）：
   ```python
   from email.message import EmailMessage
   import smtplib

   msg = EmailMessage()
   msg["From"] = "sender@example.com"
   msg["To"] = "ops@example.com"
   msg["Subject"] = "ipsense 告警：IP 已变更"
   msg.set_content("检测到公网 IP 发生变化，请核查。")

   with smtplib.SMTP_SSL("smtp.example.com", 465) as smtp:   # 587 时改 SMTP(...) + starttls()
       smtp.login("sender@example.com", "YOUR_AUTH_CODE")
       smtp.send_message(msg)
   ```
5. **官方 Python SDK**：**有**，即 Python **标准库** `smtplib` + `email`，无需 `pip install`。
6. **免费额度 / 频率限制**：协议本身不限；由邮件服务商规定（QQ/163/Gmail 各有每日发信量、单封收件人数、附件大小上限）。免费邮箱普遍有反垃圾限流。
7. **中国大陆可直连**：取决于服务商——国内邮箱（QQ/163/企业邮）可直连；Gmail / Outlook 等境外服务在大陆通常**不可直连**（需代理）。

**适配备注**：这是唯一**非 HTTP** 渠道，不能用统一的 `requests` 发送器；适配层需允许 adapter 自定义传输实现。`config` 字段：`host`、`port`、`security`（`ssl` / `starttls` / `none`）、`username`、`password`、``from_addr`、`to_addrs`。成功判定为「未抛异常」（无响应体）。

---

### 2.8 企业微信应用（企业号应用消息） — 置信度：高

**官方文档**：<https://developer.work.weixin.qq.com/document/90002/90151/90854>（发送应用消息，最后更新 2025/09/24）、<https://developer.work.weixin.qq.com/document/25176> / <https://developer.work.weixin.qq.com/document/42543>（获取 access_token）。

> **与 §2.1 群机器人的本质区别**：群机器人是「一个 Webhook URL 直接往某个群发消息」；应用消息是「企业自建应用凭证 → 换取 access_token → 向指定成员/部门/标签推送到应用会话」。前者凭证是 `key`，后者凭证是 `corpid`+`corpsecret`+`agentid`，限流模型也完全不同。

1. **官方接口 URL**（两步）：
   - 取凭证：`GET https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ID&corpsecret=SECRET`
   - 发消息：`POST https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=ACCESS_TOKEN`
2. **鉴权方式**：`corpid`（企业 ID）+ `corpsecret`（应用 Secret）→ `access_token`；`agentid`（应用 ID）放在 JSON body；`touser` / `toparty` / `totag` 指定接收者（`touser:"@all"` 为全体）。**`access_token` 有效期 `expires_in: 7200` 秒，必须后台缓存，不能频繁调用 gettoken（会触发频率拦截）**；每个应用 secret 独立、token 独立。官方要求 access_token 只在后台使用、不得下发前端。
3. **HTTP 方法与 body**：`POST`，`Content-Type: application/json`，**JSON body**：
   ```json
   {"touser":"abelzhu|ZhuShengben","msgtype":"text","agentid":1000002,
    "text":{"content":"我就试一下"},"safe":0,
    "enable_duplicate_check":1,"duplicate_check_interval":1800}
   ```
   支持 text / image / voice / video / file / textcard / news / mpnews / markdown / template_card 等。
4. **最小可运行示例**：
   ```python
   import requests

   CORPID, CORPSECRET, AGENTID, TOUSER = "YOUR_CORPID", "YOUR_SECRET", 1000002, "@all"
   s = requests.Session()

   tok = s.get("https://qyapi.weixin.qq.com/cgi-bin/gettoken",
               params={"corpid": CORPID, "corpsecret": CORPSECRET}, timeout=10).json()
   assert tok["errcode"] == 0, tok

   r = s.post("https://qyapi.weixin.qq.com/cgi-bin/message/send",
              params={"access_token": tok["access_token"]},
              json={"touser": TOUSER, "msgtype": "text", "agentid": AGENTID,
                    "text": {"content": "ipsense 告警：IP 已变更"}, "safe": 0},
              timeout=10)
   print(r.json())   # {"errcode":0,"errmsg":"ok","msgid":"..."}
   ```
5. **官方 Python SDK**：**无官方 Python SDK**（社区有 `wechatpy`）。直接 HTTP 即可。
6. **免费额度 / 频率限制**：免费；每应用不超过 **账号上限数 × 200 人次/天**（一次 API 发给 1000 人算 1000 人次；如企业账号上限 500 人，则每应用每天 100000 人次）。官方建议避开每小时 0 分 / 30 分这两个推送高峰。支持 `enable_duplicate_check` 重复消息检查（默认 1800 秒窗口）。
7. **中国大陆可直连**：是（腾讯 `qyapi.weixin.qq.com`）。

**适配备注**：`config`：`corpid`、`corpsecret`、`agentid`、`touser`。适配层需实现 **access_token 缓存 + 过期重取**（7200s，建议提前 300s 刷新），且缓存 key 要按 `corpid+agentid` 区分。另需在管理后台配置应用**可见范围**与**企业可信 IP**（若开启），否则 `invaliduser` / `81013`。这是 10 个渠道中**唯一需要两步请求 + 状态缓存**的。

---

### 2.9 通用 Webhook（自定义 POST） — 置信度：高（自定义协议）

**官方资料**：无外部官方文档——这是 **ipsense 自己定义的出站约定**，目标是给用户自建系统 / Home Assistant / n8n / Grafana / 其他告警平台用的兜底通道。

1. **官方接口 URL**：**无**，由用户填写任意 `https://...`。
2. **鉴权方式**：自定义，建议支持：无、`Authorization: Bearer xxx`、`Basic`、`X-*`` 自定义头、query token、HMAC 签名（可选，参考钉钉加签）。
3. **HTTP 方法与 body**：建议 `POST` + `Content-Type: application/json`，**JSON body**。建议 ipsense 定义一个稳定、可版本化的负载（示例）：
   ```json
   {"source":"ipsense","version":"2.0.0","event":"ip_changed",
    "title":"ipsense 告警","text":"公网 IP 已变更",
    "timestamp":"2026-11-26T08:00:00+08:00",
    "detail":{"old_ip":"1.2.3.4","new_ip":"5.6.7.8"}}
   ```
   同时允许用户配置 **自定义 body 模板**（Jinja2 / 变量占位 `{{title}}`、`{{text}}`）与自定义 headers，以对接只接受固定格式的第三方。
4. **最小可运行示例**：
   ```bash
   curl -X POST 'https://your-endpoint.example.com/hook' \
     -H 'Content-Type: application/json' \
     -H 'Authorization: Bearer YOUR_TOKEN' \
     -d '{"title":"ipsense 告警","text":"IP 已变更"}'
   ```
5. **官方 Python SDK**：无渠道 SDK；用 `requests`。
6. **免费额度 / 频率限制**：取决于目标服务；协议本身不限。
7. **中国大陆可直连**：取决于目标 URL（内网地址可直连，境外地址可能不通）。

**适配备注**：`config`：`url`、`method`、`headers`、`body_template`、`auth`、`success_matcher`（如「HTTP 2xx」或「JSONPath `$.code == 0`」）。**成功判定必须可配置**，因为自定义端点没有统一返回码。注意 SSRF 风险：应对用户填写的 URL 做校验/限制（禁止内网元数据地址、限制协议为 http/https、设置超时）。

---

### 2.10 MeoW — 置信度：高（官方 API 文档）；稳定性：中（个人服务）

**核实结论**：MeoW 是**专为鸿蒙（HarmonyOS）用户打造的消息提醒 App**（作者「方程 / 盼望星辰」，博客 `blog.starchen.top`），为开发者提供 HTTP 推送接口。
**官方资料**：API 文档 <https://www.chuckfang.com/MeoW/api_doc.html>（页面内嵌 **OpenAPI 3.1** 规范，标注 `STATUS · OPERATIONAL`）、官方 Skill 仓库 <https://github.com/fkccoding/meow-push-skill>、介绍文 <https://cloud.tencent.com.cn/developer/article/2547226>。另在 fnOS 生态「敲门 Knock」文档 <https://docs.fnknock.cn/zh-tw/guide/event-center-and-notifications> 中被列为 `HarmonyOS MeoW` 通知渠道，并写明「官方 API 使用预设的 `https://api.chuckfang.com`；自架相容服务请填写其 Base URL」——**与本次查证互相印证**。

> 与 PushPlus 不同，MeoW **没有 token/key**：用「用户昵称」当接收识别码。这是最容易接错的一点。

1. **官方接口 URL**：`https://api.chuckfang.com/`（官方亦提供 `http://api.chuckfang.com/`，推荐 HTTPS）。
   - GET：`/{昵称}/{title}/{msg}` 或省略 title 的 `/{昵称}/{msg}`；
   - POST：`/{昵称}` 或 `/{昵称}/[title]`。
   - 支持自架相容服务，此时 base 由用户填写。
2. **鉴权方式**：**无 token / 无 key / 无签名**。路径中的**昵称**即接收标识（须为目标用户已在 MeoW App 注册的昵称，**不允许包含斜杠 `/`**，中文需 URL 编码）。昵称等同于凭证，应比照敏感凭据保存；昵称无法预先校验，未注册返回业务码 `404`。
3. **HTTP 方法与 body**：`GET` 或 `POST`。POST 支持 4 种 Content-Type：`application/json`、`application/x-www-form-urlencoded`、`text/plain`、`multipart/form-data`。
   - 公共参数：`title`（Body > 路径 > 默认 `MeoW`）、`msg`（内容，必填）、`url`（跳转链接）、`imgUrl`（图标，建议 216×216 PNG）、`category`（自定义分类，≤10 字）、`msgType`（`text` 默认 / `html`）、`htmlHeight`（仅 html 生效，默认 200）。
   - 注意 `msgType` 与 `htmlHeight` 是**请求参数（query）**，不属于 JSON 正文；`url`/`imgUrl`/`category` 可放 query 或 body（body 优先）。
4. **最小可运行示例**：
   ```bash
   # GET（最简）
   curl "https://api.chuckfang.com/YOUR_NICK/ipsense%E5%91%8A%E8%AD%A6/IP%E5%B7%B2%E5%8F%98%E6%9B%B4?category=alerts"

   # POST JSON
   curl -X POST "https://api.chuckfang.com/YOUR_NICK" \
     -H 'Content-Type: application/json' \
     -d '{"title":"ipsense 告警","msg":"IP 已变更","url":"https://nas.local","category":"服务器告警"}'
   ```
   响应：`{"status":200,"data":true,"msg":"发送成功"}`（**HTTP 状态统一为 200，业务码在 `status` 字段**）。
5. **官方 Python SDK**：**无**，官方明确「无需 SDK，一个 URL 即可完成集成」。有官方 `meow-push-skill`（GitHub `fkccoding/meow-push-skill`，TypeScript CLI，面向大模型集成），**不是 Python SDK**。
6. **免费额度 / 频率限制**：非会员 **3 秒 1 条、每分钟 15 条、每小时 60 条、每天 1000 条**；超过任一限制返回业务码 `429`。业务状态码：`200` 成功、`400` 参数/分类错误、`403` 内容策略禁止、`404` 昵称未注册、`429` 频率超限、`500` 服务器错误。官方提示：**尽量不要通过多人共享的公共出口 IP 请求**（可能被判为攻击），可信 IP 可联系开发者加白。
7. **中国大陆可直连**：是（国内域名 `api.chuckfang.com`），但为**个人开发者运营的免费服务，无企业 SLA**，建议实测并在适配层做好失败降级。

**适配备注**：`config`：`base_url`（默认 `https://api.chuckfang.com`）、`nickname`、`msg_type`/`category` 等。成功判定 `status == 200`（**不能只看 HTTP 200**）。发送前**必须让用户确认昵称拼写**——因为 404 只能靠「真实发一次」才知道，而这次尝试本身已是一条推送，不能用试发去探测昵称。

---

### 2.11 加签算法对照（钉钉 vs 飞书，务必分开实现）

两者都叫「签名/加签」、都用 HmacSHA256 + Base64 + `timestamp + "\n" + secret`，但**四处关键差异**，混用会 100% 校验失败：

| 对比项 | 钉钉群机器人（加签） | 飞书自定义机器人（签名校验） |
| --- | --- | --- |
| 时间戳单位 | **毫秒**（`round(time.time()*1000)`） | **秒**（`int(time.time())`） |
| HMAC 的 key | `secret` | `timestamp + "\n" + secret`（拼接串当 key） |
| HMAC 的消息 | `timestamp + "\n" + secret` | **空字节串 `b""`** |
| 结果处理 | Base64 → **urlEncode（`quote_plus`）** | Base64（**不再 urlEncode**） |
| 参数位置 | **URL query**：`&timestamp=..&sign=..` | **JSON body 顶层**：`"timestamp"`、`"sign"` |
| 有效窗口 | 与请求时间误差 ≤ 1 小时 | 距当前时间 ≤ 3600 秒 |
| 安全设置族 | 关键词 / 加签 / IP 段（三选一或叠加） | 关键词 / IP 白名单 / 签名校验（三选一或叠加） |

对照代码：

```python
import time, hmac, hashlib, base64, urllib.parse

def dingtalk_sign(secret):
    ts = str(round(time.time() * 1000))
    s = f"{ts}\n{secret}"
    h = hmac.new(secret.encode(), s.encode(), hashlib.sha256).digest()
    return ts, urllib.parse.quote_plus(base64.b64encode(h))   # → query

def feishu_sign(secret):
    ts = str(int(time.time()))
    s = f"{ts}\n{secret}"
    h = hmac.new(s.encode("utf-8"), b"", hashlib.sha256).digest()
    return ts, base64.b64encode(h).decode("utf-8")            # → JSON body
```

---

## 3. 统一适配层建议

### 3.1 抽象接口

把「发一条预警」收敛为一个与渠道无关的函数，**每渠道一个 adapter**：

```python
# notify/adapters/base.py  （本报告中的建议代码，非产品代码）
from dataclasses import dataclass, field
from typing import Any, Protocol

@dataclass
class SendResult:
    ok: bool
    channel: str
    message: str = ""          # 面向用户的可读结果
    raw: Any = None            # 原始响应，便于排障
    retryable: bool = False    # 是否值得重试（限流/5xx 为 True，参数错误为 False）

class Adapter(Protocol):
    name: str
    def send(self, title: str, text: str, config: dict) -> SendResult: ...

# notify/__init__.py
REGISTRY: dict[str, Adapter] = {}

def send(title: str, text: str, config: dict) -> SendResult:
    """统一入口。config["channel"] 决定走哪个 adapter。"""
    channel = config["channel"]
    adapter = REGISTRY.get(channel)
    if adapter is None:
        return SendResult(False, channel, f"未注册的渠道: {channel}")
    return adapter.send(title, text, config)
```

`config` 为一个扁平 dict（**由 UI 表单生成、加密存储**），约定公共字段：

| 公共字段 | 说明 |
| --- | --- |
| `channel` | `wecom_bot` / `dingtalk` / `feishu` / `bark` / `pushplus` / `magicpush` / `smtp` / `wecom_app` / `webhook` / `meow` |
| `enabled`, `timeout`, `retry` | 开关、超时秒数、重试次数 |
| `title_prefix` | 统一标题前缀（也用于满足钉钉/飞书「关键词」安全设置） |
| 各渠道私有字段 | 见 §3.2 差异矩阵 |

### 3.2 十个 adapter 的差异矩阵（实现时逐格填）

| channel | 目标 URL 来源 | 鉴权位置 | 签名 | body 形态 | 请求次数 | 成功判定 | 关键 config 字段 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `wecom_bot` | 固定 + `key` | URL query | 无 | JSON (`msgtype/text`) | 1 | `errcode == 0` | `webhook_url` |
| `dingtalk` | 固定 + `access_token` | URL query | 可选（毫秒/query/urlEncode） | JSON (`msgtype/text`) | 1 | `errcode == 0` | `access_token`, `secret`, `keyword` |
| `feishu` | 固定 + hook id | URL 路径 | 可选（秒/body/不编码） | JSON (`msg_type/content`) | 1 | `code == 0` | `webhook_url`, `secret`, `keyword` |
| `bark` | 可配（默认 `api.day.app`） | path 或 body 的 `device_key` | 无（可选 Basic Auth） | JSON (`/push`) | 1 | HTTP 2xx | `base_url`, `device_key`, `basic_*` |
| `pushplus` | 固定 | body/query `token` | 无 | JSON (`token/title/content`) | 1（**异步，code≠送达**） | `code == 200`，另需流水号/回调查送达 | `token`, `template`, `channel`, `topic` |
| `magicpush` | **用户自托管 base（必填）** | URL 路径 token 或 `Bearer` 头 | 无 | JSON (`title/content/type`) | 1 | `success == true` 且 `failedCount == 0` | `base_url`, `push_token` |
| `smtp` | 用户 `host:port` | `login()` | 无（SSL/STARTTLS） | `EmailMessage`（**非 HTTP**） | 1（协议会话） | 未抛异常 | `host`,`port`,`security`,`user`,`pass`,`from`,`to` |
| `wecom_app` | 固定两步 | `corpid`+`corpsecret`→`access_token`(query)，`agentid`(body) | 无 | JSON (`touser/agentid/text`) | **2（+token 缓存）** | `errcode == 0` | `corpid`,`corpsecret`,`agentid`,`touser` |
| `webhook` | 用户 URL | 可配 header/query | 可选 HMAC | 可配模板（JSON） | 1 | **可配** `success_matcher` | `url`,`method`,`headers`,`body_template`,`auth` |
| `meow` | 默认 `api.chuckfang.com` | **路径「昵称」**（无 token） | 无 | GET 路径 / POST JSON | 1 | `status == 200`（业务码） | `base_url`,`nickname`,`category`,`msg_type` |

### 3.3 建议的目录结构（每渠道一个文件）

```
notify/
  __init__.py            # send(title, text, config) + REGISTRY + 并发/聚合调度
  base.py                # Adapter Protocol, SendResult, 公共 HTTP 助手(超时/重试/UA)
  adapters/
    wecom_bot.py  dingtalk.py  feishu.py  bark.py  pushplus.py
    magicpush.py  smtp.py      wecom_app.py  webhook.py  meow.py
  signing.py             # dingtalk_sign() / feishu_sign() 集中放，附单元测试
  token_cache.py         # 仅 wecom_app 用：access_token 7200s 缓存 + 提前刷新
  validate.py            # 配置校验、URL 白名单/SSRF 防护、敏感字段加密
```

### 3.4 工程要点（针对 ipsense 的告警场景）

1. **成功判定不可一刀切**：10 个渠道的「成功」字段各不相同（见 §3.2），尤其 **PushPlus 是异步**（`code=200` 只表示收到）、**MeoW 是业务码在 `status`**、**SMTP 无响应体**、**通用 Webhook 完全自定义**。建议 `SendResult` 保留 `raw` 原样落日志。
2. **限流是硬约束，必须先聚合再发送**：ipsense 是「IP 动态感知」，IP 抖动/重复探测可能产生突发告警。最严的是 **PushPlus 实名用户 1 分钟 5 次 / 200 次每天**、**MeoW 3 秒 1 条 / 15 条每分**、**三个群机器人 20 条每分**。建议在调度层做时间窗合并（同事件 60s 内只发一次）+ 全局令牌桶 + 按渠道配额，避免触发封禁（PushPlus 超 2000 次会停微信渠道 7 天）。
3. **凭证安全**：企业微信群机器人 `key`、PushPlus `token`、MagicPush `push_token`、MeoW `nickname` 都属于「拿到即可冒充发送」的凭据，须加密存储、日志脱敏、UI 打码。
4. **关键词安全设置会吞消息**：钉钉/飞书若启用关键词，text 不含关键词即静默失败。用 `title_prefix` 统一注入关键词（如 `[ipsense]`），并在配置里提示用户把该前缀加入关键词列表。
5. **加签算法必须分开实现并单测**：见 §2.11，钉钉/飞书差异四处，建议 `signing.py` 里各写一个函数 + 用官方示例向量做单元测试。
6. **access_token 缓存**：仅企业微信应用需要，按 `(corpid, agentid)` 缓存 7200s、提前 300s 刷新，并实现「token 失效重取一次」的重试。
7. **超时与非 HTTP 通道**：所有 HTTP adapter 统一 `timeout`（建议 5~10s）；`smtp` 是唯一非 HTTP 通道，允许 adapter 自带传输实现，不要强行走 `requests`。
8. **失败降级与并发**：多渠道同时发时用并发 + 单渠道失败不影响其他渠道；返回聚合结果；`retryable` 仅对限流/5xx/网络错误置 True，参数错误/未实名/昵称未注册不重试。
9. **SSRF 防护**：通用 Webhook 与 MagicPush 的 base URL 由用户填写，需限制协议为 http/https、禁止内网元数据地址（如 `169.254.169.254`）、可选域名白名单。
10. **可观测性**：保留 `raw` 响应与业务码，提供「测试发送」按钮；对 PushPlus/MeoW 这类第三方服务失败要能明确提示「实名认证」「昵称未注册」「频率超限」等具体原因。

---

## 4. 待确认清单（需用户 / 产品侧补充）

| # | 事项 | 关联渠道 | 为什么必须确认 |
| --- | --- | --- | --- |
| 1 | **魔法推送的实际服务地址（base URL）+ 推送 Token** | 魔法推送 | 官方无统一 SaaS 地址，文档 base 为占位符 `https://your-domain.com/api`；社区示例 `magicpush..heiyu.space` 为脱敏值，不可用。需用户填自己 Docker/懒猫部署的 host:port 与「接口管理」生成的 token。另需确认是否已部署、版本（`1.12.0`）与是否启用 Bearer 头鉴权。 |
| 2 | **是否已部署 MagicPush，以及是否打算用它做统一分发** | 魔法推送 / 全部 | MagicPush 已内置本清单多数渠道；若采用「通用 Webhook → MagicPush → 多渠道」可省去 9 个 adapter，但引入单点依赖。需产品决策。 |
| 3 | **Bark 用官方公共服务还是自建**；`base_url`、`device_key`、是否启用 Basic Auth、是否用 `ciphertext` 加密 | Bark | 公共服务 `api.day.app` 依赖 APNs、无 SLA；告警含 IP 等敏感信息时建议自建 + 加密。 |
| 4 | **PushPlus 是否已完成实名认证**；使用哪个 `channel`、`token`、`template`；是否需要回调/流水号查送达 | PushPlus | 未实名返回 `905`、额度 0；默认 `wechat` 仅 200 次/天，`webhook` 渠道 1000 次/天；接口异步，送达判定策略需定。 |
| 5 | **MeoW 接收昵称**（须已在 App 注册、不含 `/`）、是否会员、是否自架相容服务 | MeoW | 无 token，昵称即凭证；昵称未注册只能靠真实推送才知（404），不能用试发探测；会员/非会员限流不同；官方提示避免共享出口 IP。 |
| 6 | **企业微信应用的 `corpid` / `corpsecret` / `agentid` / `touser`**；应用可见范围；是否开启可信 IP 白名单 | 企业微信应用 | 缺一不可；可见范围/可信 IP 配错会返回 `invaliduser`、`unlicenseduser` 或 `81013`。 |
| 7 | **钉钉 / 飞书各采用哪种安全设置**（关键词 / 加签 / 签名校验 / IP 白名单）；加签 secret（钉钉 `SEC` 开头）；关键词列表 | 钉钉、飞书 | 决定 adapter 是否计算签名、签名算法分支、以及是否在 text 注入 `title_prefix` 关键词。 |
| 8 | **企业微信群机器人完整 Webhook URL（含 `key`）**，并确认是内部群 | 企业微信群机器人 | URL 即凭证，需保密；外部群无法添加消息推送。 |
| 9 | **SMTP 全套参数**：`host`、`port`、`security`（465 SSL / 587 STARTTLS / 25）、账号、**授权码**、发件人、收件人；是否境内服务商 | SMTP | 邮件服务商差异大，国内邮箱多用授权码而非登录密码；境外服务大陆不可直连。 |
| 10 | **通用 Webhook 的目标 URL、method、headers、body 模板、鉴权方式、成功判定表达式** | 通用 Webhook | 自定义端点无统一返回码，`success_matcher` 必须可配；同时需定 SSRF 白名单策略。 |
| 11 | **大陆直连性实测**：`api.day.app`（Bark）、`api.chuckfang.com`（MeoW）、MagicPush 自托管地址 | Bark / MeoW / 魔法推送 | 前两者为个人/公共服务，无 SLA；建议 2.0.0 发布前在 fnOS 目标网络环境实测连通性与延迟。 |
| 12 | **告警聚合/去重策略与全局配额** | 全部 | IP 抖动易触发限流（PushPlus 1 分钟 5 次最严），需定时间窗合并、令牌桶、每渠道日配额与失败降级规则。 |
| 13 | **统一出站 payload 版本**（`source`/`event`/`timestamp`/`detail` 字段） | 通用 Webhook / MagicPush | 自定义 Webhook 与 MagicPush 的 body 模板需要稳定、可版本化的契约，便于用户侧解析。 |

---

## 附录：本次核验引用的官方 / 权威链接

| 渠道 | 链接 |
| --- | --- |
| 企业微信群机器人 | <https://developer.work.weixin.qq.com/document/path/91770> · <https://open.work.weixin.qq.com/help2/pc/14931> |
| 钉钉群机器人 | <https://open.dingtalk.com/document/orgapp/custom-robots-send-group-messages> · <https://open.dingtalk.com/document/orgapp/customize-robot-security-settings> |
| 飞书自定义机器人 | <https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot> · <https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN> |
| Bark | <https://bark.day.app/> · <https://github.com/Finb/bark-server> · <https://github.com/Finb/bark-server/blob/master/docs/API_V2.md> |
| PushPlus | <https://www.pushplus.plus> · <https://www.pushplus.plus/doc/> · <https://www.pushplus.plus/doc/help/limit.html> · <https://www.pushplus.plus/doc/guide/sdk.html> · <https://api.pushplus.plus/api-107787114> |
| 魔法推送 | <https://github.com/magiccode1412/magicpush> · <https://github.com/magiccode1412/magicpush/blob/main/apps/website/guide/dev/api-reference.md> · <https://magicpush.160621.xyz/> |
| SMTP | <https://docs.python.org/3/library/smtplib.html> |
| 企业微信应用 | <https://developer.work.weixin.qq.com/document/90002/90151/90854> · <https://developer.work.weixin.qq.com/document/25176> |
| MeoW | <https://www.chuckfang.com/MeoW/api_doc.html> · <https://github.com/fkccoding/meow-push-skill> |
| 旁证（fnOS 生态） | <https://docs.fnknock.cn/zh-tw/guide/event-center-and-notifications>（Knock 将 MeoW 列为 HarmonyOS 渠道） · <https://lazycat.cloud/appstore/detail/cloud.lazycat.app.magicpush> · <https://club.ugnas.com/forum.php?mod=viewthread&tid=5277> |

> 说明：本报告中所有 URL 均来自上述官方页面原文或搜索结果原文，未作推测性补全。凡官方文档使用占位符（如 `your-domain.com`、`****`、`{token}`）之处，本报告保留占位并明确标注「需用户确认」，未编造任何真实域名或参数。
